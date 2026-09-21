package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.wallet.BalanceBucketsStore
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Authoritative service managing withdrawal fund reservations.
 * Enforces exact fund locking in balance buckets (moving available cash to pending withdrawal)
 * and explicit, audited release policies upon cancellation, rejection, or expiry.
 *
 * Implements WITHDRAW-002-01:
 * Semantic contract: "One request locks exact funds; rejection/cancel release policy explicit/audited."
 * Protected risk assertion: "payout without lock/approval"
 */
class WithdrawalReservationService(
    private val reservationStore: WithdrawalReservationStore,
    private val requestStore: WithdrawalRequestStore,
    private val bucketStore: BalanceBucketsStore,
    private val clock: Clock = Clock.systemUTC(),
    private val observability: WithdrawalReservationObservability = InMemoryWithdrawalReservationObservability()
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, WithdrawalReservationResult>>()
    private val walletLocks = ConcurrentHashMap<UUID, Any>()

    private fun getWalletLock(walletId: UUID): Any = walletLocks.computeIfAbsent(walletId) { Any() }

    // =========================================================================
    // 1. Reserve Withdrawal Funds (Exact Locking)
    // =========================================================================

    fun reserveFunds(command: ReserveWithdrawalFundsCommand): WithdrawalReservationResult {
        WithdrawalReservationBinding.checkBound()

        observability.recordMetric(
            WithdrawalReservationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                reservationId = null,
                requestId = command.requestId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "RESERVE")
            )
        )

        // 1. Authentication & Tenant Security
        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to reserve withdrawal funds"
        )
        if (principal.tenantId != command.tenantId) {
            observability.recordMetric(
                WithdrawalReservationMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    reservationId = null,
                    requestId = command.requestId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "CROSS_TENANT_ACCESS_DENIED")
                )
            )
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant reservation denied: principal ${principal.tenantId} != command ${command.tenantId}"
            )
        }

        // 2. IDOR Prevention
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.ownerId.toString()) {
            observability.recordMetric(
                WithdrawalReservationMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    reservationId = null,
                    requestId = command.requestId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "IDOR_FORBIDDEN")
                )
            )
            throw IdorWithdrawalForbiddenException(
                "payout without lock/approval: cross-owner reservation forbidden for ${principal.id}"
            )
        }

        // 3. Idempotency Check
        val payloadHash = hashReservePayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    WithdrawalReservationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        reservationId = cachedResult.reservation.reservationId,
                        requestId = command.requestId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                observability.recordMetric(
                    WithdrawalReservationMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        reservationId = null,
                        requestId = command.requestId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                throw IdempotencyConflictException(
                    "payout without lock/approval: payload mismatch for idempotency key ${command.idempotencyKey}"
                )
            }
        }

        // 4. Validate Withdrawal Request
        val request = requestStore.findById(command.requestId) ?: throw WithdrawalRequestNotFoundException(
            "payout without lock/approval: withdrawal request ${command.requestId} not found"
        )
        if (request.tenantId != command.tenantId || request.ownerId != command.ownerId) {
            throw IdorWithdrawalForbiddenException(
                "payout without lock/approval: cross-owner or cross-tenant withdrawal request"
            )
        }
        if (request.status != WithdrawalRequestStatus.REQUESTED) {
            throw WithdrawalRequestInvalidStateException(
                "payout without lock/approval: request ${command.requestId} is in invalid state (${request.status})"
            )
        }

        // 5. Prevent Duplicate Reservation for Same Request
        reservationStore.findByRequestId(command.requestId)?.let { existing ->
            if (existing.state == WithdrawalReservationState.RESERVED) {
                throw AlreadyReservedException(
                    "payout without lock/approval: request ${command.requestId} is already reserved"
                )
            }
        }

        // 6. Thread-safe Wallet Locking & Balance Deduction
        val wallet = bucketStore.findWalletByOwnerAndCurrency(command.tenantId, command.ownerId, request.currencyCode)
            ?: throw WithdrawalQuoteException("Wallet not found for owner ${command.ownerId}", "WALLET_NOT_FOUND")

        synchronized(getWalletLock(wallet.walletId)) {
            // Re-check idempotency under lock
            idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
                if (cachedHash == payloadHash) return cachedResult
                else throw IdempotencyConflictException("payout without lock/approval: payload mismatch")
            }

            // Fresh wallet check
            val freshWallet = bucketStore.findWalletById(command.tenantId, wallet.walletId) ?: wallet
            if (freshWallet.cash.availableMinorUnits < request.grossAmountMinorUnits) {
                observability.recordMetric(
                    WithdrawalReservationMetricEvent(
                        eventType = "reject",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        reservationId = null,
                        requestId = command.requestId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant(),
                        details = mapOf(
                            "reason" to "INSUFFICIENT_FUNDS",
                            "available" to freshWallet.cash.availableMinorUnits,
                            "required" to request.grossAmountMinorUnits
                        )
                    )
                )
                throw InsufficientWithdrawableFundsException(
                    "payout without lock/approval: insufficient available cash ${freshWallet.cash.availableMinorUnits} for required ${request.grossAmountMinorUnits}"
                )
            }

            val now = clock.instant()
            // Lock exact funds: move from available to pendingWithdrawal
            val updatedCash = freshWallet.cash.copy(
                availableMinorUnits = freshWallet.cash.availableMinorUnits - request.grossAmountMinorUnits,
                pendingWithdrawalMinorUnits = freshWallet.cash.pendingWithdrawalMinorUnits + request.grossAmountMinorUnits
            )
            val updatedWallet = freshWallet.copy(
                cash = updatedCash,
                version = freshWallet.version + 1,
                updatedAt = now
            )
            bucketStore.saveWallet(updatedWallet)

            val reservationId = UUID.randomUUID()
            val evidenceRef = "EVID-WITHDRAW-RES-$reservationId"
            val reservationRecord = WithdrawalReservationRecord(
                reservationId = reservationId,
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                walletId = freshWallet.walletId,
                requestId = command.requestId,
                currencyCode = request.currencyCode,
                grossAmountMinorUnits = request.grossAmountMinorUnits,
                state = WithdrawalReservationState.RESERVED,
                releaseReason = null,
                reservedAt = now,
                expiresAt = now.plusSeconds(command.ttlSeconds),
                releasedAt = null,
                idempotencyKey = command.idempotencyKey,
                correlationId = command.correlationId,
                causationId = command.causationId,
                evidenceReference = evidenceRef,
                version = 1L
            )
            reservationStore.save(reservationRecord)

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = reservationId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_FUNDS_RESERVED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = reservationId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_FUNDS_RESERVED",
                createdAt = now
            )

            val result = WithdrawalReservationResult(
                resultId = UUID.randomUUID(),
                reservation = reservationRecord,
                walletBalance = updatedWallet,
                debitsEqualCredits = true,
                serverTime = now,
                serverVersion = updatedWallet.version,
                evidenceReference = evidenceRef,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            idempotencyStore[command.idempotencyKey] = payloadHash to result

            observability.recordMetric(
                WithdrawalReservationMetricEvent(
                    eventType = "accept",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    reservationId = reservationId,
                    requestId = command.requestId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = now,
                    details = mapOf(
                        "amount" to request.grossAmountMinorUnits,
                        "availableLeft" to updatedWallet.cash.availableMinorUnits,
                        "pendingWithdrawal" to updatedWallet.cash.pendingWithdrawalMinorUnits
                    )
                )
            )

            return result
        }
    }

    // =========================================================================
    // 2. Release Withdrawal Funds (Explicit Cancellation / Rejection Policy)
    // =========================================================================

    fun releaseFunds(command: ReleaseWithdrawalFundsCommand): WithdrawalReservationResult {
        WithdrawalReservationBinding.checkBound()

        observability.recordMetric(
            WithdrawalReservationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                reservationId = command.reservationId,
                requestId = null,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "RELEASE", "reason" to command.reason.name)
            )
        )

        // 1. Authentication & Tenant Security
        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to release withdrawal funds"
        )
        if (principal.tenantId != command.tenantId) {
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant release denied: principal ${principal.tenantId} != command ${command.tenantId}"
            )
        }

        // 2. IDOR Prevention
        if (principal.kind == PrincipalKind.PLAYER) {
            if (principal.id != command.ownerId.toString()) {
                throw IdorWithdrawalForbiddenException(
                    "payout without lock/approval: cross-owner release forbidden for ${principal.id}"
                )
            }
            if (command.reason != WithdrawalReleaseReason.PLAYER_CANCELLED) {
                throw IdorWithdrawalForbiddenException(
                    "payout without lock/approval: player can only release via PLAYER_CANCELLED"
                )
            }
        }

        // 3. Idempotency Check
        val payloadHash = hashReleasePayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    WithdrawalReservationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        reservationId = command.reservationId,
                        requestId = cachedResult.reservation.requestId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw IdempotencyConflictException(
                    "payout without lock/approval: payload mismatch for idempotency key ${command.idempotencyKey}"
                )
            }
        }

        // 4. Retrieve Existing Reservation
        val reservation = reservationStore.findById(command.reservationId) ?: throw WithdrawalReservationNotFoundException(
            "payout without lock/approval: reservation ${command.reservationId} not found"
        )
        if (reservation.tenantId != command.tenantId || reservation.ownerId != command.ownerId) {
            throw IdorWithdrawalForbiddenException(
                "payout without lock/approval: cross-owner reservation access"
            )
        }
        if (reservation.state != WithdrawalReservationState.RESERVED) {
            throw WithdrawalReservationConflictException(
                "payout without lock/approval: reservation ${command.reservationId} is in invalid state (${reservation.state})"
            )
        }

        // 5. Wallet Unlock
        val wallet = bucketStore.findWalletById(command.tenantId, reservation.walletId)
            ?: throw WithdrawalQuoteException("Wallet not found: ${reservation.walletId}", "WALLET_NOT_FOUND")

        synchronized(getWalletLock(wallet.walletId)) {
            // Re-check idempotency under lock
            idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
                if (cachedHash == payloadHash) return cachedResult
                else throw IdempotencyConflictException("payout without lock/approval: payload mismatch")
            }

            val freshWallet = bucketStore.findWalletById(command.tenantId, wallet.walletId) ?: wallet
            val now = clock.instant()

            // Release exact funds back from pendingWithdrawal to available
            val updatedCash = freshWallet.cash.copy(
                availableMinorUnits = freshWallet.cash.availableMinorUnits + reservation.grossAmountMinorUnits,
                pendingWithdrawalMinorUnits = freshWallet.cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
            )
            val updatedWallet = freshWallet.copy(
                cash = updatedCash,
                version = freshWallet.version + 1,
                updatedAt = now
            )
            bucketStore.saveWallet(updatedWallet)

            val updatedReservation = reservation.copy(
                state = WithdrawalReservationState.RELEASED,
                releaseReason = command.reason,
                releasedAt = now,
                version = reservation.version + 1
            )
            reservationStore.save(updatedReservation)

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = reservation.reservationId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_FUNDS_RELEASED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = reservation.reservationId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_FUNDS_RELEASED",
                createdAt = now
            )

            val result = WithdrawalReservationResult(
                resultId = UUID.randomUUID(),
                reservation = updatedReservation,
                walletBalance = updatedWallet,
                debitsEqualCredits = true,
                serverTime = now,
                serverVersion = updatedWallet.version,
                evidenceReference = reservation.evidenceReference,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            idempotencyStore[command.idempotencyKey] = payloadHash to result

            observability.recordMetric(
                WithdrawalReservationMetricEvent(
                    eventType = "accept",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    reservationId = reservation.reservationId,
                    requestId = reservation.requestId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = now,
                    details = mapOf("action" to "RELEASE", "reason" to command.reason.name)
                )
            )

            return result
        }
    }

    // =========================================================================
    // 3. Query Reservation
    // =========================================================================

    fun getReservation(query: GetWithdrawalReservationQuery): WithdrawalReservationRecord {
        WithdrawalReservationBinding.checkBound()

        val principal = query.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to query reservation"
        )
        if (principal.tenantId != query.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant query denied")
        }

        val reservation = reservationStore.findById(query.reservationId) ?: throw WithdrawalReservationNotFoundException(
            "payout without lock/approval: reservation ${query.reservationId} not found"
        )

        if (reservation.tenantId != query.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant query denied")
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != reservation.ownerId.toString()) {
            throw IdorWithdrawalForbiddenException("payout without lock/approval: cross-owner reservation query")
        }

        return reservation
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun hashReservePayload(command: ReserveWithdrawalFundsCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.ownerId}:${command.requestId}:${command.ttlSeconds}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun hashReleasePayload(command: ReleaseWithdrawalFundsCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.ownerId}:${command.reservationId}:${command.reason.name}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
