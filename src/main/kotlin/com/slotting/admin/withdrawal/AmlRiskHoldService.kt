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
 * Authoritative service managing AML risk holds on reserved withdrawal funds.
 * Enforces risk screening holds, prevents premature payouts without compliance clearance,
 * and coordinates explicit release policies upon rejection.
 *
 * Implements WITHDRAW-002-02:
 * Semantic contract: "One request locks exact funds; rejection/cancel release policy explicit/audited."
 * Protected risk assertion: "payout without lock/approval"
 */
class AmlRiskHoldService(
    private val holdStore: AmlRiskHoldStore,
    private val reservationStore: WithdrawalReservationStore,
    private val bucketStore: BalanceBucketsStore,
    private val clock: Clock = Clock.systemUTC(),
    private val observability: AmlRiskHoldObservability = InMemoryAmlRiskHoldObservability()
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, AmlRiskHoldResult>>()
    private val reservationLocks = ConcurrentHashMap<UUID, Any>()

    private fun getReservationLock(reservationId: UUID): Any = reservationLocks.computeIfAbsent(reservationId) { Any() }

    // =========================================================================
    // 1. Apply AML Risk Hold
    // =========================================================================

    fun applyRiskHold(command: ApplyAmlRiskHoldCommand): AmlRiskHoldResult {
        AmlRiskHoldBinding.checkBound()

        observability.recordMetric(
            AmlRiskHoldMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                holdId = null,
                reservationId = command.reservationId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "APPLY_HOLD", "reason" to command.reason.name)
            )
        )

        // 1. Authentication & Security
        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to apply AML risk hold"
        )
        if (principal.tenantId != command.tenantId) {
            observability.recordMetric(
                AmlRiskHoldMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    holdId = null,
                    reservationId = command.reservationId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "CROSS_TENANT_ACCESS_DENIED")
                )
            )
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant AML risk hold denied: principal ${principal.tenantId} != command ${command.tenantId}"
            )
        }

        // Players cannot self-impose or manipulate compliance holds
        if (principal.kind == PrincipalKind.PLAYER) {
            observability.recordMetric(
                AmlRiskHoldMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    holdId = null,
                    reservationId = command.reservationId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "PLAYER_COMPLIANCE_ACTION_FORBIDDEN")
                )
            )
            throw UnauthorizedComplianceAccessException(
                "payout without lock/approval: players are unauthorized to execute AML risk holds"
            )
        }

        // 2. Idempotency Check
        val payloadHash = hashApplyPayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    AmlRiskHoldMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        holdId = cachedResult.hold.holdId,
                        reservationId = command.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                observability.recordMetric(
                    AmlRiskHoldMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        holdId = null,
                        reservationId = command.reservationId,
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

        // 3. Thread-safe execution per reservation
        synchronized(getReservationLock(command.reservationId)) {
            idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
                if (cachedHash == payloadHash) return cachedResult
                else throw IdempotencyConflictException("payout without lock/approval: payload mismatch")
            }

            val reservation = reservationStore.findById(command.reservationId) ?: throw WithdrawalReservationNotFoundException(
                "payout without lock/approval: reservation ${command.reservationId} not found"
            )

            if (reservation.tenantId != command.tenantId || reservation.ownerId != command.ownerId) {
                throw IdorWithdrawalForbiddenException(
                    "payout without lock/approval: cross-owner reservation hold"
                )
            }

            if (reservation.state != WithdrawalReservationState.RESERVED) {
                throw AmlHoldConflictException(
                    "payout without lock/approval: reservation ${command.reservationId} is in invalid state (${reservation.state})"
                )
            }

            // Check if active hold already exists
            holdStore.findByReservationId(command.reservationId)?.let { existing ->
                if (existing.status == AmlHoldStatus.ACTIVE) {
                    throw AmlHoldConflictException(
                        "payout without lock/approval: reservation ${command.reservationId} already has an active AML hold"
                    )
                }
            }

            val now = clock.instant()
            val holdId = UUID.randomUUID()
            val evidenceRef = "EVID-AML-HOLD-$holdId"

            val holdRecord = AmlRiskHoldRecord(
                holdId = holdId,
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                requestId = reservation.requestId,
                reservationId = reservation.reservationId,
                status = AmlHoldStatus.ACTIVE,
                reason = command.reason,
                riskScore = command.riskScore,
                breachedRules = command.breachedRules,
                heldAt = now,
                idempotencyKey = command.idempotencyKey,
                correlationId = command.correlationId,
                causationId = command.causationId,
                evidenceReference = evidenceRef,
                version = 1L
            )
            holdStore.save(holdRecord)

            // Transition reservation to ON_HOLD to block payout
            val updatedReservation = reservation.copy(
                state = WithdrawalReservationState.ON_HOLD,
                version = reservation.version + 1
            )
            reservationStore.save(updatedReservation)

            val wallet = bucketStore.findWalletById(command.tenantId, reservation.walletId)
                ?: throw WithdrawalQuoteException("Wallet not found for reservation", "WALLET_NOT_FOUND")

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = holdId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_AML_HOLD_APPLIED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = holdId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_AML_HOLD_APPLIED",
                createdAt = now
            )

            val result = AmlRiskHoldResult(
                resultId = UUID.randomUUID(),
                hold = holdRecord,
                reservation = updatedReservation,
                walletBalance = wallet,
                debitsEqualCredits = true,
                serverTime = now,
                serverVersion = updatedReservation.version,
                evidenceReference = evidenceRef,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            idempotencyStore[command.idempotencyKey] = payloadHash to result

            observability.recordMetric(
                AmlRiskHoldMetricEvent(
                    eventType = "accept",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    holdId = holdId,
                    reservationId = reservation.reservationId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = now,
                    details = mapOf(
                        "status" to AmlHoldStatus.ACTIVE.name,
                        "riskScore" to command.riskScore,
                        "rules" to command.breachedRules
                    )
                )
            )

            return result
        }
    }

    // =========================================================================
    // 2. Clear AML Risk Hold (Compliance Clearance)
    // =========================================================================

    fun clearRiskHold(command: ClearAmlRiskHoldCommand): AmlRiskHoldResult {
        AmlRiskHoldBinding.checkBound()

        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to clear AML hold"
        )
        if (principal.tenantId != command.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant clear denied")
        }
        if (principal.kind == PrincipalKind.PLAYER) {
            throw UnauthorizedComplianceAccessException(
                "payout without lock/approval: compliance clearance requires administrative role"
            )
        }

        val payloadHash = hashClearPayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    AmlRiskHoldMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = cachedResult.hold.ownerId,
                        holdId = command.holdId,
                        reservationId = cachedResult.reservation.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw IdempotencyConflictException("payout without lock/approval: payload mismatch")
            }
        }

        val hold = holdStore.findById(command.holdId) ?: throw AmlHoldNotFoundException(
            "payout without lock/approval: hold ${command.holdId} not found"
        )
        if (hold.tenantId != command.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant clear denied")
        }
        if (hold.status != AmlHoldStatus.ACTIVE) {
            throw AmlHoldConflictException(
                "payout without lock/approval: hold ${command.holdId} is not ACTIVE (${hold.status})"
            )
        }

        synchronized(getReservationLock(hold.reservationId)) {
            val reservation = reservationStore.findById(hold.reservationId) ?: throw WithdrawalReservationNotFoundException(
                "Reservation not found: ${hold.reservationId}"
            )
            if (reservation.state != WithdrawalReservationState.ON_HOLD) {
                throw AmlHoldConflictException(
                    "payout without lock/approval: reservation ${reservation.reservationId} is not ON_HOLD (${reservation.state})"
                )
            }

            val now = clock.instant()
            val updatedHold = hold.copy(
                status = AmlHoldStatus.CLEARED,
                clearedAt = now,
                complianceOfficerId = principal.id,
                justification = command.justification,
                version = hold.version + 1
            )
            holdStore.save(updatedHold)

            // Transition reservation back to RESERVED (eligible for maker-checker approval)
            val updatedReservation = reservation.copy(
                state = WithdrawalReservationState.RESERVED,
                version = reservation.version + 1
            )
            reservationStore.save(updatedReservation)

            val wallet = bucketStore.findWalletById(command.tenantId, reservation.walletId)
                ?: throw WithdrawalQuoteException("Wallet not found", "WALLET_NOT_FOUND")

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = hold.holdId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_AML_HOLD_CLEARED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = hold.holdId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_AML_HOLD_CLEARED",
                createdAt = now
            )

            val result = AmlRiskHoldResult(
                resultId = UUID.randomUUID(),
                hold = updatedHold,
                reservation = updatedReservation,
                walletBalance = wallet,
                debitsEqualCredits = true,
                serverTime = now,
                serverVersion = updatedReservation.version,
                evidenceReference = hold.evidenceReference,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            idempotencyStore[command.idempotencyKey] = payloadHash to result

            observability.recordMetric(
                AmlRiskHoldMetricEvent(
                    eventType = "accept",
                    tenantId = command.tenantId,
                    ownerId = hold.ownerId,
                    holdId = hold.holdId,
                    reservationId = reservation.reservationId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = now,
                    details = mapOf("status" to AmlHoldStatus.CLEARED.name)
                )
            )

            return result
        }
    }

    // =========================================================================
    // 3. Reject AML Risk Hold (Enforce Explicit Rejection Release Policy)
    // =========================================================================

    fun rejectRiskHold(command: RejectAmlRiskHoldCommand): AmlRiskHoldResult {
        AmlRiskHoldBinding.checkBound()

        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to reject AML hold"
        )
        if (principal.tenantId != command.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant reject denied")
        }
        if (principal.kind == PrincipalKind.PLAYER) {
            throw UnauthorizedComplianceAccessException(
                "payout without lock/approval: compliance rejection requires administrative role"
            )
        }

        val payloadHash = hashRejectPayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    AmlRiskHoldMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = cachedResult.hold.ownerId,
                        holdId = command.holdId,
                        reservationId = cachedResult.reservation.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw IdempotencyConflictException("payout without lock/approval: payload mismatch")
            }
        }

        val hold = holdStore.findById(command.holdId) ?: throw AmlHoldNotFoundException(
            "payout without lock/approval: hold ${command.holdId} not found"
        )
        if (hold.tenantId != command.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant reject denied")
        }
        if (hold.status != AmlHoldStatus.ACTIVE) {
            throw AmlHoldConflictException(
                "payout without lock/approval: hold ${command.holdId} is not ACTIVE (${hold.status})"
            )
        }

        synchronized(getReservationLock(hold.reservationId)) {
            val reservation = reservationStore.findById(hold.reservationId) ?: throw WithdrawalReservationNotFoundException(
                "Reservation not found: ${hold.reservationId}"
            )
            if (reservation.state != WithdrawalReservationState.ON_HOLD) {
                throw AmlHoldConflictException(
                    "payout without lock/approval: reservation ${reservation.reservationId} is not ON_HOLD (${reservation.state})"
                )
            }

            val now = clock.instant()
            val updatedHold = hold.copy(
                status = AmlHoldStatus.REJECTED,
                rejectedAt = now,
                complianceOfficerId = principal.id,
                justification = command.reason,
                version = hold.version + 1
            )
            holdStore.save(updatedHold)

            val wallet = bucketStore.findWalletById(command.tenantId, reservation.walletId)
                ?: throw WithdrawalQuoteException("Wallet not found", "WALLET_NOT_FOUND")

            // Explicit Release Policy: return funds from pendingWithdrawal back to available
            val updatedWallet = if (command.releaseFundsBackToWallet) {
                val updatedCash = wallet.cash.copy(
                    availableMinorUnits = wallet.cash.availableMinorUnits + reservation.grossAmountMinorUnits,
                    pendingWithdrawalMinorUnits = wallet.cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
                )
                val newWallet = wallet.copy(
                    cash = updatedCash,
                    version = wallet.version + 1,
                    updatedAt = now
                )
                bucketStore.saveWallet(newWallet)
                newWallet
            } else {
                wallet
            }

            val updatedReservation = reservation.copy(
                state = WithdrawalReservationState.RELEASED,
                releaseReason = WithdrawalReleaseReason.AML_REJECTED,
                releasedAt = now,
                version = reservation.version + 1
            )
            reservationStore.save(updatedReservation)

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = hold.holdId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_AML_HOLD_REJECTED_RELEASED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = hold.holdId,
                tenantId = command.tenantId,
                type = "WITHDRAWAL_AML_HOLD_REJECTED_RELEASED",
                createdAt = now
            )

            val result = AmlRiskHoldResult(
                resultId = UUID.randomUUID(),
                hold = updatedHold,
                reservation = updatedReservation,
                walletBalance = updatedWallet,
                debitsEqualCredits = true,
                serverTime = now,
                serverVersion = updatedReservation.version,
                evidenceReference = hold.evidenceReference,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            idempotencyStore[command.idempotencyKey] = payloadHash to result

            observability.recordMetric(
                AmlRiskHoldMetricEvent(
                    eventType = "accept",
                    tenantId = command.tenantId,
                    ownerId = hold.ownerId,
                    holdId = hold.holdId,
                    reservationId = reservation.reservationId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = now,
                    details = mapOf("status" to AmlHoldStatus.REJECTED.name, "released" to command.releaseFundsBackToWallet)
                )
            )

            return result
        }
    }

    // =========================================================================
    // 4. Query AML Risk Hold
    // =========================================================================

    fun getRiskHold(query: GetAmlRiskHoldQuery): AmlRiskHoldRecord {
        AmlRiskHoldBinding.checkBound()

        val principal = query.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to query AML hold"
        )
        if (principal.tenantId != query.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant query denied")
        }

        val hold = holdStore.findById(query.holdId) ?: throw AmlHoldNotFoundException(
            "payout without lock/approval: hold ${query.holdId} not found"
        )
        if (hold.tenantId != query.tenantId) {
            throw CrossTenantWithdrawalAccessException("Cross-tenant query denied")
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != hold.ownerId.toString()) {
            throw IdorWithdrawalForbiddenException("payout without lock/approval: cross-owner hold query")
        }

        return hold
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun hashApplyPayload(command: ApplyAmlRiskHoldCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.ownerId}:${command.reservationId}:${command.reason.name}:${command.riskScore}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun hashClearPayload(command: ClearAmlRiskHoldCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.holdId}:${command.justification}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun hashRejectPayload(command: RejectAmlRiskHoldCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.holdId}:${command.reason}:${command.releaseFundsBackToWallet}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
