package com.slotting.admin.wallet

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Authoritative backend service managing wager and withdrawal reservations.
 *
 * Implements WALLET-003:
 * Semantic contract: "Terminal transitions idempotent; expiry is worker command, never silent deletion."
 * Protected risk assertion: "double reserve/overdraft/race"
 */
class WalletReservationService(
    private val reservationStore: WalletReservationStore,
    private val bucketStore: BalanceBucketsStore,
    private val clock: Clock = Clock.systemUTC(),
    private val observability: WalletReservationObservability = InMemoryWalletReservationObservability()
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, WalletReservationResult>>()
    private val walletLocks = ConcurrentHashMap<UUID, Any>()
    private val reservationLocks = ConcurrentHashMap<UUID, Any>()

    private fun getWalletLock(walletId: UUID): Any = walletLocks.computeIfAbsent(walletId) { Any() }
    private fun getReservationLock(reservationId: UUID): Any = reservationLocks.computeIfAbsent(reservationId) { Any() }

    // =========================================================================
    // 1. Create Reservation (Wager or Withdrawal)
    // =========================================================================

    fun createReservation(command: CreateReservationCommand): WalletReservationResult {
        WalletReservationBinding.checkBound()

        observability.recordMetric(
            ReservationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                reservationId = null,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "CREATE", "type" to command.type.name, "amount" to command.amountMinorUnits)
            )
        )

        // 1. Authentication & Security
        val principal = command.principal ?: throw UnauthorizedWalletAccessException(
            "Authentication required for reservation creation"
        )
        if (principal.tenantId != command.tenantId) {
            observability.recordMetric(
                ReservationMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    reservationId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "CROSS_TENANT_ACCESS_DENIED")
                )
            )
            throw CrossTenantAccessException(
                "Cross-tenant reservation creation denied: principal ${principal.tenantId} != command ${command.tenantId}"
            )
        }

        // 2. Input validation
        if (command.amountMinorUnits <= 0L) {
            observability.recordMetric(
                ReservationMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    reservationId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "INVALID_AMOUNT")
                )
            )
            throw InvalidReservationAmountException("Reservation amount must be strictly positive: ${command.amountMinorUnits}")
        }
        if (command.ttlSeconds <= 0L) {
            throw InvalidReservationAmountException("TTL seconds must be positive: ${command.ttlSeconds}")
        }

        // 3. Idempotency Check
        val payloadHash = hashCommandPayload("CREATE", command.tenantId, command.walletId, command.amountMinorUnits, command.type.name, command.reference)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        reservationId = cachedResult.reservation.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        reservationId = null,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }
        }

        // 4. Thread-safe execution per wallet to prevent race conditions and overdraft
        synchronized(getWalletLock(command.walletId)) {
            // Re-check idempotency under lock
            idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
                if (cachedHash == payloadHash) return cachedResult
                else throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }

            val wallet = bucketStore.findWalletById(command.tenantId, command.walletId)
                ?: throw WalletNotFoundException("Wallet not found: ${command.walletId}")

            if (wallet.tenantId != command.tenantId) {
                throw CrossTenantAccessException("Wallet tenant ${wallet.tenantId} != command ${command.tenantId}")
            }

            // Version check
            if (command.expectedVersion > 0 && wallet.version != command.expectedVersion) {
                throw StaleVersionException("Stale wallet version: expected ${command.expectedVersion}, got ${wallet.version}")
            }

            val breakdown: ReservationBucketBreakdown
            val updatedCash: CashBuckets
            val updatedBonus: BonusBuckets

            when (command.type) {
                ReservationType.WITHDRAWAL -> {
                    // Bonus funds are strictly non-withdrawable
                    if (wallet.cash.availableMinorUnits < command.amountMinorUnits) {
                        observability.recordMetric(
                            ReservationMetricEvent(
                                eventType = "reject",
                                tenantId = command.tenantId,
                                reservationId = null,
                                correlationId = command.correlationId,
                                causationId = command.causationId,
                                timestamp = clock.instant(),
                                details = mapOf("reason" to "INSUFFICIENT_FUNDS", "available" to wallet.cash.availableMinorUnits, "required" to command.amountMinorUnits)
                            )
                        )
                        throw InsufficientReservationBalanceException(
                            "Insufficient available cash for withdrawal: available ${wallet.cash.availableMinorUnits}, requested ${command.amountMinorUnits}"
                        )
                    }
                    breakdown = ReservationBucketBreakdown(
                        cashMinorUnits = command.amountMinorUnits,
                        bonusMinorUnits = 0L
                    )
                    updatedCash = wallet.cash.copy(
                        availableMinorUnits = wallet.cash.availableMinorUnits - command.amountMinorUnits,
                        lockedMinorUnits = wallet.cash.lockedMinorUnits + command.amountMinorUnits
                    )
                    updatedBonus = wallet.bonus
                }
                ReservationType.WAGER -> {
                    // Total available wagering balance = cash available + bonus active
                    if (wallet.availableWageringMinorUnits < command.amountMinorUnits) {
                        observability.recordMetric(
                            ReservationMetricEvent(
                                eventType = "reject",
                                tenantId = command.tenantId,
                                reservationId = null,
                                correlationId = command.correlationId,
                                causationId = command.causationId,
                                timestamp = clock.instant(),
                                details = mapOf("reason" to "INSUFFICIENT_FUNDS", "available" to wallet.availableWageringMinorUnits, "required" to command.amountMinorUnits)
                            )
                        )
                        throw InsufficientReservationBalanceException(
                            "Insufficient wagering balance: available ${wallet.availableWageringMinorUnits}, requested ${command.amountMinorUnits}"
                        )
                    }

                    // Cash-first wagering precedence
                    val cashToLock = if (command.preferCashFirst) {
                        minOf(wallet.cash.availableMinorUnits, command.amountMinorUnits)
                    } else {
                        0L
                    }
                    val bonusToLock = command.amountMinorUnits - cashToLock

                    breakdown = ReservationBucketBreakdown(
                        cashMinorUnits = cashToLock,
                        bonusMinorUnits = bonusToLock
                    )
                    updatedCash = wallet.cash.copy(
                        availableMinorUnits = wallet.cash.availableMinorUnits - cashToLock,
                        lockedMinorUnits = wallet.cash.lockedMinorUnits + cashToLock
                    )
                    updatedBonus = wallet.bonus.copy(
                        activeMinorUnits = wallet.bonus.activeMinorUnits - bonusToLock,
                        lockedMinorUnits = wallet.bonus.lockedMinorUnits + bonusToLock
                    )
                }
            }

            val now = clock.instant()
            val updatedWallet = wallet.copy(
                cash = updatedCash,
                bonus = updatedBonus,
                version = wallet.version + 1,
                updatedAt = now
            )
            bucketStore.saveWallet(updatedWallet)

            val reservationId = UUID.randomUUID()
            val reservationRecord = WalletReservationRecord(
                reservationId = reservationId,
                tenantId = command.tenantId,
                walletId = wallet.walletId,
                ownerId = wallet.ownerId,
                currencyCode = wallet.currencyCode,
                type = command.type,
                amountMinorUnits = command.amountMinorUnits,
                breakdown = breakdown,
                status = ReservationStatus.RESERVED,
                reference = command.reference,
                expiresAt = now.plusSeconds(command.ttlSeconds),
                reservedAt = now,
                idempotencyKey = command.idempotencyKey,
                correlationId = command.correlationId,
                causationId = command.causationId,
                evidenceReference = "EVID-RESERVE-$reservationId",
                version = 1L
            )
            reservationStore.save(reservationRecord)

            val auditEvent = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = reservationId,
                tenantId = command.tenantId,
                type = "WALLET_RESERVATION_CREATED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId
            )
            val outboxEvent = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = reservationId,
                tenantId = command.tenantId,
                type = "WALLET_RESERVATION_CREATED",
                createdAt = now
            )

            val result = WalletReservationResult(
                resultId = UUID.randomUUID(),
                reservation = reservationRecord,
                previousStatus = null,
                debitsEqualCredits = true,
                serverTime = now,
                serverVersion = updatedWallet.version,
                evidenceReference = reservationRecord.evidenceReference,
                auditEvent = auditEvent,
                outboxEvent = outboxEvent,
                hasAndroidDbImpact = false,
                hasAndroidLifecycleClaim = false
            )

            idempotencyStore[command.idempotencyKey] = payloadHash to result
            observability.recordMetric(
                ReservationMetricEvent(
                    eventType = "accept",
                    tenantId = command.tenantId,
                    reservationId = reservationId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = now,
                    details = mapOf("status" to "RESERVED", "amount" to command.amountMinorUnits)
                )
            )
            return result
        }
    }

    // =========================================================================
    // 2. Capture Reservation
    // =========================================================================

    fun captureReservation(command: CaptureReservationCommand): WalletReservationResult {
        WalletReservationBinding.checkBound()

        observability.recordMetric(
            ReservationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                reservationId = command.reservationId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "CAPTURE")
            )
        )

        val principal = command.principal ?: throw UnauthorizedWalletAccessException("Authentication required")
        if (principal.tenantId != command.tenantId) {
            throw CrossTenantAccessException("Cross-tenant reservation capture denied")
        }

        val payloadHash = hashCommandPayload("CAPTURE", command.tenantId, command.reservationId)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        reservationId = command.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }
        }

        synchronized(getReservationLock(command.reservationId)) {
            // Re-check idempotency under lock
            idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
                if (cachedHash == payloadHash) return cachedResult
                else throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }

            val reservation = reservationStore.findById(command.reservationId)
                ?: throw ReservationNotFoundException("Reservation not found: ${command.reservationId}")

            if (reservation.tenantId != command.tenantId) {
                throw CrossTenantAccessException("Reservation tenant ${reservation.tenantId} != command ${command.tenantId}")
            }

            // Semantic contract: Terminal transitions idempotent!
            if (reservation.status == ReservationStatus.CAPTURED) {
                val now = clock.instant()
                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = reservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_CAPTURE_IDEMPOTENT_REPLAY",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                val outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = reservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_CAPTURE_IDEMPOTENT_REPLAY",
                    createdAt = now
                )
                val replayResult = WalletReservationResult(
                    resultId = UUID.randomUUID(),
                    reservation = reservation,
                    previousStatus = ReservationStatus.CAPTURED,
                    debitsEqualCredits = true,
                    serverTime = now,
                    serverVersion = reservation.version,
                    evidenceReference = reservation.evidenceReference,
                    auditEvent = auditEvent,
                    outboxEvent = outboxEvent
                )
                idempotencyStore[command.idempotencyKey] = payloadHash to replayResult
                return replayResult
            }

            if (reservation.status == ReservationStatus.RELEASED || reservation.status == ReservationStatus.EXPIRED) {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        reservationId = command.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant(),
                        details = mapOf("reason" to "TERMINAL_STATUS_CONFLICT", "currentStatus" to reservation.status.name)
                    )
                )
                throw TerminalReservationTransitionException(
                    "Cannot capture reservation ${reservation.reservationId} in terminal status ${reservation.status}"
                )
            }

            val now = clock.instant()
            if (now.isAfter(reservation.expiresAt)) {
                throw ReservationExpiredException("Reservation ${reservation.reservationId} expired at ${reservation.expiresAt}")
            }

            // Execute capture under wallet lock
            synchronized(getWalletLock(reservation.walletId)) {
                val wallet = bucketStore.findWalletById(reservation.tenantId, reservation.walletId)
                    ?: throw WalletNotFoundException("Wallet not found: ${reservation.walletId}")

                // Permanently deduct locked funds (debit)
                val updatedCash = wallet.cash.copy(
                    lockedMinorUnits = wallet.cash.lockedMinorUnits - reservation.breakdown.cashMinorUnits
                )
                val updatedBonus = wallet.bonus.copy(
                    lockedMinorUnits = wallet.bonus.lockedMinorUnits - reservation.breakdown.bonusMinorUnits
                )
                val updatedWallet = wallet.copy(
                    cash = updatedCash,
                    bonus = updatedBonus,
                    version = wallet.version + 1,
                    updatedAt = now
                )
                bucketStore.saveWallet(updatedWallet)

                val updatedReservation = reservation.copy(
                    status = ReservationStatus.CAPTURED,
                    capturedAt = now,
                    version = reservation.version + 1
                )
                reservationStore.save(updatedReservation)

                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = updatedReservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_CAPTURED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                val outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = updatedReservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_CAPTURED",
                    createdAt = now
                )

                val result = WalletReservationResult(
                    resultId = UUID.randomUUID(),
                    reservation = updatedReservation,
                    previousStatus = ReservationStatus.RESERVED,
                    debitsEqualCredits = true,
                    serverTime = now,
                    serverVersion = updatedWallet.version,
                    evidenceReference = updatedReservation.evidenceReference,
                    auditEvent = auditEvent,
                    outboxEvent = outboxEvent
                )

                idempotencyStore[command.idempotencyKey] = payloadHash to result
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "terminal_result",
                        tenantId = command.tenantId,
                        reservationId = updatedReservation.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = now,
                        details = mapOf("status" to "CAPTURED")
                    )
                )
                return result
            }
        }
    }

    // =========================================================================
    // 3. Release Reservation
    // =========================================================================

    fun releaseReservation(command: ReleaseReservationCommand): WalletReservationResult {
        WalletReservationBinding.checkBound()

        observability.recordMetric(
            ReservationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                reservationId = command.reservationId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "RELEASE", "reason" to command.reason)
            )
        )

        val principal = command.principal ?: throw UnauthorizedWalletAccessException("Authentication required")
        if (principal.tenantId != command.tenantId) {
            throw CrossTenantAccessException("Cross-tenant reservation release denied")
        }

        val payloadHash = hashCommandPayload("RELEASE", command.tenantId, command.reservationId, command.reason)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        reservationId = command.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }
        }

        synchronized(getReservationLock(command.reservationId)) {
            idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
                if (cachedHash == payloadHash) return cachedResult
                else throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }

            val reservation = reservationStore.findById(command.reservationId)
                ?: throw ReservationNotFoundException("Reservation not found: ${command.reservationId}")

            if (reservation.tenantId != command.tenantId) {
                throw CrossTenantAccessException("Reservation tenant ${reservation.tenantId} != command ${command.tenantId}")
            }

            // Semantic contract: Terminal transitions idempotent!
            if (reservation.status == ReservationStatus.RELEASED) {
                val now = clock.instant()
                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = reservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_RELEASE_IDEMPOTENT_REPLAY",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                val outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = reservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_RELEASE_IDEMPOTENT_REPLAY",
                    createdAt = now
                )
                val replayResult = WalletReservationResult(
                    resultId = UUID.randomUUID(),
                    reservation = reservation,
                    previousStatus = ReservationStatus.RELEASED,
                    debitsEqualCredits = true,
                    serverTime = now,
                    serverVersion = reservation.version,
                    evidenceReference = reservation.evidenceReference,
                    auditEvent = auditEvent,
                    outboxEvent = outboxEvent
                )
                idempotencyStore[command.idempotencyKey] = payloadHash to replayResult
                return replayResult
            }

            if (reservation.status == ReservationStatus.CAPTURED || reservation.status == ReservationStatus.EXPIRED) {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        reservationId = command.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant(),
                        details = mapOf("reason" to "TERMINAL_STATUS_CONFLICT", "currentStatus" to reservation.status.name)
                    )
                )
                throw TerminalReservationTransitionException(
                    "Cannot release reservation ${reservation.reservationId} in terminal status ${reservation.status}"
                )
            }

            val now = clock.instant()

            // Unlock locked funds back to available under wallet lock
            synchronized(getWalletLock(reservation.walletId)) {
                val wallet = bucketStore.findWalletById(reservation.tenantId, reservation.walletId)
                    ?: throw WalletNotFoundException("Wallet not found: ${reservation.walletId}")

                val updatedCash = wallet.cash.copy(
                    availableMinorUnits = wallet.cash.availableMinorUnits + reservation.breakdown.cashMinorUnits,
                    lockedMinorUnits = wallet.cash.lockedMinorUnits - reservation.breakdown.cashMinorUnits
                )
                val updatedBonus = wallet.bonus.copy(
                    activeMinorUnits = wallet.bonus.activeMinorUnits + reservation.breakdown.bonusMinorUnits,
                    lockedMinorUnits = wallet.bonus.lockedMinorUnits - reservation.breakdown.bonusMinorUnits
                )
                val updatedWallet = wallet.copy(
                    cash = updatedCash,
                    bonus = updatedBonus,
                    version = wallet.version + 1,
                    updatedAt = now
                )
                bucketStore.saveWallet(updatedWallet)

                val updatedReservation = reservation.copy(
                    status = ReservationStatus.RELEASED,
                    releasedAt = now,
                    version = reservation.version + 1
                )
                reservationStore.save(updatedReservation)

                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = updatedReservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_RELEASED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                val outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = updatedReservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_RELEASED",
                    createdAt = now
                )

                val result = WalletReservationResult(
                    resultId = UUID.randomUUID(),
                    reservation = updatedReservation,
                    previousStatus = ReservationStatus.RESERVED,
                    debitsEqualCredits = true,
                    serverTime = now,
                    serverVersion = updatedWallet.version,
                    evidenceReference = updatedReservation.evidenceReference,
                    auditEvent = auditEvent,
                    outboxEvent = outboxEvent
                )

                idempotencyStore[command.idempotencyKey] = payloadHash to result
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "terminal_result",
                        tenantId = command.tenantId,
                        reservationId = updatedReservation.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = now,
                        details = mapOf("status" to "RELEASED", "reason" to command.reason)
                    )
                )
                return result
            }
        }
    }

    // =========================================================================
    // 4. Expire Reservation (Audited worker command, NEVER silent deletion)
    // =========================================================================

    fun expireReservation(command: ExpireReservationCommand): WalletReservationResult {
        WalletReservationBinding.checkBound()

        observability.recordMetric(
            ReservationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                reservationId = command.reservationId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "EXPIRE", "workerId" to command.workerId)
            )
        )

        val principal = command.principal ?: throw UnauthorizedWalletAccessException("Authentication required")
        if (principal.tenantId != command.tenantId) {
            throw CrossTenantAccessException("Cross-tenant reservation expiry denied")
        }

        val payloadHash = hashCommandPayload("EXPIRE", command.tenantId, command.reservationId, command.workerId)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        reservationId = command.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }
        }

        synchronized(getReservationLock(command.reservationId)) {
            idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
                if (cachedHash == payloadHash) return cachedResult
                else throw IdempotencyConflictException("Payload mismatch for idempotency key: ${command.idempotencyKey}")
            }

            val reservation = reservationStore.findById(command.reservationId)
                ?: throw ReservationNotFoundException("Reservation not found: ${command.reservationId}")

            if (reservation.tenantId != command.tenantId) {
                throw CrossTenantAccessException("Reservation tenant ${reservation.tenantId} != command ${command.tenantId}")
            }

            // Semantic contract: Terminal transitions idempotent!
            if (reservation.status == ReservationStatus.EXPIRED) {
                val now = clock.instant()
                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = reservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_EXPIRE_IDEMPOTENT_REPLAY",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                val outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = reservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_EXPIRE_IDEMPOTENT_REPLAY",
                    createdAt = now
                )
                val replayResult = WalletReservationResult(
                    resultId = UUID.randomUUID(),
                    reservation = reservation,
                    previousStatus = ReservationStatus.EXPIRED,
                    debitsEqualCredits = true,
                    serverTime = now,
                    serverVersion = reservation.version,
                    evidenceReference = reservation.evidenceReference,
                    auditEvent = auditEvent,
                    outboxEvent = outboxEvent
                )
                idempotencyStore[command.idempotencyKey] = payloadHash to replayResult
                return replayResult
            }

            if (reservation.status == ReservationStatus.CAPTURED || reservation.status == ReservationStatus.RELEASED) {
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        reservationId = command.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant(),
                        details = mapOf("reason" to "TERMINAL_STATUS_CONFLICT", "currentStatus" to reservation.status.name)
                    )
                )
                throw TerminalReservationTransitionException(
                    "Cannot expire reservation ${reservation.reservationId} in terminal status ${reservation.status}"
                )
            }

            val now = clock.instant()

            // Unlock locked funds back to available under wallet lock
            synchronized(getWalletLock(reservation.walletId)) {
                val wallet = bucketStore.findWalletById(reservation.tenantId, reservation.walletId)
                    ?: throw WalletNotFoundException("Wallet not found: ${reservation.walletId}")

                val updatedCash = wallet.cash.copy(
                    availableMinorUnits = wallet.cash.availableMinorUnits + reservation.breakdown.cashMinorUnits,
                    lockedMinorUnits = wallet.cash.lockedMinorUnits - reservation.breakdown.cashMinorUnits
                )
                val updatedBonus = wallet.bonus.copy(
                    activeMinorUnits = wallet.bonus.activeMinorUnits + reservation.breakdown.bonusMinorUnits,
                    lockedMinorUnits = wallet.bonus.lockedMinorUnits - reservation.breakdown.bonusMinorUnits
                )
                val updatedWallet = wallet.copy(
                    cash = updatedCash,
                    bonus = updatedBonus,
                    version = wallet.version + 1,
                    updatedAt = now
                )
                bucketStore.saveWallet(updatedWallet)

                // Semantic contract: "expiry is worker command, never silent deletion."
                // Record is preserved with status EXPIRED, never removed from store!
                val updatedReservation = reservation.copy(
                    status = ReservationStatus.EXPIRED,
                    expiredAt = now,
                    version = reservation.version + 1
                )
                reservationStore.save(updatedReservation)

                val auditEvent = AuditEvent(
                    eventId = UUID.randomUUID(),
                    resultId = updatedReservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_EXPIRED",
                    occurredAt = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId
                )
                val outboxEvent = OutboxEvent(
                    eventId = UUID.randomUUID(),
                    resultId = updatedReservation.reservationId,
                    tenantId = command.tenantId,
                    type = "WALLET_RESERVATION_EXPIRED",
                    createdAt = now
                )

                val result = WalletReservationResult(
                    resultId = UUID.randomUUID(),
                    reservation = updatedReservation,
                    previousStatus = ReservationStatus.RESERVED,
                    debitsEqualCredits = true,
                    serverTime = now,
                    serverVersion = updatedWallet.version,
                    evidenceReference = updatedReservation.evidenceReference,
                    auditEvent = auditEvent,
                    outboxEvent = outboxEvent
                )

                idempotencyStore[command.idempotencyKey] = payloadHash to result
                observability.recordMetric(
                    ReservationMetricEvent(
                        eventType = "terminal_result",
                        tenantId = command.tenantId,
                        reservationId = updatedReservation.reservationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = now,
                        details = mapOf("status" to "EXPIRED", "workerId" to command.workerId)
                    )
                )
                return result
            }
        }
    }

    // =========================================================================
    // Query API
    // =========================================================================

    fun getReservation(reservationId: UUID): WalletReservationRecord? =
        reservationStore.findById(reservationId)

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun hashCommandPayload(action: String, vararg parts: Any?): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(action.toByteArray(StandardCharsets.UTF_8))
        parts.forEach { part ->
            md.update(part?.toString()?.toByteArray(StandardCharsets.UTF_8) ?: ByteArray(0))
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
