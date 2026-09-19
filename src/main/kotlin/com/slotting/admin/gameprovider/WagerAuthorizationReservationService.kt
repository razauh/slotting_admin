package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerRegistrationStore
import com.slotting.admin.identity.ServerEligibilityStore
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce GAME-006: Wager authorization/reservation.
 * Protected risk: "insufficient/self-excluded/duplicate/concurrent bet"
 * Semantic contract: "One idempotency key→one reservation; server owns amount/limits/round eligibility."
 */
object WagerAuthorizationReservationBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("insufficient/self-excluded/duplicate/concurrent bet")
        }
    }
}

enum class WagerReservationStatus {
    RESERVED,
    COMMITTED,
    RELEASED,
    EXPIRED,
}

data class PlayerWalletBalanceRecord(
    val tenantId: String,
    val playerId: UUID,
    val currencyCode: String,
    var availableBalanceMinorUnits: Long,
    var reservedBalanceMinorUnits: Long,
    var version: Long = 1L,
)

data class WagerReservationRecord(
    val reservationId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val canonicalRoundId: UUID,
    val canonicalTransactionId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    var status: WagerReservationStatus,
    val reservedAt: Instant,
    val expiresAt: Instant,
    var committedAt: Instant? = null,
    var releasedAt: Instant? = null,
    var expiredAt: Instant? = null,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    var version: Long = 1L,
)

data class AuthorizeAndReserveWagerCommand(
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val jurisdictionCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class CommitWagerReservationCommand(
    val tenantId: String,
    val reservationId: UUID,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ReleaseWagerReservationCommand(
    val tenantId: String,
    val reservationId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ExpireWagerReservationCommand(
    val tenantId: String,
    val reservationId: UUID,
    val correlationId: String,
    val causationId: String,
)

data class WagerReservationResult(
    val resultId: UUID,
    val reservationId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val canonicalRoundId: UUID,
    val canonicalTransactionId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: WagerReservationStatus,
    val availableBalanceMinorUnits: Long,
    val reservedBalanceMinorUnits: Long,
    val expiresAt: Instant,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface WagerAuthorizationReservationStore {
    fun findWalletBalance(tenantId: String, playerId: UUID, currencyCode: String): PlayerWalletBalanceRecord?
    fun saveWalletBalance(balance: PlayerWalletBalanceRecord)
    fun findReservation(tenantId: String, reservationId: UUID): WagerReservationRecord?
    fun findReservationByExternalTx(tenantId: String, providerId: String, externalTransactionId: String): WagerReservationRecord?
    fun saveReservation(
        reservation: WagerReservationRecord,
        result: WagerReservationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateReservation(
        reservation: WagerReservationRecord,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WagerReservationResult>?
    fun findTerminalIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WagerReservationResult>?
    fun saveTerminalIdempotency(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: WagerReservationResult,
    )
}

class InMemoryWagerAuthorizationReservationStore : WagerAuthorizationReservationStore {
    private val balances = ConcurrentHashMap<String, PlayerWalletBalanceRecord>()
    private val reservations = ConcurrentHashMap<String, WagerReservationRecord>()
    private val reservationsByExtTx = ConcurrentHashMap<String, WagerReservationRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, WagerReservationResult>>()
    private val terminalIdempotency = ConcurrentHashMap<String, Pair<String, WagerReservationResult>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun balKey(tenantId: String, playerId: UUID, currency: String) = "$tenantId:$playerId:$currency"
    private fun resKey(tenantId: String, reservationId: UUID) = "$tenantId:$reservationId"
    private fun txKey(tenantId: String, providerId: String, externalTxId: String) = "$tenantId:$providerId:$externalTxId"

    @Synchronized
    override fun findWalletBalance(tenantId: String, playerId: UUID, currencyCode: String): PlayerWalletBalanceRecord? {
        return balances[balKey(tenantId, playerId, currencyCode)]?.copy()
    }

    @Synchronized
    override fun saveWalletBalance(balance: PlayerWalletBalanceRecord) {
        balances[balKey(balance.tenantId, balance.playerId, balance.currencyCode)] = balance.copy()
    }

    @Synchronized
    override fun findReservation(tenantId: String, reservationId: UUID): WagerReservationRecord? {
        return reservations[resKey(tenantId, reservationId)]?.copy()
    }

    @Synchronized
    override fun findReservationByExternalTx(tenantId: String, providerId: String, externalTransactionId: String): WagerReservationRecord? {
        return reservationsByExtTx[txKey(tenantId, providerId, externalTransactionId)]?.copy()
    }

    @Synchronized
    override fun saveReservation(
        reservation: WagerReservationRecord,
        result: WagerReservationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        reservations[resKey(reservation.tenantId, reservation.reservationId)] = reservation.copy()
        reservationsByExtTx[txKey(reservation.tenantId, reservation.providerId, reservation.externalTransactionId)] = reservation.copy()
        idempotency["${reservation.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateReservation(
        reservation: WagerReservationRecord,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        reservations[resKey(reservation.tenantId, reservation.reservationId)] = reservation.copy()
        reservationsByExtTx[txKey(reservation.tenantId, reservation.providerId, reservation.externalTransactionId)] = reservation.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WagerReservationResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun findTerminalIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WagerReservationResult>? {
        return terminalIdempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun saveTerminalIdempotency(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: WagerReservationResult,
    ) {
        terminalIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

interface WagerAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryWagerAlertSink : WagerAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

class WagerAuthorizationReservationService(
    private val roundTransactionMapService: RoundProviderTransactionMapService,
    private val operatorEnablementService: OperatorJurisdictionEnablementService,
    private val registrationStore: PlayerRegistrationStore,
    private val eligibilityStore: ServerEligibilityStore,
    private val reservationStore: WagerAuthorizationReservationStore,
    private val alertSink: WagerAlertSink = InMemoryWagerAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
    private val reservationTtlSeconds: Long = 60L,
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintReserve(cmd: AuthorizeAndReserveWagerCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.providerId}:${cmd.gameId}:${cmd.externalRoundId}:${cmd.externalTransactionId}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.jurisdictionCode}:${cmd.expectedVersion}")
    }

    private fun fingerprintTerminal(tenantId: String, reservationId: UUID, action: String): String {
        return sha256("$tenantId:$reservationId:$action")
    }

    @Synchronized
    fun authorizeAndReserveWager(command: AuthorizeAndReserveWagerCommand): WagerReservationResult {
        WagerAuthorizationReservationBinding.checkBound()

        // 1. Structural Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.externalRoundId.isBlank() ||
            command.externalTransactionId.isBlank() ||
            command.jurisdictionCode.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.amountMinorUnits <= 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Strict Idempotency (One idempotency key -> one reservation)
        val fp = fingerprintReserve(command)
        reservationStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 3. Recheck Duplicate External Transaction ID (ID Collision)
        val existingReservation = reservationStore.findReservationByExternalTx(
            command.tenantId,
            command.providerId,
            command.externalTransactionId,
        )
        if (existingReservation != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 4. Recheck Player Account & Responsible Gaming (AUTHZ-001)
        val registration = try {
            registrationStore.findById(command.tenantId, command.playerId)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (registration.status != PlayerAccountStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val compliance = try {
            eligibilityStore.findComplianceProfile(command.tenantId, command.playerId)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (compliance != null) {
            if (compliance.responsiblePlay.selfExcluded) {
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "HIGH",
                    alertType = "SELF_EXCLUDED_WAGER_ATTEMPT",
                    detail = "Self-excluded player ${command.playerId} attempted wager",
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            compliance.responsiblePlay.selfExclusionUntil?.let { until ->
                if (until.isAfter(now)) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            compliance.responsiblePlay.coolOffUntil?.let { until ->
                if (until.isAfter(now)) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            compliance.responsiblePlay.singleWagerLimitMinor?.let { limit ->
                if (command.amountMinorUnits > limit) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
            compliance.responsiblePlay.dailyWagerLimitMinor?.let { limit ->
                if (compliance.responsiblePlay.currentDailyWagerMinor + command.amountMinorUnits > limit) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
            }
        }

        // 5. Recheck Operator & Jurisdiction Game Enablement (GAME-002-02, GAME-004)
        val eligibility = try {
            operatorEnablementService.evaluateEligibility(
                EvaluateGameLaunchEligibilityCommand(
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    gameId = command.gameId,
                    playerId = command.playerId.toString(),
                    jurisdictionCode = command.jurisdictionCode,
                    requestedBetMinorUnits = command.amountMinorUnits,
                    currencyCode = command.currencyCode,
                )
            )
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (!eligibility.eligible) {
            val code = eligibility.rejectionReasonCode ?: AuthErrorCode.FORBIDDEN
            throw AuthenticationFailure.Rejected(code)
        }

        // 6. Solvency & Balance Reservation (WALLET-003)
        // Retrieve or initialize player wallet balance
        val wallet = reservationStore.findWalletBalance(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (wallet.availableBalanceMinorUnits < command.amountMinorUnits) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "MEDIUM",
                alertType = "INSUFFICIENT_FUNDS_WAGER_ATTEMPT",
                detail = "Player ${command.playerId} has ${wallet.availableBalanceMinorUnits} < wager ${command.amountMinorUnits}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 7. Authoritative Round & Transaction Mapping (GAME-005)
        val roundMapResult = try {
            roundTransactionMapService.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    externalRoundId = command.externalRoundId,
                    externalTransactionId = command.externalTransactionId,
                    playerId = command.playerId,
                    gameId = command.gameId,
                    transactionType = ProviderTransactionType.BET,
                    amountMinorUnits = command.amountMinorUnits,
                    currencyCode = command.currencyCode,
                    settleRound = false,
                    idempotencyKey = "tx-map-${command.idempotencyKey}",
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
            )
        } catch (e: AuthenticationFailure) {
            throw e
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // 8. Atomically Reserve Funds
        wallet.availableBalanceMinorUnits -= command.amountMinorUnits
        wallet.reservedBalanceMinorUnits += command.amountMinorUnits
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        // 9. Create Authoritative Reservation Record
        val reservationId = UUID.randomUUID()
        val expiresAt = now.plusSeconds(reservationTtlSeconds)
        val evidenceRef = sha256("${command.tenantId}:$reservationId:${roundMapResult.canonicalRoundId}:${roundMapResult.canonicalTransactionId}:${now.toEpochMilli()}")

        val reservationRecord = WagerReservationRecord(
            reservationId = reservationId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            status = WagerReservationStatus.RESERVED,
            reservedAt = now,
            expiresAt = expiresAt,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
        )

        val resultId = UUID.randomUUID()
        val result = WagerReservationResult(
            resultId = resultId,
            reservationId = reservationId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            status = WagerReservationStatus.RESERVED,
            availableBalanceMinorUnits = wallet.availableBalanceMinorUnits,
            reservedBalanceMinorUnits = wallet.reservedBalanceMinorUnits,
            expiresAt = expiresAt,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_AUTHORIZED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_AUTHORIZED",
            createdAt = now,
        )

        reservationStore.saveReservation(
            reservation = reservationRecord,
            result = result,
            idempotencyKey = command.idempotencyKey,
            fingerprint = fp,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    @Synchronized
    fun commitReservation(command: CommitWagerReservationCommand): WagerReservationResult {
        WagerAuthorizationReservationBinding.checkBound()

        val fp = fingerprintTerminal(command.tenantId, command.reservationId, "COMMIT")
        reservationStore.findTerminalIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val reservation = reservationStore.findReservation(command.tenantId, command.reservationId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        val now = clock.instant()
        val wallet = reservationStore.findWalletBalance(reservation.tenantId, reservation.playerId, reservation.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // Idempotent terminal transition
        if (reservation.status == WagerReservationStatus.COMMITTED) {
            val result = toResult(reservation, wallet, now)
            reservationStore.saveTerminalIdempotency(command.tenantId, command.idempotencyKey, fp, result)
            return result
        }

        if (reservation.status != WagerReservationStatus.RESERVED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Commit: Deduct from reserved balance (funds permanently settled/debited)
        wallet.reservedBalanceMinorUnits -= reservation.amountMinorUnits
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        reservation.status = WagerReservationStatus.COMMITTED
        reservation.committedAt = now
        reservation.version += 1L

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_COMMITTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = audit.resultId,
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_COMMITTED",
            createdAt = now,
        )

        reservationStore.updateReservation(reservation, audit, outbox)

        val result = toResult(reservation, wallet, now, audit.resultId)
        reservationStore.saveTerminalIdempotency(command.tenantId, command.idempotencyKey, fp, result)
        return result
    }

    @Synchronized
    fun releaseReservation(command: ReleaseWagerReservationCommand): WagerReservationResult {
        WagerAuthorizationReservationBinding.checkBound()

        val fp = fingerprintTerminal(command.tenantId, command.reservationId, "RELEASE:${command.reason}")
        reservationStore.findTerminalIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val reservation = reservationStore.findReservation(command.tenantId, command.reservationId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        val now = clock.instant()
        val wallet = reservationStore.findWalletBalance(reservation.tenantId, reservation.playerId, reservation.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // Idempotent terminal transition
        if (reservation.status == WagerReservationStatus.RELEASED) {
            val result = toResult(reservation, wallet, now)
            reservationStore.saveTerminalIdempotency(command.tenantId, command.idempotencyKey, fp, result)
            return result
        }

        if (reservation.status != WagerReservationStatus.RESERVED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Release: return funds to available balance
        wallet.reservedBalanceMinorUnits -= reservation.amountMinorUnits
        wallet.availableBalanceMinorUnits += reservation.amountMinorUnits
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        reservation.status = WagerReservationStatus.RELEASED
        reservation.releasedAt = now
        reservation.version += 1L

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_RELEASED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = audit.resultId,
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_RELEASED",
            createdAt = now,
        )

        reservationStore.updateReservation(reservation, audit, outbox)

        val result = toResult(reservation, wallet, now, audit.resultId)
        reservationStore.saveTerminalIdempotency(command.tenantId, command.idempotencyKey, fp, result)
        return result
    }

    @Synchronized
    fun expireReservation(command: ExpireWagerReservationCommand): WagerReservationResult {
        WagerAuthorizationReservationBinding.checkBound()

        val reservation = reservationStore.findReservation(command.tenantId, command.reservationId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        val now = clock.instant()
        val wallet = reservationStore.findWalletBalance(reservation.tenantId, reservation.playerId, reservation.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // Idempotent terminal transition
        if (reservation.status == WagerReservationStatus.EXPIRED) {
            return toResult(reservation, wallet, now)
        }

        if (reservation.status != WagerReservationStatus.RESERVED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Expiry is worker command, never silent deletion
        wallet.reservedBalanceMinorUnits -= reservation.amountMinorUnits
        wallet.availableBalanceMinorUnits += reservation.amountMinorUnits
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        reservation.status = WagerReservationStatus.EXPIRED
        reservation.expiredAt = now
        reservation.version += 1L

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_EXPIRED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = audit.resultId,
            tenantId = command.tenantId,
            type = "WAGER_RESERVATION_EXPIRED",
            createdAt = now,
        )

        reservationStore.updateReservation(reservation, audit, outbox)
        return toResult(reservation, wallet, now, audit.resultId)
    }

    private fun toResult(
        res: WagerReservationRecord,
        wallet: PlayerWalletBalanceRecord,
        now: Instant,
        resultId: UUID = UUID.randomUUID(),
    ): WagerReservationResult {
        return WagerReservationResult(
            resultId = resultId,
            reservationId = res.reservationId,
            tenantId = res.tenantId,
            playerId = res.playerId,
            providerId = res.providerId,
            gameId = res.gameId,
            externalRoundId = res.externalRoundId,
            externalTransactionId = res.externalTransactionId,
            canonicalRoundId = res.canonicalRoundId,
            canonicalTransactionId = res.canonicalTransactionId,
            amountMinorUnits = res.amountMinorUnits,
            currencyCode = res.currencyCode,
            status = res.status,
            availableBalanceMinorUnits = wallet.availableBalanceMinorUnits,
            reservedBalanceMinorUnits = wallet.reservedBalanceMinorUnits,
            expiresAt = res.expiresAt,
            serverTime = now,
            evidenceReference = res.evidenceReference,
        )
    }
}
