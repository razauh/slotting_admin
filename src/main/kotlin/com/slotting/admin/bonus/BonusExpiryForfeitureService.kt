package com.slotting.admin.bonus

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce BONUS-002-01: Expire and forfeit bonus with compensation.
 * Semantic contract: "Expiry timezone/version explicit; player receipt and audit."
 * Protected risk: "silent expiry/double forfeit"
 */
object BonusExpiryForfeitureBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("silent expiry/double forfeit")
        }
    }
}

data class PlayerBonusReceipt(
    val receiptId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val grantId: UUID,
    val actionType: String, // "EXPIRED", "FORFEITED", "COMPENSATED"
    val forfeitedBonusMinorUnits: Long,
    val compensationMinorUnits: Long,
    val remainingCashMinorUnits: Long,
    val remainingBonusMinorUnits: Long,
    val expiryTimestamp: Instant,
    val expiryTimezone: String, // Explicit IANA timezone or "UTC"
    val serverVersion: Long,
    val reason: String,
    val evidenceReference: String,
    val issuedAt: Instant
)

data class ExpireBonusCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val grantId: UUID,
    val currencyCode: String,
    val expiryTimezone: String = "UTC",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class BonusExpiryResult(
    val resultId: UUID,
    val receipt: PlayerBonusReceipt,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class ForfeitBonusCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val grantId: UUID,
    val currencyCode: String,
    val forfeitReason: String,
    val compensationAmountMinorUnits: Long = 0L,
    val expiryTimezone: String = "UTC",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class BonusForfeitureResult(
    val resultId: UUID,
    val receipt: PlayerBonusReceipt,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class BatchExpireBonusesCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val asOfTime: Instant,
    val expiryTimezone: String = "UTC",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class BatchExpireBonusesResult(
    val resultId: UUID,
    val tenantId: String,
    val expiredGrantCount: Int,
    val totalForfeitedMinorUnits: Long,
    val receipts: List<PlayerBonusReceipt>,
    val serverTime: Instant,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface BonusExpiryStore : BonusGrantStore {
    fun saveReceipt(receipt: PlayerBonusReceipt)
    fun findReceipt(tenantId: String, receiptId: UUID): PlayerBonusReceipt?
    fun findReceipts(tenantId: String, playerId: UUID): List<PlayerBonusReceipt>
    fun findAllActiveGrants(tenantId: String): List<BonusGrantRecord>
    fun findAllGrants(tenantId: String): List<BonusGrantRecord>
}

class InMemoryBonusExpiryStore(
    val delegate: InMemoryBonusGrantStore = InMemoryBonusGrantStore()
) : BonusExpiryStore, BonusGrantStore by delegate {
    val receipts = ConcurrentHashMap<UUID, PlayerBonusReceipt>()

    override fun saveReceipt(receipt: PlayerBonusReceipt) {
        receipts[receipt.receiptId] = receipt
    }

    override fun findReceipt(tenantId: String, receiptId: UUID): PlayerBonusReceipt? {
        val r = receipts[receiptId]
        return if (r?.tenantId == tenantId) r else null
    }

    override fun findReceipts(tenantId: String, playerId: UUID): List<PlayerBonusReceipt> {
        return receipts.values.filter { it.tenantId == tenantId && it.playerId == playerId }
    }

    override fun findAllActiveGrants(tenantId: String): List<BonusGrantRecord> {
        return delegate.grants.values.filter { it.tenantId == tenantId && it.status == BonusGrantStatus.ACTIVE }
    }

    override fun findAllGrants(tenantId: String): List<BonusGrantRecord> {
        return delegate.grants.values.filter { it.tenantId == tenantId }
    }
}

class BonusExpiryForfeitureService(
    private val store: BonusExpiryStore,
    private val alertSink: BonusAlertSink = InMemoryBonusAlertSink(),
    private val clock: Clock = Clock.systemUTC()
) {

    private fun validateHeaders(
        tenantId: String,
        correlationId: String,
        causationId: String,
        idempotencyKey: String,
        expectedVersion: Long
    ) {
        if (tenantId.isBlank() || correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun validateTimezone(timezoneStr: String) {
        if (timezoneStr.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        try {
            ZoneId.of(timezoneStr)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun computeFingerprint(command: ExpireBonusCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.grantId.toString(),
            command.currencyCode,
            command.expiryTimezone,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: ForfeitBonusCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.grantId.toString(),
            command.currencyCode,
            command.forfeitReason,
            command.compensationAmountMinorUnits,
            command.expiryTimezone,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: BatchExpireBonusesCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.asOfTime.toString(),
            command.expiryTimezone
        ).joinToString("|")
    }

    /**
     * Authoritatively expire a bonus grant that has reached its expiration time.
     * Prevents silent expiry by issuing a durable PlayerBonusReceipt and publishing audit/outbox events.
     * Prevents double forfeit by rejecting non-ACTIVE grants.
     */
    fun expireBonus(command: ExpireBonusCommand): BonusExpiryResult = synchronized(store) {
        BonusExpiryForfeitureBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )
        validateTimezone(command.expiryTimezone)

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is BonusExpiryResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val grant = store.findGrant(command.tenantId, command.grantId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (grant.playerId != command.playerId || grant.currencyCode != command.currencyCode) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // DOUBLE FORFEIT PREVENTION: Grant must be ACTIVE
        if (grant.status != BonusGrantStatus.ACTIVE) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "DOUBLE_FORFEIT_OR_EXPIRY_ATTEMPT",
                message = "Grant ${grant.grantId} is already in state ${grant.status}; cannot expire"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        if (now.isBefore(grant.expiresAt)) {
            // Cannot expire before expiry timestamp
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val expiredAmount = minOf(grant.amountMinorUnits, wallet.bonusMinorUnits)

        // Mutate grant state
        grant.status = BonusGrantStatus.EXPIRED
        grant.version += 1L
        store.saveGrant(grant)

        // Mutate wallet
        wallet.bonusMinorUnits -= expiredAmount
        wallet.version += 1L
        store.saveWallet(wallet)

        // Double entry ledger: Debit Player Bonus Liability, Credit Casino Expiry Recovery
        if (expiredAmount > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "bonus-expiry:${grant.grantId}",
                    debitAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                    creditAccount = "CASINO_BONUS_EXPIRY_RECOVERY",
                    amountMinorUnits = expiredAmount,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-expiry:${command.tenantId}:${command.playerId}:${grant.grantId}:$resultId:${wallet.version}"

        val receipt = PlayerBonusReceipt(
            receiptId = UUID.randomUUID(),
            tenantId = command.tenantId,
            playerId = command.playerId,
            grantId = grant.grantId,
            actionType = "EXPIRED",
            forfeitedBonusMinorUnits = expiredAmount,
            compensationMinorUnits = 0L,
            remainingCashMinorUnits = wallet.cashMinorUnits,
            remainingBonusMinorUnits = wallet.bonusMinorUnits,
            expiryTimestamp = grant.expiresAt,
            expiryTimezone = command.expiryTimezone,
            serverVersion = wallet.version,
            reason = "Bonus expired at ${grant.expiresAt}",
            evidenceReference = evidenceReference,
            issuedAt = now
        )
        store.saveReceipt(receipt)

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_EXPIRED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_EXPIRED",
            createdAt = now
        )

        val result = BonusExpiryResult(
            resultId = resultId,
            receipt = receipt,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Authoritatively forfeit a bonus grant with optional compensation (e.g., goodwill or locked funds return).
     * Prevents silent expiry/forfeit by issuing a player receipt with explicit timezone/version and audit lineage.
     * Prevents double forfeit by rejecting already forfeited/expired/converted grants.
     */
    fun forfeitBonus(command: ForfeitBonusCommand): BonusForfeitureResult = synchronized(store) {
        BonusExpiryForfeitureBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )
        validateTimezone(command.expiryTimezone)

        if (command.forfeitReason.isBlank() || command.compensationAmountMinorUnits < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is BonusForfeitureResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Player can only forfeit their own bonus; admin can forfeit with proper roles
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.playerId.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // If compensation is provided (>0L), only ADMIN role can authorize compensation
        if (command.compensationAmountMinorUnits > 0L && principal.kind != PrincipalKind.ADMIN) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "UNAUTHORIZED_COMPENSATION_ATTEMPT",
                message = "Non-admin principal ${principal.id} attempted to grant compensation"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val grant = store.findGrant(command.tenantId, command.grantId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (grant.playerId != command.playerId || grant.currencyCode != command.currencyCode) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // DOUBLE FORFEIT PREVENTION: Grant must be in ACTIVE status
        if (grant.status != BonusGrantStatus.ACTIVE) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "DOUBLE_FORFEIT_OR_EXPIRY_ATTEMPT",
                message = "Grant ${grant.grantId} is already in state ${grant.status}; cannot forfeit"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val forfeitedAmount = minOf(grant.amountMinorUnits, wallet.bonusMinorUnits)
        val compensation = command.compensationAmountMinorUnits

        // Mutate grant state
        grant.status = BonusGrantStatus.FORFEITED
        grant.version += 1L
        store.saveGrant(grant)

        // Mutate wallet: wipe forfeited bonus and credit compensation to cash
        wallet.bonusMinorUnits -= forfeitedAmount
        wallet.cashMinorUnits += compensation
        wallet.version += 1L
        store.saveWallet(wallet)

        // Ledger entry 1: Forfeited bonus recovery
        if (forfeitedAmount > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "bonus-forfeit:${grant.grantId}",
                    debitAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                    creditAccount = "CASINO_BONUS_FORFEITURE_RECOVERY",
                    amountMinorUnits = forfeitedAmount,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }

        // Ledger entry 2: Compensation credit
        if (compensation > 0L) {
            store.recordLedgerEntry(
                BonusLedgerEntry(
                    entryId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    transactionReference = "bonus-compensation:${grant.grantId}",
                    debitAccount = "CASINO_BONUS_COMPENSATION_EXPENSE",
                    creditAccount = "PLAYER_CASH_LIABILITY:${wallet.playerId}",
                    amountMinorUnits = compensation,
                    currencyCode = command.currencyCode,
                    createdAt = now
                )
            )
        }

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-forfeit:${command.tenantId}:${command.playerId}:${grant.grantId}:$resultId:${wallet.version}"

        val receipt = PlayerBonusReceipt(
            receiptId = UUID.randomUUID(),
            tenantId = command.tenantId,
            playerId = command.playerId,
            grantId = grant.grantId,
            actionType = if (compensation > 0L) "COMPENSATED" else "FORFEITED",
            forfeitedBonusMinorUnits = forfeitedAmount,
            compensationMinorUnits = compensation,
            remainingCashMinorUnits = wallet.cashMinorUnits,
            remainingBonusMinorUnits = wallet.bonusMinorUnits,
            expiryTimestamp = now,
            expiryTimezone = command.expiryTimezone,
            serverVersion = wallet.version,
            reason = command.forfeitReason,
            evidenceReference = evidenceReference,
            issuedAt = now
        )
        store.saveReceipt(receipt)

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (compensation > 0L) "BONUS_FORFEITED_WITH_COMPENSATION" else "BONUS_FORFEITED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = if (compensation > 0L) "BONUS_FORFEITED_WITH_COMPENSATION" else "BONUS_FORFEITED",
            createdAt = now
        )

        val result = BonusForfeitureResult(
            resultId = resultId,
            receipt = receipt,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Batch job to scan and authoritatively expire all active grants whose expiresAt <= asOfTime.
     * Generates a player receipt for each expired grant to ensure zero silent expiry.
     */
    fun batchExpireBonuses(command: BatchExpireBonusesCommand): BatchExpireBonusesResult = synchronized(store) {
        BonusExpiryForfeitureBinding.checkBound()

        if (command.tenantId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() || command.idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        validateTimezone(command.expiryTimezone)

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is BatchExpireBonusesResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        // Only Admin or System can run batch expiry
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val activeGrants = store.findAllActiveGrants(command.tenantId)
        val eligibleGrants = activeGrants.filter { !it.expiresAt.isAfter(command.asOfTime) }

        val receipts = mutableListOf<PlayerBonusReceipt>()
        var totalForfeited = 0L
        val now = clock.instant()

        for (grant in eligibleGrants) {
            val wallet = store.findWallet(command.tenantId, grant.playerId, grant.currencyCode) ?: continue
            val expiredAmount = minOf(grant.amountMinorUnits, wallet.bonusMinorUnits)

            grant.status = BonusGrantStatus.EXPIRED
            grant.version += 1L
            store.saveGrant(grant)

            wallet.bonusMinorUnits -= expiredAmount
            wallet.version += 1L
            store.saveWallet(wallet)

            if (expiredAmount > 0L) {
                totalForfeited += expiredAmount
                store.recordLedgerEntry(
                    BonusLedgerEntry(
                        entryId = UUID.randomUUID(),
                        tenantId = command.tenantId,
                        transactionReference = "batch-expiry:${grant.grantId}",
                        debitAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
                        creditAccount = "CASINO_BONUS_EXPIRY_RECOVERY",
                        amountMinorUnits = expiredAmount,
                        currencyCode = grant.currencyCode,
                        createdAt = now
                    )
                )
            }

            val receipt = PlayerBonusReceipt(
                receiptId = UUID.randomUUID(),
                tenantId = command.tenantId,
                playerId = grant.playerId,
                grantId = grant.grantId,
                actionType = "EXPIRED",
                forfeitedBonusMinorUnits = expiredAmount,
                compensationMinorUnits = 0L,
                remainingCashMinorUnits = wallet.cashMinorUnits,
                remainingBonusMinorUnits = wallet.bonusMinorUnits,
                expiryTimestamp = grant.expiresAt,
                expiryTimezone = command.expiryTimezone,
                serverVersion = wallet.version,
                reason = "Batch expiry as of ${command.asOfTime}",
                evidenceReference = "batch-expiry:${command.tenantId}:${grant.grantId}:${wallet.version}",
                issuedAt = now
            )
            store.saveReceipt(receipt)
            receipts.add(receipt)
        }

        val resultId = UUID.randomUUID()
        val evidenceRef = "batch-expiry-job:${command.tenantId}:$resultId"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BATCH_BONUS_EXPIRY_COMPLETED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BATCH_BONUS_EXPIRY_COMPLETED",
            createdAt = now
        )

        val result = BatchExpireBonusesResult(
            resultId = resultId,
            tenantId = command.tenantId,
            expiredGrantCount = receipts.size,
            totalForfeitedMinorUnits = totalForfeited,
            receipts = receipts,
            serverTime = now,
            evidenceReference = evidenceRef,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun getPlayerReceipts(tenantId: String, playerId: UUID): List<PlayerBonusReceipt> {
        return store.findReceipts(tenantId, playerId)
    }

    fun getReceipt(tenantId: String, receiptId: UUID): PlayerBonusReceipt? {
        return store.findReceipt(tenantId, receiptId)
    }
}
