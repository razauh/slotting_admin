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
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce BONUS-001-01: Post isolated bonus grants.
 * Semantic contract: "Cash/bonus conservation and isolation; conversion prohibited unless explicitly approved."
 * Protected risk: "bonus spent/withdrawn as cash"
 */
object BonusGrantBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bonus spent/withdrawn as cash")
        }
    }
}

enum class BonusGrantType {
    WELCOME_BONUS,
    DEPOSIT_MATCH,
    FREE_PLAY_CREDIT,
    LOYALTY_REWARD,
    ADMIN_DISCRETIONARY
}

enum class BonusGrantStatus {
    ACTIVE,
    CONVERTED,
    EXPIRED,
    FORFEITED,
    CANCELLED
}

enum class BucketType {
    CASH,
    BONUS,
    LOCKED_CASH
}

data class PlayerWalletBuckets(
    val tenantId: String,
    val playerId: UUID,
    val currencyCode: String,
    var cashMinorUnits: Long = 0L,
    var bonusMinorUnits: Long = 0L,
    var lockedCashMinorUnits: Long = 0L,
    var version: Long = 1L
) {
    val totalBalanceMinorUnits: Long
        get() = cashMinorUnits + bonusMinorUnits + lockedCashMinorUnits

    val withdrawableCashMinorUnits: Long
        get() = cashMinorUnits // Bonus funds are strictly NON-CASH and non-withdrawable
}

data class BonusGrantRecord(
    val grantId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val bonusType: BonusGrantType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val wageringRequirementMultiplier: Double,
    val wageringRequirementMinorUnits: Long,
    var wageringProgressMinorUnits: Long = 0L,
    var status: BonusGrantStatus = BonusGrantStatus.ACTIVE,
    val reason: String,
    val createdAt: Instant,
    val expiresAt: Instant,
    var version: Long = 1L
)

data class BonusLedgerEntry(
    val entryId: UUID,
    val tenantId: String,
    val transactionReference: String,
    val debitAccount: String,
    val creditAccount: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val createdAt: Instant
)

data class PostBonusGrantCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val bonusType: BonusGrantType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val wageringRequirementMultiplier: Double = 0.0,
    val ttlSeconds: Long = 86400L * 30, // 30 days
    val grantReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class PostBonusGrantResult(
    val resultId: UUID,
    val grantId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val bonusType: BonusGrantType,
    val grantedAmountMinorUnits: Long,
    val currencyCode: String,
    val newCashBalanceMinorUnits: Long,
    val newBonusBalanceMinorUnits: Long,
    val withdrawableCashMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class AttemptWithdrawalCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class WithdrawalResult(
    val resultId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val withdrawnCashMinorUnits: Long,
    val remainingCashMinorUnits: Long,
    val remainingBonusMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class ConvertBonusCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val grantId: UUID,
    val conversionReason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class ConvertBonusResult(
    val resultId: UUID,
    val grantId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val convertedAmountMinorUnits: Long,
    val newCashBalanceMinorUnits: Long,
    val newBonusBalanceMinorUnits: Long,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface BonusGrantStore {
    fun findWallet(tenantId: String, playerId: UUID, currencyCode: String): PlayerWalletBuckets?
    fun saveWallet(wallet: PlayerWalletBuckets)
    fun findGrant(tenantId: String, grantId: UUID): BonusGrantRecord?
    fun saveGrant(grant: BonusGrantRecord)
    fun recordLedgerEntry(entry: BonusLedgerEntry)
    fun getLedgerEntries(tenantId: String): List<BonusLedgerEntry>
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

class InMemoryBonusGrantStore : BonusGrantStore {
    val wallets = ConcurrentHashMap<String, PlayerWalletBuckets>()
    val grants = ConcurrentHashMap<UUID, BonusGrantRecord>()
    val ledger = mutableListOf<BonusLedgerEntry>()
    val idempotency = ConcurrentHashMap<String, Pair<String, Any>>()

    override fun findWallet(tenantId: String, playerId: UUID, currencyCode: String): PlayerWalletBuckets? {
        return wallets["$tenantId:$playerId:$currencyCode"]
    }

    override fun saveWallet(wallet: PlayerWalletBuckets) {
        wallets["${wallet.tenantId}:${wallet.playerId}:${wallet.currencyCode}"] = wallet
    }

    override fun findGrant(tenantId: String, grantId: UUID): BonusGrantRecord? {
        val g = grants[grantId]
        return if (g?.tenantId == tenantId) g else null
    }

    override fun saveGrant(grant: BonusGrantRecord) {
        grants[grant.grantId] = grant
    }

    override fun recordLedgerEntry(entry: BonusLedgerEntry) {
        ledger.add(entry)
    }

    override fun getLedgerEntries(tenantId: String): List<BonusLedgerEntry> {
        return ledger.filter { it.tenantId == tenantId }
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any) {
        idempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

interface BonusAlertSink {
    fun sendAlert(tenantId: String, alertType: String, message: String)
}

class InMemoryBonusAlertSink : BonusAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, alertType: String, message: String) {
        alerts.add("$tenantId:$alertType:$message")
    }
}

class BonusGrantService(
    private val store: BonusGrantStore,
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

    private fun computeFingerprint(command: PostBonusGrantCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.bonusType.name,
            command.amountMinorUnits,
            command.currencyCode,
            command.wageringRequirementMultiplier,
            command.grantReason,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: AttemptWithdrawalCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.amountMinorUnits,
            command.currencyCode,
            command.expectedVersion
        ).joinToString("|")
    }

    private fun computeFingerprint(command: ConvertBonusCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.grantId.toString(),
            command.conversionReason,
            command.expectedVersion
        ).joinToString("|")
    }

    fun postBonusGrant(command: PostBonusGrantCommand): PostBonusGrantResult = synchronized(store) {
        // 1. Fail-closed binding check
        BonusGrantBinding.checkBound()

        // 2. Input and header validation
        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        if (command.amountMinorUnits <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (!command.currencyCode.matches(Regex("[A-Z]{3}"))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.grantReason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Idempotency check
        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is PostBonusGrantResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Principal authentication and authorization
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.kind != PrincipalKind.ADMIN) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "UNAUTHORIZED_BONUS_GRANT_ATTEMPT",
                message = "Non-admin principal ${principal.id} attempted to grant bonus"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Wallet lookup or initialization with version checking
        var wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
        if (wallet == null) {
            wallet = PlayerWalletBuckets(
                tenantId = command.tenantId,
                playerId = command.playerId,
                currencyCode = command.currencyCode,
                cashMinorUnits = 0L,
                bonusMinorUnits = 0L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        } else {
            if (command.expectedVersion != wallet.version) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
            }
        }

        val now = clock.instant()
        val grantId = UUID.randomUUID()
        val wageringRequiredMinorUnits = (command.amountMinorUnits * command.wageringRequirementMultiplier).toLong()

        // 6. Credit isolated BONUS bucket; CASH bucket remains completely untouched!
        wallet.bonusMinorUnits += command.amountMinorUnits
        wallet.version += 1L
        store.saveWallet(wallet)

        // 7. Double-entry ledger record: Debit Casino Promotion Expense, Credit Player Bonus Bucket Liability
        val ledgerEntry = BonusLedgerEntry(
            entryId = UUID.randomUUID(),
            tenantId = command.tenantId,
            transactionReference = "grant:$grantId",
            debitAccount = "CASINO_PROMOTION_EXPENSE",
            creditAccount = "PLAYER_BONUS_LIABILITY:${wallet.playerId}",
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            createdAt = now
        )
        store.recordLedgerEntry(ledgerEntry)

        // 8. Record Grant
        val grantRecord = BonusGrantRecord(
            grantId = grantId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            bonusType = command.bonusType,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            wageringRequirementMultiplier = command.wageringRequirementMultiplier,
            wageringRequirementMinorUnits = wageringRequiredMinorUnits,
            wageringProgressMinorUnits = 0L,
            status = BonusGrantStatus.ACTIVE,
            reason = command.grantReason,
            createdAt = now,
            expiresAt = now.plusSeconds(command.ttlSeconds),
            version = 1L
        )
        store.saveGrant(grantRecord)

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-grant:${command.tenantId}:${command.playerId}:$grantId:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_GRANT_POSTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_GRANT_POSTED",
            createdAt = now
        )

        val result = PostBonusGrantResult(
            resultId = resultId,
            grantId = grantId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            bonusType = command.bonusType,
            grantedAmountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            newCashBalanceMinorUnits = wallet.cashMinorUnits,
            newBonusBalanceMinorUnits = wallet.bonusMinorUnits,
            withdrawableCashMinorUnits = wallet.withdrawableCashMinorUnits,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun attemptWithdrawal(command: AttemptWithdrawalCommand): WithdrawalResult = synchronized(store) {
        // 1. Fail-closed binding check
        BonusGrantBinding.checkBound()

        // 2. Input and header validation
        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        if (command.amountMinorUnits <= 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Idempotency check
        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is WithdrawalResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Principal check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.playerId.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 5. CORE ENFORCEMENT: Bonus spent/withdrawn as cash is strictly PROHIBITED!
        // Only withdrawable cash (from the CASH bucket) may be withdrawn.
        if (command.amountMinorUnits > wallet.withdrawableCashMinorUnits) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "BONUS_WITHDRAWAL_ATTEMPT_DENIED",
                message = "Player ${command.playerId} attempted to withdraw ${command.amountMinorUnits} exceeding withdrawable cash ${wallet.withdrawableCashMinorUnits} (bonus bucket: ${wallet.bonusMinorUnits})"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        wallet.cashMinorUnits -= command.amountMinorUnits
        wallet.version += 1L
        store.saveWallet(wallet)

        // Record cash debit ledger entry
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = command.tenantId,
                transactionReference = "withdrawal:${UUID.randomUUID()}",
                debitAccount = "PLAYER_CASH_LIABILITY:${wallet.playerId}",
                creditAccount = "PAYMENT_SETTLEMENT_OUTBOX",
                amountMinorUnits = command.amountMinorUnits,
                currencyCode = command.currencyCode,
                createdAt = now
            )
        )

        val resultId = UUID.randomUUID()
        val evidenceReference = "cash-withdrawal:${command.tenantId}:${command.playerId}:$resultId:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASH_WITHDRAWAL_PROCESSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASH_WITHDRAWAL_PROCESSED",
            createdAt = now
        )

        val result = WithdrawalResult(
            resultId = resultId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            withdrawnCashMinorUnits = command.amountMinorUnits,
            remainingCashMinorUnits = wallet.cashMinorUnits,
            remainingBonusMinorUnits = wallet.bonusMinorUnits,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun convertBonus(command: ConvertBonusCommand): ConvertBonusResult = synchronized(store) {
        // 1. Fail-closed binding check
        BonusGrantBinding.checkBound()

        // 2. Input and header validation
        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )

        // 3. Idempotency check
        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is ConvertBonusResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 4. Principal check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val grant = store.findGrant(command.tenantId, command.grantId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (grant.playerId != command.playerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (grant.status != BonusGrantStatus.ACTIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        if (now.isAfter(grant.expiresAt)) {
            grant.status = BonusGrantStatus.EXPIRED
            store.saveGrant(grant)
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 5. CORE ENFORCEMENT: Conversion prohibited unless wagering requirement explicitly met OR approved by SUPER_ADMIN
        val isWageringMet = grant.wageringProgressMinorUnits >= grant.wageringRequirementMinorUnits
        val isSuperAdminApproved = principal.kind == PrincipalKind.ADMIN && principal.roles.contains(AdminRole.SUPER_ADMIN)

        if (!isWageringMet && !isSuperAdminApproved) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                alertType = "UNAUTHORIZED_BONUS_CONVERSION_ATTEMPT",
                message = "Conversion denied: wagering progress ${grant.wageringProgressMinorUnits} < required ${grant.wageringRequirementMinorUnits}"
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val wallet = store.findWallet(command.tenantId, command.playerId, grant.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != wallet.version) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 6. Atomic Conservation: Transfer from BONUS bucket to CASH bucket
        val convertAmount = minOf(grant.amountMinorUnits, wallet.bonusMinorUnits)
        wallet.bonusMinorUnits -= convertAmount
        wallet.cashMinorUnits += convertAmount
        wallet.version += 1L
        store.saveWallet(wallet)

        grant.status = BonusGrantStatus.CONVERTED
        grant.version += 1L
        store.saveGrant(grant)

        // Record balanced conversion ledger entry
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = command.tenantId,
                transactionReference = "convert:${grant.grantId}",
                debitAccount = "PLAYER_BONUS_LIABILITY:${command.playerId}",
                creditAccount = "PLAYER_CASH_LIABILITY:${command.playerId}",
                amountMinorUnits = convertAmount,
                currencyCode = grant.currencyCode,
                createdAt = now
            )
        )

        val resultId = UUID.randomUUID()
        val evidenceReference = "bonus-convert:${command.tenantId}:${command.playerId}:${grant.grantId}:${wallet.version}"

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_CONVERTED_TO_CASH",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_CONVERTED_TO_CASH",
            createdAt = now
        )

        val result = ConvertBonusResult(
            resultId = resultId,
            grantId = grant.grantId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            convertedAmountMinorUnits = convertAmount,
            newCashBalanceMinorUnits = wallet.cashMinorUnits,
            newBonusBalanceMinorUnits = wallet.bonusMinorUnits,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }
}
