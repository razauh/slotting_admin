package com.slotting.admin.bonus

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce BONUS-002-02: Disclose bonus expiry in statements.
 * Semantic contract: "Expiry timezone/version explicit; player receipt and audit."
 * Protected risk: "silent expiry/double forfeit"
 */
object BonusStatementDisclosureBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("silent expiry/double forfeit")
        }
    }
}

data class BonusActiveDisclosure(
    val grantId: UUID,
    val bonusType: BonusGrantType,
    val grantedAmountMinorUnits: Long,
    val currentBonusBalanceMinorUnits: Long,
    val wageringRequiredMinorUnits: Long,
    val wageringProgressMinorUnits: Long,
    val remainingWageringMinorUnits: Long,
    val expiresAt: Instant,
    val expiryTimezone: String,
    val status: BonusGrantStatus,
    val isExpired: Boolean
)

data class BonusExpiryDisclosure(
    val receiptId: UUID,
    val grantId: UUID,
    val actionType: String, // "EXPIRED", "FORFEITED", "COMPENSATED"
    val forfeitedBonusMinorUnits: Long,
    val compensationMinorUnits: Long,
    val expiryTimestamp: Instant,
    val expiryTimezone: String,
    val serverVersion: Long,
    val reason: String,
    val evidenceReference: String
)

data class PlayerBonusStatement(
    val statementId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val statementTimezone: String,
    val generatedAt: Instant,
    val serverVersion: Long,
    val currentCashBalanceMinorUnits: Long,
    val currentBonusBalanceMinorUnits: Long,
    val activeBonusDisclosures: List<BonusActiveDisclosure>,
    val expiryDisclosures: List<BonusExpiryDisclosure>,
    val totalExpiredOrForfeitedDuringPeriodMinorUnits: Long,
    val totalCompensationDuringPeriodMinorUnits: Long,
    val evidenceReference: String
)

data class GenerateBonusStatementCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerId: UUID,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val statementTimezone: String = "UTC",
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long
)

data class GenerateBonusStatementResult(
    val resultId: UUID,
    val statement: PlayerBonusStatement,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface BonusStatementStore : BonusExpiryStore {
    fun saveStatement(statement: PlayerBonusStatement)
    fun findStatement(tenantId: String, statementId: UUID): PlayerBonusStatement?
    fun findStatementsForPlayer(tenantId: String, playerId: UUID): List<PlayerBonusStatement>
    fun findAllGrantsForPlayer(tenantId: String, playerId: UUID): List<BonusGrantRecord>
}

class InMemoryBonusStatementStore(
    private val expiryStore: BonusExpiryStore = InMemoryBonusExpiryStore()
) : BonusStatementStore, BonusExpiryStore by expiryStore {
    val statements = ConcurrentHashMap<UUID, PlayerBonusStatement>()

    override fun saveStatement(statement: PlayerBonusStatement) {
        statements[statement.statementId] = statement
    }

    override fun findStatement(tenantId: String, statementId: UUID): PlayerBonusStatement? {
        val s = statements[statementId]
        return if (s?.tenantId == tenantId) s else null
    }

    override fun findStatementsForPlayer(tenantId: String, playerId: UUID): List<PlayerBonusStatement> {
        return statements.values.filter { it.tenantId == tenantId && it.playerId == playerId }
    }

    override fun findAllGrantsForPlayer(tenantId: String, playerId: UUID): List<BonusGrantRecord> {
        return expiryStore.findAllGrants(tenantId).filter { it.playerId == playerId }
    }
}

class BonusStatementDisclosureService(
    private val store: BonusStatementStore,
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

    private fun computeFingerprint(command: GenerateBonusStatementCommand): String {
        return listOf(
            command.principal?.tenantId,
            command.principal?.id,
            command.tenantId,
            command.playerId.toString(),
            command.currencyCode,
            command.periodStart.toString(),
            command.periodEnd.toString(),
            command.statementTimezone,
            command.expectedVersion
        ).joinToString("|")
    }

    /**
     * Authoritatively generates and discloses bonus expiration and forfeiture records in player statements.
     * Prevents silent expiry by disclosing explicit expiry timestamps, timezones, versions, receipts, and line-item audits.
     */
    fun generateStatement(command: GenerateBonusStatementCommand): GenerateBonusStatementResult = synchronized(store) {
        BonusStatementDisclosureBinding.checkBound()

        validateHeaders(
            tenantId = command.tenantId,
            correlationId = command.correlationId,
            causationId = command.causationId,
            idempotencyKey = command.idempotencyKey,
            expectedVersion = command.expectedVersion
        )
        validateTimezone(command.statementTimezone)

        if (command.periodStart.isAfter(command.periodEnd)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = computeFingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint && cachedRes is GenerateBonusStatementResult) {
                return cachedRes
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

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

        val now = clock.instant()

        // 1. Gather all grants for this player to disclose active / expiring bonuses
        val playerGrants = store.findAllGrantsForPlayer(command.tenantId, command.playerId)
        val activeDisclosures = playerGrants.map { grant ->
            val remainingWagering = maxOf(0L, grant.wageringRequirementMinorUnits - grant.wageringProgressMinorUnits)
            val isExpired = now.isAfter(grant.expiresAt) || grant.status == BonusGrantStatus.EXPIRED
            BonusActiveDisclosure(
                grantId = grant.grantId,
                bonusType = grant.bonusType,
                grantedAmountMinorUnits = grant.amountMinorUnits,
                currentBonusBalanceMinorUnits = if (grant.status == BonusGrantStatus.ACTIVE) grant.amountMinorUnits else 0L,
                wageringRequiredMinorUnits = grant.wageringRequirementMinorUnits,
                wageringProgressMinorUnits = grant.wageringProgressMinorUnits,
                remainingWageringMinorUnits = remainingWagering,
                expiresAt = grant.expiresAt,
                expiryTimezone = command.statementTimezone,
                status = grant.status,
                isExpired = isExpired
            )
        }

        // 2. Gather receipts within the requested period [periodStart, periodEnd]
        val allReceipts = store.findReceipts(command.tenantId, command.playerId)
        val periodReceipts = allReceipts.filter { receipt ->
            !receipt.issuedAt.isBefore(command.periodStart) && !receipt.issuedAt.isAfter(command.periodEnd)
        }

        val expiryDisclosures = periodReceipts.map { receipt ->
            BonusExpiryDisclosure(
                receiptId = receipt.receiptId,
                grantId = receipt.grantId,
                actionType = receipt.actionType,
                forfeitedBonusMinorUnits = receipt.forfeitedBonusMinorUnits,
                compensationMinorUnits = receipt.compensationMinorUnits,
                expiryTimestamp = receipt.expiryTimestamp,
                expiryTimezone = receipt.expiryTimezone,
                serverVersion = receipt.serverVersion,
                reason = receipt.reason,
                evidenceReference = receipt.evidenceReference
            )
        }

        val totalForfeited = expiryDisclosures.sumOf { it.forfeitedBonusMinorUnits }
        val totalComp = expiryDisclosures.sumOf { it.compensationMinorUnits }

        val statementId = UUID.randomUUID()
        val evidenceReference = "bonus-statement:${command.tenantId}:${command.playerId}:$statementId:${wallet.version}"

        val statement = PlayerBonusStatement(
            statementId = statementId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            currencyCode = command.currencyCode,
            periodStart = command.periodStart,
            periodEnd = command.periodEnd,
            statementTimezone = command.statementTimezone,
            generatedAt = now,
            serverVersion = wallet.version,
            currentCashBalanceMinorUnits = wallet.cashMinorUnits,
            currentBonusBalanceMinorUnits = wallet.bonusMinorUnits,
            activeBonusDisclosures = activeDisclosures,
            expiryDisclosures = expiryDisclosures,
            totalExpiredOrForfeitedDuringPeriodMinorUnits = totalForfeited,
            totalCompensationDuringPeriodMinorUnits = totalComp,
            evidenceReference = evidenceReference
        )

        store.saveStatement(statement)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_STATEMENT_DISCLOSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "BONUS_STATEMENT_DISCLOSED",
            createdAt = now
        )

        val result = GenerateBonusStatementResult(
            resultId = resultId,
            statement = statement,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        store.saveIdempotency(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    fun getStatement(tenantId: String, statementId: UUID): PlayerBonusStatement? {
        return store.findStatement(tenantId, statementId)
    }

    fun getStatementsForPlayer(tenantId: String, playerId: UUID): List<PlayerBonusStatement> {
        return store.findStatementsForPlayer(tenantId, playerId)
    }
}
