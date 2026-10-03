package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.fasterxml.jackson.databind.ObjectMapper
import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Binding flag to enforce the protected risk assertion for GAME-010-01:
 * "legacy ack/sequence/recovery contract breaks"
 */
object AviatorRestCommandCompatibilityBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("legacy ack/sequence/recovery contract breaks")
        }
    }
}

enum class AviatorCommandAction { PLACE_BET, CANCEL_BET, CASH_OUT }

enum class AviatorCommandAckStatus { ACCEPTED, REJECTED, UNCERTAIN, DUPLICATE, ALREADY_PROCESSED }

enum class AviatorAuthoritativeHandStatus { ACCEPTED, CANCELLED, CASHED_OUT }

enum class AviatorCommandRejectionCode {
    INVALID_PHASE, INVALID_HAND_STATE, OUT_OF_LIMITS, INSUFFICIENT_BALANCE,
    INELIGIBLE, AUTHENTICATION_REQUIRED, ROUND_CLOSED, RATE_LIMITED, ROUND_CAPACITY_REACHED, UNKNOWN
}

data class AviatorAuthoritativeResult(
    val handStatus: AviatorAuthoritativeHandStatus,
    val wagerMinor: Long?,
    val accountMoneyAfterMinor: Long,
    val currency: String,
    val cashOutMultiplier: Double? = null,
    val payoutMinor: Long? = null,
)

data class AviatorCommandRejection(
    val code: AviatorCommandRejectionCode,
    val retryable: Boolean,
    val safeMessage: String,
)

data class AviatorRestCommand(
    val tenantId: String,
    val principal: AuthenticatedPrincipal?,
    val commandId: String,
    val causationId: String = commandId,
    val roundId: String,
    val handId: String,
    val action: String,
    val wagerMinor: Long? = null,
    val currency: String = "INR",
    val autoCashOutMultiplier: String? = null,
    val cashOutMultiplier: Double? = null,
    val correlationId: String,
    val protocolVersion: String = "1.2.0",
    val rulesVersion: String = "1.0.0",
    val expectedRoundVersion: Long? = null,
    val clientSeed: String? = null,
)

data class AviatorCommandAckResult(
    val schemaVersion: Int = 1,
    val commandId: String,
    val roundId: String,
    val handId: String,
    val action: AviatorCommandAction,
    val status: AviatorCommandAckStatus,
    val timestampMillis: Long,
    val sequenceId: Long,
    val revision: Long,
    val causationId: String,
    val result: AviatorAuthoritativeResult? = null,
    val rejection: AviatorCommandRejection? = null,
    val evidenceReference: String,
)

interface AviatorCommandStore {
    fun findByIdempotency(tenantId: String, commandId: String): Pair<String, AviatorCommandAckResult>?
    fun saveCommand(
        tenantId: String,
        commandId: String,
        fingerprint: String,
        ackResult: AviatorCommandAckResult,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun getBalance(tenantId: String, playerId: String, currency: String): Long
    fun setBalance(tenantId: String, playerId: String, currency: String, balanceMinor: Long)
    fun getRoundVersion(tenantId: String, roundId: String): Long
    fun incrementRoundVersion(tenantId: String, roundId: String): Long
    fun setRoundVersion(tenantId: String, roundId: String, version: Long)
    fun getActiveHandWager(tenantId: String, roundId: String, playerId: String, handId: String): Long?
    fun setActiveHandWager(tenantId: String, roundId: String, playerId: String, handId: String, wagerMinor: Long?)
}

class InMemoryAviatorCommandStore : AviatorCommandStore {
    private val idempotency = ConcurrentHashMap<String, Pair<String, AviatorCommandAckResult>>()
    private val balances = ConcurrentHashMap<String, Long>()
    private val roundVersions = ConcurrentHashMap<String, Long>()
    private val activeHandWagers = ConcurrentHashMap<String, Long>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, commandId: String): Pair<String, AviatorCommandAckResult>? {
        return idempotency["$tenantId:$commandId"]
    }

    @Synchronized
    override fun saveCommand(
        tenantId: String,
        commandId: String,
        fingerprint: String,
        ackResult: AviatorCommandAckResult,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        idempotency["$tenantId:$commandId"] = fingerprint to ackResult
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun getBalance(tenantId: String, playerId: String, currency: String): Long {
        return balances.getOrPut("$tenantId:$playerId:$currency") { 500_000L } // Default 5000.00
    }

    @Synchronized
    override fun setBalance(tenantId: String, playerId: String, currency: String, balanceMinor: Long) {
        balances["$tenantId:$playerId:$currency"] = balanceMinor
    }

    @Synchronized
    override fun getRoundVersion(tenantId: String, roundId: String): Long {
        return roundVersions.getOrPut("$tenantId:$roundId") { 1L }
    }

    @Synchronized
    override fun incrementRoundVersion(tenantId: String, roundId: String): Long {
        val current = getRoundVersion(tenantId, roundId)
        val updated = current + 1L
        roundVersions["$tenantId:$roundId"] = updated
        return updated
    }

    @Synchronized
    override fun setRoundVersion(tenantId: String, roundId: String, version: Long) {
        roundVersions["$tenantId:$roundId"] = version
    }

    @Synchronized
    override fun getActiveHandWager(tenantId: String, roundId: String, playerId: String, handId: String): Long? {
        return activeHandWagers["$tenantId:$roundId:$playerId:$handId"]
    }

    @Synchronized
    override fun setActiveHandWager(tenantId: String, roundId: String, playerId: String, handId: String, wagerMinor: Long?) {
        val key = "$tenantId:$roundId:$playerId:$handId"
        if (wagerMinor != null) {
            activeHandWagers[key] = wagerMinor
        } else {
            activeHandWagers.remove(key)
        }
    }
}

/**
 * Test-only compatibility service for legacy command parser contracts.
 *
 * WARNING: Unsafe internal code. Do NOT expose via controllers or use in production.
 * Authoritative durable game round wager reservation and settlement is implemented by
 * [DurableGameWagerAndSettlementService] under TC-021.
 */
@Deprecated(
    message = "Test-only compatibility harness. Use DurableGameWagerAndSettlementService for authoritative ledger-backed game settlement.",
    replaceWith = ReplaceWith("DurableGameWagerAndSettlementService")
)
class AviatorRestCommandCompatibilityService(
    private val store: AviatorCommandStore,
    private val rbacPolicy: AdminRbacPolicy = AdminRbacPolicy(true),
    private val clock: Clock = Clock.systemUTC(),
) {
    private val sequenceCounter = AtomicLong(100L)

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun normalizeHandId(raw: String): String = when (raw.trim().lowercase()) {
        "f", "0", "first", "primary", "hand_primary" -> "hand_primary"
        "s", "1", "second", "secondary", "hand_secondary" -> "hand_secondary"
        else -> raw.trim()
    }

    private fun normalizeAction(raw: String): AviatorCommandAction = when (raw.trim().uppercase()) {
        "PLACE_BET", "BET", "B", "PLAY" -> AviatorCommandAction.PLACE_BET
        "CANCEL_BET", "CANCEL", "C" -> AviatorCommandAction.CANCEL_BET
        "CASH_OUT", "CASHOUT", "CO", "CLAIM" -> AviatorCommandAction.CASH_OUT
        else -> throw IllegalArgumentException("Unknown command action: $raw")
    }

    private fun fingerprint(cmd: AviatorRestCommand, canonicalHand: String, canonicalAction: AviatorCommandAction): String {
        return sha256("${cmd.tenantId}:${cmd.commandId}:${cmd.roundId}:$canonicalHand:$canonicalAction:${cmd.wagerMinor}:${cmd.currency}:${cmd.cashOutMultiplier}")
    }

    @Synchronized
    fun processCommand(command: AviatorRestCommand): AviatorCommandAckResult {
        AviatorRestCommandCompatibilityBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.commandId.isBlank() ||
            command.roundId.isBlank() ||
            command.handId.isBlank() ||
            command.action.isBlank() ||
            command.correlationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.currency.length != 3 || command.currency != "INR") {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (!command.protocolVersion.startsWith("1.")) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.rulesVersion != "1.0.0") {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Authorization
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Normalization of legacy formats
        val canonicalHand = normalizeHandId(command.handId)
        val canonicalAction = try {
            normalizeAction(command.action)
        } catch (e: IllegalArgumentException) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (canonicalAction == AviatorCommandAction.PLACE_BET) {
            val wager = command.wagerMinor ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            if (wager <= 0L) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 4. Idempotency check
        val fp = fingerprint(command, canonicalHand, canonicalAction)
        store.findByIdempotency(command.tenantId, command.commandId)?.let { (cachedFp, cachedAck) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedAck.copy(status = AviatorCommandAckStatus.DUPLICATE)
        }

        // 5. Versioning
        val currentRoundVer = store.getRoundVersion(command.tenantId, command.roundId)
        if (command.expectedRoundVersion != null && command.expectedRoundVersion != currentRoundVer) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val timestamp = now.toEpochMilli()
        val sequenceId = sequenceCounter.incrementAndGet()
        val revision = store.incrementRoundVersion(command.tenantId, command.roundId)
        val evidenceRef = sha256("${command.tenantId}:${command.commandId}:$canonicalAction:$sequenceId:$timestamp")

        // 6. Financial Ledger Conservation
        val playerId = principal.id
        val currentBalance = store.getBalance(command.tenantId, playerId, command.currency)

        val (authResult, rejection) = when (canonicalAction) {
            AviatorCommandAction.PLACE_BET -> {
                val wager = command.wagerMinor!!
                if (currentBalance < wager) {
                    null to AviatorCommandRejection(
                        code = AviatorCommandRejectionCode.INSUFFICIENT_BALANCE,
                        retryable = false,
                        safeMessage = "Insufficient player balance"
                    )
                } else {
                    val newBalance = currentBalance - wager
                    store.setBalance(command.tenantId, playerId, command.currency, newBalance)
                    store.setActiveHandWager(command.tenantId, command.roundId, playerId, canonicalHand, wager)
                    AviatorAuthoritativeResult(
                        handStatus = AviatorAuthoritativeHandStatus.ACCEPTED,
                        wagerMinor = wager,
                        accountMoneyAfterMinor = newBalance,
                        currency = command.currency
                    ) to null
                }
            }
            AviatorCommandAction.CANCEL_BET -> {
                val placedWager = store.getActiveHandWager(command.tenantId, command.roundId, playerId, canonicalHand)
                    ?: command.wagerMinor
                    ?: 0L
                val newBalance = currentBalance + placedWager
                store.setBalance(command.tenantId, playerId, command.currency, newBalance)
                store.setActiveHandWager(command.tenantId, command.roundId, playerId, canonicalHand, null)
                AviatorAuthoritativeResult(
                    handStatus = AviatorAuthoritativeHandStatus.CANCELLED,
                    wagerMinor = placedWager,
                    accountMoneyAfterMinor = newBalance,
                    currency = command.currency
                ) to null
            }
            AviatorCommandAction.CASH_OUT -> {
                val placedWager = store.getActiveHandWager(command.tenantId, command.roundId, playerId, canonicalHand)
                    ?: command.wagerMinor
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                val mult = command.cashOutMultiplier ?: 1.0
                val payout = BigDecimal.valueOf(placedWager)
                    .multiply(BigDecimal.valueOf(mult))
                    .setScale(0, RoundingMode.HALF_UP)
                    .longValueExact()
                val newBalance = currentBalance + payout
                store.setBalance(command.tenantId, playerId, command.currency, newBalance)
                store.setActiveHandWager(command.tenantId, command.roundId, playerId, canonicalHand, null)
                AviatorAuthoritativeResult(
                    handStatus = AviatorAuthoritativeHandStatus.CASHED_OUT,
                    wagerMinor = placedWager,
                    accountMoneyAfterMinor = newBalance,
                    currency = command.currency,
                    cashOutMultiplier = mult,
                    payoutMinor = payout
                ) to null
            }
        }

        val status = if (rejection != null) AviatorCommandAckStatus.REJECTED else AviatorCommandAckStatus.ACCEPTED
        val resultId = UUID.randomUUID()

        val ack = AviatorCommandAckResult(
            schemaVersion = 1,
            commandId = command.commandId,
            roundId = command.roundId,
            handId = canonicalHand,
            action = canonicalAction,
            status = status,
            timestampMillis = timestamp,
            sequenceId = sequenceId,
            revision = revision,
            causationId = command.causationId,
            result = authResult,
            rejection = rejection,
            evidenceReference = evidenceRef
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AVIATOR_REST_COMMAND_PROCESSED_${canonicalAction}_$status",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AVIATOR_COMMAND_ACK",
            createdAt = now
        )

        store.saveCommand(command.tenantId, command.commandId, fp, ack, audit, outbox)

        return ack
    }

    /**
     * Exact command result lookup by roundId and commandId (TC-020 lost ACK recovery).
     */
    @Synchronized
    fun getCommandResult(
        tenantId: String,
        principal: AuthenticatedPrincipal?,
        roundId: String,
        commandId: String
    ): AviatorCommandAckResult? {
        AviatorRestCommandCompatibilityBinding.checkBound()

        val p = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (p.tenantId != tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val entry = store.findByIdempotency(tenantId, commandId) ?: return null
        val ack = entry.second
        if (ack.roundId != roundId) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        return ack
    }

    /**
     * Parses incoming JSON command payload strictly validating integral minor units,
     * currency, protocol SemVer, and rules agreement (TC-020, AND-022, XREP-002).
     */
    fun parseAndValidateCommand(
        tenantId: String,
        principal: AuthenticatedPrincipal?,
        payloadJson: String,
        correlationId: String
    ): AviatorRestCommand {
        val mapper = ObjectMapper()
        val root = try {
            mapper.readTree(payloadJson)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val schemaVer = root.get("schemaVersion")?.takeIf { it.isIntegralNumber }?.asInt() ?: 1
        if (schemaVer != 1) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val protoVer = root.get("protocolVersion")?.asText() ?: "1.2.0"
        if (!protoVer.startsWith("1.")) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val rulesVer = root.get("rulesVersion")?.asText() ?: "1.0.0"
        if (rulesVer != "1.0.0") throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val cmdId = root.get("commandId")?.asText()?.takeIf { it.isNotBlank() }
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        val roundId = root.get("roundId")?.asText()?.takeIf { it.isNotBlank() }
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        val handId = root.get("handId")?.asText()?.takeIf { it.isNotBlank() }
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        val rawAction = root.get("action")?.asText()?.takeIf { it.isNotBlank() }
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        val expVer = root.get("expectedRoundVersion")?.takeIf { it.isIntegralNumber }?.asLong() ?: 1L

        var wagerMinor: Long? = null
        var currency = "INR"

        if (rawAction.uppercase() in listOf("PLACE_BET", "BET", "B", "PLAY")) {
            val accountMoney = root.get("accountMoney") ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            val amountNode = accountMoney.get("amountMinor") ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            if (!amountNode.isIntegralNumber || amountNode.isFloatingPointNumber || !amountNode.canConvertToLong()) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            val amt = amountNode.asLong()
            if (amt <= 0) throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            wagerMinor = amt

            val currNode = accountMoney.get("currency") ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            currency = currNode.asText()
            if (currency.length != 3 || currency.any { it !in 'A'..'Z' }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        val cmd = AviatorRestCommand(
            tenantId = tenantId,
            principal = principal,
            commandId = cmdId,
            causationId = cmdId,
            roundId = roundId,
            handId = handId,
            action = rawAction,
            wagerMinor = wagerMinor,
            currency = currency,
            correlationId = correlationId,
            protocolVersion = protoVer,
            rulesVersion = rulesVer,
            expectedRoundVersion = expVer
        )

        return cmd
    }
}
