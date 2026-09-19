package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce GAME-005: Round/provider transaction map.
 * Protected risk: "ID collision/currency mismatch"
 * Semantic contract: "Unique provider+tenant+transaction; immutable lineage."
 */
object RoundProviderTransactionBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("ID collision/currency mismatch")
        }
    }
}

enum class ProviderTransactionType {
    BET,
    WIN,
    REFUND,
    ROLLBACK,
    JACKPOT,
}

enum class CanonicalRoundStatus {
    OPEN,
    SETTLED,
    CANCELLED,
}

data class ProviderTransactionRecord(
    val canonicalTransactionId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val canonicalRoundId: UUID,
    val playerId: UUID,
    val gameId: String,
    val transactionType: ProviderTransactionType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val parentTransactionId: UUID?,
    val sequenceNumber: Long,
    val recordedAt: Instant,
    val evidenceReference: String,
)

data class CanonicalRoundRecord(
    val canonicalRoundId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val playerId: UUID,
    val gameId: String,
    val currencyCode: String,
    var status: CanonicalRoundStatus,
    var totalDebitMinorUnits: Long,
    var totalCreditMinorUnits: Long,
    var netOutcomeMinorUnits: Long,
    var transactionCount: Int,
    val openedAt: Instant,
    var settledAt: Instant? = null,
    var version: Long = 1L,
)

data class MapProviderTransactionCommand(
    val principal: AuthenticatedPrincipal? = null,
    val sessionId: String? = null,
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val playerId: UUID,
    val gameId: String,
    val transactionType: ProviderTransactionType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val parentTransactionId: UUID? = null,
    val settleRound: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ProviderTransactionMapResult(
    val resultId: UUID,
    val canonicalTransactionId: UUID,
    val canonicalRoundId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val playerId: UUID,
    val gameId: String,
    val transactionType: ProviderTransactionType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val roundStatus: CanonicalRoundStatus,
    val roundTotalDebitMinorUnits: Long,
    val roundTotalCreditMinorUnits: Long,
    val roundNetOutcomeMinorUnits: Long,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface RoundProviderTransactionStore {
    fun findTransactionByExternalId(tenantId: String, providerId: String, externalTransactionId: String): ProviderTransactionRecord?
    fun findRoundByExternalId(tenantId: String, providerId: String, externalRoundId: String): CanonicalRoundRecord?
    fun findRoundTransactions(tenantId: String, canonicalRoundId: UUID): List<ProviderTransactionRecord>
    fun saveTransactionAndRound(
        transaction: ProviderTransactionRecord,
        round: CanonicalRoundRecord,
        result: ProviderTransactionMapResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ProviderTransactionMapResult>?
    fun saveRound(round: CanonicalRoundRecord) {}
}

class InMemoryRoundProviderTransactionStore : RoundProviderTransactionStore {
    private val transactionsByExtId = ConcurrentHashMap<String, ProviderTransactionRecord>()
    private val roundsByExtId = ConcurrentHashMap<String, CanonicalRoundRecord>()
    private val roundTransactions = ConcurrentHashMap<UUID, MutableList<ProviderTransactionRecord>>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, ProviderTransactionMapResult>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun txKey(tenantId: String, providerId: String, externalTransactionId: String) =
        "$tenantId:$providerId:$externalTransactionId"

    private fun roundKey(tenantId: String, providerId: String, externalRoundId: String) =
        "$tenantId:$providerId:$externalRoundId"

    @Synchronized
    override fun findTransactionByExternalId(tenantId: String, providerId: String, externalTransactionId: String): ProviderTransactionRecord? {
        return transactionsByExtId[txKey(tenantId, providerId, externalTransactionId)]
    }

    @Synchronized
    override fun findRoundByExternalId(tenantId: String, providerId: String, externalRoundId: String): CanonicalRoundRecord? {
        return roundsByExtId[roundKey(tenantId, providerId, externalRoundId)]?.copy()
    }

    @Synchronized
    override fun findRoundTransactions(tenantId: String, canonicalRoundId: UUID): List<ProviderTransactionRecord> {
        return roundTransactions[canonicalRoundId]?.map { it.copy() } ?: emptyList()
    }

    @Synchronized
    override fun saveTransactionAndRound(
        transaction: ProviderTransactionRecord,
        round: CanonicalRoundRecord,
        result: ProviderTransactionMapResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        transactionsByExtId[txKey(transaction.tenantId, transaction.providerId, transaction.externalTransactionId)] = transaction
        roundsByExtId[roundKey(round.tenantId, round.providerId, round.externalRoundId)] = round.copy()
        roundTransactions.computeIfAbsent(round.canonicalRoundId) { mutableListOf() }.add(transaction)
        idempotency["${transaction.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ProviderTransactionMapResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun saveRound(round: CanonicalRoundRecord) {
        roundsByExtId[roundKey(round.tenantId, round.providerId, round.externalRoundId)] = round.copy()
    }
}

class RoundProviderTransactionMapService(
    private val store: RoundProviderTransactionStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: MapProviderTransactionCommand): String {
        return sha256("${cmd.tenantId}:${cmd.providerId}:${cmd.externalRoundId}:${cmd.externalTransactionId}:${cmd.playerId}:${cmd.gameId}:${cmd.transactionType}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.parentTransactionId}:${cmd.settleRound}:${cmd.expectedVersion}")
    }

    @Synchronized
    fun mapTransaction(command: MapProviderTransactionCommand): ProviderTransactionMapResult {
        RoundProviderTransactionBinding.checkBound()

        // 1. Structural Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.externalRoundId.isBlank() ||
            command.externalTransactionId.isBlank() ||
            command.gameId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.amountMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        if (command.principal != null) {
            if (command.principal.tenantId != command.tenantId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        // 2. Idempotency Check
        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 3. Check for ID Collision (Protected Risk: ID collision)
        // Unique provider + tenant + transaction
        val existingTx = store.findTransactionByExternalId(command.tenantId, command.providerId, command.externalTransactionId)
        if (existingTx != null) {
            // If existing transaction matches exactly, but under a different idempotency key, or has different payload
            if (existingTx.amountMinorUnits != command.amountMinorUnits ||
                existingTx.transactionType != command.transactionType ||
                existingTx.playerId != command.playerId ||
                existingTx.gameId != command.gameId ||
                existingTx.currencyCode != command.currencyCode ||
                existingTx.externalRoundId != command.externalRoundId
            ) {
                // ID collision with conflicting payload
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            // ID already mapped
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 4. Round Lookup or Creation & Currency Mismatch Check (Protected Risk: currency mismatch)
        var round = store.findRoundByExternalId(command.tenantId, command.providerId, command.externalRoundId)

        if (round != null) {
            // Currency Mismatch Check: Round currency MUST match transaction currency
            if (round.currencyCode != command.currencyCode) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            // Player and Game consistency within round
            if (round.playerId != command.playerId || round.gameId != command.gameId) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            // Check if round is already settled (immutable lineage: cannot append new transactions to settled round unless rollback)
            if (round.status == CanonicalRoundStatus.SETTLED && command.transactionType != ProviderTransactionType.ROLLBACK) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }

            if (round.status == CanonicalRoundStatus.CANCELLED) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        } else {
            // Opening transaction in a new round
            val canonicalRoundId = UUID.randomUUID()
            round = CanonicalRoundRecord(
                canonicalRoundId = canonicalRoundId,
                tenantId = command.tenantId,
                providerId = command.providerId,
                externalRoundId = command.externalRoundId,
                playerId = command.playerId,
                gameId = command.gameId,
                currencyCode = command.currencyCode,
                status = CanonicalRoundStatus.OPEN,
                totalDebitMinorUnits = 0L,
                totalCreditMinorUnits = 0L,
                netOutcomeMinorUnits = 0L,
                transactionCount = 0,
                openedAt = now,
            )
        }

        // 5. Parent Transaction Validation for ROLLBACK / REFUND (Immutable Lineage)
        if (command.transactionType == ProviderTransactionType.ROLLBACK || command.transactionType == ProviderTransactionType.REFUND) {
            if (command.parentTransactionId == null) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            val roundTxs = store.findRoundTransactions(command.tenantId, round.canonicalRoundId)
            val parentTx = roundTxs.find { it.canonicalTransactionId == command.parentTransactionId }
            if (parentTx == null) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
            // Currency of rollback must match parent
            if (parentTx.currencyCode != command.currencyCode) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // 6. Update Round Totals and State
        val nextSeq = (round.transactionCount + 1).toLong()
        when (command.transactionType) {
            ProviderTransactionType.BET -> {
                round.totalDebitMinorUnits += command.amountMinorUnits
            }
            ProviderTransactionType.WIN, ProviderTransactionType.JACKPOT -> {
                round.totalCreditMinorUnits += command.amountMinorUnits
            }
            ProviderTransactionType.REFUND, ProviderTransactionType.ROLLBACK -> {
                // Immutable compensation: adjusts totals
                round.totalCreditMinorUnits += command.amountMinorUnits
            }
        }
        round.netOutcomeMinorUnits = round.totalCreditMinorUnits - round.totalDebitMinorUnits
        round.transactionCount += 1
        round.version += 1L

        if (command.settleRound) {
            round.status = CanonicalRoundStatus.SETTLED
            round.settledAt = now
        }

        // 7. Create Canonical Transaction Record
        val canonicalTransactionId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:${command.providerId}:${command.externalTransactionId}:$canonicalTransactionId:${now.toEpochMilli()}")

        val txRecord = ProviderTransactionRecord(
            canonicalTransactionId = canonicalTransactionId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            canonicalRoundId = round.canonicalRoundId,
            playerId = command.playerId,
            gameId = command.gameId,
            transactionType = command.transactionType,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            parentTransactionId = command.parentTransactionId,
            sequenceNumber = nextSeq,
            recordedAt = now,
            evidenceReference = evidenceRef,
        )

        val resultId = UUID.randomUUID()
        val result = ProviderTransactionMapResult(
            resultId = resultId,
            canonicalTransactionId = canonicalTransactionId,
            canonicalRoundId = round.canonicalRoundId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            playerId = command.playerId,
            gameId = command.gameId,
            transactionType = command.transactionType,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            roundStatus = round.status,
            roundTotalDebitMinorUnits = round.totalDebitMinorUnits,
            roundTotalCreditMinorUnits = round.totalCreditMinorUnits,
            roundNetOutcomeMinorUnits = round.netOutcomeMinorUnits,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PROVIDER_TRANSACTION_MAPPED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PROVIDER_TRANSACTION_MAPPED",
            createdAt = now,
        )

        store.saveTransactionAndRound(
            transaction = txRecord,
            round = round,
            result = result,
            idempotencyKey = command.idempotencyKey,
            fingerprint = fp,
            audit = audit,
            outbox = outbox,
        )

        return result
    }
}
