package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding check enforcing the protected risk assertion:
 * "duplicate/out-of-order/rollback corrupts balance"
 */
object GameRefundRollbackBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("duplicate/out-of-order/rollback corrupts balance")
        }
    }
}

enum class GameRefundRollbackType {
    REFUND,
    ROLLBACK_COMPENSATION,
}

enum class GameRefundRollbackStatus {
    REFUNDED,
    COMPENSATED_ROLLBACK,
    QUARANTINED_UNSUPPORTED_SEQUENCE,
    RECONCILED,
    REJECTED,
}

data class RefundRollbackLedgerLeg(
    val accountReference: String,
    val direction: String, // "DEBIT" or "CREDIT"
    val amountMinorUnits: Long,
    val currencyCode: String,
)

data class GameRefundRollbackRecord(
    val operationId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val targetExternalTransactionId: String?,
    val operationType: GameRefundRollbackType,
    val canonicalRoundId: UUID?,
    val canonicalTransactionId: UUID?,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: GameRefundRollbackStatus,
    val reason: String,
    val quarantineReason: String?,
    val executedAt: Instant,
    val ledgerEntries: List<RefundRollbackLedgerLeg>,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
)

data class GameRefundRollbackResult(
    val resultId: UUID,
    val operationId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val targetExternalTransactionId: String?,
    val operationType: GameRefundRollbackType,
    val canonicalRoundId: UUID?,
    val canonicalTransactionId: UUID?,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: GameRefundRollbackStatus,
    val playerBalanceMinorUnits: Long,
    val quarantineReason: String?,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class PostGameRefundCommand(
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val referenceExternalTransactionId: String? = null,
    val refundAmountMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class PostRollbackCompensationCommand(
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val targetExternalTransactionId: String,
    val targetTransactionType: ProviderTransactionType,
    val compensationAmountMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ReconcileQuarantinedRefundRollbackCommand(
    val tenantId: String,
    val operationId: UUID,
    val reviewerAdminId: UUID,
    val resolutionNotes: String,
    val correlationId: String,
    val causationId: String,
)

interface GameRefundRollbackStore {
    fun findOperationById(tenantId: String, operationId: UUID): GameRefundRollbackRecord?
    fun findOperationByExternalTx(tenantId: String, providerId: String, externalTransactionId: String): GameRefundRollbackRecord?
    fun findOperationsForRound(tenantId: String, canonicalRoundId: UUID): List<GameRefundRollbackRecord>
    fun findOperationsForTargetTx(tenantId: String, providerId: String, targetExternalTxId: String): List<GameRefundRollbackRecord>
    fun saveOperation(
        record: GameRefundRollbackRecord,
        result: GameRefundRollbackResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateOperation(
        record: GameRefundRollbackRecord,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameRefundRollbackResult>?
    fun listQuarantined(tenantId: String): List<GameRefundRollbackRecord>
}

class InMemoryGameRefundRollbackStore : GameRefundRollbackStore {
    private val operations = ConcurrentHashMap<String, GameRefundRollbackRecord>()
    private val operationsByExtTx = ConcurrentHashMap<String, GameRefundRollbackRecord>()
    private val roundOperations = ConcurrentHashMap<UUID, MutableList<GameRefundRollbackRecord>>()
    private val targetTxOperations = ConcurrentHashMap<String, MutableList<GameRefundRollbackRecord>>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, GameRefundRollbackResult>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun opKey(tenantId: String, opId: UUID) = "$tenantId:$opId"
    private fun txKey(tenantId: String, providerId: String, extTx: String) = "$tenantId:$providerId:$extTx"

    @Synchronized
    override fun findOperationById(tenantId: String, operationId: UUID): GameRefundRollbackRecord? {
        return operations[opKey(tenantId, operationId)]?.copy()
    }

    @Synchronized
    override fun findOperationByExternalTx(tenantId: String, providerId: String, externalTransactionId: String): GameRefundRollbackRecord? {
        return operationsByExtTx[txKey(tenantId, providerId, externalTransactionId)]?.copy()
    }

    @Synchronized
    override fun findOperationsForRound(tenantId: String, canonicalRoundId: UUID): List<GameRefundRollbackRecord> {
        return roundOperations[canonicalRoundId]?.map { it.copy() } ?: emptyList()
    }

    @Synchronized
    override fun findOperationsForTargetTx(tenantId: String, providerId: String, targetExternalTxId: String): List<GameRefundRollbackRecord> {
        return targetTxOperations[txKey(tenantId, providerId, targetExternalTxId)]?.map { it.copy() } ?: emptyList()
    }

    @Synchronized
    override fun saveOperation(
        record: GameRefundRollbackRecord,
        result: GameRefundRollbackResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        operations[opKey(record.tenantId, record.operationId)] = record.copy()
        operationsByExtTx[txKey(record.tenantId, record.providerId, record.externalTransactionId)] = record.copy()
        if (record.canonicalRoundId != null) {
            roundOperations.computeIfAbsent(record.canonicalRoundId) { mutableListOf() }.add(record)
        }
        if (record.targetExternalTransactionId != null) {
            targetTxOperations.computeIfAbsent(txKey(record.tenantId, record.providerId, record.targetExternalTransactionId)) { mutableListOf() }.add(record)
        }
        idempotency["${record.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateOperation(record: GameRefundRollbackRecord, audit: AuditEvent, outbox: OutboxEvent) {
        operations[opKey(record.tenantId, record.operationId)] = record.copy()
        operationsByExtTx[txKey(record.tenantId, record.providerId, record.externalTransactionId)] = record.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameRefundRollbackResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun listQuarantined(tenantId: String): List<GameRefundRollbackRecord> {
        return operations.values
            .filter { it.tenantId == tenantId && it.status == GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE }
            .map { it.copy() }
    }
}

interface GameRefundRollbackAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryGameRefundRollbackAlertSink : GameRefundRollbackAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

class GameRefundRollbackService(
    private val roundStore: RoundProviderTransactionStore,
    private val roundMapService: RoundProviderTransactionMapService,
    private val reservationStore: WagerAuthorizationReservationStore,
    private val refundRollbackStore: GameRefundRollbackStore,
    private val alertSink: GameRefundRollbackAlertSink = InMemoryGameRefundRollbackAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRefund(cmd: PostGameRefundCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.providerId}:${cmd.gameId}:${cmd.externalRoundId}:${cmd.externalTransactionId}:${cmd.referenceExternalTransactionId}:${cmd.refundAmountMinorUnits}:${cmd.currencyCode}:${cmd.expectedVersion}")
    }

    private fun fingerprintRollback(cmd: PostRollbackCompensationCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.providerId}:${cmd.gameId}:${cmd.externalRoundId}:${cmd.externalTransactionId}:${cmd.targetExternalTransactionId}:${cmd.targetTransactionType}:${cmd.compensationAmountMinorUnits}:${cmd.currencyCode}:${cmd.expectedVersion}")
    }

    @Synchronized
    fun postGameRefund(command: PostGameRefundCommand): GameRefundRollbackResult {
        GameRefundRollbackBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.externalRoundId.isBlank() ||
            command.externalTransactionId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.refundAmountMinorUnits <= 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Idempotency Check
        val fp = fingerprintRefund(command)
        refundRollbackStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 3. Duplicate External Transaction Check
        val existingTx = refundRollbackStore.findOperationByExternalTx(
            command.tenantId,
            command.providerId,
            command.externalTransactionId,
        )
        if (existingTx != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 4. Round Lookup & Out-of-Order Verification (Protected Risk: out-of-order)
        val round = roundStore.findRoundByExternalId(command.tenantId, command.providerId, command.externalRoundId)

        // Unsupported sequence: Refund arrives for non-existent round or round without prior BET
        val isUnsupportedSequence = if (round == null) {
            true
        } else {
            val transactions = roundStore.findRoundTransactions(command.tenantId, round.canonicalRoundId)
            transactions.none { it.transactionType == ProviderTransactionType.BET }
        }

        if (isUnsupportedSequence) {
            val existingWallet = reservationStore.findWalletBalance(command.tenantId, command.playerId, command.currencyCode)
            val currentBal = existingWallet?.availableBalanceMinorUnits ?: 0L

            // Semantic Contract: Unsupported sequence quarantines/reconciles. Never corrupt balance!
            val quarantineReason = "Unsupported sequence: Refund received without prior active round or prior bet for round ${command.externalRoundId}"
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "HIGH",
                alertType = "GAME_REFUND_OUT_OF_ORDER_QUARANTINED",
                detail = quarantineReason,
            )

            val opId = UUID.randomUUID()
            val resultId = UUID.randomUUID()
            val evidenceRef = sha256("${command.tenantId}:$opId:${command.externalRoundId}:QUARANTINED:${now.toEpochMilli()}")

            val record = GameRefundRollbackRecord(
                operationId = opId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                providerId = command.providerId,
                gameId = command.gameId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                targetExternalTransactionId = command.referenceExternalTransactionId,
                operationType = GameRefundRollbackType.REFUND,
                canonicalRoundId = round?.canonicalRoundId,
                canonicalTransactionId = null,
                amountMinorUnits = command.refundAmountMinorUnits,
                currencyCode = command.currencyCode,
                status = GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE,
                reason = command.reason,
                quarantineReason = quarantineReason,
                executedAt = now,
                ledgerEntries = emptyList(),
                correlationId = command.correlationId,
                causationId = command.causationId,
                evidenceReference = evidenceRef,
            )

            val result = GameRefundRollbackResult(
                resultId = resultId,
                operationId = opId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                providerId = command.providerId,
                gameId = command.gameId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                targetExternalTransactionId = command.referenceExternalTransactionId,
                operationType = GameRefundRollbackType.REFUND,
                canonicalRoundId = round?.canonicalRoundId,
                canonicalTransactionId = null,
                amountMinorUnits = command.refundAmountMinorUnits,
                currencyCode = command.currencyCode,
                status = GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE,
                playerBalanceMinorUnits = currentBal, // Unchanged!
                quarantineReason = quarantineReason,
                serverTime = now,
                evidenceReference = evidenceRef,
            )

            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "GAME_REFUND_QUARANTINED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "GAME_REFUND_QUARANTINED",
                createdAt = now,
            )

            refundRollbackStore.saveOperation(record, result, command.idempotencyKey, fp, audit, outbox)
            return result
        }

        val activeRound = round!!

        // Consistency checks
        if (activeRound.currencyCode != command.currencyCode ||
            activeRound.playerId != command.playerId ||
            activeRound.gameId != command.gameId
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Cannot refund a round if already cancelled
        if (activeRound.status == CanonicalRoundStatus.CANCELLED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Conservation check: total refunds cannot exceed total bets placed in this round
        val roundTxs = roundStore.findRoundTransactions(command.tenantId, activeRound.canonicalRoundId)
        val totalBetAmount = roundTxs
            .filter { it.transactionType == ProviderTransactionType.BET }
            .sumOf { it.amountMinorUnits }
        val priorRefundAmount = roundTxs
            .filter { it.transactionType == ProviderTransactionType.REFUND }
            .sumOf { it.amountMinorUnits }

        if (priorRefundAmount + command.refundAmountMinorUnits > totalBetAmount) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // If reference transaction ID specified, ensure it exists, matches BET, and matches round
        val parentBet = if (command.referenceExternalTransactionId != null) {
            val refTx = roundStore.findTransactionByExternalId(command.tenantId, command.providerId, command.referenceExternalTransactionId)
            if (refTx == null || refTx.canonicalRoundId != activeRound.canonicalRoundId || refTx.transactionType != ProviderTransactionType.BET) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            refTx
        } else {
            roundTxs.firstOrNull { it.transactionType == ProviderTransactionType.BET }
                ?: throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 5. Wallet Lookup
        val wallet = reservationStore.findWalletBalance(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // 6. Map REFUND Transaction to Canonical Round
        val roundMapResult = roundMapService.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = command.tenantId,
                providerId = command.providerId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                playerId = command.playerId,
                gameId = command.gameId,
                transactionType = ProviderTransactionType.REFUND,
                amountMinorUnits = command.refundAmountMinorUnits,
                currencyCode = command.currencyCode,
                parentTransactionId = parentBet.canonicalTransactionId,
                settleRound = false,
                idempotencyKey = "tx-refund-map-${command.idempotencyKey}",
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        // 7. Double-entry Ledger Entries (Debits equal credits)
        val ledgerLegs = listOf(
            RefundRollbackLedgerLeg(
                accountReference = "CASINO_HOLDING_POOL:${command.tenantId}:${command.currencyCode}",
                direction = "DEBIT",
                amountMinorUnits = command.refundAmountMinorUnits,
                currencyCode = command.currencyCode,
            ),
            RefundRollbackLedgerLeg(
                accountReference = "PLAYER_WALLET:${command.tenantId}:${command.playerId}:${command.currencyCode}",
                direction = "CREDIT",
                amountMinorUnits = command.refundAmountMinorUnits,
                currencyCode = command.currencyCode,
            ),
        )

        // 8. Atomically Credit Player Wallet Balance
        wallet.availableBalanceMinorUnits += command.refundAmountMinorUnits
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        // 9. Persist Refund Record
        val opId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:$opId:${roundMapResult.canonicalRoundId}:${roundMapResult.canonicalTransactionId}:${now.toEpochMilli()}")

        val record = GameRefundRollbackRecord(
            operationId = opId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            targetExternalTransactionId = command.referenceExternalTransactionId,
            operationType = GameRefundRollbackType.REFUND,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            amountMinorUnits = command.refundAmountMinorUnits,
            currencyCode = command.currencyCode,
            status = GameRefundRollbackStatus.REFUNDED,
            reason = command.reason,
            quarantineReason = null,
            executedAt = now,
            ledgerEntries = ledgerLegs,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
        )

        val result = GameRefundRollbackResult(
            resultId = resultId,
            operationId = opId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            targetExternalTransactionId = command.referenceExternalTransactionId,
            operationType = GameRefundRollbackType.REFUND,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            amountMinorUnits = command.refundAmountMinorUnits,
            currencyCode = command.currencyCode,
            status = GameRefundRollbackStatus.REFUNDED,
            playerBalanceMinorUnits = wallet.availableBalanceMinorUnits,
            quarantineReason = null,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_REFUND_POSTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_REFUND_POSTED",
            createdAt = now,
        )

        refundRollbackStore.saveOperation(record, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun postRollbackCompensation(command: PostRollbackCompensationCommand): GameRefundRollbackResult {
        GameRefundRollbackBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.externalRoundId.isBlank() ||
            command.externalTransactionId.isBlank() ||
            command.targetExternalTransactionId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.compensationAmountMinorUnits <= 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Idempotency Check
        val fp = fingerprintRollback(command)
        refundRollbackStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 3. Duplicate External Transaction Check
        val existingTx = refundRollbackStore.findOperationByExternalTx(
            command.tenantId,
            command.providerId,
            command.externalTransactionId,
        )
        if (existingTx != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 4. Target Transaction Lookup & Out-of-Order Verification (Protected Risk: out-of-order)
        val round = roundStore.findRoundByExternalId(command.tenantId, command.providerId, command.externalRoundId)
        val targetTx = roundStore.findTransactionByExternalId(command.tenantId, command.providerId, command.targetExternalTransactionId)

        // Unsupported sequence: Target transaction not yet posted or round missing
        val isUnsupportedSequence = (round == null || targetTx == null)

        if (isUnsupportedSequence) {
            val existingWallet = reservationStore.findWalletBalance(command.tenantId, command.playerId, command.currencyCode)
            val currentBal = existingWallet?.availableBalanceMinorUnits ?: 0L

            val quarantineReason = "Unsupported sequence: Rollback received for unposted target transaction ${command.targetExternalTransactionId} in round ${command.externalRoundId}"
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "HIGH",
                alertType = "GAME_ROLLBACK_OUT_OF_ORDER_QUARANTINED",
                detail = quarantineReason,
            )

            val opId = UUID.randomUUID()
            val resultId = UUID.randomUUID()
            val evidenceRef = sha256("${command.tenantId}:$opId:${command.externalRoundId}:QUARANTINED:${now.toEpochMilli()}")

            val record = GameRefundRollbackRecord(
                operationId = opId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                providerId = command.providerId,
                gameId = command.gameId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                targetExternalTransactionId = command.targetExternalTransactionId,
                operationType = GameRefundRollbackType.ROLLBACK_COMPENSATION,
                canonicalRoundId = round?.canonicalRoundId,
                canonicalTransactionId = null,
                amountMinorUnits = command.compensationAmountMinorUnits,
                currencyCode = command.currencyCode,
                status = GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE,
                reason = command.reason,
                quarantineReason = quarantineReason,
                executedAt = now,
                ledgerEntries = emptyList(),
                correlationId = command.correlationId,
                causationId = command.causationId,
                evidenceReference = evidenceRef,
            )

            val result = GameRefundRollbackResult(
                resultId = resultId,
                operationId = opId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                providerId = command.providerId,
                gameId = command.gameId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                targetExternalTransactionId = command.targetExternalTransactionId,
                operationType = GameRefundRollbackType.ROLLBACK_COMPENSATION,
                canonicalRoundId = round?.canonicalRoundId,
                canonicalTransactionId = null,
                amountMinorUnits = command.compensationAmountMinorUnits,
                currencyCode = command.currencyCode,
                status = GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE,
                playerBalanceMinorUnits = currentBal, // Unchanged!
                quarantineReason = quarantineReason,
                serverTime = now,
                evidenceReference = evidenceRef,
            )

            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "GAME_ROLLBACK_QUARANTINED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "GAME_ROLLBACK_QUARANTINED",
                createdAt = now,
            )

            refundRollbackStore.saveOperation(record, result, command.idempotencyKey, fp, audit, outbox)
            return result
        }

        val activeRound = round!!
        val validTargetTx = targetTx!!

        // Consistency checks
        if (validTargetTx.tenantId != command.tenantId ||
            validTargetTx.providerId != command.providerId ||
            validTargetTx.playerId != command.playerId ||
            validTargetTx.gameId != command.gameId ||
            validTargetTx.currencyCode != command.currencyCode ||
            validTargetTx.externalRoundId != command.externalRoundId ||
            validTargetTx.transactionType != command.targetTransactionType
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Check already compensated
        val existingRollbacks = refundRollbackStore.findOperationsForTargetTx(command.tenantId, command.providerId, command.targetExternalTransactionId)
            .filter { it.status == GameRefundRollbackStatus.COMPENSATED_ROLLBACK }
        if (existingRollbacks.isNotEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Conservation check: cannot compensate more than original transaction amount
        if (command.compensationAmountMinorUnits > validTargetTx.amountMinorUnits) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 5. Wallet Lookup
        val wallet = reservationStore.findWalletBalance(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // 6. Map ROLLBACK Transaction to Canonical Round
        val roundMapResult = roundMapService.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = command.tenantId,
                providerId = command.providerId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                playerId = command.playerId,
                gameId = command.gameId,
                transactionType = ProviderTransactionType.ROLLBACK,
                amountMinorUnits = command.compensationAmountMinorUnits,
                currencyCode = command.currencyCode,
                parentTransactionId = validTargetTx.canonicalTransactionId,
                settleRound = false,
                idempotencyKey = "tx-rollback-map-${command.idempotencyKey}",
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        // 7. Reversal Ledger Legs (Debits equal credits)
        val ledgerLegs = when (command.targetTransactionType) {
            ProviderTransactionType.WIN -> {
                // Reversal of WIN: Debit player wallet, Credit casino payout pool
                listOf(
                    RefundRollbackLedgerLeg(
                        accountReference = "PLAYER_WALLET:${command.tenantId}:${command.playerId}:${command.currencyCode}",
                        direction = "DEBIT",
                        amountMinorUnits = command.compensationAmountMinorUnits,
                        currencyCode = command.currencyCode,
                    ),
                    RefundRollbackLedgerLeg(
                        accountReference = "CASINO_PAYOUT_POOL:${command.tenantId}:${command.currencyCode}",
                        direction = "CREDIT",
                        amountMinorUnits = command.compensationAmountMinorUnits,
                        currencyCode = command.currencyCode,
                    ),
                )
            }
            ProviderTransactionType.BET -> {
                // Reversal of BET: Credit player wallet, Debit casino holding pool
                listOf(
                    RefundRollbackLedgerLeg(
                        accountReference = "CASINO_HOLDING_POOL:${command.tenantId}:${command.currencyCode}",
                        direction = "DEBIT",
                        amountMinorUnits = command.compensationAmountMinorUnits,
                        currencyCode = command.currencyCode,
                    ),
                    RefundRollbackLedgerLeg(
                        accountReference = "PLAYER_WALLET:${command.tenantId}:${command.playerId}:${command.currencyCode}",
                        direction = "CREDIT",
                        amountMinorUnits = command.compensationAmountMinorUnits,
                        currencyCode = command.currencyCode,
                    ),
                )
            }
            else -> throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 8. Atomically Update Player Wallet Balance
        when (command.targetTransactionType) {
            ProviderTransactionType.WIN -> {
                wallet.availableBalanceMinorUnits -= command.compensationAmountMinorUnits
            }
            ProviderTransactionType.BET -> {
                wallet.availableBalanceMinorUnits += command.compensationAmountMinorUnits
            }
            else -> throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        // 9. Persist Compensating Record (Never delete posted original transaction!)
        val opId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:$opId:${roundMapResult.canonicalRoundId}:${roundMapResult.canonicalTransactionId}:${now.toEpochMilli()}")

        val record = GameRefundRollbackRecord(
            operationId = opId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            targetExternalTransactionId = command.targetExternalTransactionId,
            operationType = GameRefundRollbackType.ROLLBACK_COMPENSATION,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            amountMinorUnits = command.compensationAmountMinorUnits,
            currencyCode = command.currencyCode,
            status = GameRefundRollbackStatus.COMPENSATED_ROLLBACK,
            reason = command.reason,
            quarantineReason = null,
            executedAt = now,
            ledgerEntries = ledgerLegs,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
        )

        val result = GameRefundRollbackResult(
            resultId = resultId,
            operationId = opId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            targetExternalTransactionId = command.targetExternalTransactionId,
            operationType = GameRefundRollbackType.ROLLBACK_COMPENSATION,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            amountMinorUnits = command.compensationAmountMinorUnits,
            currencyCode = command.currencyCode,
            status = GameRefundRollbackStatus.COMPENSATED_ROLLBACK,
            playerBalanceMinorUnits = wallet.availableBalanceMinorUnits,
            quarantineReason = null,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_ROLLBACK_POSTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_ROLLBACK_POSTED",
            createdAt = now,
        )

        refundRollbackStore.saveOperation(record, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun reconcileQuarantinedOperation(command: ReconcileQuarantinedRefundRollbackCommand): GameRefundRollbackRecord {
        GameRefundRollbackBinding.checkBound()

        val record = refundRollbackStore.findOperationById(command.tenantId, command.operationId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (record.status != GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val updated = record.copy(
            status = GameRefundRollbackStatus.RECONCILED,
            quarantineReason = "Reconciled by admin ${command.reviewerAdminId}: ${command.resolutionNotes}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = record.operationId,
            tenantId = command.tenantId,
            type = "GAME_REFUND_ROLLBACK_RECONCILED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = record.operationId,
            tenantId = command.tenantId,
            type = "GAME_REFUND_ROLLBACK_RECONCILED",
            createdAt = now,
        )

        refundRollbackStore.updateOperation(updated, audit, outbox)
        return updated
    }
}
