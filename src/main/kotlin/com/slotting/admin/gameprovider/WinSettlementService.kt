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
 * Gate to enforce GAME-007-01: Post win settlement.
 * Protected risk: "duplicate/out-of-order/rollback corrupts balance"
 * Semantic contract: "Never delete posted entry; unsupported sequence quarantines/reconciles."
 */
object WinSettlementBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("duplicate/out-of-order/rollback corrupts balance")
        }
    }
}

enum class WinSettlementStatus {
    SETTLED,
    QUARANTINED_UNSUPPORTED_SEQUENCE,
    COMPENSATED_ROLLBACK,
    REJECTED,
}

data class SettlementLedgerLeg(
    val accountReference: String,
    val direction: String, // "DEBIT" or "CREDIT"
    val amountMinorUnits: Long,
    val currencyCode: String,
)

data class WinSettlementRecord(
    val settlementId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val canonicalRoundId: UUID?,
    val canonicalTransactionId: UUID?,
    val winAmountMinorUnits: Long,
    val currencyCode: String,
    var status: WinSettlementStatus,
    val quarantineReason: String? = null,
    val isRollback: Boolean = false,
    val parentSettlementId: UUID? = null,
    val settledAt: Instant,
    val ledgerEntries: List<SettlementLedgerLeg>,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
    var version: Long = 1L,
)

data class PostWinSettlementCommand(
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val winAmountMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RollbackWinSettlementCommand(
    val tenantId: String,
    val settlementId: UUID,
    val externalTransactionId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class WinSettlementResult(
    val resultId: UUID,
    val settlementId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val providerId: String,
    val gameId: String,
    val externalRoundId: String,
    val externalTransactionId: String,
    val canonicalRoundId: UUID?,
    val canonicalTransactionId: UUID?,
    val winAmountMinorUnits: Long,
    val currencyCode: String,
    val status: WinSettlementStatus,
    val playerBalanceMinorUnits: Long,
    val quarantineReason: String?,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface WinSettlementStore {
    fun findSettlement(tenantId: String, settlementId: UUID): WinSettlementRecord?
    fun findSettlementByExternalTx(tenantId: String, providerId: String, externalTransactionId: String): WinSettlementRecord?
    fun findSettlementsForRound(tenantId: String, canonicalRoundId: UUID): List<WinSettlementRecord>
    fun saveSettlement(
        record: WinSettlementRecord,
        result: WinSettlementResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateSettlement(
        record: WinSettlementRecord,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WinSettlementResult>?
    fun listQuarantined(tenantId: String): List<WinSettlementRecord>
}

class InMemoryWinSettlementStore : WinSettlementStore {
    private val settlements = ConcurrentHashMap<String, WinSettlementRecord>()
    private val settlementsByExtTx = ConcurrentHashMap<String, WinSettlementRecord>()
    private val roundSettlements = ConcurrentHashMap<UUID, MutableList<WinSettlementRecord>>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, WinSettlementResult>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun sKey(tenantId: String, settlementId: UUID) = "$tenantId:$settlementId"
    private fun txKey(tenantId: String, providerId: String, externalTxId: String) = "$tenantId:$providerId:$externalTxId"

    @Synchronized
    override fun findSettlement(tenantId: String, settlementId: UUID): WinSettlementRecord? {
        return settlements[sKey(tenantId, settlementId)]?.copy()
    }

    @Synchronized
    override fun findSettlementByExternalTx(tenantId: String, providerId: String, externalTransactionId: String): WinSettlementRecord? {
        return settlementsByExtTx[txKey(tenantId, providerId, externalTransactionId)]?.copy()
    }

    @Synchronized
    override fun findSettlementsForRound(tenantId: String, canonicalRoundId: UUID): List<WinSettlementRecord> {
        return roundSettlements[canonicalRoundId]?.map { it.copy() } ?: emptyList()
    }

    @Synchronized
    override fun saveSettlement(
        record: WinSettlementRecord,
        result: WinSettlementResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        settlements[sKey(record.tenantId, record.settlementId)] = record.copy()
        settlementsByExtTx[txKey(record.tenantId, record.providerId, record.externalTransactionId)] = record.copy()
        if (record.canonicalRoundId != null) {
            roundSettlements.computeIfAbsent(record.canonicalRoundId) { mutableListOf() }.add(record)
        }
        idempotency["${record.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateSettlement(
        record: WinSettlementRecord,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        settlements[sKey(record.tenantId, record.settlementId)] = record.copy()
        settlementsByExtTx[txKey(record.tenantId, record.providerId, record.externalTransactionId)] = record.copy()
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, WinSettlementResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun listQuarantined(tenantId: String): List<WinSettlementRecord> {
        return settlements.values
            .filter { it.tenantId == tenantId && it.status == WinSettlementStatus.QUARANTINED_UNSUPPORTED_SEQUENCE }
            .map { it.copy() }
    }
}

interface WinSettlementAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryWinSettlementAlertSink : WinSettlementAlertSink {
    val alerts = mutableListOf<String>()
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

class WinSettlementService(
    private val roundStore: RoundProviderTransactionStore,
    private val roundMapService: RoundProviderTransactionMapService,
    private val reservationStore: WagerAuthorizationReservationStore,
    private val settlementStore: WinSettlementStore,
    private val alertSink: WinSettlementAlertSink = InMemoryWinSettlementAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintPost(cmd: PostWinSettlementCommand): String {
        return sha256("${cmd.tenantId}:${cmd.playerId}:${cmd.providerId}:${cmd.gameId}:${cmd.externalRoundId}:${cmd.externalTransactionId}:${cmd.winAmountMinorUnits}:${cmd.currencyCode}:${cmd.expectedVersion}")
    }

    private fun fingerprintRollback(cmd: RollbackWinSettlementCommand): String {
        return sha256("${cmd.tenantId}:${cmd.settlementId}:${cmd.externalTransactionId}:${cmd.reason}:${cmd.expectedVersion}")
    }

    @Synchronized
    fun postWinSettlement(command: PostWinSettlementCommand): WinSettlementResult {
        WinSettlementBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.externalRoundId.isBlank() ||
            command.externalTransactionId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.winAmountMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Idempotency Check (One accepted key -> one result)
        val fp = fingerprintPost(command)
        settlementStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 3. Duplicate External Transaction Check (Protected Risk: duplicate bet/win)
        val existingTx = settlementStore.findSettlementByExternalTx(
            command.tenantId,
            command.providerId,
            command.externalTransactionId,
        )
        if (existingTx != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 4. Round Lookup & Out-Of-Order Verification (Protected Risk: out-of-order)
        val round = roundStore.findRoundByExternalId(command.tenantId, command.providerId, command.externalRoundId)

        // Unsupported sequence: Win arrives without prior existing round or with no prior BET
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
            val quarantineReason = "Unsupported sequence: Win settlement received without prior active round or prior bet for round ${command.externalRoundId}"
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "HIGH",
                alertType = "WIN_SETTLEMENT_OUT_OF_ORDER_QUARANTINED",
                detail = quarantineReason,
            )

            val settlementId = UUID.randomUUID()
            val resultId = UUID.randomUUID()
            val evidenceRef = sha256("${command.tenantId}:$settlementId:${command.externalRoundId}:QUARANTINED:${now.toEpochMilli()}")

            val record = WinSettlementRecord(
                settlementId = settlementId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                providerId = command.providerId,
                gameId = command.gameId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                canonicalRoundId = round?.canonicalRoundId,
                canonicalTransactionId = null,
                winAmountMinorUnits = command.winAmountMinorUnits,
                currencyCode = command.currencyCode,
                status = WinSettlementStatus.QUARANTINED_UNSUPPORTED_SEQUENCE,
                quarantineReason = quarantineReason,
                settledAt = now,
                ledgerEntries = emptyList(),
                correlationId = command.correlationId,
                causationId = command.causationId,
                evidenceReference = evidenceRef,
            )

            val result = WinSettlementResult(
                resultId = resultId,
                settlementId = settlementId,
                tenantId = command.tenantId,
                playerId = command.playerId,
                providerId = command.providerId,
                gameId = command.gameId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                canonicalRoundId = round?.canonicalRoundId,
                canonicalTransactionId = null,
                winAmountMinorUnits = command.winAmountMinorUnits,
                currencyCode = command.currencyCode,
                status = WinSettlementStatus.QUARANTINED_UNSUPPORTED_SEQUENCE,
                playerBalanceMinorUnits = currentBal, // Unchanged!
                quarantineReason = quarantineReason,
                serverTime = now,
                evidenceReference = evidenceRef,
            )

            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "WIN_SETTLEMENT_QUARANTINED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "WIN_SETTLEMENT_QUARANTINED",
                createdAt = now,
            )

            settlementStore.saveSettlement(record, result, command.idempotencyKey, fp, audit, outbox)
            return result
        }

        // Required non-null round checked above
        val activeRound = round!!

        // Check currency consistency
        if (activeRound.currencyCode != command.currencyCode) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Check player and game consistency
        if (activeRound.playerId != command.playerId || activeRound.gameId != command.gameId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Check if round was already settled
        if (activeRound.status == CanonicalRoundStatus.SETTLED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 5. Wallet Lookup
        val wallet = reservationStore.findWalletBalance(command.tenantId, command.playerId, command.currencyCode)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // 6. Map WIN Transaction to Canonical Round (GAME-005)
        val roundMapResult = roundMapService.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = command.tenantId,
                providerId = command.providerId,
                externalRoundId = command.externalRoundId,
                externalTransactionId = command.externalTransactionId,
                playerId = command.playerId,
                gameId = command.gameId,
                transactionType = ProviderTransactionType.WIN,
                amountMinorUnits = command.winAmountMinorUnits,
                currencyCode = command.currencyCode,
                settleRound = true, // Settles the round
                idempotencyKey = "tx-win-map-${command.idempotencyKey}",
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        // 7. Double-entry Ledger Entries (LEDGER-001/LEDGER-002: sum debits == sum credits)
        val ledgerLegs = if (command.winAmountMinorUnits > 0) {
            listOf(
                SettlementLedgerLeg(
                    accountReference = "CASINO_PAYOUT_POOL:${command.tenantId}:${command.currencyCode}",
                    direction = "DEBIT",
                    amountMinorUnits = command.winAmountMinorUnits,
                    currencyCode = command.currencyCode,
                ),
                SettlementLedgerLeg(
                    accountReference = "PLAYER_WALLET:${command.tenantId}:${command.playerId}:${command.currencyCode}",
                    direction = "CREDIT",
                    amountMinorUnits = command.winAmountMinorUnits,
                    currencyCode = command.currencyCode,
                ),
            )
        } else {
            emptyList()
        }

        // 8. Atomically Update Player Wallet Balance
        wallet.availableBalanceMinorUnits += command.winAmountMinorUnits
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        // 9. Persist Win Settlement Record (Never delete posted entry)
        val settlementId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:$settlementId:${roundMapResult.canonicalRoundId}:${roundMapResult.canonicalTransactionId}:${now.toEpochMilli()}")

        val settlementRecord = WinSettlementRecord(
            settlementId = settlementId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            winAmountMinorUnits = command.winAmountMinorUnits,
            currencyCode = command.currencyCode,
            status = WinSettlementStatus.SETTLED,
            quarantineReason = null,
            settledAt = now,
            ledgerEntries = ledgerLegs,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
        )

        val result = WinSettlementResult(
            resultId = resultId,
            settlementId = settlementId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            providerId = command.providerId,
            gameId = command.gameId,
            externalRoundId = command.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            canonicalRoundId = roundMapResult.canonicalRoundId,
            canonicalTransactionId = roundMapResult.canonicalTransactionId,
            winAmountMinorUnits = command.winAmountMinorUnits,
            currencyCode = command.currencyCode,
            status = WinSettlementStatus.SETTLED,
            playerBalanceMinorUnits = wallet.availableBalanceMinorUnits,
            quarantineReason = null,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WIN_SETTLEMENT_POSTED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WIN_SETTLEMENT_POSTED",
            createdAt = now,
        )

        settlementStore.saveSettlement(settlementRecord, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun rollbackWinSettlement(command: RollbackWinSettlementCommand): WinSettlementResult {
        WinSettlementBinding.checkBound()

        if (command.tenantId.isBlank() ||
            command.externalTransactionId.isBlank() ||
            command.reason.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintRollback(command)
        settlementStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // Lookup original settlement (Never delete posted entry)
        val originalSettlement = settlementStore.findSettlement(command.tenantId, command.settlementId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (originalSettlement.status != WinSettlementStatus.SETTLED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val wallet = reservationStore.findWalletBalance(
            originalSettlement.tenantId,
            originalSettlement.playerId,
            originalSettlement.currencyCode,
        ) ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // Deduct previously credited win amount (compensating debit)
        if (wallet.availableBalanceMinorUnits < originalSettlement.winAmountMinorUnits) {
            // Player already withdrew or spent funds -> alert ops
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "ROLLBACK_INSUFFICIENT_FUNDS",
                detail = "Player balance ${wallet.availableBalanceMinorUnits} insufficient to rollback win ${originalSettlement.winAmountMinorUnits}",
            )
        }

        // Adjust balance (compensating entry)
        wallet.availableBalanceMinorUnits -= originalSettlement.winAmountMinorUnits
        wallet.version += 1L
        reservationStore.saveWalletBalance(wallet)

        // Post compensating transaction in RoundProviderTransactionMap
        val roundMapResult = if (originalSettlement.canonicalRoundId != null) {
            roundMapService.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = command.tenantId,
                    providerId = originalSettlement.providerId,
                    externalRoundId = originalSettlement.externalRoundId,
                    externalTransactionId = command.externalTransactionId,
                    playerId = originalSettlement.playerId,
                    gameId = originalSettlement.gameId,
                    transactionType = ProviderTransactionType.ROLLBACK,
                    amountMinorUnits = originalSettlement.winAmountMinorUnits,
                    currencyCode = originalSettlement.currencyCode,
                    parentTransactionId = originalSettlement.canonicalTransactionId,
                    settleRound = false,
                    idempotencyKey = "tx-rb-map-${command.idempotencyKey}",
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
            )
        } else null

        // Compensating ledger legs (reversed double-entry)
        val compensatingLegs = listOf(
            SettlementLedgerLeg(
                accountReference = "PLAYER_WALLET:${command.tenantId}:${originalSettlement.playerId}:${originalSettlement.currencyCode}",
                direction = "DEBIT",
                amountMinorUnits = originalSettlement.winAmountMinorUnits,
                currencyCode = originalSettlement.currencyCode,
            ),
            SettlementLedgerLeg(
                accountReference = "CASINO_PAYOUT_POOL:${command.tenantId}:${originalSettlement.currencyCode}",
                direction = "CREDIT",
                amountMinorUnits = originalSettlement.winAmountMinorUnits,
                currencyCode = originalSettlement.currencyCode,
            ),
        )

        val rollbackSettlementId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:$rollbackSettlementId:${originalSettlement.settlementId}:COMPENSATING_ROLLBACK:${now.toEpochMilli()}")

        // Append new compensating record (Original record remains unchanged in posted history!)
        val compensatingRecord = WinSettlementRecord(
            settlementId = rollbackSettlementId,
            tenantId = command.tenantId,
            playerId = originalSettlement.playerId,
            providerId = originalSettlement.providerId,
            gameId = originalSettlement.gameId,
            externalRoundId = originalSettlement.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            canonicalRoundId = originalSettlement.canonicalRoundId,
            canonicalTransactionId = roundMapResult?.canonicalTransactionId,
            winAmountMinorUnits = originalSettlement.winAmountMinorUnits,
            currencyCode = originalSettlement.currencyCode,
            status = WinSettlementStatus.COMPENSATED_ROLLBACK,
            isRollback = true,
            parentSettlementId = originalSettlement.settlementId,
            settledAt = now,
            ledgerEntries = compensatingLegs,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
        )

        val result = WinSettlementResult(
            resultId = resultId,
            settlementId = rollbackSettlementId,
            tenantId = command.tenantId,
            playerId = originalSettlement.playerId,
            providerId = originalSettlement.providerId,
            gameId = originalSettlement.gameId,
            externalRoundId = originalSettlement.externalRoundId,
            externalTransactionId = command.externalTransactionId,
            canonicalRoundId = originalSettlement.canonicalRoundId,
            canonicalTransactionId = roundMapResult?.canonicalTransactionId,
            winAmountMinorUnits = originalSettlement.winAmountMinorUnits,
            currencyCode = originalSettlement.currencyCode,
            status = WinSettlementStatus.COMPENSATED_ROLLBACK,
            playerBalanceMinorUnits = wallet.availableBalanceMinorUnits,
            quarantineReason = null,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WIN_SETTLEMENT_COMPENSATED_ROLLBACK",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "WIN_SETTLEMENT_COMPENSATED_ROLLBACK",
            createdAt = now,
        )

        settlementStore.saveSettlement(compensatingRecord, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }
}
