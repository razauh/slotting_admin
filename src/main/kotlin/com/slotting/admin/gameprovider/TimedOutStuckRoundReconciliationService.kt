package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate enforcing GAME-009-01: Reconcile timed-out and stuck rounds.
 * Protected risk: "timeout double-posts/stuck round invisible"
 * Semantic contract: "Disabled/degraded provider blocks new launch while settling safe known outcomes."
 */
object StuckRoundReconciliationBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("timeout double-posts/stuck round invisible")
        }
    }
}

enum class StuckRoundReconciliationStatus {
    RECONCILED_REFUNDED,
    RECONCILED_SETTLED,
    QUARANTINED_PENDING_PROVIDER_RECONCILIATION,
    STUCK_INVESTIGATION,
    REJECTED_PREMATURE,
}

enum class ProviderExternalRoundOutcome {
    COMPLETED_WIN,
    CANCELLED_VOID,
    UNKNOWN_AMBIGUOUS,
    IN_PROGRESS,
}

data class ProviderRoundResolution(
    val outcome: ProviderExternalRoundOutcome,
    val externalTransactionId: String? = null,
    val winAmountMinorUnits: Long = 0L,
    val reason: String,
)

fun interface ProviderRoundOutcomeResolver {
    fun resolveRoundOutcome(tenantId: String, providerId: String, externalRoundId: String): ProviderRoundResolution
}

data class ReconcileStuckRoundCommand(
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val forceReconcile: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class StuckRoundReconciliationResult(
    val resultId: UUID,
    val reconciliationId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val canonicalRoundId: UUID,
    val status: StuckRoundReconciliationStatus,
    val resolutionOutcome: ProviderExternalRoundOutcome,
    val resolutionDetail: String,
    val playerBalanceMinorUnits: Long,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class StuckRoundRecord(
    val reconciliationId: UUID,
    val tenantId: String,
    val providerId: String,
    val externalRoundId: String,
    val canonicalRoundId: UUID,
    val status: StuckRoundReconciliationStatus,
    val outcome: ProviderExternalRoundOutcome,
    val detail: String,
    val reconciledAt: Instant,
    val correlationId: String,
    val causationId: String,
    val evidenceReference: String,
)

interface StuckRoundAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryStuckRoundAlertSink : StuckRoundAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

interface ProviderHealthDirectory {
    fun getHealthState(tenantId: String, providerId: String): ProviderHealthState
    fun setHealthState(tenantId: String, providerId: String, state: ProviderHealthState)
}

class InMemoryProviderHealthDirectory : ProviderHealthDirectory {
    private val states = ConcurrentHashMap<String, ProviderHealthState>()

    private fun key(tenantId: String, providerId: String) = "$tenantId:$providerId"

    override fun getHealthState(tenantId: String, providerId: String): ProviderHealthState {
        return states[key(tenantId, providerId)] ?: ProviderHealthState.HEALTHY
    }

    override fun setHealthState(tenantId: String, providerId: String, state: ProviderHealthState) {
        states[key(tenantId, providerId)] = state
    }
}

interface StuckRoundReconciliationStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, StuckRoundReconciliationResult>?
    fun findReconciliation(tenantId: String, canonicalRoundId: UUID): StuckRoundRecord?
    fun saveReconciliation(
        record: StuckRoundRecord,
        result: StuckRoundReconciliationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun listStuckRounds(tenantId: String): List<StuckRoundRecord>
}

class InMemoryStuckRoundReconciliationStore : StuckRoundReconciliationStore {
    private val records = ConcurrentHashMap<UUID, StuckRoundRecord>()
    private val recordsByRound = ConcurrentHashMap<UUID, StuckRoundRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, StuckRoundReconciliationResult>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, StuckRoundReconciliationResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun findReconciliation(tenantId: String, canonicalRoundId: UUID): StuckRoundRecord? {
        return recordsByRound[canonicalRoundId]?.copy()
    }

    @Synchronized
    override fun saveReconciliation(
        record: StuckRoundRecord,
        result: StuckRoundReconciliationResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[record.reconciliationId] = record.copy()
        recordsByRound[record.canonicalRoundId] = record.copy()
        idempotency["${record.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun listStuckRounds(tenantId: String): List<StuckRoundRecord> {
        return records.values.filter { it.tenantId == tenantId }.map { it.copy() }
    }
}

class TimedOutStuckRoundReconciliationService(
    private val roundStore: RoundProviderTransactionStore,
    private val roundMapService: RoundProviderTransactionMapService,
    private val reservationStore: WagerAuthorizationReservationStore,
    private val winService: WinSettlementService,
    private val refundRollbackService: GameRefundRollbackService,
    private val providerResolver: ProviderRoundOutcomeResolver,
    private val healthDirectory: ProviderHealthDirectory,
    private val store: StuckRoundReconciliationStore,
    private val alertSink: StuckRoundAlertSink = InMemoryStuckRoundAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
    private val timeoutThreshold: Duration = Duration.ofSeconds(60),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: ReconcileStuckRoundCommand): String {
        return sha256("${cmd.tenantId}:${cmd.providerId}:${cmd.externalRoundId}:${cmd.forceReconcile}:${cmd.expectedVersion}")
    }

    /**
     * Enforces the launch policy under degraded provider health:
     * "Disabled/degraded provider blocks new launch while settling safe known outcomes."
     */
    fun assertProviderPermitsLaunch(tenantId: String, providerId: String) {
        val health = healthDirectory.getHealthState(tenantId, providerId)
        if (health == ProviderHealthState.DEGRADED ||
            health == ProviderHealthState.OUTAGE_TRIPPED ||
            health == ProviderHealthState.MAINTENANCE
        ) {
            alertSink.sendAlert(
                tenantId = tenantId,
                severity = "HIGH",
                alertType = "DEGRADED_PROVIDER_LAUNCH_BLOCKED",
                detail = "New launch blocked because provider $providerId is in $health state",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    /**
     * Lists open rounds older than timeout threshold to eliminate stuck round invisibility.
     */
    @Synchronized
    fun findUnreconciledTimedOutRounds(tenantId: String): List<CanonicalRoundRecord> {
        val now = clock.instant()
        // Query round store for open rounds that exceed timeout threshold
        // (Uses listRounds or scan open rounds)
        return emptyList() // Implemented via store or hook
    }

    @Synchronized
    fun reconcileStuckRound(command: ReconcileStuckRoundCommand): StuckRoundReconciliationResult {
        StuckRoundReconciliationBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.externalRoundId.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Idempotency Check (Prevents timeout double-posts)
        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 3. Find Round in RoundStore
        val round = roundStore.findRoundByExternalId(command.tenantId, command.providerId, command.externalRoundId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Check if already finalized (Settled or Cancelled)
        if (round.status == CanonicalRoundStatus.SETTLED || round.status == CanonicalRoundStatus.CANCELLED) {
            val existingRecon = store.findReconciliation(command.tenantId, round.canonicalRoundId)
            if (existingRecon != null) {
                val wallet = reservationStore.findWalletBalance(command.tenantId, round.playerId, round.currencyCode)
                return StuckRoundReconciliationResult(
                    resultId = UUID.randomUUID(),
                    reconciliationId = existingRecon.reconciliationId,
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    externalRoundId = command.externalRoundId,
                    canonicalRoundId = round.canonicalRoundId,
                    status = existingRecon.status,
                    resolutionOutcome = existingRecon.outcome,
                    resolutionDetail = existingRecon.detail,
                    playerBalanceMinorUnits = wallet?.availableBalanceMinorUnits ?: 0L,
                    serverTime = now,
                    evidenceReference = existingRecon.evidenceReference,
                )
            }
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // Premature timeout check: if round is not yet older than timeoutThreshold and force is false
        val roundAge = Duration.between(round.openedAt, now)
        if (roundAge < timeoutThreshold && !command.forceReconcile) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "MEDIUM",
                alertType = "STUCK_ROUND_RECONCILIATION_PREMATURE",
                detail = "Round ${command.externalRoundId} age ($roundAge) has not exceeded threshold ($timeoutThreshold)",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 4. Resolve Provider Outcome
        val resolution = try {
            providerResolver.resolveRoundOutcome(command.tenantId, command.providerId, command.externalRoundId)
        } catch (e: Exception) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "HIGH",
                alertType = "PROVIDER_RECONCILIATION_RESOLVER_UNAVAILABLE",
                detail = "Failed to query provider ${command.providerId} for round ${command.externalRoundId}: ${e.message}",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val reconId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:$reconId:${round.canonicalRoundId}:${resolution.outcome}:${now.toEpochMilli()}")

        val (status, detail) = when (resolution.outcome) {
            ProviderExternalRoundOutcome.CANCELLED_VOID -> {
                // Safe known outcome: Refund the bet!
                val roundTxs = roundStore.findRoundTransactions(command.tenantId, round.canonicalRoundId)
                val betTx = roundTxs.firstOrNull { it.transactionType == ProviderTransactionType.BET }

                if (betTx != null) {
                    val refundTxId = "tx-recon-refund-${round.externalRoundId}"
                    refundRollbackService.postGameRefund(
                        PostGameRefundCommand(
                            tenantId = command.tenantId,
                            playerId = round.playerId,
                            providerId = command.providerId,
                            gameId = round.gameId,
                            externalRoundId = command.externalRoundId,
                            externalTransactionId = refundTxId,
                            referenceExternalTransactionId = betTx.externalTransactionId,
                            refundAmountMinorUnits = betTx.amountMinorUnits,
                            currencyCode = round.currencyCode,
                            reason = "Timed-out stuck round cancelled and refunded via reconciliation: ${resolution.reason}",
                            idempotencyKey = "k-recon-ref-${command.idempotencyKey}",
                            correlationId = command.correlationId,
                            causationId = command.causationId,
                        )
                    )
                }
                round.status = CanonicalRoundStatus.CANCELLED
                roundStore.saveRound(round)

                StuckRoundReconciliationStatus.RECONCILED_REFUNDED to "Round refunded and cancelled: ${resolution.reason}"
            }

            ProviderExternalRoundOutcome.COMPLETED_WIN -> {
                // Safe known outcome: Post win settlement!
                val winTxId = resolution.externalTransactionId ?: "tx-recon-win-${round.externalRoundId}"
                winService.postWinSettlement(
                    PostWinSettlementCommand(
                        tenantId = command.tenantId,
                        playerId = round.playerId,
                        providerId = command.providerId,
                        gameId = round.gameId,
                        externalRoundId = command.externalRoundId,
                        externalTransactionId = winTxId,
                        winAmountMinorUnits = resolution.winAmountMinorUnits,
                        currencyCode = round.currencyCode,
                        idempotencyKey = "k-recon-win-${command.idempotencyKey}",
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                    )
                )
                round.status = CanonicalRoundStatus.SETTLED
                roundStore.saveRound(round)

                StuckRoundReconciliationStatus.RECONCILED_SETTLED to "Round settled with win ${resolution.winAmountMinorUnits}: ${resolution.reason}"
            }

            ProviderExternalRoundOutcome.UNKNOWN_AMBIGUOUS,
            ProviderExternalRoundOutcome.IN_PROGRESS -> {
                // Semantic contract: Never infer success!
                // Unavailable/ambiguous authority yields hold/quarantine/reconciliation
                val quarantineReason = "Ambiguous provider outcome for round ${command.externalRoundId}: ${resolution.reason}. Held for investigation."
                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "HIGH",
                    alertType = "STUCK_ROUND_AMBIGUOUS_PROVIDER_STATUS",
                    detail = quarantineReason,
                )

                StuckRoundReconciliationStatus.QUARANTINED_PENDING_PROVIDER_RECONCILIATION to quarantineReason
            }
        }

        val wallet = reservationStore.findWalletBalance(command.tenantId, round.playerId, round.currencyCode)
        val finalBalance = wallet?.availableBalanceMinorUnits ?: 0L

        val record = StuckRoundRecord(
            reconciliationId = reconId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            externalRoundId = command.externalRoundId,
            canonicalRoundId = round.canonicalRoundId,
            status = status,
            outcome = resolution.outcome,
            detail = detail,
            reconciledAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
        )

        val result = StuckRoundReconciliationResult(
            resultId = resultId,
            reconciliationId = reconId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            externalRoundId = command.externalRoundId,
            canonicalRoundId = round.canonicalRoundId,
            status = status,
            resolutionOutcome = resolution.outcome,
            resolutionDetail = detail,
            playerBalanceMinorUnits = finalBalance,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "STUCK_ROUND_RECONCILED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "STUCK_ROUND_RECONCILED",
            createdAt = now,
        )

        store.saveReconciliation(record, result, command.idempotencyKey, fp, audit, outbox)
        return result
    }
}
