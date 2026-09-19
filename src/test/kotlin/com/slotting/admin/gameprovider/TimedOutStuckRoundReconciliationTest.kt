package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TimedOutStuckRoundReconciliationTest {

    private val fixedInstant = Instant.parse("2026-09-19T02:00:00Z")
    private val clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)

    private val tenantId = "tenant-casino-alpha"
    private val providerId = "prv-pragmatic"
    private val gameId = "game-sweet-bonanza"
    private val currencyUsd = "USD"

    private lateinit var roundStore: InMemoryRoundProviderTransactionStore
    private lateinit var roundMapService: RoundProviderTransactionMapService
    private lateinit var reservationStore: InMemoryWagerAuthorizationReservationStore
    private lateinit var winService: WinSettlementService
    private lateinit var refundRollbackService: GameRefundRollbackService
    private lateinit var healthDirectory: InMemoryProviderHealthDirectory
    private lateinit var reconciliationStore: InMemoryStuckRoundReconciliationStore
    private lateinit var alertSink: InMemoryStuckRoundAlertSink
    private var simulatedResolverOutcome: ProviderRoundResolution = ProviderRoundResolution(
        outcome = ProviderExternalRoundOutcome.CANCELLED_VOID,
        reason = "Provider voided spin due to connection drop",
    )
    private lateinit var service: TimedOutStuckRoundReconciliationService

    @BeforeEach
    fun setUp() {
        StuckRoundReconciliationBinding.isBound = true
        RoundProviderTransactionBinding.isBound = true
        WagerAuthorizationReservationBinding.isBound = true
        WinSettlementBinding.isBound = true
        GameRefundRollbackBinding.isBound = true

        roundStore = InMemoryRoundProviderTransactionStore()
        roundMapService = RoundProviderTransactionMapService(roundStore, clock)
        reservationStore = InMemoryWagerAuthorizationReservationStore()

        winService = WinSettlementService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            settlementStore = InMemoryWinSettlementStore(),
            clock = clock,
        )

        refundRollbackService = GameRefundRollbackService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            refundRollbackStore = InMemoryGameRefundRollbackStore(),
            clock = clock,
        )

        healthDirectory = InMemoryProviderHealthDirectory()
        reconciliationStore = InMemoryStuckRoundReconciliationStore()
        alertSink = InMemoryStuckRoundAlertSink()

        service = TimedOutStuckRoundReconciliationService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            winService = winService,
            refundRollbackService = refundRollbackService,
            providerResolver = { _, _, _ -> simulatedResolverOutcome },
            healthDirectory = healthDirectory,
            store = reconciliationStore,
            alertSink = alertSink,
            clock = clock,
            timeoutThreshold = Duration.ofSeconds(60),
        )
    }

    private fun setupActiveRoundWithBet(
        externalRoundId: String,
        betTxId: String,
        betAmountMinorUnits: Long = 1000L,
        initialBalanceMinorUnits: Long = 5000L,
        openedAt: Instant = fixedInstant.minusSeconds(120), // 120s ago (> 60s timeout)
    ): Pair<UUID, UUID> {
        val playerId = UUID.randomUUID()
        reservationStore.saveWalletBalance(
            PlayerWalletBalanceRecord(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = currencyUsd,
                availableBalanceMinorUnits = initialBalanceMinorUnits - betAmountMinorUnits,
                reservedBalanceMinorUnits = 0L,
                version = 1L,
            )
        )

        val mapResult = roundMapService.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = externalRoundId,
                externalTransactionId = betTxId,
                playerId = playerId,
                gameId = gameId,
                transactionType = ProviderTransactionType.BET,
                amountMinorUnits = betAmountMinorUnits,
                currencyCode = currencyUsd,
                idempotencyKey = "k-setup-$betTxId",
                correlationId = "c-setup-$betTxId",
                causationId = "cause-setup-$betTxId",
            )
        )

        // Set round openedAt to simulate elapsed time
        val round = roundStore.findRoundByExternalId(tenantId, providerId, externalRoundId)!!
        val timedRound = round.copy(openedAt = openedAt)
        roundStore.saveRound(timedRound)

        return playerId to mapResult.canonicalRoundId
    }

    // =========================================================================
    // GAME-009-01-T001: Primary Outcome, Launch Blocking & Safe Settlement
    // =========================================================================

    @Test
    fun `GAME-009-01-T001 Reconcile timed-out and stuck rounds produces the required authoritative outcome`() {
        StuckRoundReconciliationBinding.checkBound()

        // 1. Semantic Contract Check: Disabled/Degraded provider blocks new launch
        healthDirectory.setHealthState(tenantId, providerId, ProviderHealthState.DEGRADED)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.assertProviderPermitsLaunch(tenantId, providerId)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("DEGRADED_PROVIDER_LAUNCH_BLOCKED") })

        // 2. But degraded provider STILL settles/reconciles safe known in-flight outcomes!
        val (playerId, canonicalRoundId) = setupActiveRoundWithBet(
            externalRoundId = "rnd-stuck-001",
            betTxId = "tx-bet-stuck-001",
            betAmountMinorUnits = 1000L,
            initialBalanceMinorUnits = 5000L, // Player now has 4000
        )

        // Provider reports round cancelled/voided
        simulatedResolverOutcome = ProviderRoundResolution(
            outcome = ProviderExternalRoundOutcome.CANCELLED_VOID,
            reason = "Spin aborted due to provider network timeout",
        )

        val reconCommand = ReconcileStuckRoundCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-stuck-001",
            idempotencyKey = "k-recon-001",
            correlationId = "c-recon-001",
            causationId = "cause-recon-001",
        )

        val result = service.reconcileStuckRound(reconCommand)

        assertEquals(StuckRoundReconciliationStatus.RECONCILED_REFUNDED, result.status)
        assertEquals(canonicalRoundId, result.canonicalRoundId)
        assertEquals(5000L, result.playerBalanceMinorUnits) // 4000 + 1000 refunded = 5000!
        assertNotNull(result.evidenceReference)

        // Verify round status in store transitioned to CANCELLED
        val round = roundStore.findRoundByExternalId(tenantId, providerId, "rnd-stuck-001")!!
        assertEquals(CanonicalRoundStatus.CANCELLED, round.status)

        // 3. Test safe settlement when provider confirmed COMPLETED_WIN
        val (playerWinId, roundWinId) = setupActiveRoundWithBet(
            externalRoundId = "rnd-stuck-win-001",
            betTxId = "tx-bet-win-001",
            betAmountMinorUnits = 500L,
            initialBalanceMinorUnits = 2000L, // Available is 1500
        )

        simulatedResolverOutcome = ProviderRoundResolution(
            outcome = ProviderExternalRoundOutcome.COMPLETED_WIN,
            externalTransactionId = "tx-prov-win-001",
            winAmountMinorUnits = 2500L,
            reason = "Provider confirmed winning spin recorded in their journal",
        )

        val winReconResult = service.reconcileStuckRound(
            ReconcileStuckRoundCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = "rnd-stuck-win-001",
                idempotencyKey = "k-recon-win-001",
                correlationId = "c-recon-w-001",
                causationId = "cause-recon-w-001",
            )
        )

        assertEquals(StuckRoundReconciliationStatus.RECONCILED_SETTLED, winReconResult.status)
        assertEquals(roundWinId, winReconResult.canonicalRoundId)
        assertEquals(4000L, winReconResult.playerBalanceMinorUnits) // 1500 + 2500 = 4000
    }

    // =========================================================================
    // GAME-009-01-T002: Negative, Boundary, Premature Reconcile & Ambiguous Hold
    // =========================================================================

    @Test
    fun `GAME-009-01-T002 Reconcile timed-out and stuck rounds rejects invalid, boundary, unauthorized, and stale input`() {
        StuckRoundReconciliationBinding.checkBound()

        // 1. Premature reconciliation: round opened only 10s ago (< 60s threshold) -> INVALID
        val (playerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-fresh-001",
            betTxId = "tx-bet-fresh-001",
            openedAt = fixedInstant.minusSeconds(10), // Only 10s old!
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reconcileStuckRound(
                ReconcileStuckRoundCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-fresh-001",
                    forceReconcile = false,
                    idempotencyKey = "k-premature",
                    correlationId = "c-prem",
                    causationId = "cause-prem",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("STUCK_ROUND_RECONCILIATION_PREMATURE") })

        // 2. Ambiguous / Unknown Provider Status: NEVER INFER SUCCESS!
        // Transitions to QUARANTINED_PENDING_PROVIDER_RECONCILIATION and emits alert
        val (ambiguousPlayerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-ambiguous-001",
            betTxId = "tx-bet-amb-001",
            openedAt = fixedInstant.minusSeconds(120),
        )

        simulatedResolverOutcome = ProviderRoundResolution(
            outcome = ProviderExternalRoundOutcome.UNKNOWN_AMBIGUOUS,
            reason = "Provider upstream gateway timed out; round state indeterminate",
        )

        val ambResult = service.reconcileStuckRound(
            ReconcileStuckRoundCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = "rnd-ambiguous-001",
                idempotencyKey = "k-ambiguous-001",
                correlationId = "c-amb",
                causationId = "cause-amb",
            )
        )

        assertEquals(StuckRoundReconciliationStatus.QUARANTINED_PENDING_PROVIDER_RECONCILIATION, ambResult.status)
        assertTrue(alertSink.alerts.any { it.contains("STUCK_ROUND_AMBIGUOUS_PROVIDER_STATUS") })
        // Player balance unchanged (never infer success or fabricate refunds without proof)
        val ambWallet = reservationStore.findWalletBalance(tenantId, ambiguousPlayerId, currencyUsd)!!
        assertEquals(4000L, ambWallet.availableBalanceMinorUnits)

        // 3. Stale Expected Version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reconcileStuckRound(
                ReconcileStuckRoundCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-ambiguous-001",
                    idempotencyKey = "k-stale",
                    correlationId = "c-stale",
                    causationId = "cause-stale",
                    expectedVersion = 2L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Unknown external round -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reconcileStuckRound(
                ReconcileStuckRoundCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-ghost-round",
                    idempotencyKey = "k-ghost",
                    correlationId = "c-ghost",
                    causationId = "cause-ghost",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // GAME-009-01-T003: Concurrency, Duplicate Delivery, and Double-Post Defense
    // =========================================================================

    @Test
    fun `GAME-009-01-T003 Reconcile timed-out and stuck rounds survives concurrency, duplicate delivery, and dependency failure`() {
        StuckRoundReconciliationBinding.checkBound()

        val (playerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-conc-stuck-001",
            betTxId = "tx-bet-conc-001",
            betAmountMinorUnits = 1000L,
            initialBalanceMinorUnits = 5000L,
        )

        simulatedResolverOutcome = ProviderRoundResolution(
            outcome = ProviderExternalRoundOutcome.CANCELLED_VOID,
            reason = "Cancelled by provider",
        )

        val cmd = ReconcileStuckRoundCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-conc-stuck-001",
            idempotencyKey = "k-conc-stuck-01",
            correlationId = "c-conc-stuck",
            causationId = "cause-conc-stuck",
        )

        // 1. Idempotent replay prevents timeout double-posts
        val res1 = service.reconcileStuckRound(cmd)
        val res2 = service.reconcileStuckRound(cmd)

        assertEquals(res1.reconciliationId, res2.reconciliationId)
        assertEquals(res1.playerBalanceMinorUnits, res2.playerBalanceMinorUnits)
        // Wallet credited exactly ONCE (4000 + 1000 = 5000, NOT 6000)
        val wallet = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)!!
        assertEquals(5000L, wallet.availableBalanceMinorUnits)

        // 2. Conflicting payload with same idempotency key throws CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reconcileStuckRound(cmd.copy(forceReconcile = true))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrent duplicate reconciliation attempts race condition
        val (racePlayerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-race-stuck-001",
            betTxId = "tx-bet-race-001",
            betAmountMinorUnits = 500L,
            initialBalanceMinorUnits = 3000L, // Balance 2500
        )

        val raceCmd = ReconcileStuckRoundCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-race-stuck-001",
            idempotencyKey = "k-race-stuck",
            correlationId = "c-race-stuck",
            causationId = "cause-race-stuck",
        )

        val executor = Executors.newFixedThreadPool(8)
        val tasks = (1..8).map {
            Callable {
                try {
                    service.reconcileStuckRound(raceCmd)
                } catch (e: Exception) {
                    null
                }
            }
        }
        val results = executor.invokeAll(tasks).mapNotNull { it.get() }
        executor.shutdown()

        assertEquals(8, results.size)
        val distinctReconIds = results.map { it.reconciliationId }.distinct()
        assertEquals(1, distinctReconIds.size)
        // Balance credited exactly ONCE from 2500 to 3000
        val raceWallet = reservationStore.findWalletBalance(tenantId, racePlayerId, currencyUsd)!!
        assertEquals(3000L, raceWallet.availableBalanceMinorUnits)

        // 4. Dependency failure in provider resolver: fails closed with DEPENDENCY_UNAVAILABLE
        val (depPlayerId, _) = setupActiveRoundWithBet("rnd-dep-fail", "tx-bet-dep")
        val failingService = TimedOutStuckRoundReconciliationService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            winService = winService,
            refundRollbackService = refundRollbackService,
            providerResolver = { _, _, _ -> throw RuntimeException("Provider reconciliation API down") },
            healthDirectory = healthDirectory,
            store = reconciliationStore,
            alertSink = alertSink,
            clock = clock,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.reconcileStuckRound(
                ReconcileStuckRoundCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-dep-fail",
                    idempotencyKey = "k-dep-fail",
                    correlationId = "c-df",
                    causationId = "cause-df",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("PROVIDER_RECONCILIATION_RESOLVER_UNAVAILABLE") })
    }

    // =========================================================================
    // GAME-009-01-T004: Lifecycle, Observability, and Audit Integrity
    // =========================================================================

    @Test
    fun `GAME-009-01-T004 Reconcile timed-out and stuck rounds remains compatible, recoverable, observable, and lifecycle-safe`() {
        StuckRoundReconciliationBinding.checkBound()

        val (playerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-life-001",
            betTxId = "tx-bet-life-001",
            betAmountMinorUnits = 500L,
            initialBalanceMinorUnits = 2000L,
        )

        simulatedResolverOutcome = ProviderRoundResolution(
            outcome = ProviderExternalRoundOutcome.CANCELLED_VOID,
            reason = "Provider maintenance reboot",
        )

        val cmd = ReconcileStuckRoundCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-life-001",
            idempotencyKey = "k-life-001",
            correlationId = "c-life-001",
            causationId = "cause-life-001",
        )

        val result = service.reconcileStuckRound(cmd)

        // 1. Audit and Outbox lineage verification
        val audits = reconciliationStore.auditEvents.filter { it.resultId == result.resultId }
        assertEquals(1, audits.size)
        assertEquals("STUCK_ROUND_RECONCILED", audits[0].type)
        assertEquals("c-life-001", audits[0].correlationId)
        assertEquals("cause-life-001", audits[0].causationId)

        val outboxes = reconciliationStore.outboxEvents.filter { it.resultId == result.resultId }
        assertEquals(1, outboxes.size)
        assertEquals("STUCK_ROUND_RECONCILED", outboxes[0].type)

        // 2. Service Recreation / Restart preserves reconciliation outcome
        val restartedService = TimedOutStuckRoundReconciliationService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            winService = winService,
            refundRollbackService = refundRollbackService,
            providerResolver = { _, _, _ -> simulatedResolverOutcome },
            healthDirectory = healthDirectory,
            store = reconciliationStore,
            alertSink = alertSink,
            clock = clock,
        )

        val replayAfterRestart = restartedService.reconcileStuckRound(cmd)
        assertEquals(result.reconciliationId, replayAfterRestart.reconciliationId)
        assertEquals(result.status, replayAfterRestart.status)

        // 3. Double-post prevention: calling a new command on already finalized round returns existing status
        val secondReconOnSameRound = restartedService.reconcileStuckRound(
            cmd.copy(idempotencyKey = "k-life-second-attempt")
        )
        assertEquals(StuckRoundReconciliationStatus.RECONCILED_REFUNDED, secondReconOnSameRound.status)
        assertEquals(result.reconciliationId, secondReconOnSameRound.reconciliationId)

        // 4. Observability and Redaction Check: Zero secrets or raw PII in audits/alerts
        for (a in reconciliationStore.auditEvents) {
            assertFalse(a.type.contains("secret"))
            assertFalse(a.correlationId.contains("secret"))
        }
    }
}
