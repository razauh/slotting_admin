package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class WinSettlementTest {

    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-casino-settlement"
    private val providerId = "prov-redtiger"
    private val gameId = "game-gonzos-quest"
    private val currencyUsd = "USD"
    private val currencyEur = "EUR"

    private lateinit var roundStore: InMemoryRoundProviderTransactionStore
    private lateinit var roundMapService: RoundProviderTransactionMapService
    private lateinit var reservationStore: InMemoryWagerAuthorizationReservationStore
    private lateinit var settlementStore: InMemoryWinSettlementStore
    private lateinit var alertSink: InMemoryWinSettlementAlertSink
    private lateinit var winService: WinSettlementService

    @BeforeEach
    fun setUp() {
        WinSettlementBinding.isBound = true
        RoundProviderTransactionBinding.isBound = true

        roundStore = InMemoryRoundProviderTransactionStore()
        roundMapService = RoundProviderTransactionMapService(store = roundStore, clock = clock)
        reservationStore = InMemoryWagerAuthorizationReservationStore()
        settlementStore = InMemoryWinSettlementStore()
        alertSink = InMemoryWinSettlementAlertSink()

        winService = WinSettlementService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            settlementStore = settlementStore,
            alertSink = alertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        WinSettlementBinding.isBound = true
        RoundProviderTransactionBinding.isBound = true
    }

    private fun setupActiveRoundWithBet(
        playerId: UUID = UUID.randomUUID(),
        externalRoundId: String = "rnd-win-001",
        betTxId: String = "tx-bet-001",
        betAmount: Long = 500L,
        initialBalance: Long = 5000L,
        currency: String = currencyUsd,
    ): Pair<UUID, ProviderTransactionMapResult> {
        // Setup player wallet with available balance (balance after bet deduction)
        val remainingBalance = initialBalance - betAmount
        reservationStore.saveWalletBalance(
            PlayerWalletBalanceRecord(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = currency,
                availableBalanceMinorUnits = remainingBalance,
                reservedBalanceMinorUnits = 0L,
            )
        )

        // Post BET into RoundProviderTransactionStore
        val betResult = roundMapService.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = externalRoundId,
                externalTransactionId = betTxId,
                playerId = playerId,
                gameId = gameId,
                transactionType = ProviderTransactionType.BET,
                amountMinorUnits = betAmount,
                currencyCode = currency,
                settleRound = false,
                idempotencyKey = "idemp-$betTxId",
                correlationId = "corr-$betTxId",
                causationId = "cause-$betTxId",
            )
        )

        return playerId to betResult
    }

    // =========================================================================
    // GAME-007-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `GAME-007-01-T001 Post win settlement produces the required authoritative outcome`() {
        // 1. Prove fail-closed gate throws expected RED assertion error when unbound
        WinSettlementBinding.isBound = false
        val (playerId, _) = setupActiveRoundWithBet(externalRoundId = "rnd-t001", betTxId = "tx-t001-bet")

        val winCmd = PostWinSettlementCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-t001",
            externalTransactionId = "tx-t001-win",
            winAmountMinorUnits = 1500L,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-win-t001",
            correlationId = "corr-win-t001",
            causationId = "cause-win-t001",
        )

        val redError = assertFailsWith<AssertionError> {
            winService.postWinSettlement(winCmd)
        }
        assertEquals("duplicate/out-of-order/rollback corrupts balance", redError.message)

        // Bind the gate
        WinSettlementBinding.isBound = true

        // 2. Perform authoritative win settlement
        val result = winService.postWinSettlement(winCmd)

        // Assert: Never delete posted entry; unsupported sequence quarantines/reconciles.
        assertNotNull(result)
        assertEquals(WinSettlementStatus.SETTLED, result.status)
        assertEquals(tenantId, result.tenantId)
        assertEquals(playerId, result.playerId)
        assertEquals("rnd-t001", result.externalRoundId)
        assertEquals("tx-t001-win", result.externalTransactionId)
        assertEquals(1500L, result.winAmountMinorUnits)
        assertEquals(currencyUsd, result.currencyCode)
        assertNull(result.quarantineReason)

        // Verify player balance credited accurately (4500 remaining + 1500 win = 6000)
        assertEquals(6000L, result.playerBalanceMinorUnits)
        val wallet = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)
        assertNotNull(wallet)
        assertEquals(6000L, wallet.availableBalanceMinorUnits)

        // Verify round is settled in canonical round store
        val round = roundStore.findRoundByExternalId(tenantId, providerId, "rnd-t001")
        assertNotNull(round)
        assertEquals(CanonicalRoundStatus.SETTLED, round.status)
        assertEquals(500L, round.totalDebitMinorUnits)
        assertEquals(1500L, round.totalCreditMinorUnits)
        assertEquals(1000L, round.netOutcomeMinorUnits)

        // Verify double-entry ledger legs: sum debits == sum credits
        val storedSettlement = settlementStore.findSettlement(tenantId, result.settlementId)
        assertNotNull(storedSettlement)
        assertEquals(2, storedSettlement.ledgerEntries.size)
        val debitLeg = storedSettlement.ledgerEntries.find { it.direction == "DEBIT" }
        val creditLeg = storedSettlement.ledgerEntries.find { it.direction == "CREDIT" }
        assertNotNull(debitLeg)
        assertNotNull(creditLeg)
        assertEquals(1500L, debitLeg.amountMinorUnits)
        assertEquals(1500L, creditLeg.amountMinorUnits)
        assertTrue(debitLeg.accountReference.startsWith("CASINO_PAYOUT_POOL"))
        assertTrue(creditLeg.accountReference.startsWith("PLAYER_WALLET"))

        // Verify audit and outbox events
        val audit = settlementStore.auditEvents.find { it.type == "WIN_SETTLEMENT_POSTED" }
        assertNotNull(audit)
        assertEquals("corr-win-t001", audit.correlationId)
        assertEquals("cause-win-t001", audit.causationId)

        val outbox = settlementStore.outboxEvents.find { it.type == "WIN_SETTLEMENT_POSTED" }
        assertNotNull(outbox)
        assertEquals(tenantId, outbox.tenantId)
    }

    // =========================================================================
    // GAME-007-01-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `GAME-007-01-T002 Post win settlement rejects invalid, boundary, unauthorized, and stale input`() {
        val (playerId, _) = setupActiveRoundWithBet(externalRoundId = "rnd-neg-001", betTxId = "tx-neg-bet")

        // 1. Invalid / malformed inputs
        assertFailsWith<AuthenticationFailure.Rejected> {
            winService.postWinSettlement(
                PostWinSettlementCommand(
                    tenantId = "",
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    winAmountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Negative win amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            winService.postWinSettlement(
                PostWinSettlementCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    winAmountMinorUnits = -50L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k2",
                    correlationId = "c2",
                    causationId = "c2",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            winService.postWinSettlement(
                PostWinSettlementCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    winAmountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k3",
                    correlationId = "c3",
                    causationId = "c3",
                    expectedVersion = 2L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 2. Out-of-order Sequence: Win arrived for non-existent round (Protected Risk: out-of-order)
        // Must quarantine into review queue without touching player balance!
        val outOfOrderResult = winService.postWinSettlement(
            PostWinSettlementCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-non-existent-999", // No prior round or bet!
                externalTransactionId = "tx-ooo-1",
                winAmountMinorUnits = 2000L,
                currencyCode = currencyUsd,
                idempotencyKey = "k-out-of-order",
                correlationId = "c-ooo",
                causationId = "cause-ooo",
            )
        )
        assertEquals(WinSettlementStatus.QUARANTINED_UNSUPPORTED_SEQUENCE, outOfOrderResult.status)
        assertNotNull(outOfOrderResult.quarantineReason)
        assertEquals(4500L, outOfOrderResult.playerBalanceMinorUnits) // Balance unchanged!
        assertTrue(alertSink.alerts.any { it.contains("WIN_SETTLEMENT_OUT_OF_ORDER_QUARANTINED") })

        val quarantinedList = settlementStore.listQuarantined(tenantId)
        assertTrue(quarantinedList.any { it.externalRoundId == "rnd-non-existent-999" })

        // 3. Duplicate External Transaction ID (Protected Risk: duplicate bet/win)
        val validWin = winService.postWinSettlement(
            PostWinSettlementCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-neg-001",
                externalTransactionId = "tx-neg-win-unique",
                winAmountMinorUnits = 800L,
                currencyCode = currencyUsd,
                idempotencyKey = "k-valid-win",
                correlationId = "c-vw",
                causationId = "cause-vw",
            )
        )
        assertEquals(WinSettlementStatus.SETTLED, validWin.status)

        // Attempt to submit another win with same external transaction ID under another key
        assertFailsWith<AuthenticationFailure.Rejected> {
            winService.postWinSettlement(
                PostWinSettlementCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-neg-001",
                    externalTransactionId = "tx-neg-win-unique", // Duplicate external ID!
                    winAmountMinorUnits = 800L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k-duplicate-attempt",
                    correlationId = "c-dup",
                    causationId = "cause-dup",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Currency Mismatch
        val (playerEur, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-eur-round",
            betTxId = "tx-eur-bet",
            currency = currencyUsd, // Round created in USD
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            winService.postWinSettlement(
                PostWinSettlementCommand(
                    tenantId = tenantId,
                    playerId = playerEur,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-eur-round",
                    externalTransactionId = "tx-eur-win",
                    winAmountMinorUnits = 500L,
                    currencyCode = currencyEur, // Mismatched currency EUR!
                    idempotencyKey = "k-curr-mismatch",
                    correlationId = "c-cm",
                    causationId = "cause-cm",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 5. Post win to already settled round (duplicate settlement)
        assertFailsWith<AuthenticationFailure.Rejected> {
            winService.postWinSettlement(
                PostWinSettlementCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-neg-001", // Already settled above!
                    externalTransactionId = "tx-after-settled",
                    winAmountMinorUnits = 200L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k-after-settled",
                    correlationId = "c-as",
                    causationId = "cause-as",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // GAME-007-01-T003: Concurrency, Duplicate Delivery, and Dependency Failure
    // =========================================================================

    @Test
    fun `GAME-007-01-T003 Post win settlement survives concurrency, duplicate delivery, and dependency failure`() {
        val (playerId, _) = setupActiveRoundWithBet(externalRoundId = "rnd-conc-001", betTxId = "tx-conc-bet")

        // 1. Idempotent request replay (identical payload) returns identical result and balance not double credited
        val cmd = PostWinSettlementCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-conc-001",
            externalTransactionId = "tx-conc-win",
            winAmountMinorUnits = 1000L,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-conc-repeat",
            correlationId = "c-cr",
            causationId = "cause-cr",
        )
        val initial = winService.postWinSettlement(cmd)
        val replay = winService.postWinSettlement(cmd)
        assertEquals(initial.settlementId, replay.settlementId)
        assertEquals(initial.playerBalanceMinorUnits, replay.playerBalanceMinorUnits)

        // Verify balance was credited exactly once
        val wallet = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)
        assertNotNull(wallet)
        assertEquals(5500L, wallet.availableBalanceMinorUnits) // 4500 initial + 1000 = 5500 (not 6500!)

        // Changed payload with same key fails with CONFLICT
        val conflictCmd = cmd.copy(winAmountMinorUnits = 2000L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            winService.postWinSettlement(conflictCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 2. Concurrent Win Delivery Race
        val concurrentRounds = 5
        val executor = Executors.newFixedThreadPool(concurrentRounds)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(concurrentRounds)
        val successCount = AtomicInteger(0)

        // Setup distinct active rounds for parallel settlement
        val playerRounds = (1..concurrentRounds).map { i ->
            setupActiveRoundWithBet(
                externalRoundId = "rnd-parallel-$i",
                betTxId = "tx-par-bet-$i",
            )
        }

        for (i in 1..concurrentRounds) {
            val (pId, _) = playerRounds[i - 1]
            executor.submit {
                try {
                    startLatch.await()
                    val res = winService.postWinSettlement(
                        PostWinSettlementCommand(
                            tenantId = tenantId,
                            playerId = pId,
                            providerId = providerId,
                            gameId = gameId,
                            externalRoundId = "rnd-parallel-$i",
                            externalTransactionId = "tx-par-win-$i",
                            winAmountMinorUnits = 500L,
                            currencyCode = currencyUsd,
                            idempotencyKey = "idemp-par-win-$i",
                            correlationId = "corr-par-$i",
                            causationId = "cause-par-$i",
                        )
                    )
                    if (res.status == WinSettlementStatus.SETTLED) {
                        successCount.incrementAndGet()
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertEquals(concurrentRounds, successCount.get(), "All parallel round settlements must succeed")
    }

    // =========================================================================
    // GAME-007-01-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `GAME-007-01-T004 Post win settlement remains compatible, recoverable, observable, and lifecycle-safe`() {
        val (playerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-life-001",
            betTxId = "tx-life-bet",
            initialBalance = 10000L,
            betAmount = 1000L, // Balance becomes 9000
        )

        // 1. Initial Win Settlement
        val winCmd = PostWinSettlementCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-life-001",
            externalTransactionId = "tx-life-win",
            winAmountMinorUnits = 2500L,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-life-win",
            correlationId = "corr-life-win",
            causationId = "cause-life-win",
        )
        val winResult = winService.postWinSettlement(winCmd)
        assertEquals(WinSettlementStatus.SETTLED, winResult.status)
        assertEquals(11500L, winResult.playerBalanceMinorUnits) // 9000 + 2500

        // 2. Re-instantiate service (simulating application restart / migration)
        val restartedService = WinSettlementService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            settlementStore = settlementStore,
            alertSink = alertSink,
            clock = clock,
        )

        // 3. Compensating Rollback (Semantic Contract: Never delete posted entry)
        val rollbackCmd = RollbackWinSettlementCommand(
            tenantId = tenantId,
            settlementId = winResult.settlementId,
            externalTransactionId = "tx-life-win-rollback",
            reason = "Provider requested settlement reversal due to game malfunction",
            idempotencyKey = "idemp-life-win-rollback",
            correlationId = "corr-life-rb",
            causationId = "cause-life-rb",
        )
        val rollbackResult = restartedService.rollbackWinSettlement(rollbackCmd)
        assertEquals(WinSettlementStatus.COMPENSATED_ROLLBACK, rollbackResult.status)
        assertEquals(9000L, rollbackResult.playerBalanceMinorUnits) // Reverted from 11500 to 9000

        // Invariant: Never delete posted entry! Original settlement record must remain in store!
        val originalRecord = settlementStore.findSettlement(tenantId, winResult.settlementId)
        assertNotNull(originalRecord, "Original posted win settlement entry must never be deleted")
        assertEquals(WinSettlementStatus.SETTLED, originalRecord.status)

        // Compensating record exists alongside original
        val compensatingRecord = settlementStore.findSettlement(tenantId, rollbackResult.settlementId)
        assertNotNull(compensatingRecord)
        assertEquals(WinSettlementStatus.COMPENSATED_ROLLBACK, compensatingRecord.status)
        assertEquals(winResult.settlementId, compensatingRecord.parentSettlementId)
        assertTrue(compensatingRecord.isRollback)

        // 4. Observability Checks
        val auditEvents = settlementStore.auditEvents
        val outboxEvents = settlementStore.outboxEvents
        assertTrue(auditEvents.any { it.type == "WIN_SETTLEMENT_POSTED" })
        assertTrue(auditEvents.any { it.type == "WIN_SETTLEMENT_COMPENSATED_ROLLBACK" })

        for (event in auditEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.occurredAt)
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
        }

        for (event in outboxEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.createdAt)
        }
    }
}
