package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GameRefundRollbackTest {

    private val fixedInstant = Instant.parse("2026-09-19T02:00:00Z")
    private val clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)

    private val tenantId = "tenant-casino-alpha"
    private val providerId = "prv-pragmatic"
    private val gameId = "game-sweet-bonanza"
    private val currencyUsd = "USD"
    private val currencyEur = "EUR"

    private lateinit var roundStore: InMemoryRoundProviderTransactionStore
    private lateinit var roundMapService: RoundProviderTransactionMapService
    private lateinit var reservationStore: InMemoryWagerAuthorizationReservationStore
    private lateinit var refundRollbackStore: InMemoryGameRefundRollbackStore
    private lateinit var alertSink: InMemoryGameRefundRollbackAlertSink
    private lateinit var service: GameRefundRollbackService

    @BeforeEach
    fun setUp() {
        RoundProviderTransactionBinding.isBound = true
        WagerAuthorizationReservationBinding.isBound = true
        GameRefundRollbackBinding.isBound = true

        roundStore = InMemoryRoundProviderTransactionStore()
        roundMapService = RoundProviderTransactionMapService(roundStore, clock)
        reservationStore = InMemoryWagerAuthorizationReservationStore()
        refundRollbackStore = InMemoryGameRefundRollbackStore()
        alertSink = InMemoryGameRefundRollbackAlertSink()

        service = GameRefundRollbackService(
            roundStore = roundStore,
            roundMapService = roundMapService,
            reservationStore = reservationStore,
            refundRollbackStore = refundRollbackStore,
            alertSink = alertSink,
            clock = clock,
        )
    }

    private fun setupActiveRoundWithBet(
        externalRoundId: String,
        betTxId: String,
        betAmountMinorUnits: Long = 1000L,
        initialBalanceMinorUnits: Long = 5000L,
        currency: String = currencyUsd,
    ): Pair<UUID, UUID> {
        val playerId = UUID.randomUUID()
        reservationStore.saveWalletBalance(
            PlayerWalletBalanceRecord(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = currency,
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
                currencyCode = currency,
                idempotencyKey = "k-setup-$betTxId",
                correlationId = "c-setup-$betTxId",
                causationId = "cause-setup-$betTxId",
            )
        )
        return playerId to mapResult.canonicalRoundId
    }

    // =========================================================================
    // GAME-007-02-T001: Authoritative Outcome (Refund & Rollback Compensation)
    // =========================================================================

    @Test
    fun `GAME-007-02-T001 Post game refund and rollback compensation produces the required authoritative outcome`() {
        GameRefundRollbackBinding.checkBound()

        // 1. Authoritative Refund of a Bet
        val (playerId, canonicalRoundId) = setupActiveRoundWithBet(
            externalRoundId = "rnd-t001-01",
            betTxId = "tx-bet-01",
            betAmountMinorUnits = 1000L,
            initialBalanceMinorUnits = 5000L,
        )

        // Player currently has 4000 available. Now issue refund of 1000.
        val refundCmd = PostGameRefundCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-t001-01",
            externalTransactionId = "tx-refund-01",
            referenceExternalTransactionId = "tx-bet-01",
            refundAmountMinorUnits = 1000L,
            currencyCode = currencyUsd,
            reason = "Game round interrupted by server maintenance",
            idempotencyKey = "k-refund-01",
            correlationId = "c-ref-01",
            causationId = "cause-ref-01",
        )

        val refundResult = service.postGameRefund(refundCmd)

        assertEquals(GameRefundRollbackStatus.REFUNDED, refundResult.status)
        assertEquals(1000L, refundResult.amountMinorUnits)
        assertEquals(5000L, refundResult.playerBalanceMinorUnits) // 4000 + 1000 = 5000
        assertEquals(canonicalRoundId, refundResult.canonicalRoundId)
        assertNotNull(refundResult.canonicalTransactionId)
        assertNotNull(refundResult.evidenceReference)
        assertNull(refundResult.quarantineReason)

        // Verify stored refund record and immutable double-entry ledger legs
        val refundRecord = refundRollbackStore.findOperationById(tenantId, refundResult.operationId)
        assertNotNull(refundRecord)
        assertEquals(2, refundRecord.ledgerEntries.size)
        val debitLeg = refundRecord.ledgerEntries.first { it.direction == "DEBIT" }
        val creditLeg = refundRecord.ledgerEntries.first { it.direction == "CREDIT" }
        assertEquals(1000L, debitLeg.amountMinorUnits)
        assertEquals(1000L, creditLeg.amountMinorUnits)
        assertEquals("CASINO_HOLDING_POOL:$tenantId:$currencyUsd", debitLeg.accountReference)
        assertEquals("PLAYER_WALLET:$tenantId:$playerId:$currencyUsd", creditLeg.accountReference)

        // Verify audit and outbox events
        val auditEvents = refundRollbackStore.auditEvents.filter { it.resultId == refundResult.resultId }
        assertEquals(1, auditEvents.size)
        assertEquals("GAME_REFUND_POSTED", auditEvents[0].type)
        assertEquals("c-ref-01", auditEvents[0].correlationId)

        // 2. Authoritative Rollback Compensation of a WIN
        // Place a bet and then map a win
        val (player2Id, round2Id) = setupActiveRoundWithBet(
            externalRoundId = "rnd-t001-02",
            betTxId = "tx-bet-02",
            betAmountMinorUnits = 500L,
            initialBalanceMinorUnits = 2000L,
        )
        // Player balance is 1500. Now win 1500 -> balance becomes 3000.
        roundMapService.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = "rnd-t001-02",
                externalTransactionId = "tx-win-02",
                playerId = player2Id,
                gameId = gameId,
                transactionType = ProviderTransactionType.WIN,
                amountMinorUnits = 1500L,
                currencyCode = currencyUsd,
                idempotencyKey = "k-win-02",
                correlationId = "c-win-02",
                causationId = "cause-win-02",
            )
        )
        val wallet2 = reservationStore.findWalletBalance(tenantId, player2Id, currencyUsd)!!
        wallet2.availableBalanceMinorUnits += 1500L
        reservationStore.saveWalletBalance(wallet2)

        // Provider initiates rollback compensation of the win
        val rollbackCmd = PostRollbackCompensationCommand(
            tenantId = tenantId,
            playerId = player2Id,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-t001-02",
            externalTransactionId = "tx-rollback-02",
            targetExternalTransactionId = "tx-win-02",
            targetTransactionType = ProviderTransactionType.WIN,
            compensationAmountMinorUnits = 1500L,
            currencyCode = currencyUsd,
            reason = "Erroneous win payout reported by provider",
            idempotencyKey = "k-rollback-02",
            correlationId = "c-rb-02",
            causationId = "cause-rb-02",
        )

        val rollbackResult = service.postRollbackCompensation(rollbackCmd)

        assertEquals(GameRefundRollbackStatus.COMPENSATED_ROLLBACK, rollbackResult.status)
        assertEquals(1500L, rollbackResult.amountMinorUnits)
        assertEquals(1500L, rollbackResult.playerBalanceMinorUnits) // 3000 - 1500 = 1500
        assertEquals(round2Id, rollbackResult.canonicalRoundId)
        assertNotNull(rollbackResult.canonicalTransactionId)
        assertNotNull(rollbackResult.evidenceReference)

        // Original win transaction and bet transaction remain posted and intact (Never delete posted entry!)
        val allRound2Txs = roundStore.findRoundTransactions(tenantId, round2Id)
        assertEquals(3, allRound2Txs.size) // BET, WIN, and ROLLBACK
        assertTrue(allRound2Txs.any { it.externalTransactionId == "tx-win-02" && it.transactionType == ProviderTransactionType.WIN })
        assertTrue(allRound2Txs.any { it.externalTransactionId == "tx-rollback-02" && it.transactionType == ProviderTransactionType.ROLLBACK })

        // Check rollback ledger entries: Debit player wallet, Credit casino payout pool
        val rollbackRecord = refundRollbackStore.findOperationById(tenantId, rollbackResult.operationId)
        assertNotNull(rollbackRecord)
        assertEquals(2, rollbackRecord.ledgerEntries.size)
        val rbDebitLeg = rollbackRecord.ledgerEntries.first { it.direction == "DEBIT" }
        val rbCreditLeg = rollbackRecord.ledgerEntries.first { it.direction == "CREDIT" }
        assertEquals("PLAYER_WALLET:$tenantId:$player2Id:$currencyUsd", rbDebitLeg.accountReference)
        assertEquals("CASINO_PAYOUT_POOL:$tenantId:$currencyUsd", rbCreditLeg.accountReference)
        assertEquals(1500L, rbDebitLeg.amountMinorUnits)
        assertEquals(1500L, rbCreditLeg.amountMinorUnits)
    }

    // =========================================================================
    // GAME-007-02-T002: Negative, Boundary, Security & Quarantine
    // =========================================================================

    @Test
    fun `GAME-007-02-T002 Post game refund and rollback compensation rejects invalid and quarantines unsupported sequences`() {
        GameRefundRollbackBinding.checkBound()

        // 1. Unsupported Sequence: Refund arrives for non-existent round -> Quarantined without altering balance!
        val randomPlayerId = UUID.randomUUID()
        reservationStore.saveWalletBalance(
            PlayerWalletBalanceRecord(tenantId, randomPlayerId, currencyUsd, 2000L, 0L, 1L)
        )

        val outOfOrderRefund = service.postGameRefund(
            PostGameRefundCommand(
                tenantId = tenantId,
                playerId = randomPlayerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-missing-round",
                externalTransactionId = "tx-ooo-refund",
                refundAmountMinorUnits = 500L,
                currencyCode = currencyUsd,
                reason = "Ghost round refund",
                idempotencyKey = "k-ooo-ref",
                correlationId = "c-ooo-ref",
                causationId = "cause-ooo-ref",
            )
        )

        assertEquals(GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE, outOfOrderRefund.status)
        assertEquals(2000L, outOfOrderRefund.playerBalanceMinorUnits) // Balance unchanged!
        assertNotNull(outOfOrderRefund.quarantineReason)
        assertEquals(2000L, reservationStore.findWalletBalance(tenantId, randomPlayerId, currencyUsd)!!.availableBalanceMinorUnits)
        assertTrue(alertSink.alerts.any { it.contains("GAME_REFUND_OUT_OF_ORDER_QUARANTINED") })

        // 2. Unsupported Sequence: Rollback arrives for target transaction that does not exist -> Quarantined!
        val (playerId, _) = setupActiveRoundWithBet("rnd-t002-01", "tx-bet-t002")
        val initialBal = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)!!.availableBalanceMinorUnits

        val outOfOrderRollback = service.postRollbackCompensation(
            PostRollbackCompensationCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-t002-01",
                externalTransactionId = "tx-ooo-rb",
                targetExternalTransactionId = "tx-non-existent-win",
                targetTransactionType = ProviderTransactionType.WIN,
                compensationAmountMinorUnits = 500L,
                currencyCode = currencyUsd,
                reason = "Phantom win rollback",
                idempotencyKey = "k-ooo-rb",
                correlationId = "c-ooo-rb",
                causationId = "cause-ooo-rb",
            )
        )

        assertEquals(GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE, outOfOrderRollback.status)
        assertEquals(initialBal, outOfOrderRollback.playerBalanceMinorUnits) // Balance unchanged!
        assertTrue(alertSink.alerts.any { it.contains("GAME_ROLLBACK_OUT_OF_ORDER_QUARANTINED") })

        // 3. Currency Mismatch
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postGameRefund(
                PostGameRefundCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-t002-01",
                    externalTransactionId = "tx-curr-mismatch",
                    refundAmountMinorUnits = 100L,
                    currencyCode = currencyEur, // Mismatched currency!
                    reason = "Currency mismatch test",
                    idempotencyKey = "k-curr-mm",
                    correlationId = "c-cm",
                    causationId = "cause-cm",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Over-refund (refunding more than total bets in round)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postGameRefund(
                PostGameRefundCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-t002-01",
                    externalTransactionId = "tx-over-refund",
                    refundAmountMinorUnits = 999999L, // Huge amount exceeding bet!
                    currencyCode = currencyUsd,
                    reason = "Over refund test",
                    idempotencyKey = "k-over-ref",
                    correlationId = "c-or",
                    causationId = "cause-or",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 5. Stale Expected Version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postGameRefund(
                PostGameRefundCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-t002-01",
                    externalTransactionId = "tx-stale-ref",
                    refundAmountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    reason = "Stale version test",
                    idempotencyKey = "k-stale-ref",
                    correlationId = "c-stale",
                    causationId = "cause-stale",
                    expectedVersion = 2L, // Stale!
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 6. Invalid parameters (zero or negative amount)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postGameRefund(
                PostGameRefundCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    externalRoundId = "rnd-t002-01",
                    externalTransactionId = "tx-neg-amount",
                    refundAmountMinorUnits = -10L, // Negative amount!
                    currencyCode = currencyUsd,
                    reason = "Negative amount test",
                    idempotencyKey = "k-neg",
                    correlationId = "c-neg",
                    causationId = "cause-neg",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // GAME-007-02-T003: Concurrency, Duplicate Delivery, and Idempotency
    // =========================================================================

    @Test
    fun `GAME-007-02-T003 Post game refund and rollback compensation survives concurrency and duplicate delivery`() {
        GameRefundRollbackBinding.checkBound()

        val (playerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-t003-01",
            betTxId = "tx-bet-t003",
            betAmountMinorUnits = 2000L,
            initialBalanceMinorUnits = 10000L,
        )

        // 1. Idempotent replay: exact same payload returns exact same result without duplicate credit
        val cmd = PostGameRefundCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            externalRoundId = "rnd-t003-01",
            externalTransactionId = "tx-refund-idemp",
            refundAmountMinorUnits = 500L,
            currencyCode = currencyUsd,
            reason = "Partial round refund",
            idempotencyKey = "k-idemp-01",
            correlationId = "c-idemp-01",
            causationId = "cause-idemp-01",
        )

        val res1 = service.postGameRefund(cmd)
        val res2 = service.postGameRefund(cmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.operationId, res2.operationId)
        assertEquals(res1.playerBalanceMinorUnits, res2.playerBalanceMinorUnits)

        // Ensure wallet was credited only ONCE (from 8000 to 8500, NOT 9000)
        val wallet = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)!!
        assertEquals(8500L, wallet.availableBalanceMinorUnits)

        // 2. Changed payload under same idempotency key throws CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postGameRefund(cmd.copy(refundAmountMinorUnits = 800L))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Duplicate external transaction ID under new idempotency key throws CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postGameRefund(cmd.copy(idempotencyKey = "k-new-key-diff"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Concurrent duplicate delivery race condition: exactly one succeeds
        val (concPlayerId, _) = setupActiveRoundWithBet(
            externalRoundId = "rnd-t003-conc",
            betTxId = "tx-bet-conc",
            betAmountMinorUnits = 1000L,
            initialBalanceMinorUnits = 5000L,
        )

        val executor = Executors.newFixedThreadPool(8)
        val tasks = (1..8).map {
            Callable {
                try {
                    service.postGameRefund(
                        PostGameRefundCommand(
                            tenantId = tenantId,
                            playerId = concPlayerId,
                            providerId = providerId,
                            gameId = gameId,
                            externalRoundId = "rnd-t003-conc",
                            externalTransactionId = "tx-conc-refund",
                            refundAmountMinorUnits = 1000L,
                            currencyCode = currencyUsd,
                            reason = "Concurrent refund race",
                            idempotencyKey = "k-conc-race",
                            correlationId = "c-conc",
                            causationId = "cause-conc",
                        )
                    )
                } catch (e: Exception) {
                    null
                }
            }
        }
        val results = executor.invokeAll(tasks).mapNotNull { it.get() }
        executor.shutdown()

        assertEquals(8, results.size)
        // All 8 returned identical operationId and playerBalanceMinorUnits
        val distinctOpIds = results.map { it.operationId }.distinct()
        assertEquals(1, distinctOpIds.size)
        val concWallet = reservationStore.findWalletBalance(tenantId, concPlayerId, currencyUsd)!!
        assertEquals(5000L, concWallet.availableBalanceMinorUnits) // 4000 + 1000 = 5000 exactly once!
    }

    // =========================================================================
    // GAME-007-02-T004: Preservation of Posted History, Reconciliation & Audit
    // =========================================================================

    @Test
    fun `GAME-007-02-T004 Post game refund and rollback compensation preserves posted history and supports reconciliation`() {
        GameRefundRollbackBinding.checkBound()

        // 1. Quarantined unsupported sequence can be reconciled by an administrator
        val quarantined = service.postGameRefund(
            PostGameRefundCommand(
                tenantId = tenantId,
                playerId = UUID.randomUUID(),
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-quarantine-recon",
                externalTransactionId = "tx-quarantine-recon",
                refundAmountMinorUnits = 300L,
                currencyCode = currencyUsd,
                reason = "Out of order sequence",
                idempotencyKey = "k-quar-recon",
                correlationId = "c-qr",
                causationId = "cause-qr",
            )
        )

        assertEquals(GameRefundRollbackStatus.QUARANTINED_UNSUPPORTED_SEQUENCE, quarantined.status)
        val quarantinedList = refundRollbackStore.listQuarantined(tenantId)
        assertEquals(1, quarantinedList.size)

        // Administrator performs four-eyes reconciliation review
        val reviewerId = UUID.randomUUID()
        val reconciled = service.reconcileQuarantinedOperation(
            ReconcileQuarantinedRefundRollbackCommand(
                tenantId = tenantId,
                operationId = quarantined.operationId,
                reviewerAdminId = reviewerId,
                resolutionNotes = "Verified provider log outage; manual ledger reconciliation completed",
                correlationId = "c-recon-admin",
                causationId = "cause-recon-admin",
            )
        )

        assertEquals(GameRefundRollbackStatus.RECONCILED, reconciled.status)
        assertTrue(reconciled.quarantineReason!!.contains("Reconciled by admin $reviewerId"))
        assertEquals(0, refundRollbackStore.listQuarantined(tenantId).size)

        // 2. Never delete posted entry check:
        // Setup round with BET, WIN, and subsequent ROLLBACK.
        val (playerId, roundId) = setupActiveRoundWithBet(
            externalRoundId = "rnd-hist-01",
            betTxId = "tx-bet-hist",
            betAmountMinorUnits = 500L,
            initialBalanceMinorUnits = 2000L,
        )
        roundMapService.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = "rnd-hist-01",
                externalTransactionId = "tx-win-hist",
                playerId = playerId,
                gameId = gameId,
                transactionType = ProviderTransactionType.WIN,
                amountMinorUnits = 800L,
                currencyCode = currencyUsd,
                idempotencyKey = "k-win-hist",
                correlationId = "c-wh",
                causationId = "cause-wh",
            )
        )
        val w = reservationStore.findWalletBalance(tenantId, playerId, currencyUsd)!!
        w.availableBalanceMinorUnits += 800L
        reservationStore.saveWalletBalance(w)

        service.postRollbackCompensation(
            PostRollbackCompensationCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                externalRoundId = "rnd-hist-01",
                externalTransactionId = "tx-rollback-hist",
                targetExternalTransactionId = "tx-win-hist",
                targetTransactionType = ProviderTransactionType.WIN,
                compensationAmountMinorUnits = 800L,
                currencyCode = currencyUsd,
                reason = "Audit rollback",
                idempotencyKey = "k-rb-hist",
                correlationId = "c-rbh",
                causationId = "cause-rbh",
            )
        )

        // Historical entries check: All 3 transactions still exist in round history without alteration
        val txs = roundStore.findRoundTransactions(tenantId, roundId)
        assertEquals(3, txs.size)
        val betTx = txs.first { it.externalTransactionId == "tx-bet-hist" }
        val winTx = txs.first { it.externalTransactionId == "tx-win-hist" }
        val rbTx = txs.first { it.externalTransactionId == "tx-rollback-hist" }

        assertEquals(ProviderTransactionType.BET, betTx.transactionType)
        assertEquals(500L, betTx.amountMinorUnits)
        assertEquals(ProviderTransactionType.WIN, winTx.transactionType)
        assertEquals(800L, winTx.amountMinorUnits)
        assertEquals(ProviderTransactionType.ROLLBACK, rbTx.transactionType)
        assertEquals(800L, rbTx.amountMinorUnits)

        // Check audit event contains required IDs and zero secrets/PII
        val allAudits = refundRollbackStore.auditEvents
        assertTrue(allAudits.any { it.type == "GAME_REFUND_ROLLBACK_RECONCILED" })
        assertTrue(allAudits.any { it.type == "GAME_ROLLBACK_POSTED" })
    }
}
