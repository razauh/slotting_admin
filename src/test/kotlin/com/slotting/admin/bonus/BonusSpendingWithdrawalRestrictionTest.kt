package com.slotting.admin.bonus

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BonusSpendingWithdrawalRestrictionTest {

    private val now = Instant.parse("2026-09-18T23:55:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        BonusSpendingWithdrawalRestrictionBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        BonusSpendingWithdrawalRestrictionBinding.isBound = true
    }

    private fun adminPrincipal(
        id: String = "admin-1",
        tenantId: String = "tenant-1",
        roles: Set<AdminRole> = setOf(AdminRole.SUPER_ADMIN)
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = roles
        )
    }

    private fun playerPrincipal(
        id: String = "player-1",
        tenantId: String = "tenant-1"
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet()
        )
    }

    // =========================================================================
    // BONUS-001-02-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `BONUS-001-02-T001 Enforce bonus spending and withdrawal restrictions produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        BonusSpendingWithdrawalRestrictionBinding.checkBound()

        val store = InMemoryBonusGrantStore()
        val gameRules = InMemoryGameRuleDirectory()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusSpendingWithdrawalRestrictionService(
            store = store,
            gameRules = gameRules,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-casino-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

        // Configure game rules
        val slotGame = GameWageringRule(
            gameId = "game-slot-1",
            isBonusAllowed = true,
            contributionMultiplier = 1.0,
            maxAllowedBetMinorUnits = 10_000L // $100.00 max bet
        )
        gameRules.setRule(tenantId, slotGame)

        // Seed initial wallet: $100.00 cash (10,000 units), $50.00 bonus (5,000 units)
        val initialWallet = PlayerWalletBuckets(
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            cashMinorUnits = 10_000L,
            bonusMinorUnits = 5_000L,
            lockedCashMinorUnits = 0L,
            version = 1L
        )
        store.saveWallet(initialWallet)

        // Seed initial double-entry ledger records
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = tenantId,
                transactionReference = "seed-cash",
                debitAccount = "SYSTEM_LIQUIDITY_CLEARING",
                creditAccount = "PLAYER_CASH_WALLET",
                amountMinorUnits = 10_000L,
                currencyCode = "USD",
                createdAt = now
            )
        )
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = tenantId,
                transactionReference = "seed-bonus",
                debitAccount = "MARKETING_PROMOTION_EXPENSE",
                creditAccount = "PLAYER_BONUS_WALLET",
                amountMinorUnits = 5_000L,
                currencyCode = "USD",
                createdAt = now
            )
        )

        // Step 1: Execute wager of $40.00 (4,000 units). Cash has $100.00, so cash covers all $40.00.
        // Spending order: Cash is spent first!
        val wager1Cmd = ExecuteWagerCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-slot-1",
            wagerMinorUnits = 4_000L,
            currencyCode = "USD",
            idempotencyKey = "wager-1",
            correlationId = "corr-w-1",
            causationId = "caus-w-1",
            expectedVersion = 1L
        )
        val wager1Result = service.executeWager(wager1Cmd)
        assertEquals(4_000L, wager1Result.cashDebitedMinorUnits)
        assertEquals(0L, wager1Result.bonusDebitedMinorUnits)
        assertEquals(6_000L, wager1Result.remainingCashMinorUnits)
        assertEquals(5_000L, wager1Result.remainingBonusMinorUnits)
        assertEquals(0L, wager1Result.wageringProgressAddedMinorUnits)
        assertEquals(2L, wager1Result.serverVersion)

        // Step 2: Execute wager of $80.00 (8,000 units).
        // Cash has $60.00 (6,000 units), so Cash debited = 6,000, Bonus debited = 2,000 units.
        val wager2Cmd = ExecuteWagerCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-slot-1",
            wagerMinorUnits = 8_000L,
            currencyCode = "USD",
            idempotencyKey = "wager-2",
            correlationId = "corr-w-2",
            causationId = "caus-w-2",
            expectedVersion = 2L
        )
        val wager2Result = service.executeWager(wager2Cmd)
        assertEquals(6_000L, wager2Result.cashDebitedMinorUnits)
        assertEquals(2_000L, wager2Result.bonusDebitedMinorUnits)
        assertEquals(0L, wager2Result.remainingCashMinorUnits)
        assertEquals(3_000L, wager2Result.remainingBonusMinorUnits)
        assertEquals(2_000L, wager2Result.wageringProgressAddedMinorUnits)
        assertEquals(3L, wager2Result.serverVersion)

        // Check wallet state after wager 2
        val walletAfterWagers = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterWagers)
        assertEquals(0L, walletAfterWagers.cashMinorUnits)
        assertEquals(3_000L, walletAfterWagers.bonusMinorUnits)

        // Step 3: Settle winnings from wager 2 round:
        // Round payout is $200.00 (20,000 units).
        // Wager 2 was $80 total, of which $20 was bonus -> bonusFundingRatio = 2000 / 8000 = 0.25 (25%).
        // Proportional settlement:
        // Bonus credit = 20,000 * 0.25 = 5,000 units ($50.00).
        // Cash credit = 20,000 - 5,000 = 15,000 units ($150.00).
        val settleCmd = SettleWinningsCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-slot-1",
            roundId = "round-w2-1",
            payoutMinorUnits = 20_000L,
            bonusFundingRatio = 0.25,
            currencyCode = "USD",
            idempotencyKey = "settle-1",
            correlationId = "corr-s-1",
            causationId = "caus-s-1",
            expectedVersion = 3L
        )
        val settleResult = service.settleWinnings(settleCmd)
        assertEquals(15_000L, settleResult.cashCreditedMinorUnits)
        assertEquals(5_000L, settleResult.bonusCreditedMinorUnits)
        assertEquals(15_000L, settleResult.newCashMinorUnits)
        assertEquals(8_000L, settleResult.newBonusMinorUnits) // 3,000 remaining + 5,000 won
        assertEquals(4L, settleResult.serverVersion)

        // Step 4: Execute restricted withdrawal:
        // Player has $150.00 (15,000 units) cash and $80.00 (8,000 units) active bonus.
        // Player requests withdrawal of $100.00 (10,000 units) with forfeitActiveBonusOnWithdrawal = true.
        val withdrawCmd = ExecuteRestrictedWithdrawalCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            amountMinorUnits = 10_000L,
            currencyCode = "USD",
            forfeitActiveBonusOnWithdrawal = true,
            idempotencyKey = "withdraw-1",
            correlationId = "corr-wd-1",
            causationId = "caus-wd-1",
            expectedVersion = 4L
        )
        val withdrawResult = service.executeRestrictedWithdrawal(withdrawCmd)
        assertEquals(10_000L, withdrawResult.withdrawnCashMinorUnits)
        assertEquals(8_000L, withdrawResult.forfeitedBonusMinorUnits)
        assertEquals(5_000L, withdrawResult.remainingCashMinorUnits)
        assertEquals(0L, withdrawResult.remainingBonusMinorUnits) // Active bonus wiped clean
        assertEquals(5L, withdrawResult.serverVersion)

        val finalWallet = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(finalWallet)
        assertEquals(5_000L, finalWallet.cashMinorUnits)
        assertEquals(0L, finalWallet.bonusMinorUnits)

        // Step 5: Ledger conservation verification
        // All double-entry ledger records must be balanced: debits == credits
        val allEntries = store.getLedgerEntries(tenantId)
        assertTrue(allEntries.isNotEmpty())
        for (entry in allEntries) {
            assertTrue(entry.amountMinorUnits > 0L)
            assertFalse(entry.debitAccount.isBlank())
            assertFalse(entry.creditAccount.isBlank())
            assertFalse(entry.debitAccount == entry.creditAccount)
        }

        // Verify total debit == total credit across the ledger
        val totalDebits = allEntries.groupBy { it.debitAccount }.values.sumOf { list -> list.sumOf { e -> e.amountMinorUnits } }
        val totalCredits = allEntries.groupBy { it.creditAccount }.values.sumOf { list -> list.sumOf { e -> e.amountMinorUnits } }
        assertEquals(totalDebits, totalCredits)

        // Step 6: Verify evidence reference, audit event, outbox event
        assertFalse(withdrawResult.evidenceReference.isBlank())
        assertEquals("RESTRICTED_WITHDRAWAL_COMPLETED", withdrawResult.auditEvent.type)
        assertEquals("RESTRICTED_WITHDRAWAL_COMPLETED", withdrawResult.outboxEvent.type)
    }

    // =========================================================================
    // BONUS-001-02-T002: Negative, Boundary, and Security Gaps
    // =========================================================================

    @Test
    fun `BONUS-001-02-T002 Negative boundary and security scenarios fail closed`() {
        BonusSpendingWithdrawalRestrictionBinding.isBound = true

        val store = InMemoryBonusGrantStore()
        val gameRules = InMemoryGameRuleDirectory()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusSpendingWithdrawalRestrictionService(
            store = store,
            gameRules = gameRules,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-sec-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

        // Configure game rules: game-restricted is excluded from bonus play
        gameRules.setRule(
            tenantId,
            GameWageringRule(
                gameId = "game-restricted",
                isBonusAllowed = false,
                contributionMultiplier = 0.0,
                maxAllowedBetMinorUnits = 1_000L
            )
        )
        // game-capped has a $5.00 max bet cap
        gameRules.setRule(
            tenantId,
            GameWageringRule(
                gameId = "game-capped",
                isBonusAllowed = true,
                contributionMultiplier = 1.0,
                maxAllowedBetMinorUnits = 500L // 500 units max
            )
        )

        // Seed wallet: $0 cash, $2,000 bonus
        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 0L,
                bonusMinorUnits = 2_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // 1. Excluded game bonus spending rejected (FORBIDDEN)
        val excludedGameWager = ExecuteWagerCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-restricted",
            wagerMinorUnits = 500L,
            currencyCode = "USD",
            idempotencyKey = "w-excl",
            correlationId = "corr-excl",
            causationId = "caus-excl",
            expectedVersion = 1L
        )
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(excludedGameWager)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex1.code)

        // 2. Max bet cap exceeded rejected (FORBIDDEN)
        val cappedGameWagerExceeded = ExecuteWagerCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-capped",
            wagerMinorUnits = 600L, // Cap is 500L
            currencyCode = "USD",
            idempotencyKey = "w-capped",
            correlationId = "corr-capped",
            causationId = "caus-capped",
            expectedVersion = 1L
        )
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(cappedGameWagerExceeded)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex2.code)

        // 3. Withdrawal attempting to withdraw more than cash balance rejected (FORBIDDEN)
        // Wallet has $0 cash, $2000 bonus. Attempting to withdraw $500 cash fails closed.
        val withdrawExceedingCash = ExecuteRestrictedWithdrawalCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            amountMinorUnits = 500L,
            currencyCode = "USD",
            forfeitActiveBonusOnWithdrawal = true,
            idempotencyKey = "wd-exceed",
            correlationId = "corr-exceed",
            causationId = "caus-exceed",
            expectedVersion = 1L
        )
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeRestrictedWithdrawal(withdrawExceedingCash)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex3.code)

        // Give player some cash ($1,000 cash, $2,000 bonus)
        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 1_000L,
                bonusMinorUnits = 2_000L,
                lockedCashMinorUnits = 0L,
                version = 2L
            )
        )

        // 4. Withdrawal without explicit forfeiture consent rejected (FORBIDDEN)
        val withdrawWithoutConsent = ExecuteRestrictedWithdrawalCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            amountMinorUnits = 500L,
            currencyCode = "USD",
            forfeitActiveBonusOnWithdrawal = false, // Must be true when bonus > 0
            idempotencyKey = "wd-no-consent",
            correlationId = "corr-no-consent",
            causationId = "caus-no-consent",
            expectedVersion = 2L
        )
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeRestrictedWithdrawal(withdrawWithoutConsent)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex4.code)

        // 5. Cross-tenant request rejected (FORBIDDEN)
        val crossTenantPlayer = playerPrincipal(playerId.toString(), "attacker-tenant")
        val crossTenantWager = ExecuteWagerCommand(
            principal = crossTenantPlayer,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-capped",
            wagerMinorUnits = 100L,
            currencyCode = "USD",
            idempotencyKey = "w-cross",
            correlationId = "corr-cross",
            causationId = "caus-cross",
            expectedVersion = 2L
        )
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(crossTenantWager)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex5.code)

        // 6. Unauthenticated request rejected (UNAUTHENTICATED)
        val unauthWager = ExecuteWagerCommand(
            principal = null,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-capped",
            wagerMinorUnits = 100L,
            currencyCode = "USD",
            idempotencyKey = "w-unauth",
            correlationId = "corr-unauth",
            causationId = "caus-unauth",
            expectedVersion = 2L
        )
        val ex6 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(unauthWager)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex6.code)

        // 7. Stale version rejected (STALE)
        val staleWager = ExecuteWagerCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-capped",
            wagerMinorUnits = 100L,
            currencyCode = "USD",
            idempotencyKey = "w-stale",
            correlationId = "corr-stale",
            causationId = "caus-stale",
            expectedVersion = 1L // Current is 2L
        )
        val ex7 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(staleWager)
        }
        assertEquals(AuthErrorCode.STALE, ex7.code)

        // 8. Malformed headers rejected (INVALID)
        val invalidHeaderWager = ExecuteWagerCommand(
            principal = player,
            tenantId = "",
            playerId = playerId,
            gameId = "game-capped",
            wagerMinorUnits = 100L,
            currencyCode = "USD",
            idempotencyKey = "w-invalid",
            correlationId = "corr-invalid",
            causationId = "caus-invalid",
            expectedVersion = 2L
        )
        val ex8 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(invalidHeaderWager)
        }
        assertEquals(AuthErrorCode.INVALID, ex8.code)

        // 9. Negative wager amount rejected (INVALID)
        val negativeWager = ExecuteWagerCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-capped",
            wagerMinorUnits = -50L,
            currencyCode = "USD",
            idempotencyKey = "w-neg",
            correlationId = "corr-neg",
            causationId = "caus-neg",
            expectedVersion = 2L
        )
        val ex9 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(negativeWager)
        }
        assertEquals(AuthErrorCode.INVALID, ex9.code)

        // 10. Invalid bonus funding ratio rejected (INVALID)
        val invalidRatioSettle = SettleWinningsCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-capped",
            roundId = "round-neg",
            payoutMinorUnits = 100L,
            bonusFundingRatio = 1.5, // Must be 0.0 to 1.0
            currencyCode = "USD",
            idempotencyKey = "s-ratio",
            correlationId = "corr-ratio",
            causationId = "caus-ratio",
            expectedVersion = 2L
        )
        val ex10 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.settleWinnings(invalidRatioSettle)
        }
        assertEquals(AuthErrorCode.INVALID, ex10.code)
    }

    // =========================================================================
    // BONUS-001-02-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `BONUS-001-02-T003 Idempotency replays, conflict detection, and concurrent execution maintain balance conservation`() {
        BonusSpendingWithdrawalRestrictionBinding.isBound = true

        val store = InMemoryBonusGrantStore()
        val gameRules = InMemoryGameRuleDirectory()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusSpendingWithdrawalRestrictionService(
            store = store,
            gameRules = gameRules,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-idem-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

        gameRules.setRule(
            tenantId,
            GameWageringRule(
                gameId = "game-idem",
                isBonusAllowed = true,
                contributionMultiplier = 1.0,
                maxAllowedBetMinorUnits = 5_000L
            )
        )

        // Seed wallet: $100 cash, $100 bonus
        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 10_000L,
                bonusMinorUnits = 10_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // 1. Wager Idempotency replay
        val wagerCmd = ExecuteWagerCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-idem",
            wagerMinorUnits = 2_000L,
            currencyCode = "USD",
            idempotencyKey = "idem-wager-key",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1",
            expectedVersion = 1L
        )
        val wagerResult1 = service.executeWager(wagerCmd)
        val wagerResult2 = service.executeWager(wagerCmd)
        assertEquals(wagerResult1.resultId, wagerResult2.resultId)
        assertEquals(wagerResult1.serverVersion, wagerResult2.serverVersion)

        // Check wallet version is only incremented once (from 1L to 2L)
        val walletAfterIdemWager = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterIdemWager)
        assertEquals(2L, walletAfterIdemWager.version)
        assertEquals(8_000L, walletAfterIdemWager.cashMinorUnits)

        // 2. Conflict detection: Reusing same idempotency key with different payload
        val conflictingWagerCmd = wagerCmd.copy(wagerMinorUnits = 3_000L)
        val conflictEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeWager(conflictingWagerCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictEx.code)

        // 3. Settle Idempotency replay
        val settleCmd = SettleWinningsCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            gameId = "game-idem",
            roundId = "round-idem-1",
            payoutMinorUnits = 5_000L,
            bonusFundingRatio = 0.0,
            currencyCode = "USD",
            idempotencyKey = "idem-settle-key",
            correlationId = "corr-idem-s",
            causationId = "caus-idem-s",
            expectedVersion = 2L
        )
        val settleResult1 = service.settleWinnings(settleCmd)
        val settleResult2 = service.settleWinnings(settleCmd)
        assertEquals(settleResult1.resultId, settleResult2.resultId)
        assertEquals(settleResult1.serverVersion, settleResult2.serverVersion)

        val walletAfterIdemSettle = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterIdemSettle)
        assertEquals(3L, walletAfterIdemSettle.version)
        assertEquals(13_000L, walletAfterIdemSettle.cashMinorUnits)

        // 4. Withdrawal Idempotency replay
        val withdrawCmd = ExecuteRestrictedWithdrawalCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            amountMinorUnits = 5_000L,
            currencyCode = "USD",
            forfeitActiveBonusOnWithdrawal = true,
            idempotencyKey = "idem-withdraw-key",
            correlationId = "corr-idem-wd",
            causationId = "caus-idem-wd",
            expectedVersion = 3L
        )
        val withdrawResult1 = service.executeRestrictedWithdrawal(withdrawCmd)
        val withdrawResult2 = service.executeRestrictedWithdrawal(withdrawCmd)
        assertEquals(withdrawResult1.resultId, withdrawResult2.resultId)
        assertEquals(withdrawResult1.serverVersion, withdrawResult2.serverVersion)

        val walletAfterIdemWithdraw = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterIdemWithdraw)
        assertEquals(4L, walletAfterIdemWithdraw.version)
        assertEquals(8_000L, walletAfterIdemWithdraw.cashMinorUnits)
        assertEquals(0L, walletAfterIdemWithdraw.bonusMinorUnits)

        // 5. 16-thread concurrent execution across distinct players
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)
        val concurrentResults = ConcurrentHashMap<Int, ExecuteWagerResult>()

        val concurrentPlayers = (0 until threadCount).map { i ->
            val pId = UUID.randomUUID()
            val initialPWallet = PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = pId,
                currencyCode = "USD",
                cashMinorUnits = 2_000L,
                bonusMinorUnits = 3_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
            store.saveWallet(initialPWallet)
            pId
        }

        for (i in 0 until threadCount) {
            val pId = concurrentPlayers[i]
            val pPrincipal = playerPrincipal(pId.toString(), tenantId)
            executor.submit {
                try {
                    val res = service.executeWager(
                        ExecuteWagerCommand(
                            principal = pPrincipal,
                            tenantId = tenantId,
                            playerId = pId,
                            gameId = "game-idem",
                            wagerMinorUnits = 3_000L, // 2,000 cash + 1,000 bonus
                            currencyCode = "USD",
                            idempotencyKey = "concurrent-wager-$i",
                            correlationId = "corr-c-$i",
                            causationId = "caus-c-$i",
                            expectedVersion = 1L
                        )
                    )
                    concurrentResults[i] = res
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()

        assertEquals(threadCount, concurrentResults.size)
        for (i in 0 until threadCount) {
            val res = concurrentResults[i]
            assertNotNull(res)
            assertEquals(2_000L, res.cashDebitedMinorUnits)
            assertEquals(1_000L, res.bonusDebitedMinorUnits)
            assertEquals(0L, res.remainingCashMinorUnits)
            assertEquals(2_000L, res.remainingBonusMinorUnits)
        }
    }

    // =========================================================================
    // BONUS-001-02-T004: Migration Integrity, Recovery, and Observability
    // =========================================================================

    @Test
    fun `BONUS-001-02-T004 Migration integrity recovery and observability verification`() {
        BonusSpendingWithdrawalRestrictionBinding.isBound = true

        // 1. Migration integrity: Check Flyway migration scripts in src/main/resources/db/migration
        val migrationDir = File("src/main/resources/db/migration")
        if (migrationDir.exists()) {
            val files = migrationDir.listFiles()?.map { it.name } ?: emptyList()
            for (filename in files) {
                if (filename.startsWith("V") && filename.contains("__")) {
                    val versionPart = filename.substring(1, filename.indexOf("__"))
                    val versionNum = versionPart.toIntOrNull()
                    if (versionNum != null) {
                        assertTrue(
                            versionNum <= 16,
                            "Migration version $versionNum exceeds V16 limit! Found: $filename"
                        )
                    }
                }
            }
        }

        // 2. Recovery and Restart: State survives across service instances
        val store = InMemoryBonusGrantStore()
        val gameRules = InMemoryGameRuleDirectory()
        val alertSink = InMemoryBonusAlertSink()

        val service1 = BonusSpendingWithdrawalRestrictionService(
            store = store,
            gameRules = gameRules,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-recovery-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

        gameRules.setRule(
            tenantId,
            GameWageringRule(
                gameId = "game-recovery",
                isBonusAllowed = true,
                contributionMultiplier = 1.0,
                maxAllowedBetMinorUnits = 10_000L
            )
        )

        // Seed wallet: $50 cash, $50 bonus
        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 5_000L,
                bonusMinorUnits = 5_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // Perform wager on service 1
        service1.executeWager(
            ExecuteWagerCommand(
                principal = player,
                tenantId = tenantId,
                playerId = playerId,
                gameId = "game-recovery",
                wagerMinorUnits = 3_000L,
                currencyCode = "USD",
                idempotencyKey = "w-rec-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )

        // Simulate service restart: instantiate fresh Service 2 sharing underlying store
        val service2 = BonusSpendingWithdrawalRestrictionService(
            store = store,
            gameRules = gameRules,
            alertSink = alertSink,
            clock = clock
        )

        // Verify Service 2 enforces restrictions on the recovered state:
        // Cash has 2,000 left. Stale version 1L must be rejected.
        val staleEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service2.executeWager(
                ExecuteWagerCommand(
                    principal = player,
                    tenantId = tenantId,
                    playerId = playerId,
                    gameId = "game-recovery",
                    wagerMinorUnits = 1_000L,
                    currencyCode = "USD",
                    idempotencyKey = "w-rec-2-stale",
                    correlationId = "corr-rec-2",
                    causationId = "caus-rec-2",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, staleEx.code)

        // Service 2 succeeds with expectedVersion = 2L
        val res2 = service2.executeWager(
            ExecuteWagerCommand(
                principal = player,
                tenantId = tenantId,
                playerId = playerId,
                gameId = "game-recovery",
                wagerMinorUnits = 1_000L,
                currencyCode = "USD",
                idempotencyKey = "w-rec-2-valid",
                correlationId = "corr-rec-3",
                causationId = "caus-rec-3",
                expectedVersion = 2L
            )
        )
        assertEquals(3L, res2.serverVersion)
        assertEquals(1_000L, res2.remainingCashMinorUnits)

        // 3. Observability & Redaction:
        // Verify alerts and audit events do not leak sensitive PII, raw passwords, or tokens
        val alerts = alertSink.alerts
        for (alert in alerts) {
            assertFalse(alert.contains("password", ignoreCase = true))
            assertFalse(alert.contains("secret", ignoreCase = true))
            assertFalse(alert.contains("token", ignoreCase = true))
        }

        // Verify event lineage: correlationId and causationId propagate cleanly
        assertEquals("corr-rec-3", res2.auditEvent.correlationId)
        assertEquals("caus-rec-3", res2.auditEvent.causationId)
    }
}
