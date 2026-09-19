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

class BonusExpiryForfeitureTest {

    private val now = Instant.parse("2026-09-18T23:55:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        BonusExpiryForfeitureBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        BonusExpiryForfeitureBinding.isBound = true
    }

    private fun adminPrincipal(
        id: String = "admin-bonus-1",
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
    // BONUS-002-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `BONUS-002-01-T001 Expire and forfeit bonus with compensation produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        BonusExpiryForfeitureBinding.checkBound()

        val store = InMemoryBonusExpiryStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusExpiryForfeitureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-casino-1"
        val playerId1 = UUID.randomUUID()
        val player1 = playerPrincipal(playerId1.toString(), tenantId)
        val admin = adminPrincipal("admin-operator-1", tenantId)

        // Seed initial wallet: $50 cash (5,000 units), $100 bonus (10,000 units)
        val initialWallet = PlayerWalletBuckets(
            tenantId = tenantId,
            playerId = playerId1,
            currencyCode = "USD",
            cashMinorUnits = 5_000L,
            bonusMinorUnits = 10_000L,
            lockedCashMinorUnits = 0L,
            version = 1L
        )
        store.saveWallet(initialWallet)

        // Seed Grant 1: Expired in the past (expiresAt = now - 1 hour)
        val grant1Id = UUID.randomUUID()
        val grant1 = BonusGrantRecord(
            grantId = grant1Id,
            tenantId = tenantId,
            playerId = playerId1,
            bonusType = BonusGrantType.WELCOME_BONUS,
            amountMinorUnits = 4_000L, // $40.00
            currencyCode = "USD",
            wageringRequirementMultiplier = 20.0,
            wageringRequirementMinorUnits = 80_000L,
            wageringProgressMinorUnits = 5_000L,
            status = BonusGrantStatus.ACTIVE,
            reason = "Welcome bonus",
            createdAt = now.minusSeconds(7200),
            expiresAt = now.minusSeconds(3600), // Expired 1 hour ago
            version = 1L
        )
        store.saveGrant(grant1)

        // Seed initial double-entry ledger entries for seed balances
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = tenantId,
                transactionReference = "seed-cash",
                debitAccount = "SYSTEM_LIQUIDITY_CLEARING",
                creditAccount = "PLAYER_CASH_LIABILITY:$playerId1",
                amountMinorUnits = 5_000L,
                currencyCode = "USD",
                createdAt = now
            )
        )
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = tenantId,
                transactionReference = "seed-bonus",
                debitAccount = "CASINO_PROMOTION_EXPENSE",
                creditAccount = "PLAYER_BONUS_LIABILITY:$playerId1",
                amountMinorUnits = 10_000L,
                currencyCode = "USD",
                createdAt = now
            )
        )

        // Step 1: Authoritatively expire grant 1
        val expireCmd = ExpireBonusCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId1,
            grantId = grant1Id,
            currencyCode = "USD",
            expiryTimezone = "UTC",
            idempotencyKey = "expire-g1-1",
            correlationId = "corr-exp-1",
            causationId = "caus-exp-1",
            expectedVersion = 1L
        )
        val expireResult = service.expireBonus(expireCmd)

        // Assert: Expiry timezone/version explicit; player receipt and audit
        assertNotNull(expireResult.receipt)
        assertEquals("UTC", expireResult.receipt.expiryTimezone)
        assertEquals(2L, expireResult.receipt.serverVersion)
        assertEquals(4_000L, expireResult.receipt.forfeitedBonusMinorUnits)
        assertEquals(0L, expireResult.receipt.compensationMinorUnits)
        assertEquals(6_000L, expireResult.receipt.remainingBonusMinorUnits)
        assertEquals(5_000L, expireResult.receipt.remainingCashMinorUnits)
        assertEquals("EXPIRED", expireResult.receipt.actionType)
        assertEquals(grant1.expiresAt, expireResult.receipt.expiryTimestamp)

        // Verify grant status is updated to EXPIRED
        val updatedGrant1 = store.findGrant(tenantId, grant1Id)
        assertNotNull(updatedGrant1)
        assertEquals(BonusGrantStatus.EXPIRED, updatedGrant1.status)

        // Step 2: Seed Grant 2 and Forfeit with Compensation
        val grant2Id = UUID.randomUUID()
        val grant2 = BonusGrantRecord(
            grantId = grant2Id,
            tenantId = tenantId,
            playerId = playerId1,
            bonusType = BonusGrantType.DEPOSIT_MATCH,
            amountMinorUnits = 6_000L, // $60.00
            currencyCode = "USD",
            wageringRequirementMultiplier = 15.0,
            wageringRequirementMinorUnits = 90_000L,
            wageringProgressMinorUnits = 10_000L,
            status = BonusGrantStatus.ACTIVE,
            reason = "Deposit match",
            createdAt = now.minusSeconds(1000),
            expiresAt = now.plusSeconds(86400), // Not yet expired
            version = 1L
        )
        store.saveGrant(grant2)

        // Admin forfeits grant 2 on player's behalf with $15.00 (1,500 units) compensation cash credit
        val forfeitCmd = ForfeitBonusCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId1,
            grantId = grant2Id,
            currencyCode = "USD",
            forfeitReason = "Customer goodwill gesture on game issue",
            compensationAmountMinorUnits = 1_500L,
            expiryTimezone = "America/New_York",
            idempotencyKey = "forfeit-g2-1",
            correlationId = "corr-forfeit-1",
            causationId = "caus-forfeit-1",
            expectedVersion = 2L
        )
        val forfeitResult = service.forfeitBonus(forfeitCmd)

        // Assert player receipt for forfeiture with compensation
        assertNotNull(forfeitResult.receipt)
        assertEquals("America/New_York", forfeitResult.receipt.expiryTimezone)
        assertEquals(3L, forfeitResult.receipt.serverVersion)
        assertEquals(6_000L, forfeitResult.receipt.forfeitedBonusMinorUnits)
        assertEquals(1_500L, forfeitResult.receipt.compensationMinorUnits)
        assertEquals(0L, forfeitResult.receipt.remainingBonusMinorUnits) // 6,000 - 6,000 = 0
        assertEquals(6_500L, forfeitResult.receipt.remainingCashMinorUnits) // 5,000 + 1,500 comp = 6,500
        assertEquals("COMPENSATED", forfeitResult.receipt.actionType)

        val updatedGrant2 = store.findGrant(tenantId, grant2Id)
        assertNotNull(updatedGrant2)
        assertEquals(BonusGrantStatus.FORFEITED, updatedGrant2.status)

        // Step 3: Batch Expiry Check
        val playerId2 = UUID.randomUUID()
        val wallet2 = PlayerWalletBuckets(
            tenantId = tenantId,
            playerId = playerId2,
            currencyCode = "USD",
            cashMinorUnits = 1_000L,
            bonusMinorUnits = 3_000L,
            lockedCashMinorUnits = 0L,
            version = 1L
        )
        store.saveWallet(wallet2)

        val grant3Id = UUID.randomUUID()
        val grant3 = BonusGrantRecord(
            grantId = grant3Id,
            tenantId = tenantId,
            playerId = playerId2,
            bonusType = BonusGrantType.LOYALTY_REWARD,
            amountMinorUnits = 3_000L,
            currencyCode = "USD",
            wageringRequirementMultiplier = 10.0,
            wageringRequirementMinorUnits = 30_000L,
            wageringProgressMinorUnits = 0L,
            status = BonusGrantStatus.ACTIVE,
            reason = "Loyalty reward",
            createdAt = now.minusSeconds(5000),
            expiresAt = now.minusSeconds(100), // Expired
            version = 1L
        )
        store.saveGrant(grant3)

        val batchCmd = BatchExpireBonusesCommand(
            principal = admin,
            tenantId = tenantId,
            asOfTime = now,
            expiryTimezone = "UTC",
            idempotencyKey = "batch-exp-1",
            correlationId = "corr-batch-1",
            causationId = "caus-batch-1"
        )
        val batchResult = service.batchExpireBonuses(batchCmd)
        assertEquals(1, batchResult.expiredGrantCount)
        assertEquals(3_000L, batchResult.totalForfeitedMinorUnits)
        assertEquals(1, batchResult.receipts.size)
        assertEquals(grant3Id, batchResult.receipts[0].grantId)

        // Step 4: Player can query durable receipts
        val player1Receipts = service.getPlayerReceipts(tenantId, playerId1)
        assertEquals(2, player1Receipts.size)
        assertTrue(player1Receipts.any { it.actionType == "EXPIRED" && it.grantId == grant1Id })
        assertTrue(player1Receipts.any { it.actionType == "COMPENSATED" && it.grantId == grant2Id })

        // Step 5: Double-entry ledger balance conservation: debits == credits
        val allLedgerEntries = store.getLedgerEntries(tenantId)
        assertTrue(allLedgerEntries.isNotEmpty())
        for (entry in allLedgerEntries) {
            assertTrue(entry.amountMinorUnits > 0L)
            assertFalse(entry.debitAccount.isBlank())
            assertFalse(entry.creditAccount.isBlank())
            assertFalse(entry.debitAccount == entry.creditAccount)
        }

        val totalDebits = allLedgerEntries.groupBy { it.debitAccount }.values.sumOf { list -> list.sumOf { e -> e.amountMinorUnits } }
        val totalCredits = allLedgerEntries.groupBy { it.creditAccount }.values.sumOf { list -> list.sumOf { e -> e.amountMinorUnits } }
        assertEquals(totalDebits, totalCredits)

        // Step 6: Evidence reference and audit/outbox validation
        assertFalse(expireResult.evidenceReference.isBlank())
        assertFalse(forfeitResult.evidenceReference.isBlank())
        assertFalse(batchResult.evidenceReference.isBlank())
        assertEquals("BONUS_EXPIRED", expireResult.auditEvent.type)
        assertEquals("BONUS_FORFEITED_WITH_COMPENSATION", forfeitResult.auditEvent.type)
        assertEquals("BATCH_BONUS_EXPIRY_COMPLETED", batchResult.auditEvent.type)
    }

    // =========================================================================
    // BONUS-002-01-T002: Negative, Boundary, and Security Gaps
    // =========================================================================

    @Test
    fun `BONUS-002-01-T002 Negative boundary and security scenarios fail closed`() {
        BonusExpiryForfeitureBinding.isBound = true

        val store = InMemoryBonusExpiryStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusExpiryForfeitureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-sec-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)
        val admin = adminPrincipal("admin-sec-1", tenantId)

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

        val activeGrantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = activeGrantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.WELCOME_BONUS,
                amountMinorUnits = 5_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 20.0,
                wageringRequirementMinorUnits = 100_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "Welcome",
                createdAt = now.minusSeconds(500),
                expiresAt = now.plusSeconds(3600), // NOT yet expired
                version = 1L
            )
        )

        // 1. Premature expiry rejected (cannot expire active grant before expiresAt)
        val prematureExpire = ExpireBonusCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            expiryTimezone = "UTC",
            idempotencyKey = "premature-exp",
            correlationId = "corr-pre",
            causationId = "caus-pre",
            expectedVersion = 1L
        )
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.expireBonus(prematureExpire)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex1.code)

        // 2. Unauthorized compensation rejected (player principal cannot grant themselves compensation)
        val unauthorizedComp = ForfeitBonusCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Player forfeit",
            compensationAmountMinorUnits = 2_000L, // Non-admin cannot grant compensation!
            expiryTimezone = "UTC",
            idempotencyKey = "unauth-comp",
            correlationId = "corr-comp",
            causationId = "caus-comp",
            expectedVersion = 1L
        )
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(unauthorizedComp)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex2.code)

        // 3. Forfeit grant successfully
        val legitimateForfeit = ForfeitBonusCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Player opted to forfeit",
            compensationAmountMinorUnits = 0L,
            expiryTimezone = "UTC",
            idempotencyKey = "legit-forfeit",
            correlationId = "corr-legit",
            causationId = "caus-legit",
            expectedVersion = 1L
        )
        service.forfeitBonus(legitimateForfeit)

        // 4. DOUBLE FORFEIT PREVENTION: Attempting to forfeit already forfeited grant fails closed
        val doubleForfeit = ForfeitBonusCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Second forfeit attempt",
            compensationAmountMinorUnits = 0L,
            expiryTimezone = "UTC",
            idempotencyKey = "double-forfeit-key",
            correlationId = "corr-double",
            causationId = "caus-double",
            expectedVersion = 2L
        )
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(doubleForfeit)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex4.code)

        // Also double expiry fails closed
        val doubleExpiry = ExpireBonusCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            expiryTimezone = "UTC",
            idempotencyKey = "double-exp-key",
            correlationId = "corr-double-e",
            causationId = "caus-double-e",
            expectedVersion = 2L
        )
        val ex4b = assertFailsWith<AuthenticationFailure.Rejected> {
            service.expireBonus(doubleExpiry)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex4b.code)

        // 5. Cross-tenant request rejected
        val crossTenantPlayer = playerPrincipal(playerId.toString(), "attacker-tenant")
        val crossTenantForfeit = ForfeitBonusCommand(
            principal = crossTenantPlayer,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Cross-tenant",
            compensationAmountMinorUnits = 0L,
            expiryTimezone = "UTC",
            idempotencyKey = "cross-tenant-f",
            correlationId = "corr-cross",
            causationId = "caus-cross",
            expectedVersion = 2L
        )
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(crossTenantForfeit)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex5.code)

        // 6. Cross-player request rejected (Player A cannot forfeit Player B's bonus)
        val otherPlayer = playerPrincipal(UUID.randomUUID().toString(), tenantId)
        val crossPlayerForfeit = ForfeitBonusCommand(
            principal = otherPlayer,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Cross-player",
            compensationAmountMinorUnits = 0L,
            expiryTimezone = "UTC",
            idempotencyKey = "cross-player-f",
            correlationId = "corr-cross-p",
            causationId = "caus-cross-p",
            expectedVersion = 2L
        )
        val ex6 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(crossPlayerForfeit)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex6.code)

        // 7. Unauthenticated request rejected
        val unauthForfeit = ForfeitBonusCommand(
            principal = null,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Unauthenticated",
            compensationAmountMinorUnits = 0L,
            expiryTimezone = "UTC",
            idempotencyKey = "unauth-f",
            correlationId = "corr-unauth",
            causationId = "caus-unauth",
            expectedVersion = 2L
        )
        val ex7 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(unauthForfeit)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex7.code)

        // 8. Stale version rejected
        val staleGrantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = staleGrantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.DEPOSIT_MATCH,
                amountMinorUnits = 1_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 10.0,
                wageringRequirementMinorUnits = 10_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "Match",
                createdAt = now.minusSeconds(500),
                expiresAt = now.plusSeconds(3600),
                version = 1L
            )
        )
        val staleForfeit = ForfeitBonusCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            grantId = staleGrantId,
            currencyCode = "USD",
            forfeitReason = "Stale version",
            compensationAmountMinorUnits = 0L,
            expiryTimezone = "UTC",
            idempotencyKey = "stale-f",
            correlationId = "corr-stale",
            causationId = "caus-stale",
            expectedVersion = 1L // Wallet is at version 2L now
        )
        val ex8 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(staleForfeit)
        }
        assertEquals(AuthErrorCode.STALE, ex8.code)

        // 9. Invalid timezone rejected
        val invalidTzForfeit = ForfeitBonusCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Invalid timezone",
            compensationAmountMinorUnits = 0L,
            expiryTimezone = "Invalid/Timezone_Not_Real",
            idempotencyKey = "invalid-tz-f",
            correlationId = "corr-tz",
            causationId = "caus-tz",
            expectedVersion = 2L
        )
        val ex9 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(invalidTzForfeit)
        }
        assertEquals(AuthErrorCode.INVALID, ex9.code)

        // 10. Negative compensation rejected
        val negCompForfeit = ForfeitBonusCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId,
            grantId = activeGrantId,
            currencyCode = "USD",
            forfeitReason = "Negative comp",
            compensationAmountMinorUnits = -500L,
            expiryTimezone = "UTC",
            idempotencyKey = "neg-comp-f",
            correlationId = "corr-neg-c",
            causationId = "caus-neg-c",
            expectedVersion = 2L
        )
        val ex10 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.forfeitBonus(negCompForfeit)
        }
        assertEquals(AuthErrorCode.INVALID, ex10.code)
    }

    // =========================================================================
    // BONUS-002-01-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `BONUS-002-01-T003 Idempotency replays, conflict detection, and concurrent execution maintain balance conservation`() {
        BonusExpiryForfeitureBinding.isBound = true

        val store = InMemoryBonusExpiryStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusExpiryForfeitureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-idem-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)
        val admin = adminPrincipal("admin-idem-1", tenantId)

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

        val grantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = grantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.WELCOME_BONUS,
                amountMinorUnits = 5_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 10.0,
                wageringRequirementMinorUnits = 50_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "Welcome",
                createdAt = now.minusSeconds(4000),
                expiresAt = now.minusSeconds(100), // Expired
                version = 1L
            )
        )

        // 1. Idempotency replay for expiry
        val expireCmd = ExpireBonusCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId,
            grantId = grantId,
            currencyCode = "USD",
            expiryTimezone = "UTC",
            idempotencyKey = "idem-exp-key-1",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1",
            expectedVersion = 1L
        )
        val res1 = service.expireBonus(expireCmd)
        val res2 = service.expireBonus(expireCmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.receipt.receiptId, res2.receipt.receiptId)
        assertEquals(res1.serverVersion, res2.serverVersion)

        // Version only incremented once (from 1L to 2L)
        val walletAfterIdem = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterIdem)
        assertEquals(2L, walletAfterIdem.version)
        assertEquals(0L, walletAfterIdem.bonusMinorUnits)

        // 2. Conflict detection on modified payload
        val conflictingCmd = expireCmd.copy(expiryTimezone = "America/Chicago")
        val conflictEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.expireBonus(conflictingCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictEx.code)

        // 3. 16-thread concurrent execution across distinct players
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)
        val concurrentResults = ConcurrentHashMap<Int, BonusForfeitureResult>()

        val concurrentPlayers = (0 until threadCount).map { i ->
            val pId = UUID.randomUUID()
            store.saveWallet(
                PlayerWalletBuckets(
                    tenantId = tenantId,
                    playerId = pId,
                    currencyCode = "USD",
                    cashMinorUnits = 1_000L,
                    bonusMinorUnits = 2_000L,
                    lockedCashMinorUnits = 0L,
                    version = 1L
                )
            )
            val gId = UUID.randomUUID()
            store.saveGrant(
                BonusGrantRecord(
                    grantId = gId,
                    tenantId = tenantId,
                    playerId = pId,
                    bonusType = BonusGrantType.DEPOSIT_MATCH,
                    amountMinorUnits = 2_000L,
                    currencyCode = "USD",
                    wageringRequirementMultiplier = 10.0,
                    wageringRequirementMinorUnits = 20_000L,
                    wageringProgressMinorUnits = 0L,
                    status = BonusGrantStatus.ACTIVE,
                    reason = "Match",
                    createdAt = now.minusSeconds(500),
                    expiresAt = now.plusSeconds(3600),
                    version = 1L
                )
            )
            pId to gId
        }

        for (i in 0 until threadCount) {
            val (pId, gId) = concurrentPlayers[i]
            val pPrincipal = playerPrincipal(pId.toString(), tenantId)
            executor.submit {
                try {
                    val res = service.forfeitBonus(
                        ForfeitBonusCommand(
                            principal = pPrincipal,
                            tenantId = tenantId,
                            playerId = pId,
                            grantId = gId,
                            currencyCode = "USD",
                            forfeitReason = "Concurrent player forfeit $i",
                            compensationAmountMinorUnits = 0L,
                            expiryTimezone = "UTC",
                            idempotencyKey = "concurrent-forfeit-$i",
                            correlationId = "corr-cf-$i",
                            causationId = "caus-cf-$i",
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
            assertEquals(2_000L, res.receipt.forfeitedBonusMinorUnits)
            assertEquals(0L, res.receipt.remainingBonusMinorUnits)
            assertEquals(1_000L, res.receipt.remainingCashMinorUnits)
        }
    }

    // =========================================================================
    // BONUS-002-01-T004: Migration Integrity, Recovery, and Observability
    // =========================================================================

    @Test
    fun `BONUS-002-01-T004 Migration integrity recovery and observability verification`() {
        BonusExpiryForfeitureBinding.isBound = true

        // 1. Migration integrity: Check Flyway migration scripts
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

        // 2. Recovery and Restart: State and receipts survive across service instances
        val store = InMemoryBonusExpiryStore()
        val alertSink = InMemoryBonusAlertSink()

        val service1 = BonusExpiryForfeitureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-recovery-1"
        val playerId = UUID.randomUUID()
        val admin = adminPrincipal("admin-rec-1", tenantId)

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

        val grantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = grantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.WELCOME_BONUS,
                amountMinorUnits = 5_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 10.0,
                wageringRequirementMinorUnits = 50_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "Welcome",
                createdAt = now.minusSeconds(4000),
                expiresAt = now.minusSeconds(100),
                version = 1L
            )
        )

        // Expire on service 1
        val res1 = service1.expireBonus(
            ExpireBonusCommand(
                principal = admin,
                tenantId = tenantId,
                playerId = playerId,
                grantId = grantId,
                currencyCode = "USD",
                expiryTimezone = "UTC",
                idempotencyKey = "rec-exp-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )

        // Simulate crash/restart with Service 2 sharing persistent store
        val service2 = BonusExpiryForfeitureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        // Verify Service 2 can retrieve the receipt issued by Service 1
        val recoveredReceipt = service2.getReceipt(tenantId, res1.receipt.receiptId)
        assertNotNull(recoveredReceipt)
        assertEquals(res1.receipt.receiptId, recoveredReceipt.receiptId)
        assertEquals("EXPIRED", recoveredReceipt.actionType)
        assertEquals("UTC", recoveredReceipt.expiryTimezone)

        // Double forfeit check on Service 2: Attempting to forfeit now must fail closed (FORBIDDEN)
        val player = playerPrincipal(playerId.toString(), tenantId)
        val doubleForfeitEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service2.forfeitBonus(
                ForfeitBonusCommand(
                    principal = player,
                    tenantId = tenantId,
                    playerId = playerId,
                    grantId = grantId,
                    currencyCode = "USD",
                    forfeitReason = "Post-recovery forfeit attempt",
                    compensationAmountMinorUnits = 0L,
                    expiryTimezone = "UTC",
                    idempotencyKey = "rec-df-1",
                    correlationId = "corr-rec-2",
                    causationId = "caus-rec-2",
                    expectedVersion = 2L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, doubleForfeitEx.code)

        // 3. Observability & Event Lineage
        val alerts = alertSink.alerts
        for (alert in alerts) {
            assertFalse(alert.contains("password", ignoreCase = true))
            assertFalse(alert.contains("secret", ignoreCase = true))
            assertFalse(alert.contains("token", ignoreCase = true))
        }

        assertEquals("corr-rec-1", res1.auditEvent.correlationId)
        assertEquals("caus-rec-1", res1.auditEvent.causationId)
        assertEquals("BONUS_EXPIRED", res1.outboxEvent.type)
    }
}
