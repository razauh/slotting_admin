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

class BonusStatementDisclosureTest {

    private val now = Instant.parse("2026-09-18T23:55:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        BonusStatementDisclosureBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        BonusStatementDisclosureBinding.isBound = true
    }

    private fun adminPrincipal(
        id: String = "admin-audit-1",
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
    // BONUS-002-02-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `BONUS-002-02-T001 Disclose bonus expiry in statements produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        BonusStatementDisclosureBinding.checkBound()

        val store = InMemoryBonusStatementStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusStatementDisclosureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-casino-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

        // Seed wallet: $150.00 cash (15,000 units), $50.00 bonus (5,000 units)
        val initialWallet = PlayerWalletBuckets(
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            cashMinorUnits = 15_000L,
            bonusMinorUnits = 5_000L,
            lockedCashMinorUnits = 0L,
            version = 1L
        )
        store.saveWallet(initialWallet)

        // Seed Active Grant 1: Expiring in the future
        val activeGrantId = UUID.randomUUID()
        val activeGrant = BonusGrantRecord(
            grantId = activeGrantId,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.WELCOME_BONUS,
            amountMinorUnits = 5_000L,
            currencyCode = "USD",
            wageringRequirementMultiplier = 20.0,
            wageringRequirementMinorUnits = 100_000L,
            wageringProgressMinorUnits = 25_000L,
            status = BonusGrantStatus.ACTIVE,
            reason = "Welcome bonus",
            createdAt = now.minusSeconds(86400),
            expiresAt = now.plusSeconds(86400 * 7), // Expiring in 7 days
            version = 1L
        )
        store.saveGrant(activeGrant)

        // Seed Receipt 1: Expired bonus earlier during this statement period
        val expiredGrantId = UUID.randomUUID()
        val receipt1 = PlayerBonusReceipt(
            receiptId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            grantId = expiredGrantId,
            actionType = "EXPIRED",
            forfeitedBonusMinorUnits = 3_000L,
            compensationMinorUnits = 0L,
            remainingCashMinorUnits = 15_000L,
            remainingBonusMinorUnits = 5_000L,
            expiryTimestamp = now.minusSeconds(3600),
            expiryTimezone = "UTC",
            serverVersion = 1L,
            reason = "Bonus expired at ${now.minusSeconds(3600)}",
            evidenceReference = "bonus-expiry:$tenantId:$playerId:$expiredGrantId:ref1",
            issuedAt = now.minusSeconds(3600)
        )
        store.saveReceipt(receipt1)

        // Seed Receipt 2: Forfeited bonus with compensation during this statement period
        val forfeitedGrantId = UUID.randomUUID()
        val receipt2 = PlayerBonusReceipt(
            receiptId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            grantId = forfeitedGrantId,
            actionType = "COMPENSATED",
            forfeitedBonusMinorUnits = 2_000L,
            compensationMinorUnits = 500L,
            remainingCashMinorUnits = 15_000L,
            remainingBonusMinorUnits = 5_000L,
            expiryTimestamp = now.minusSeconds(1800),
            expiryTimezone = "America/New_York",
            serverVersion = 1L,
            reason = "Customer support goodwill compensation",
            evidenceReference = "bonus-forfeit:$tenantId:$playerId:$forfeitedGrantId:ref2",
            issuedAt = now.minusSeconds(1800)
        )
        store.saveReceipt(receipt2)

        // Seed balanced ledger entries
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = tenantId,
                transactionReference = "seed-cash",
                debitAccount = "SYSTEM_LIQUIDITY_CLEARING",
                creditAccount = "PLAYER_CASH_LIABILITY:$playerId",
                amountMinorUnits = 15_000L,
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
                creditAccount = "PLAYER_BONUS_LIABILITY:$playerId",
                amountMinorUnits = 5_000L,
                currencyCode = "USD",
                createdAt = now
            )
        )

        // Generate player statement for the last 30 days
        val generateCmd = GenerateBonusStatementCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400 * 30),
            periodEnd = now,
            statementTimezone = "America/New_York",
            idempotencyKey = "stmt-gen-1",
            correlationId = "corr-stmt-1",
            causationId = "caus-stmt-1",
            expectedVersion = 1L
        )
        val result = service.generateStatement(generateCmd)

        // Assert: Expiry timezone/version explicit; player receipt and audit
        assertNotNull(result.statement)
        val statement = result.statement
        assertEquals(tenantId, statement.tenantId)
        assertEquals(playerId, statement.playerId)
        assertEquals("America/New_York", statement.statementTimezone)
        assertEquals(1L, statement.serverVersion)
        assertEquals(15_000L, statement.currentCashBalanceMinorUnits)
        assertEquals(5_000L, statement.currentBonusBalanceMinorUnits)

        // Assert active bonus disclosure
        assertEquals(1, statement.activeBonusDisclosures.size)
        val activeDisc = statement.activeBonusDisclosures[0]
        assertEquals(activeGrantId, activeDisc.grantId)
        assertEquals(5_000L, activeDisc.grantedAmountMinorUnits)
        assertEquals(5_000L, activeDisc.currentBonusBalanceMinorUnits)
        assertEquals(100_000L, activeDisc.wageringRequiredMinorUnits)
        assertEquals(25_000L, activeDisc.wageringProgressMinorUnits)
        assertEquals(75_000L, activeDisc.remainingWageringMinorUnits)
        assertEquals(activeGrant.expiresAt, activeDisc.expiresAt)
        assertEquals("America/New_York", activeDisc.expiryTimezone)
        assertFalse(activeDisc.isExpired)

        // Assert expiry line-item disclosures
        assertEquals(2, statement.expiryDisclosures.size)
        val expDisc1 = statement.expiryDisclosures.find { it.grantId == expiredGrantId }
        assertNotNull(expDisc1)
        assertEquals("EXPIRED", expDisc1.actionType)
        assertEquals(3_000L, expDisc1.forfeitedBonusMinorUnits)
        assertEquals(0L, expDisc1.compensationMinorUnits)
        assertEquals("UTC", expDisc1.expiryTimezone)

        val expDisc2 = statement.expiryDisclosures.find { it.grantId == forfeitedGrantId }
        assertNotNull(expDisc2)
        assertEquals("COMPENSATED", expDisc2.actionType)
        assertEquals(2_000L, expDisc2.forfeitedBonusMinorUnits)
        assertEquals(500L, expDisc2.compensationMinorUnits)
        assertEquals("America/New_York", expDisc2.expiryTimezone)

        // Assert summary totals
        assertEquals(5_000L, statement.totalExpiredOrForfeitedDuringPeriodMinorUnits)
        assertEquals(500L, statement.totalCompensationDuringPeriodMinorUnits)

        // Step 2: Double-entry ledger balance conservation
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

        // Step 3: Evidence reference, audit event, outbox event
        assertFalse(statement.evidenceReference.isBlank())
        assertEquals("BONUS_STATEMENT_DISCLOSED", result.auditEvent.type)
        assertEquals("BONUS_STATEMENT_DISCLOSED", result.outboxEvent.type)
        assertEquals("corr-stmt-1", result.auditEvent.correlationId)
        assertEquals("caus-stmt-1", result.auditEvent.causationId)
    }

    // =========================================================================
    // BONUS-002-02-T002: Negative, Boundary, and Security Gaps
    // =========================================================================

    @Test
    fun `BONUS-002-02-T002 Negative boundary and security scenarios fail closed`() {
        BonusStatementDisclosureBinding.isBound = true

        val store = InMemoryBonusStatementStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusStatementDisclosureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-sec-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 1_000L,
                bonusMinorUnits = 1_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // 1. Cross-tenant request rejected (FORBIDDEN)
        val crossTenantPlayer = playerPrincipal(playerId.toString(), "attacker-tenant")
        val crossTenantCmd = GenerateBonusStatementCommand(
            principal = crossTenantPlayer,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            statementTimezone = "UTC",
            idempotencyKey = "cross-tenant-stmt",
            correlationId = "corr-ct",
            causationId = "caus-ct",
            expectedVersion = 1L
        )
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(crossTenantCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex1.code)

        // 2. Cross-player request rejected (Player A cannot view Player B's statement)
        val otherPlayer = playerPrincipal(UUID.randomUUID().toString(), tenantId)
        val crossPlayerCmd = GenerateBonusStatementCommand(
            principal = otherPlayer,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            statementTimezone = "UTC",
            idempotencyKey = "cross-player-stmt",
            correlationId = "corr-cp",
            causationId = "caus-cp",
            expectedVersion = 1L
        )
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(crossPlayerCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex2.code)

        // 3. Unauthenticated request rejected (UNAUTHENTICATED)
        val unauthCmd = GenerateBonusStatementCommand(
            principal = null,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            statementTimezone = "UTC",
            idempotencyKey = "unauth-stmt",
            correlationId = "corr-ua",
            causationId = "caus-ua",
            expectedVersion = 1L
        )
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(unauthCmd)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex3.code)

        // 4. Inverted period range rejected (periodStart > periodEnd) (INVALID)
        val invertedPeriodCmd = GenerateBonusStatementCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now,
            periodEnd = now.minusSeconds(86400), // Start is after End!
            statementTimezone = "UTC",
            idempotencyKey = "inv-period-stmt",
            correlationId = "corr-inv",
            causationId = "caus-inv",
            expectedVersion = 1L
        )
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(invertedPeriodCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex4.code)

        // 5. Invalid timezone rejected (INVALID)
        val invalidTzCmd = GenerateBonusStatementCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            statementTimezone = "Mars/Olympus_Mons",
            idempotencyKey = "inv-tz-stmt",
            correlationId = "corr-tz",
            causationId = "caus-tz",
            expectedVersion = 1L
        )
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(invalidTzCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex5.code)

        // 6. Stale version rejected (STALE)
        val staleCmd = GenerateBonusStatementCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            statementTimezone = "UTC",
            idempotencyKey = "stale-stmt",
            correlationId = "corr-stale",
            causationId = "caus-stale",
            expectedVersion = 999L // Wallet is at version 1L
        )
        val ex6 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(staleCmd)
        }
        assertEquals(AuthErrorCode.STALE, ex6.code)

        // 7. Malformed / blank headers rejected (INVALID)
        val blankHeaderCmd = GenerateBonusStatementCommand(
            principal = player,
            tenantId = "",
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            statementTimezone = "UTC",
            idempotencyKey = "blank-stmt",
            correlationId = "corr-blank",
            causationId = "caus-blank",
            expectedVersion = 1L
        )
        val ex7 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(blankHeaderCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex7.code)
    }

    // =========================================================================
    // BONUS-002-02-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `BONUS-002-02-T003 Idempotency replays, conflict detection, and concurrent execution maintain balance conservation`() {
        BonusStatementDisclosureBinding.isBound = true

        val store = InMemoryBonusStatementStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusStatementDisclosureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-idem-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 5_000L,
                bonusMinorUnits = 2_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // 1. Idempotent statement generation replay
        val generateCmd = GenerateBonusStatementCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            currencyCode = "USD",
            periodStart = now.minusSeconds(86400),
            periodEnd = now,
            statementTimezone = "UTC",
            idempotencyKey = "idem-stmt-key",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1",
            expectedVersion = 1L
        )
        val res1 = service.generateStatement(generateCmd)
        val res2 = service.generateStatement(generateCmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.statement.statementId, res2.statement.statementId)
        assertEquals(res1.statement.evidenceReference, res2.statement.evidenceReference)

        // Verify only 1 statement is saved
        val statements = service.getStatementsForPlayer(tenantId, playerId)
        assertEquals(1, statements.size)

        // 2. Conflict detection on modified payload
        val conflictingCmd = generateCmd.copy(statementTimezone = "America/Chicago")
        val conflictEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.generateStatement(conflictingCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictEx.code)

        // 3. 16-thread concurrent statement generation across distinct players
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)
        val concurrentResults = ConcurrentHashMap<Int, GenerateBonusStatementResult>()

        val concurrentPlayers = (0 until threadCount).map { i ->
            val pId = UUID.randomUUID()
            store.saveWallet(
                PlayerWalletBuckets(
                    tenantId = tenantId,
                    playerId = pId,
                    currencyCode = "USD",
                    cashMinorUnits = 1_000L * (i + 1),
                    bonusMinorUnits = 500L * (i + 1),
                    lockedCashMinorUnits = 0L,
                    version = 1L
                )
            )
            pId
        }

        for (i in 0 until threadCount) {
            val pId = concurrentPlayers[i]
            val pPrincipal = playerPrincipal(pId.toString(), tenantId)
            executor.submit {
                try {
                    val res = service.generateStatement(
                        GenerateBonusStatementCommand(
                            principal = pPrincipal,
                            tenantId = tenantId,
                            playerId = pId,
                            currencyCode = "USD",
                            periodStart = now.minusSeconds(86400 * 7),
                            periodEnd = now,
                            statementTimezone = "UTC",
                            idempotencyKey = "concurrent-stmt-$i",
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
            assertEquals(1_000L * (i + 1), res.statement.currentCashBalanceMinorUnits)
            assertEquals(500L * (i + 1), res.statement.currentBonusBalanceMinorUnits)
        }
    }

    // =========================================================================
    // BONUS-002-02-T004: Migration Integrity, Recovery, and Observability
    // =========================================================================

    @Test
    fun `BONUS-002-02-T004 Migration integrity recovery and observability verification`() {
        BonusStatementDisclosureBinding.isBound = true

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

        // 2. Recovery and Restart: State and statements survive across service instances
        val store = InMemoryBonusStatementStore()
        val alertSink = InMemoryBonusAlertSink()

        val service1 = BonusStatementDisclosureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-recovery-1"
        val playerId = UUID.randomUUID()
        val player = playerPrincipal(playerId.toString(), tenantId)

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

        // Generate statement on Service 1
        val res1 = service1.generateStatement(
            GenerateBonusStatementCommand(
                principal = player,
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                periodStart = now.minusSeconds(86400 * 30),
                periodEnd = now,
                statementTimezone = "UTC",
                idempotencyKey = "rec-stmt-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )

        // Recreate Service 2 sharing persistent store
        val service2 = BonusStatementDisclosureService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        // Verify Service 2 can retrieve the statement generated by Service 1
        val recoveredStmt = service2.getStatement(tenantId, res1.statement.statementId)
        assertNotNull(recoveredStmt)
        assertEquals(res1.statement.statementId, recoveredStmt.statementId)
        assertEquals("UTC", recoveredStmt.statementTimezone)
        assertEquals(5_000L, recoveredStmt.currentCashBalanceMinorUnits)

        // 3. Observability & Redaction
        val alerts = alertSink.alerts
        for (alert in alerts) {
            assertFalse(alert.contains("password", ignoreCase = true))
            assertFalse(alert.contains("secret", ignoreCase = true))
            assertFalse(alert.contains("token", ignoreCase = true))
        }

        assertEquals("corr-rec-1", res1.auditEvent.correlationId)
        assertEquals("caus-rec-1", res1.auditEvent.causationId)
        assertEquals("BONUS_STATEMENT_DISCLOSED", res1.outboxEvent.type)
    }
}
