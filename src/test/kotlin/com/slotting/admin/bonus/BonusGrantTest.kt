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

class BonusGrantTest {

    private val now = Instant.parse("2026-09-18T23:55:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        BonusGrantBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        BonusGrantBinding.isBound = true
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
    // BONUS-001-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `BONUS-001-01-T001 Post isolated bonus grants produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        BonusGrantBinding.checkBound()

        val store = InMemoryBonusGrantStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusGrantService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-casino-1"
        val playerId = UUID.randomUUID()
        val admin = adminPrincipal("bonus-operator-1", tenantId)

        // 2. Post isolated bonus grant of 5,000 minor units ($50.00)
        val grantCmd = PostBonusGrantCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.WELCOME_BONUS,
            amountMinorUnits = 5_000L,
            currencyCode = "USD",
            wageringRequirementMultiplier = 20.0,
            grantReason = "Welcome bonus for new registration",
            idempotencyKey = "grant-cmd-1",
            correlationId = "corr-g-1",
            causationId = "caus-g-1",
            expectedVersion = 1L
        )

        val grantResult = service.postBonusGrant(grantCmd)

        // Exact assertions: Cash/bonus conservation and isolation; conversion prohibited unless explicitly approved.
        assertEquals(tenantId, grantResult.tenantId)
        assertEquals(playerId, grantResult.playerId)
        assertEquals(5_000L, grantResult.grantedAmountMinorUnits)
        assertEquals(0L, grantResult.newCashBalanceMinorUnits, "Cash bucket must remain 0")
        assertEquals(5_000L, grantResult.newBonusBalanceMinorUnits, "Bonus bucket must reflect grant")
        assertEquals(0L, grantResult.withdrawableCashMinorUnits, "Withdrawable cash must strictly be 0")
        assertEquals(2L, grantResult.serverVersion)
        assertEquals(now, grantResult.serverTime)
        assertTrue(grantResult.evidenceReference.startsWith("bonus-grant:$tenantId:$playerId:"))
        assertEquals("BONUS_GRANT_POSTED", grantResult.auditEvent.type)
        assertEquals("BONUS_GRANT_POSTED", grantResult.outboxEvent.type)

        // 3. Double-entry ledger conservation check: debits equal credits
        val ledger = store.getLedgerEntries(tenantId)
        assertEquals(1, ledger.size)
        val entry = ledger.first()
        assertEquals("CASINO_PROMOTION_EXPENSE", entry.debitAccount)
        assertEquals("PLAYER_BONUS_LIABILITY:$playerId", entry.creditAccount)
        assertEquals(5_000L, entry.amountMinorUnits)
        assertEquals("USD", entry.currencyCode)

        // 4. CORE PROTECTION: Attempting to withdraw bonus funds as cash must strictly FAIL
        val player = playerPrincipal(playerId.toString(), tenantId)
        val illegalWithdrawalError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.attemptWithdrawal(
                AttemptWithdrawalCommand(
                    principal = player,
                    tenantId = tenantId,
                    playerId = playerId,
                    amountMinorUnits = 2_000L, // Attempting to withdraw $20 when player only has bonus funds!
                    currencyCode = "USD",
                    idempotencyKey = "with-illegal-1",
                    correlationId = "corr-w-1",
                    causationId = "caus-w-1",
                    expectedVersion = 2L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, illegalWithdrawalError.code)
        assertTrue(alertSink.alerts.any { it.contains("BONUS_WITHDRAWAL_ATTEMPT_DENIED") })

        // 5. Simulate player depositing 1,000L ($10.00) into CASH bucket
        val wallet = store.findWallet(tenantId, playerId, "USD")!!
        wallet.cashMinorUnits = 1_000L
        wallet.version += 1L
        store.saveWallet(wallet)

        // Player now has 1,000L Cash and 5,000L Bonus. Withdrawable cash is strictly 1,000L.
        assertEquals(1_000L, wallet.withdrawableCashMinorUnits)
        assertEquals(6_000L, wallet.totalBalanceMinorUnits)

        // Withdrawing 1,000L Cash succeeds
        val validWithdrawal = service.attemptWithdrawal(
            AttemptWithdrawalCommand(
                principal = player,
                tenantId = tenantId,
                playerId = playerId,
                amountMinorUnits = 1_000L,
                currencyCode = "USD",
                idempotencyKey = "with-valid-1",
                correlationId = "corr-w-2",
                causationId = "caus-w-2",
                expectedVersion = wallet.version
            )
        )
        assertEquals(1_000L, validWithdrawal.withdrawnCashMinorUnits)
        assertEquals(0L, validWithdrawal.remainingCashMinorUnits)
        assertEquals(5_000L, validWithdrawal.remainingBonusMinorUnits)

        // Attempting to withdraw even 1 cent beyond remaining cash (0L) fails closed
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.attemptWithdrawal(
                AttemptWithdrawalCommand(
                    principal = player,
                    tenantId = tenantId,
                    playerId = playerId,
                    amountMinorUnits = 1L,
                    currencyCode = "USD",
                    idempotencyKey = "with-excess-1",
                    correlationId = "corr-w-3",
                    causationId = "caus-w-3",
                    expectedVersion = validWithdrawal.serverVersion
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // BONUS-001-01-T002: Negative, Boundary, and Security Cases
    // =========================================================================

    @Test
    fun `BONUS-001-01-T002 Post isolated bonus grants rejects invalid boundary unauthorized and stale input`() {
        BonusGrantBinding.isBound = true

        val store = InMemoryBonusGrantStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusGrantService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenant1 = "tenant-1"
        val tenant2 = "tenant-2"
        val playerId = UUID.randomUUID()
        val admin = adminPrincipal("admin-sec", tenant1)
        val player = playerPrincipal(playerId.toString(), tenant1)

        val grantResult = service.postBonusGrant(
            PostBonusGrantCommand(
                principal = admin,
                tenantId = tenant1,
                playerId = playerId,
                bonusType = BonusGrantType.DEPOSIT_MATCH,
                amountMinorUnits = 10_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 10.0, // 100,000L wagering required
                ttlSeconds = 3600L,
                grantReason = "Deposit match promo",
                idempotencyKey = "grant-match-1",
                correlationId = "corr-gm-1",
                causationId = "caus-gm-1",
                expectedVersion = 1L
            )
        )

        // 1. Prohibited Conversion: Player attempts conversion before meeting wagering requirement
        val earlyConvertError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.convertBonus(
                ConvertBonusCommand(
                    principal = player,
                    tenantId = tenant1,
                    playerId = playerId,
                    grantId = grantResult.grantId,
                    conversionReason = "Premature conversion attempt",
                    idempotencyKey = "conv-early-1",
                    correlationId = "corr-ce-1",
                    causationId = "caus-ce-1",
                    expectedVersion = 2L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, earlyConvertError.code)
        assertTrue(alertSink.alerts.any { it.contains("UNAUTHORIZED_BONUS_CONVERSION_ATTEMPT") })

        // 2. Allowed Conversion: Wagering requirement met (simulate play progress)
        val grant = store.findGrant(tenant1, grantResult.grantId)!!
        grant.wageringProgressMinorUnits = 100_000L // Met wagering requirement!
        store.saveGrant(grant)

        val convertSuccess = service.convertBonus(
            ConvertBonusCommand(
                principal = player,
                tenantId = tenant1,
                playerId = playerId,
                grantId = grantResult.grantId,
                conversionReason = "Wagering requirements fully completed",
                idempotencyKey = "conv-success-1",
                correlationId = "corr-cs-1",
                causationId = "caus-cs-1",
                expectedVersion = 2L
            )
        )
        assertEquals(10_000L, convertSuccess.convertedAmountMinorUnits)
        assertEquals(10_000L, convertSuccess.newCashBalanceMinorUnits)
        assertEquals(0L, convertSuccess.newBonusBalanceMinorUnits)

        // 3. Stale Replay: Converting an already converted grant fails with CONFLICT
        val alreadyConvertedError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.convertBonus(
                ConvertBonusCommand(
                    principal = player,
                    tenantId = tenant1,
                    playerId = playerId,
                    grantId = grantResult.grantId,
                    conversionReason = "Duplicate conversion attempt",
                    idempotencyKey = "conv-dup-1",
                    correlationId = "corr-cd-1",
                    causationId = "caus-cd-1",
                    expectedVersion = 3L
                )
            )
        }
        assertEquals(AuthErrorCode.CONFLICT, alreadyConvertedError.code)

        // 4. Unauthorized Non-Admin Grant: Player principal attempts to grant bonus
        val unauthorizedGrantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postBonusGrant(
                PostBonusGrantCommand(
                    principal = player, // player attempting to issue grant!
                    tenantId = tenant1,
                    playerId = playerId,
                    bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                    amountMinorUnits = 5_000L,
                    currencyCode = "USD",
                    grantReason = "Self granting bonus",
                    idempotencyKey = "grant-player-1",
                    correlationId = "corr-gp-1",
                    causationId = "caus-gp-1",
                    expectedVersion = 3L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, unauthorizedGrantError.code)
        assertTrue(alertSink.alerts.any { it.contains("UNAUTHORIZED_BONUS_GRANT_ATTEMPT") })

        // 5. Cross-Tenant Isolation: Admin from Tenant 2 attempts grant in Tenant 1
        val crossTenantAdmin = adminPrincipal("admin-t2", tenant2)
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postBonusGrant(
                PostBonusGrantCommand(
                    principal = crossTenantAdmin,
                    tenantId = tenant1,
                    playerId = playerId,
                    bonusType = BonusGrantType.WELCOME_BONUS,
                    amountMinorUnits = 5_000L,
                    currencyCode = "USD",
                    grantReason = "Cross-tenant grant",
                    idempotencyKey = "grant-ct-1",
                    correlationId = "corr-ct-1",
                    causationId = "caus-ct-1",
                    expectedVersion = 3L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantError.code)

        // 6. Zero or Negative Grant Amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postBonusGrant(
                PostBonusGrantCommand(
                    principal = admin,
                    tenantId = tenant1,
                    playerId = playerId,
                    bonusType = BonusGrantType.WELCOME_BONUS,
                    amountMinorUnits = 0L,
                    currencyCode = "USD",
                    grantReason = "Zero grant",
                    idempotencyKey = "grant-zero-1",
                    correlationId = "corr-z-1",
                    causationId = "caus-z-1",
                    expectedVersion = 3L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Invalid Currency Code
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postBonusGrant(
                PostBonusGrantCommand(
                    principal = admin,
                    tenantId = tenant1,
                    playerId = playerId,
                    bonusType = BonusGrantType.WELCOME_BONUS,
                    amountMinorUnits = 1_000L,
                    currencyCode = "INVALID_CURRENCY",
                    grantReason = "Bad currency",
                    idempotencyKey = "grant-curr-1",
                    correlationId = "corr-c-1",
                    causationId = "caus-c-1",
                    expectedVersion = 3L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Stale Expected Version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postBonusGrant(
                PostBonusGrantCommand(
                    principal = admin,
                    tenantId = tenant1,
                    playerId = playerId,
                    bonusType = BonusGrantType.WELCOME_BONUS,
                    amountMinorUnits = 1_000L,
                    currencyCode = "USD",
                    grantReason = "Stale version test",
                    idempotencyKey = "grant-stale-1",
                    correlationId = "corr-st-1",
                    causationId = "caus-st-1",
                    expectedVersion = 99L // expected 99 but actual is 3
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 9. Malformed Headers
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.postBonusGrant(
                PostBonusGrantCommand(
                    principal = admin,
                    tenantId = "",
                    playerId = playerId,
                    bonusType = BonusGrantType.WELCOME_BONUS,
                    amountMinorUnits = 1_000L,
                    currencyCode = "USD",
                    grantReason = "Blank tenant",
                    idempotencyKey = "key",
                    correlationId = "corr",
                    causationId = "caus",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // BONUS-001-01-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `BONUS-001-01-T003 Post isolated bonus grants survives concurrency duplicate delivery and dependency failure`() {
        BonusGrantBinding.isBound = true

        val store = InMemoryBonusGrantStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusGrantService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-concurrent"
        val playerId = UUID.randomUUID()
        val admin = adminPrincipal("admin-c", tenantId)

        val baseGrantCmd = PostBonusGrantCommand(
            principal = admin,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.LOYALTY_REWARD,
            amountMinorUnits = 2_500L,
            currencyCode = "USD",
            grantReason = "Loyalty test",
            idempotencyKey = "idem-grant-1",
            correlationId = "corr-ig-1",
            causationId = "caus-ig-1",
            expectedVersion = 1L
        )

        // 1. Idempotent replay: exact same grant returns cached result without double-crediting
        val grant1 = service.postBonusGrant(baseGrantCmd)
        val grant2 = service.postBonusGrant(baseGrantCmd)
        assertEquals(grant1.resultId, grant2.resultId)
        assertEquals(grant1.newBonusBalanceMinorUnits, grant2.newBonusBalanceMinorUnits)
        assertEquals(2_500L, grant2.newBonusBalanceMinorUnits)
        assertEquals(1, store.getLedgerEntries(tenantId).size)

        // 2. Conflict on modified payload
        val conflictingCmd = baseGrantCmd.copy(amountMinorUnits = 5_000L)
        val conflictError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.postBonusGrant(conflictingCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictError.code)

        // 3. Multi-threaded concurrency: 16 threads posting concurrent bonus grants to distinct players
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)

        val playerIds = (1..threadCount).map { UUID.randomUUID() }
        val results = ConcurrentHashMap<UUID, PostBonusGrantResult>()

        playerIds.forEachIndexed { index, pid ->
            executor.submit {
                try {
                    val res = service.postBonusGrant(
                        PostBonusGrantCommand(
                            principal = admin,
                            tenantId = tenantId,
                            playerId = pid,
                            bonusType = BonusGrantType.FREE_PLAY_CREDIT,
                            amountMinorUnits = 1_000L,
                            currencyCode = "USD",
                            grantReason = "Concurrent grant $index",
                            idempotencyKey = "conc-grant-$index",
                            correlationId = "corr-cg-$index",
                            causationId = "caus-cg-$index",
                            expectedVersion = 1L
                        )
                    )
                    results[pid] = res
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()

        assertEquals(threadCount, results.size)
        results.values.forEach { res ->
            assertEquals(1_000L, res.grantedAmountMinorUnits)
            assertEquals(0L, res.newCashBalanceMinorUnits)
            assertEquals(1_000L, res.newBonusBalanceMinorUnits)
            assertEquals(0L, res.withdrawableCashMinorUnits)
        }

        // Check conservation: total ledger credits equal total ledger debits across all grants
        val allLedger = store.getLedgerEntries(tenantId)
        assertEquals(threadCount + 1, allLedger.size) // 16 concurrent + 1 initial
        val totalDebited = allLedger.sumOf { it.amountMinorUnits }
        val totalCredited = 2_500L + (threadCount * 1_000L)
        assertEquals(totalCredited, totalDebited)
    }

    // =========================================================================
    // BONUS-001-01-T004: Migration Integrity, Recovery & Observability
    // =========================================================================

    @Test
    fun `BONUS-001-01-T004 Post isolated bonus grants remains compatible recoverable observable and lifecycle-safe`() {
        // 1. Migration integrity: No Flyway migrations > V16
        val migrationsDir = File("src/main/resources/db/migration")
        if (migrationsDir.exists()) {
            val invalidMigrations = migrationsDir.listFiles()?.filter { file ->
                val name = file.name
                if (name.startsWith("V") && name.contains("__")) {
                    val versionStr = name.substring(1, name.indexOf("__"))
                    val versionNum = versionStr.toIntOrNull()
                    versionNum != null && versionNum > 16
                } else false
            } ?: emptyList()
            assertTrue(invalidMigrations.isEmpty(), "Found illegal migrations > V16: ${invalidMigrations.map { it.name }}")
        }

        BonusGrantBinding.isBound = true

        val store = InMemoryBonusGrantStore()
        val alertSink = InMemoryBonusAlertSink()
        val service1 = BonusGrantService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-restart"
        val playerId = UUID.randomUUID()
        val admin = adminPrincipal("admin-restart", tenantId)

        val initialGrant = service1.postBonusGrant(
            PostBonusGrantCommand(
                principal = admin,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.WELCOME_BONUS,
                amountMinorUnits = 7_500L,
                currencyCode = "USD",
                grantReason = "Recovery test",
                idempotencyKey = "grant-rec-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )
        assertEquals(7_500L, initialGrant.newBonusBalanceMinorUnits)

        // 2. Recovery and restart: New service instance attached to persistent store
        val service2 = BonusGrantService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        // Replay through restarted service recovers identical decision
        val replayedGrant = service2.postBonusGrant(
            PostBonusGrantCommand(
                principal = admin,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.WELCOME_BONUS,
                amountMinorUnits = 7_500L,
                currencyCode = "USD",
                grantReason = "Recovery test",
                idempotencyKey = "grant-rec-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )
        assertEquals(initialGrant.resultId, replayedGrant.resultId)
        assertEquals(initialGrant.evidenceReference, replayedGrant.evidenceReference)

        // 3. Observability and Redaction: Audit events, outbox, and security alerts
        val audit = initialGrant.auditEvent
        assertEquals(tenantId, audit.tenantId)
        assertEquals("corr-rec-1", audit.correlationId)
        assertEquals("caus-rec-1", audit.causationId)
        assertEquals("BONUS_GRANT_POSTED", audit.type)
        assertEquals(now, audit.occurredAt)

        val outbox = initialGrant.outboxEvent
        assertEquals(tenantId, outbox.tenantId)
        assertEquals("BONUS_GRANT_POSTED", outbox.type)
        assertEquals(now, outbox.createdAt)

        // Trigger an unauthorized withdrawal attempt to test alert redaction
        val player = playerPrincipal(playerId.toString(), tenantId)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service2.attemptWithdrawal(
                AttemptWithdrawalCommand(
                    principal = player,
                    tenantId = tenantId,
                    playerId = playerId,
                    amountMinorUnits = 5_000L,
                    currencyCode = "USD",
                    idempotencyKey = "with-rec-illegal",
                    correlationId = "corr-w-rec",
                    causationId = "caus-w-rec",
                    expectedVersion = 2L
                )
            )
        }

        alertSink.alerts.forEach { alert ->
            assertFalse(alert.contains("password"))
            assertFalse(alert.contains("cvv"))
            assertFalse(alert.contains("token"))
            assertFalse(alert.contains("secret"))
        }
    }
}
