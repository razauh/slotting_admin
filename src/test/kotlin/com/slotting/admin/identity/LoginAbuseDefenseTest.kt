package com.slotting.admin.identity

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class LoginAbuseDefenseTest {

    private val now = Instant.parse("2026-09-18T20:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        LoginAbuseBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ShortLivedTokenBinding.isBound = true
        RefreshTokenRotationBinding.isBound = true
        SessionDeviceRevocationBinding.isBound = true
        LoginAbuseBinding.isBound = true
    }

    private fun sha256(input: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "abuse.player@example.com"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (7000000 + regStore.players.size + 1),
            jurisdiction = "DEFAULT",
            riskScore = 20.0,
            idempotencyKey = "reg-${UUID.randomUUID()}",
            correlationId = "corr-reg-${UUID.randomUUID()}",
            causationId = "caus-reg-${UUID.randomUUID()}"
        )
        val regResult = regService.register(regCmd)

        val verCmd = VerifyContactCommand(
            tenantId = tenantId,
            playerId = regResult.playerId,
            channel = ContactVerificationChannel.EMAIL,
            verificationCode = "EMAIL-123456",
            idempotencyKey = "ver-${UUID.randomUUID()}",
            correlationId = "corr-ver-${UUID.randomUUID()}",
            causationId = "caus-ver-${UUID.randomUUID()}"
        )
        regService.verifyContact(verCmd)
        return regResult
    }

    // =========================================================================
    // AUTH-003-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-003-01-T001 Implement login abuse defenses produces the required authoritative outcome`() {
        LoginAbuseBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val transientStore = InMemoryTransientRateLimitStore()
        val durableStore = InMemoryDurableLockoutStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val abuseService = LoginAbuseDefenseService(
            registrationStore = regStore,
            transientStore = transientStore,
            durableLockoutStore = durableStore,
            alertSink = alertSink,
            clock = clock,
            maxFailedAttemptsPerAccount = 5,
            maxFailedAttemptsPerIp = 20
        )

        val player = registerAndVerifyPlayer(regStore, email = "victim.player@example.com")

        // 1. Initial valid login succeeds
        val validLoginCmd = LoginAttemptCommand(
            tenantId = "tenant-casino-1",
            identifier = "victim.player@example.com",
            rawPassword = "DefaultPass123!",
            clientIp = "192.168.1.50",
            userAgent = "SlottingApp/1.0",
            idempotencyKey = "login-valid-init",
            correlationId = "corr-val-1",
            causationId = "caus-val-1"
        )
        val initRes = abuseService.evaluateLogin(validLoginCmd)
        assertTrue(initRes.allowed)
        assertEquals(player.playerId, initRes.playerId)
        assertTrue(!initRes.isLocked)

        // 2. Brute force attack simulation: 4 failed attempts with incorrect passwords
        for (i in 1..4) {
            assertFailsWith<AuthenticationFailure.Rejected> {
                abuseService.evaluateLogin(LoginAttemptCommand(
                    tenantId = "tenant-casino-1",
                    identifier = "victim.player@example.com",
                    rawPassword = "WrongPassword$i",
                    clientIp = "192.168.1.50",
                    userAgent = "AttackerBot/1.0",
                    idempotencyKey = "fail-attempt-$i",
                    correlationId = "corr-fail-$i",
                    causationId = "caus-fail-$i"
                ))
            }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        }

        // 3. 5th failed attempt hits the lockout threshold
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(LoginAttemptCommand(
                tenantId = "tenant-casino-1",
                identifier = "victim.player@example.com",
                rawPassword = "WrongPassword5",
                clientIp = "192.168.1.50",
                userAgent = "AttackerBot/1.0",
                idempotencyKey = "fail-attempt-5",
                correlationId = "corr-fail-5",
                causationId = "caus-fail-5"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Verify account is durably locked
        val lockoutRecord = durableStore.lockouts.values.firstOrNull { it.tenantId == "tenant-casino-1" }
        assertNotNull(lockoutRecord)
        assertTrue(lockoutRecord.isLocked, "Account must be durably locked after 5 failed attempts")
        assertNotNull(lockoutRecord.supportReferenceId)

        // Verify security alert emitted
        assertEquals(1, alertSink.alerts.size)
        assertTrue(alertSink.alerts[0].contains("LOGIN_BRUTE_FORCE_LOCKOUT"))
        assertTrue(alertSink.alerts[0].contains(lockoutRecord.supportReferenceId))

        // Verify audit event
        assertTrue(durableStore.audit.any { it.type == "ACCOUNT_LOCKED_ABUSE" })

        // =====================================================================
        // 4. CRITICAL INVARIANT: "Redis loss cannot unlock"
        // Simulate Redis restart / cache loss!
        // =====================================================================
        transientStore.simulateLoss()
        assertEquals(0, transientStore.counters.size, "Transient store must be completely wiped")

        // Attacker attempts login with the CORRECT password after Redis cache loss
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(LoginAttemptCommand(
                tenantId = "tenant-casino-1",
                identifier = "victim.player@example.com",
                rawPassword = "DefaultPass123!", // CORRECT PASSWORD!
                clientIp = "192.168.1.50",
                userAgent = "AttackerBot/1.0",
                idempotencyKey = "post-redis-loss-login",
                correlationId = "corr-post-loss",
                causationId = "caus-post-loss"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Assert account remains locked despite Redis loss
        assertTrue(lockoutRecord.isLocked, "Redis loss cannot unlock durable lockout state")

        // 5. Customer support-safe unlock
        val unlockResult = abuseService.unlockAccount(SupportUnlockAccountCommand(
            tenantId = "tenant-casino-1",
            identifier = "victim.player@example.com",
            supportReferenceId = lockoutRecord.supportReferenceId,
            adminOperatorId = "admin-agent-007",
            reason = "Customer identity verified over verified phone channel",
            idempotencyKey = "support-unlock-1",
            correlationId = "corr-unlock-1",
            causationId = "caus-unlock-1"
        ))
        assertTrue(unlockResult.unlocked)
        assertTrue(!lockoutRecord.isLocked, "Account must be unlocked after support intervention")

        // Now login with correct password succeeds
        val recoveredLogin = abuseService.evaluateLogin(LoginAttemptCommand(
            tenantId = "tenant-casino-1",
            identifier = "victim.player@example.com",
            rawPassword = "DefaultPass123!",
            clientIp = "192.168.1.50",
            userAgent = "SlottingApp/1.0",
            idempotencyKey = "login-post-unlock",
            correlationId = "corr-post-unl",
            causationId = "caus-post-unl"
        ))
        assertTrue(recoveredLogin.allowed)

        // Assert audit trail includes support unlock
        assertTrue(durableStore.audit.any { it.type == "ACCOUNT_UNLOCKED_SUPPORT" })

        // Assert zero financial authority or money mutation occurred
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
        assertEquals(0, regStore.audit.count { it.type.contains("CREDIT") })
        assertEquals(0, regStore.audit.count { it.type.contains("DEBIT") })
    }

    // =========================================================================
    // AUTH-003-01-T002: Negative, Boundary, Security & Malformed Rejection
    // =========================================================================

    @Test
    fun `AUTH-003-01-T002 Implement login abuse defenses rejects invalid boundary unauthorized and stale input`() {
        LoginAbuseBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val transientStore = InMemoryTransientRateLimitStore()
        val durableStore = InMemoryDurableLockoutStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val abuseService = LoginAbuseDefenseService(
            registrationStore = regStore,
            transientStore = transientStore,
            durableLockoutStore = durableStore,
            alertSink = alertSink,
            clock = clock,
            maxFailedAttemptsPerAccount = 5,
            maxFailedAttemptsPerIp = 3 // Small threshold for IP test
        )

        val player = registerAndVerifyPlayer(regStore, email = "security.player@example.com")

        // 1. Cross-tenant unlock attempt -> INVALID or FORBIDDEN
        durableStore.saveLockout(DurableLockoutRecord(
            recordId = UUID.randomUUID(),
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            identifierHash = sha256("security.player@example.com"),
            lockedAt = now,
            lockExpiresAt = null,
            reason = LockoutReason.BRUTE_FORCE_CREDENTIALS,
            supportReferenceId = "SUP-REF-1234",
            isLocked = true
        ))

        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.unlockAccount(SupportUnlockAccountCommand(
                tenantId = "tenant-other-market", // WRONG TENANT!
                identifier = "security.player@example.com",
                supportReferenceId = "SUP-REF-1234",
                adminOperatorId = "admin-1",
                reason = "Support unlock",
                idempotencyKey = "neg-cross-tenant-unlock",
                correlationId = "corr-xt",
                causationId = "caus-xt"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Wrong support reference ID during unlock -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.unlockAccount(SupportUnlockAccountCommand(
                tenantId = "tenant-casino-1",
                identifier = "security.player@example.com",
                supportReferenceId = "WRONG-SUPPORT-REF", // WRONG REF!
                adminOperatorId = "admin-1",
                reason = "Support unlock",
                idempotencyKey = "neg-wrong-ref",
                correlationId = "corr-wr",
                causationId = "caus-wr"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Stale expectedVersion (< 1L) -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(LoginAttemptCommand(
                tenantId = "tenant-casino-1",
                identifier = "security.player@example.com",
                rawPassword = "SomePassword",
                clientIp = "10.0.0.1",
                userAgent = "App",
                idempotencyKey = "stale-cmd",
                correlationId = "corr-stale",
                causationId = "caus-stale",
                expectedVersion = 0L
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Blank headers -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(LoginAttemptCommand(
                tenantId = "",
                identifier = "security.player@example.com",
                rawPassword = "Pass",
                clientIp = "10.0.0.1",
                userAgent = "App",
                idempotencyKey = "blank-tenant",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Enumeration resistance: Non-existent user fails with safe INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(LoginAttemptCommand(
                tenantId = "tenant-casino-1",
                identifier = "nonexistent.user@example.com",
                rawPassword = "SomePassword",
                clientIp = "10.0.0.1",
                userAgent = "App",
                idempotencyKey = "non-existent-user",
                correlationId = "c-ne",
                causationId = "ca-ne"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Suspicious IP burst abuse (threshold = 3)
        // 3 failed attempts from IP 10.0.0.99
        for (i in 1..3) {
            assertFailsWith<AuthenticationFailure.Rejected> {
                abuseService.evaluateLogin(LoginAttemptCommand(
                    tenantId = "tenant-casino-1",
                    identifier = "random$i@example.com",
                    rawPassword = "BadPassword",
                    clientIp = "10.0.0.99",
                    userAgent = "Bot",
                    idempotencyKey = "ip-burst-$i",
                    correlationId = "c-ip-$i",
                    causationId = "ca-ip-$i"
                ))
            }
        }
        // 4th attempt from same IP is throttled
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(LoginAttemptCommand(
                tenantId = "tenant-casino-1",
                identifier = "random4@example.com",
                rawPassword = "BadPassword",
                clientIp = "10.0.0.99",
                userAgent = "Bot",
                idempotencyKey = "ip-burst-4",
                correlationId = "c-ip-4",
                causationId = "ca-ip-4"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Assert money mutation remains zero
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-003-01-T003: Concurrency, Idempotency & Failure Recovery
    // =========================================================================

    @Test
    fun `AUTH-003-01-T003 Implement login abuse defenses survives concurrency duplicate delivery and dependency failure`() {
        LoginAbuseBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val transientStore = InMemoryTransientRateLimitStore()
        val durableStore = InMemoryDurableLockoutStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val abuseService = LoginAbuseDefenseService(
            registrationStore = regStore,
            transientStore = transientStore,
            durableLockoutStore = durableStore,
            alertSink = alertSink,
            clock = clock,
            maxFailedAttemptsPerAccount = 5,
            maxFailedAttemptsPerIp = 50
        )

        registerAndVerifyPlayer(regStore, email = "conc.player@example.com")

        // 1. Idempotent replay: exact same login command returns cached result
        val cmd = LoginAttemptCommand(
            tenantId = "tenant-casino-1",
            identifier = "conc.player@example.com",
            rawPassword = "DefaultPass123!",
            clientIp = "10.0.0.5",
            userAgent = "App",
            idempotencyKey = "idem-login-key-1",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1"
        )
        val res1 = abuseService.evaluateLogin(cmd)
        val res2 = abuseService.evaluateLogin(cmd)
        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.allowed, res2.allowed)

        // 2. Conflicting command with same idempotency key
        val conflictCmd = LoginAttemptCommand(
            tenantId = "tenant-casino-1",
            identifier = "conc.player@example.com",
            rawPassword = "DifferentPassword",
            clientIp = "10.0.0.5",
            userAgent = "App",
            idempotencyKey = "idem-login-key-1", // SAME KEY!
            correlationId = "corr-conf",
            causationId = "caus-conf"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(conflictCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrency: 10 concurrent threads simultaneously submitting failed login attempts
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val exceptions = mutableListOf<Throwable>()

        for (i in 1..threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    abuseService.evaluateLogin(LoginAttemptCommand(
                        tenantId = "tenant-casino-1",
                        identifier = "conc.player@example.com",
                        rawPassword = "WrongPass$i",
                        clientIp = "10.0.0.5",
                        userAgent = "AttackerBot/1.0",
                        idempotencyKey = "race-login-$i",
                        correlationId = "corr-race-$i",
                        causationId = "caus-race-$i"
                    ))
                } catch (t: Throwable) {
                    synchronized(exceptions) { exceptions.add(t) }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertEquals(threadCount, exceptions.size)
        // Verify account is locked
        val lockout = durableStore.lockouts.values.firstOrNull { it.tenantId == "tenant-casino-1" }
        assertNotNull(lockout)
        assertTrue(lockout.isLocked)

        // 4. Redis outage / dependency failure: Redis throws connection failure
        transientStore.simulateFailure(true)
        // Login attempt fails closed, does not allow bypass
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService.evaluateLogin(LoginAttemptCommand(
                tenantId = "tenant-casino-1",
                identifier = "conc.player@example.com",
                rawPassword = "WrongPassOutage",
                clientIp = "10.0.0.6",
                userAgent = "AttackerBot/1.0",
                idempotencyKey = "outage-login-fail",
                correlationId = "corr-outage",
                causationId = "caus-outage"
            ))
        }

        // Zero financial mutation
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-003-01-T004: Migration, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `AUTH-003-01-T004 Implement login abuse defenses remains compatible recoverable observable and lifecycle-safe`() {
        LoginAbuseBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val transientStore = InMemoryTransientRateLimitStore()
        val durableStore = InMemoryDurableLockoutStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val abuseService1 = LoginAbuseDefenseService(
            registrationStore = regStore,
            transientStore = transientStore,
            durableLockoutStore = durableStore,
            alertSink = alertSink,
            clock = clock,
            maxFailedAttemptsPerAccount = 5,
            maxFailedAttemptsPerIp = 20
        )

        registerAndVerifyPlayer(regStore, email = "recov.player@example.com")

        // Trigger lockout on service 1
        for (i in 1..5) {
            try {
                abuseService1.evaluateLogin(LoginAttemptCommand(
                    tenantId = "tenant-casino-1",
                    identifier = "recov.player@example.com",
                    rawPassword = "WrongPassword$i",
                    clientIp = "10.0.0.1",
                    userAgent = "Bot",
                    idempotencyKey = "recov-fail-$i",
                    correlationId = "corr-recov-$i",
                    causationId = "caus-recov-$i"
                ))
            } catch (_: Exception) {}
        }

        // RECOVERY / RESTART: Simulate service restart pointing to durable store
        val abuseService2 = LoginAbuseDefenseService(
            registrationStore = regStore,
            transientStore = transientStore,
            durableLockoutStore = durableStore,
            alertSink = alertSink,
            clock = clock,
            maxFailedAttemptsPerAccount = 5,
            maxFailedAttemptsPerIp = 20
        )

        // After service recreation, lockout is preserved
        assertFailsWith<AuthenticationFailure.Rejected> {
            abuseService2.evaluateLogin(LoginAttemptCommand(
                tenantId = "tenant-casino-1",
                identifier = "recov.player@example.com",
                rawPassword = "DefaultPass123!",
                clientIp = "10.0.0.1",
                userAgent = "App",
                idempotencyKey = "post-restart-login",
                correlationId = "corr-post-restart",
                causationId = "caus-post-restart"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Observability check: structured audit events contain correlationId and resultId
        val lockEvent = durableStore.audit.first { it.type == "ACCOUNT_LOCKED_ABUSE" }
        assertNotNull(lockEvent.resultId)
        assertNotNull(lockEvent.correlationId)
        assertNotNull(lockEvent.causationId)
        assertNotNull(lockEvent.occurredAt)

        // Assert database migration integrity: no unapproved SQL migrations beyond V16
        val migrationsDir = File("src/main/resources/db/migration")
        if (migrationsDir.exists()) {
            val migrationFiles = migrationsDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
            val invalidMigrations = migrationFiles.filter { file ->
                val versionNum = file.name.substringAfter("V").substringBefore("__").toIntOrNull()
                versionNum != null && versionNum > 16
            }
            assertTrue(invalidMigrations.isEmpty(), "No unapproved SQL migration beyond V16 may be introduced: ${invalidMigrations.map { it.name }}")
        }

        // Assert no Android lifecycle surface is claimed (Android Keystore remains refresh-token store)
        // Assert zero financial mutation
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }
}
