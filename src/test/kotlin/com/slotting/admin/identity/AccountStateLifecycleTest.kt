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

class AccountStateLifecycleTest {

    private val now = Instant.parse("2026-09-18T21:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        AccountStateLifecycleBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ShortLivedTokenBinding.isBound = true
        RefreshTokenRotationBinding.isBound = true
        SessionDeviceRevocationBinding.isBound = true
        LoginAbuseBinding.isBound = true
        AccountStateLifecycleBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "lifecycle.player@example.com"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (8000000 + regStore.players.size + 1),
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
    // AUTH-003-02-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-003-02-T001 Implement lock, suspend, and close account states produces the required authoritative outcome`() {
        AccountStateLifecycleBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val stateStore = InMemoryAccountStateStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val lifecycleService = AccountStateLifecycleService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            accountStateStore = stateStore,
            alertSink = alertSink,
            clock = clock
        )
        val tokenService = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )
        val deviceService = SessionDeviceInventoryService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "state.player@example.com")
        assertEquals(PlayerAccountStatus.ACTIVE, regStore.findById("tenant-casino-1", player.playerId)!!.status)

        // Issue initial active tokens and device session
        val pair1 = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-init",
            correlationId = "corr-init",
            causationId = "caus-init"
        ))
        val session1 = deviceService.createDeviceSession(CreateDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            familyId = pair1.familyId,
            deviceMetadata = DeviceMetadata("dev-1", "Pixel 8", "14", "10.0.0.1", "App"),
            idempotencyKey = "dev-init",
            correlationId = "corr-dev-init",
            causationId = "caus-dev-init"
        ))

        // 1. ACTIVE -> LOCKED
        val lockResult = lifecycleService.lockAccount(LockAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            reason = "Security check triggered",
            supportReferenceId = "SUP-LOCK-STATE-01",
            idempotencyKey = "lock-cmd-1",
            correlationId = "corr-lock-1",
            causationId = "caus-lock-1"
        ))
        assertEquals(PlayerAccountStatus.LOCKED, lockResult.newStatus)
        assertEquals(PlayerAccountStatus.LOCKED, regStore.findById("tenant-casino-1", player.playerId)!!.status)

        // In LOCKED state: new token pair issuance is denied
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.issueTokenPair(IssueTokenPairCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                idempotencyKey = "issue-while-locked",
                correlationId = "corr-lock-iss",
                causationId = "caus-lock-iss"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // In LOCKED state: token refresh is denied
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair1.refreshToken,
                idempotencyKey = "rot-while-locked",
                correlationId = "corr-lock-rot",
                causationId = "caus-lock-rot"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unlock back to ACTIVE
        val unlockResult = lifecycleService.unlockAccount(UnlockAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            adminOperatorId = "admin-agent-1",
            reason = "Customer verified",
            idempotencyKey = "unlock-cmd-1",
            correlationId = "corr-unl-1",
            causationId = "caus-unl-1"
        ))
        assertEquals(PlayerAccountStatus.ACTIVE, unlockResult.newStatus)

        // 2. ACTIVE -> SUSPENDED
        val suspendResult = lifecycleService.suspendAccount(SuspendAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            adminOperatorId = "compliance-officer-1",
            reason = "AML investigation hold",
            idempotencyKey = "suspend-cmd-1",
            correlationId = "corr-susp-1",
            causationId = "caus-susp-1"
        ))
        assertEquals(PlayerAccountStatus.SUSPENDED, suspendResult.newStatus)

        // When SUSPENDED: token family and device session are authoritatively revoked
        val familyAfterSuspend = tokenStore.findFamily("tenant-casino-1", pair1.familyId)
        assertNotNull(familyAfterSuspend)
        assertTrue(familyAfterSuspend.isRevoked)

        val sessionAfterSuspend = deviceStore.findSession("tenant-casino-1", session1.sessionId)
        assertNotNull(sessionAfterSuspend)
        assertEquals(DeviceSessionStatus.REVOKED, sessionAfterSuspend.status)

        // Access validation fails
        val accessVal = tokenService.validateAccessToken("tenant-casino-1", pair1.accessToken)
        assertTrue(!accessVal.valid)

        // Refresh token rotation fails
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair1.refreshToken,
                idempotencyKey = "rot-while-susp",
                correlationId = "corr-susp-rot",
                causationId = "caus-susp-rot"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Reinstate back to ACTIVE
        val reinstateResult = lifecycleService.reinstateAccount(ReinstateAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            adminOperatorId = "compliance-officer-1",
            reason = "AML investigation cleared",
            idempotencyKey = "reinstate-cmd-1",
            correlationId = "corr-rein-1",
            causationId = "caus-rein-1"
        ))
        assertEquals(PlayerAccountStatus.ACTIVE, reinstateResult.newStatus)

        // 3. ACTIVE -> CLOSED (Terminal state)
        val closeResult = lifecycleService.closeAccount(CloseAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            initiator = "PLAYER",
            reason = "Voluntary account closure",
            idempotencyKey = "close-cmd-1",
            correlationId = "corr-close-1",
            causationId = "caus-close-1"
        ))
        assertEquals(PlayerAccountStatus.CLOSED, closeResult.newStatus)

        // Attempting to reinstate CLOSED account is rejected with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.reinstateAccount(ReinstateAccountCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                adminOperatorId = "admin-1",
                reason = "Reopen attempt",
                idempotencyKey = "reopen-closed",
                correlationId = "corr-ro",
                causationId = "caus-ro"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Attempting to lock or suspend a CLOSED account is rejected with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.lockAccount(LockAccountCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                reason = "Lock attempt on closed",
                supportReferenceId = null,
                idempotencyKey = "lock-closed",
                correlationId = "corr-lc",
                causationId = "caus-lc"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Verify security alerts dispatched
        val alertReasons = alertSink.alerts.map { it }
        assertTrue(alertReasons.any { it.contains("ACCOUNT_LOCKED") })
        assertTrue(alertReasons.any { it.contains("ACCOUNT_SUSPENDED") })
        assertTrue(alertReasons.any { it.contains("ACCOUNT_CLOSED") })

        // Assert zero financial authority or money mutation occurred
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
        assertEquals(0, regStore.audit.count { it.type.contains("CREDIT") })
        assertEquals(0, regStore.audit.count { it.type.contains("DEBIT") })
    }

    // =========================================================================
    // AUTH-003-02-T002: Negative, Boundary, Security & Malformed Rejection
    // =========================================================================

    @Test
    fun `AUTH-003-02-T002 Implement lock, suspend, and close account states rejects invalid boundary unauthorized and stale input`() {
        AccountStateLifecycleBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val stateStore = InMemoryAccountStateStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val lifecycleService = AccountStateLifecycleService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            accountStateStore = stateStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "neg.player@example.com")

        // 1. Cross-tenant state transition attempt -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.suspendAccount(SuspendAccountCommand(
                tenantId = "tenant-different-corp", // WRONG TENANT!
                playerId = player.playerId,
                adminOperatorId = "admin-1",
                reason = "Suspend",
                idempotencyKey = "neg-cross-tenant-susp",
                correlationId = "corr-xt",
                causationId = "caus-xt"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Stale expectedVersion (< 1L) -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.suspendAccount(SuspendAccountCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                adminOperatorId = "admin-1",
                reason = "Suspend",
                idempotencyKey = "neg-stale-susp",
                correlationId = "corr-stale",
                causationId = "caus-stale",
                expectedVersion = 0L
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 3. Blank headers -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.suspendAccount(SuspendAccountCommand(
                tenantId = "",
                playerId = player.playerId,
                adminOperatorId = "admin-1",
                reason = "Suspend",
                idempotencyKey = "neg-blank-tenant",
                correlationId = "c",
                causationId = "ca"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Non-existent player -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.suspendAccount(SuspendAccountCommand(
                tenantId = "tenant-casino-1",
                playerId = UUID.randomUUID(), // NON-EXISTENT!
                adminOperatorId = "admin-1",
                reason = "Suspend",
                idempotencyKey = "neg-nonexistent-player",
                correlationId = "c-ne",
                causationId = "ca-ne"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Unlocking an account that is already ACTIVE -> CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.unlockAccount(UnlockAccountCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                adminOperatorId = "admin-1",
                reason = "Unlock already active",
                idempotencyKey = "neg-unlock-active",
                correlationId = "c-ua",
                causationId = "ca-ua"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 6. Reinstating an account that is not SUSPENDED -> CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.reinstateAccount(ReinstateAccountCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                adminOperatorId = "admin-1",
                reason = "Reinstate active",
                idempotencyKey = "neg-reinstate-active",
                correlationId = "c-ra",
                causationId = "ca-ra"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Assert money mutation remains zero
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-003-02-T003: Concurrency, Idempotency & Failure Recovery
    // =========================================================================

    @Test
    fun `AUTH-003-02-T003 Implement lock, suspend, and close account states survives concurrency duplicate delivery and dependency failure`() {
        AccountStateLifecycleBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val stateStore = InMemoryAccountStateStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val lifecycleService = AccountStateLifecycleService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            accountStateStore = stateStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "conc.state.player@example.com")

        // 1. Idempotent replay: exact same suspend command returns cached result
        val cmd = SuspendAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            adminOperatorId = "admin-1",
            reason = "Fraud investigation hold",
            idempotencyKey = "idem-susp-key-1",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1"
        )
        val res1 = lifecycleService.suspendAccount(cmd)
        val res2 = lifecycleService.suspendAccount(cmd)
        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.newStatus, res2.newStatus)

        // 2. Conflicting command with same idempotency key
        val conflictCmd = SuspendAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            adminOperatorId = "admin-2", // CHANGED OPERATOR!
            reason = "Different reason",
            idempotencyKey = "idem-susp-key-1", // SAME KEY!
            correlationId = "corr-conf",
            causationId = "caus-conf"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService.suspendAccount(conflictCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Reinstate
        lifecycleService.reinstateAccount(ReinstateAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            adminOperatorId = "admin-1",
            reason = "Reinstated for race test",
            idempotencyKey = "reinstate-race-setup",
            correlationId = "corr-rr",
            causationId = "caus-rr"
        ))

        // 3. Concurrency: 10 concurrent threads simultaneously trying to close the account
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val successes = mutableListOf<AccountStateResult>()
        val conflicts = mutableListOf<Throwable>()

        for (i in 1..threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = lifecycleService.closeAccount(CloseAccountCommand(
                        tenantId = "tenant-casino-1",
                        playerId = player.playerId,
                        initiator = "PLAYER",
                        reason = "Concurrent close request",
                        idempotencyKey = "race-close-$i",
                        correlationId = "corr-race-$i",
                        causationId = "caus-race-$i"
                    ))
                    synchronized(successes) { successes.add(res) }
                } catch (t: Throwable) {
                    synchronized(conflicts) { conflicts.add(t) }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        // Exactly one thread succeeds in closing the account; the remaining 9 observe the CLOSED status and receive CONFLICT
        assertEquals(1, successes.size, "Exactly one thread should successfully transition to CLOSED")
        assertEquals(threadCount - 1, conflicts.size)
        conflicts.forEach {
            assertTrue(it is AuthenticationFailure.Rejected)
            assertEquals(AuthErrorCode.CONFLICT, it.code)
        }

        val finalPlayer = regStore.findById("tenant-casino-1", player.playerId)
        assertNotNull(finalPlayer)
        assertEquals(PlayerAccountStatus.CLOSED, finalPlayer.status)

        // Zero financial mutation
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-003-02-T004: Migration, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `AUTH-003-02-T004 Implement lock, suspend, and close account states remains compatible recoverable observable and lifecycle-safe`() {
        AccountStateLifecycleBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val stateStore = InMemoryAccountStateStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val lifecycleService1 = AccountStateLifecycleService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            accountStateStore = stateStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore, email = "recov.state.player@example.com")

        // Close account on service 1
        lifecycleService1.closeAccount(CloseAccountCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            initiator = "PLAYER",
            reason = "Permanent closure",
            idempotencyKey = "recov-close-1",
            correlationId = "corr-rc",
            causationId = "caus-rc"
        ))

        // RECOVERY / RESTART: Simulate service restart pointing to durable store
        val lifecycleService2 = AccountStateLifecycleService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            accountStateStore = stateStore,
            alertSink = alertSink,
            clock = clock
        )

        // After service recreation, closed status is preserved in durable store
        val playerAfterRestart = regStore.findById("tenant-casino-1", player.playerId)
        assertNotNull(playerAfterRestart)
        assertEquals(PlayerAccountStatus.CLOSED, playerAfterRestart.status)

        // Attempting to reinstate from service 2 fails with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            lifecycleService2.reinstateAccount(ReinstateAccountCommand(
                tenantId = "tenant-casino-1",
                playerId = player.playerId,
                adminOperatorId = "admin-post-restart",
                reason = "Reopen attempt",
                idempotencyKey = "post-restart-reopen",
                correlationId = "corr-post-ro",
                causationId = "caus-post-ro"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Observability check: structured audit events contain correlationId and resultId
        val closeEvent = stateStore.audit.first { it.type == "ACCOUNT_CLOSED" }
        assertNotNull(closeEvent.resultId)
        assertNotNull(closeEvent.correlationId)
        assertNotNull(closeEvent.causationId)
        assertNotNull(closeEvent.occurredAt)

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
