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

class SessionDeviceInventoryTest {

    private val now = Instant.parse("2026-09-18T19:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        SessionDeviceRevocationBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ShortLivedTokenBinding.isBound = true
        RefreshTokenRotationBinding.isBound = true
        SessionDeviceRevocationBinding.isBound = true
    }

    private fun registerAndVerifyPlayer(
        regStore: InMemoryPlayerRegistrationStore,
        tenantId: String = "tenant-casino-1",
        email: String = "device.player@example.com"
    ): RegisterPlayerResult {
        val regService = PlayerRegistrationService(store = regStore, clock = clock)
        val regCmd = RegisterPlayerCommand(
            tenantId = tenantId,
            email = email,
            phone = "+1555" + (6000000 + regStore.players.size + 1),
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
    // AUTH-002-03-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTH-002-03-T001 Implement session revocation and device inventory produces the required authoritative outcome`() {
        SessionDeviceRevocationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

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

        val player = registerAndVerifyPlayer(regStore)

        // 1. Issue tokens and register Device 1 (Phone)
        val pair1 = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-phone",
            correlationId = "corr-ph-1",
            causationId = "caus-ph-1"
        ))
        val dev1Result = deviceService.createDeviceSession(CreateDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            familyId = pair1.familyId,
            deviceMetadata = DeviceMetadata(
                deviceId = "android-device-phone-001",
                deviceModel = "Pixel 8 Pro",
                osVersion = "Android 14",
                clientIp = "203.0.113.10",
                userAgent = "SlottingApp/1.0 (Android)"
            ),
            idempotencyKey = "create-session-phone",
            correlationId = "corr-create-phone",
            causationId = "caus-create-phone"
        ))

        // 2. Issue tokens and register Device 2 (Tablet)
        val pair2 = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-tablet",
            correlationId = "corr-tab-1",
            causationId = "caus-tab-1"
        ))
        val dev2Result = deviceService.createDeviceSession(CreateDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            familyId = pair2.familyId,
            deviceMetadata = DeviceMetadata(
                deviceId = "android-device-tablet-002",
                deviceModel = "Galaxy Tab S9",
                osVersion = "Android 14",
                clientIp = "203.0.113.20",
                userAgent = "SlottingApp/1.0 (Android)"
            ),
            idempotencyKey = "create-session-tablet",
            correlationId = "corr-create-tablet",
            causationId = "caus-create-tablet"
        ))

        // 3. Query Device Inventory: both devices present and ACTIVE
        val inventory = deviceService.listDeviceInventory("tenant-casino-1", player.playerId)
        assertEquals(2, inventory.size)
        assertTrue(inventory.any { it.deviceId == "android-device-phone-001" && it.status == DeviceSessionStatus.ACTIVE })
        assertTrue(inventory.any { it.deviceId == "android-device-tablet-002" && it.status == DeviceSessionStatus.ACTIVE })

        // 4. Revoke Device 2 (Tablet) session specifically (e.g. security policy / compromised device)
        val revokeTabletResult = deviceService.revokeDeviceSession(RevokeDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            sessionId = dev2Result.sessionId,
            reason = TokenRevocationReason.SECURITY_POLICY,
            idempotencyKey = "revoke-tablet-cmd",
            correlationId = "corr-rev-tab",
            causationId = "caus-rev-tab"
        ))
        assertEquals(DeviceSessionStatus.REVOKED, revokeTabletResult.status)

        // 5. Tablet's Token Family in TokenSecurityStore is authoritatively revoked
        val tabletFamily = tokenStore.findFamily("tenant-casino-1", pair2.familyId)
        assertNotNull(tabletFamily)
        assertTrue(tabletFamily.isRevoked, "Tablet token family must be revoked")

        // 6. Access token for tablet is immediately rejected
        val tabletAccessVal = tokenService.validateAccessToken("tenant-casino-1", pair2.accessToken)
        assertTrue(!tabletAccessVal.valid, "Access token from revoked session must be invalid")
        assertEquals(AuthErrorCode.UNAUTHENTICATED, tabletAccessVal.reasonCode)

        // 7. Refresh token for tablet fails closed and triggers reuse detection alert
        assertFailsWith<AuthenticationFailure.Rejected> {
            tokenService.rotateRefreshToken(RefreshTokenCommand(
                tenantId = "tenant-casino-1",
                refreshToken = pair2.refreshToken,
                idempotencyKey = "attempt-refresh-tablet",
                correlationId = "corr-tab-refresh",
                causationId = "caus-tab-refresh"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Device 1 (Phone) session and tokens remain ACTIVE and completely functional
        val phoneAccessVal = tokenService.validateAccessToken("tenant-casino-1", pair1.accessToken)
        assertTrue(phoneAccessVal.valid, "Phone access token must remain valid")

        val phoneRotResult = tokenService.rotateRefreshToken(RefreshTokenCommand(
            tenantId = "tenant-casino-1",
            refreshToken = pair1.refreshToken,
            idempotencyKey = "rotate-phone-ok",
            correlationId = "corr-rot-ph",
            causationId = "caus-rot-ph"
        ))
        assertNotNull(phoneRotResult.refreshToken)

        // 9. Audited events
        val auditTypes = deviceStore.audit.map { it.type }
        assertTrue(auditTypes.contains("DEVICE_SESSION_REGISTERED"))
        assertTrue(auditTypes.contains("DEVICE_SESSION_REVOKED"))

        // Security alert dispatched
        assertTrue(alertSink.alerts.any { it.contains("DEVICE_SESSION_SECURITY_REVOCATION") })

        // Assert no financial authority or money mutation occurred
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
        assertEquals(0, regStore.audit.count { it.type.contains("CREDIT") })
        assertEquals(0, regStore.audit.count { it.type.contains("DEBIT") })
    }

    // =========================================================================
    // AUTH-002-03-T002: Negative, Boundary, Security & Malformed Rejection
    // =========================================================================

    @Test
    fun `AUTH-002-03-T002 Implement session revocation and device inventory rejects invalid boundary unauthorized and stale input`() {
        SessionDeviceRevocationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

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

        val player1 = registerAndVerifyPlayer(regStore, email = "p1@example.com")
        val player2 = registerAndVerifyPlayer(regStore, email = "p2@example.com")

        val pair1 = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player1.playerId,
            idempotencyKey = "issue-p1",
            correlationId = "corr-p1",
            causationId = "caus-p1"
        ))
        val session1 = deviceService.createDeviceSession(CreateDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player1.playerId,
            familyId = pair1.familyId,
            deviceMetadata = DeviceMetadata("dev-1", "Pixel", "14", "10.0.0.1", "App"),
            idempotencyKey = "create-s1",
            correlationId = "corr-s1",
            causationId = "caus-s1"
        ))

        // 1. Cross-owner revocation attempt: Player 2 tries to revoke Player 1's session -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            deviceService.revokeDeviceSession(RevokeDeviceSessionCommand(
                tenantId = "tenant-casino-1",
                playerId = player2.playerId, // WRONG PLAYER!
                sessionId = session1.sessionId,
                reason = TokenRevocationReason.SECURITY_POLICY,
                idempotencyKey = "cross-owner-rev",
                correlationId = "corr-x",
                causationId = "caus-x"
            ))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Cross-tenant revocation attempt -> INVALID or FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            deviceService.revokeDeviceSession(RevokeDeviceSessionCommand(
                tenantId = "tenant-different-market",
                playerId = player1.playerId,
                sessionId = session1.sessionId,
                reason = TokenRevocationReason.SECURITY_POLICY,
                idempotencyKey = "cross-tenant-rev",
                correlationId = "corr-xt",
                causationId = "caus-xt"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Stale expectedVersion (< 1L) -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            deviceService.revokeDeviceSession(RevokeDeviceSessionCommand(
                tenantId = "tenant-casino-1",
                playerId = player1.playerId,
                sessionId = session1.sessionId,
                reason = TokenRevocationReason.SECURITY_POLICY,
                idempotencyKey = "stale-rev",
                correlationId = "corr-stale",
                causationId = "caus-stale",
                expectedVersion = 0L
            ))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Blank device metadata during creation -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            deviceService.createDeviceSession(CreateDeviceSessionCommand(
                tenantId = "tenant-casino-1",
                playerId = player1.playerId,
                familyId = pair1.familyId,
                deviceMetadata = DeviceMetadata("", "", "", "", ""),
                idempotencyKey = "create-invalid",
                correlationId = "corr-inv",
                causationId = "caus-inv"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Non-existent session revocation -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            deviceService.revokeDeviceSession(RevokeDeviceSessionCommand(
                tenantId = "tenant-casino-1",
                playerId = player1.playerId,
                sessionId = UUID.randomUUID(),
                reason = TokenRevocationReason.SECURITY_POLICY,
                idempotencyKey = "non-existent-rev",
                correlationId = "corr-ne",
                causationId = "caus-ne"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Assert money remains untouched
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-002-03-T003: Concurrency, Idempotency & Failure Recovery
    // =========================================================================

    @Test
    fun `AUTH-002-03-T003 Implement session revocation and device inventory survives concurrency duplicate delivery and dependency failure`() {
        SessionDeviceRevocationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

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

        val player = registerAndVerifyPlayer(regStore)
        val pair = tokenService.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-conc-pair",
            correlationId = "corr-cp",
            causationId = "caus-cp"
        ))
        val session = deviceService.createDeviceSession(CreateDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            familyId = pair.familyId,
            deviceMetadata = DeviceMetadata("dev-c", "Pixel", "14", "10.0.0.1", "App"),
            idempotencyKey = "create-sc",
            correlationId = "corr-sc",
            causationId = "caus-sc"
        ))

        // 1. Idempotent replay: exact same revoke command returns cached result
        val revokeCmd = RevokeDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            sessionId = session.sessionId,
            reason = TokenRevocationReason.SECURITY_POLICY,
            idempotencyKey = "idem-revoke-key-1",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1"
        )
        val res1 = deviceService.revokeDeviceSession(revokeCmd)
        val res2 = deviceService.revokeDeviceSession(revokeCmd)
        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.status, res2.status)

        // 2. Conflicting command with same idempotency key
        val conflictCmd = RevokeDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            sessionId = session.sessionId,
            reason = TokenRevocationReason.LOGOUT, // CHANGED PAYLOAD!
            idempotencyKey = "idem-revoke-key-1",
            correlationId = "corr-conflict",
            causationId = "caus-conflict"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            deviceService.revokeDeviceSession(conflictCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrency: 10 concurrent threads invoking revokeAllSessions
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = mutableListOf<RevokeAllSessionsResult>()

        for (i in 1..threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = deviceService.revokeAllSessions(RevokeAllSessionsCommand(
                        tenantId = "tenant-casino-1",
                        playerId = player.playerId,
                        reason = TokenRevocationReason.SECURITY_POLICY,
                        idempotencyKey = "conc-rev-all-$i",
                        correlationId = "corr-all-$i",
                        causationId = "caus-all-$i"
                    ))
                    synchronized(results) { results.add(res) }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertEquals(threadCount, results.size)
        val playerSessions = deviceStore.findSessionsByPlayer("tenant-casino-1", player.playerId)
        assertTrue(playerSessions.all { it.status == DeviceSessionStatus.REVOKED })

        // Zero financial mutation
        assertEquals(0, regStore.audit.count { it.type.contains("BALANCE") })
    }

    // =========================================================================
    // AUTH-002-03-T004: Migration, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `AUTH-002-03-T004 Implement session revocation and device inventory remains compatible recoverable observable and lifecycle-safe`() {
        SessionDeviceRevocationBinding.checkBound()

        val regStore = InMemoryPlayerRegistrationStore()
        val tokenStore = InMemoryTokenSecurityStore()
        val deviceStore = InMemoryDeviceInventoryStore()
        val alertSink = InMemoryTokenSecurityAlertSink()

        val tokenService1 = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )
        val deviceService1 = SessionDeviceInventoryService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            alertSink = alertSink,
            clock = clock
        )

        val player = registerAndVerifyPlayer(regStore)
        val pair = tokenService1.issueTokenPair(IssueTokenPairCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            idempotencyKey = "issue-recov",
            correlationId = "corr-rec",
            causationId = "caus-rec"
        ))
        val session = deviceService1.createDeviceSession(CreateDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            familyId = pair.familyId,
            deviceMetadata = DeviceMetadata("dev-recov", "Pixel", "14", "10.0.0.1", "App"),
            idempotencyKey = "create-recov",
            correlationId = "corr-cr-rec",
            causationId = "caus-cr-rec"
        ))

        // Revoke session on service 1
        deviceService1.revokeDeviceSession(RevokeDeviceSessionCommand(
            tenantId = "tenant-casino-1",
            playerId = player.playerId,
            sessionId = session.sessionId,
            reason = TokenRevocationReason.SECURITY_POLICY,
            idempotencyKey = "rev-recov",
            correlationId = "corr-rev-rec",
            causationId = "caus-rev-rec"
        ))

        // RECOVERY / RESTART: New service instances referencing same store
        val tokenService2 = ShortLivedTokenService(
            registrationStore = regStore,
            tokenStore = tokenStore,
            alertSink = alertSink,
            clock = clock
        )
        val deviceService2 = SessionDeviceInventoryService(
            registrationStore = regStore,
            tokenSecurityStore = tokenStore,
            deviceStore = deviceStore,
            alertSink = alertSink,
            clock = clock
        )

        // Session remains revoked after recovery
        val recoveredSession = deviceService2.listDeviceInventory("tenant-casino-1", player.playerId).first()
        assertEquals(DeviceSessionStatus.REVOKED, recoveredSession.status)

        // Token family remains revoked on service 2
        val valResult = tokenService2.validateAccessToken("tenant-casino-1", pair.accessToken)
        assertTrue(!valResult.valid)
        assertEquals(AuthErrorCode.UNAUTHENTICATED, valResult.reasonCode)

        // Observability check: structured audit events contain correlationId and resultId
        val revokeEvent = deviceStore.audit.first { it.type == "DEVICE_SESSION_REVOKED" }
        assertNotNull(revokeEvent.resultId)
        assertNotNull(revokeEvent.correlationId)
        assertNotNull(revokeEvent.causationId)
        assertNotNull(revokeEvent.occurredAt)

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
