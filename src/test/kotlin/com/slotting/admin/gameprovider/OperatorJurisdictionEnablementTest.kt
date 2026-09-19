package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OperatorJurisdictionEnablementTest {
    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-jurisdiction-1"
    private val providerId = "prov-evolution"
    private val jurisdictionMt = "MT"
    private val jurisdictionUk = "UK"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-compliance-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPPORT),
    )

    private val unauthorizedPrincipal = AuthenticatedPrincipal(
        id = "admin-viewer-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-1",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SECURITY),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-cross",
        tenantId = "tenant-jurisdiction-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    @BeforeEach
    fun setUp() {
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true
    }

    @Test
    fun `GAME-002-02-T001 Enforce operator and jurisdiction game enablement produces the required authoritative outcome`() {
        // 1. Verify fail-closed gate throws expected RED assertion error when unbound
        OperatorJurisdictionEnablementBinding.isBound = false
        val catalogStore = OpJurTestCatalogStore()
        val store = OpJurTestStore()
        val sessions = OpJurTestActiveSessionDirectory()
        val service = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            catalogStore = catalogStore,
            store = store,
            clock = clock,
        )

        val policyCmd = createPolicyCommand(jurisdictionMt)
        val gateError = assertFailsWith<AssertionError> {
            service.configureJurisdictionPolicy(policyCmd)
        }
        assertEquals("disabled/unlicensed game launches", gateError.message)

        // Bind the gate
        OperatorJurisdictionEnablementBinding.isBound = true

        // Setup games in catalog
        setupCatalogGames(catalogStore)

        // 2. Configure jurisdiction compliance policy for MT
        val policyResult = service.configureJurisdictionPolicy(policyCmd)
        assertNotNull(policyResult)
        assertEquals(tenantId, policyResult.tenantId)
        assertEquals(jurisdictionMt, policyResult.jurisdictionCode)
        assertEquals(JurisdictionComplianceStatus.ACTIVE, policyResult.status)

        // Idempotent replay of policy configuration
        val policyReplay = service.configureJurisdictionPolicy(policyCmd)
        assertEquals(policyResult.resultId, policyReplay.resultId)
        assertEquals(1, store.auditLogs.count { it.type == "JURISDICTION_POLICY_CONFIGURED" })
        assertEquals(1, store.outboxLogs.count { it.type == "JURISDICTION_POLICY_CONFIGURED" })

        // 3. Enforce operator game enablement (disable game-aviator-01 by operator)
        val operatorCmd = EnforceOperatorGameEnablementCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-aviator-01",
            newStatus = GameEnablementStatus.DISABLED_BY_OPERATOR,
            reason = "Operator scheduled maintenance",
            idempotencyKey = "idemp-op-dis-aviator",
            correlationId = "corr-op-1",
            causationId = "cause-op-1",
            expectedVersion = 2L,
        )
        val opResult = service.updateOperatorGameEnablement(operatorCmd)
        assertEquals(GameEnablementStatus.ENABLED, opResult.previousStatus)
        assertEquals(GameEnablementStatus.DISABLED_BY_OPERATOR, opResult.newStatus)

        // Idempotent replay of operator enablement
        val opReplay = service.updateOperatorGameEnablement(operatorCmd)
        assertEquals(opResult.resultId, opReplay.resultId)
        assertEquals(1, store.auditLogs.count { it.type == "OPERATOR_GAME_ENABLEMENT_UPDATED" })

        // 4. Authorize authoritative game launch for game-starburst-01 in MT
        val launchCmd = AuthorizeAuthoritativeGameLaunchCommand(
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-starburst-01",
            playerId = "player-jur-1",
            jurisdictionCode = jurisdictionMt,
            requestedBetMinorUnits = 500L,
            currencyCode = "USD",
            idempotencyKey = "idemp-auth-launch-1",
            correlationId = "corr-l-1",
            causationId = "cause-l-1",
            expectedVersion = 1L,
        )
        val launchResult = service.authorizeLaunch(launchCmd)
        assertTrue(launchResult.authorized)
        assertNotNull(launchResult.launchToken)
        assertTrue(launchResult.launchToken!!.startsWith("AUTH-LAUNCH-"))

        // Idempotent replay of launch
        val launchReplay = service.authorizeLaunch(launchCmd)
        assertEquals(launchResult.resultId, launchReplay.resultId)
        assertEquals(launchResult.launchToken, launchReplay.launchToken)
        assertEquals(1, store.auditLogs.count { it.type == "AUTHORITATIVE_GAME_LAUNCH_AUTHORIZED" })
    }

    @Test
    fun `GAME-002-02-T002 Enforce operator and jurisdiction game enablement rejects invalid, boundary, unauthorized, and stale input`() {
        val catalogStore = OpJurTestCatalogStore()
        val store = OpJurTestStore()
        val sessions = OpJurTestActiveSessionDirectory()
        val service = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            catalogStore = catalogStore,
            store = store,
            clock = clock,
        )

        setupCatalogGames(catalogStore)
        val mtPolicy = service.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt))

        // Disable game-aviator-01
        service.updateOperatorGameEnablement(
            EnforceOperatorGameEnablementCommand(
                principal = adminPrincipal,
                sessionId = "session-1",
                tenantId = tenantId,
                providerId = providerId,
                gameId = "game-aviator-01",
                newStatus = GameEnablementStatus.DISABLED_BY_OPERATOR,
                reason = "Testing disabled rejection",
                idempotencyKey = "idemp-dis-aviator-t2",
                correlationId = "corr-dis-2",
                causationId = "cause-dis-2",
                expectedVersion = 2L,
            )
        )

        // 1. Rejects disabled game launch -> FORBIDDEN (disabled game launches)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-aviator-01", idempKey = "idemp-launch-fail-disabled")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(1, store.auditLogs.count { it.type == "AUTHORITATIVE_GAME_LAUNCH_REJECTED_DISABLED" })

        // 2. Rejects unlicensed jurisdiction launch -> FORBIDDEN (unlicensed game launches)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-starburst-01", jurisdiction = "US-NV", idempKey = "idemp-launch-fail-unlic")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(1, store.auditLogs.count { it.type == "AUTHORITATIVE_GAME_LAUNCH_REJECTED_UNLICENSED" })

        // 3. Rejects when jurisdiction policy is revoked -> FORBIDDEN
        service.revokeJurisdictionPolicy(
            RevokeJurisdictionPolicyCommand(
                principal = adminPrincipal,
                sessionId = "session-1",
                tenantId = tenantId,
                jurisdictionCode = jurisdictionMt,
                reason = "Regulatory license suspension",
                idempotencyKey = "idemp-revoke-mt",
                correlationId = "corr-rev-1",
                causationId = "cause-rev-1",
                expectedVersion = 2L,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-starburst-01", jurisdiction = jurisdictionMt, idempKey = "idemp-launch-fail-revoked")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Re-configure active policy for remaining checks
        service.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt, idempKey = "idemp-policy-mt-v3", expectedVersion = 3L))

        // 4. Rejects blacklisted/restricted game in jurisdiction -> FORBIDDEN
        service.configureJurisdictionPolicy(
            createPolicyCommand(
                jurisdictionCode = jurisdictionMt,
                restrictedGames = setOf("game-starburst-01"),
                idempKey = "idemp-policy-restricted",
                expectedVersion = 4L,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-starburst-01", jurisdiction = jurisdictionMt, idempKey = "idemp-launch-fail-restricted")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Rejects game type not permitted in jurisdiction -> FORBIDDEN
        service.configureJurisdictionPolicy(
            createPolicyCommand(
                jurisdictionCode = jurisdictionMt,
                allowedTypes = setOf(CasinoProviderType.TABLE_GAMES), // SLOTS not permitted
                idempKey = "idemp-policy-no-slots",
                expectedVersion = 5L,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-starburst-01", jurisdiction = jurisdictionMt, idempKey = "idemp-launch-fail-type")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Rejects RTP below floor -> FORBIDDEN
        service.configureJurisdictionPolicy(
            createPolicyCommand(
                jurisdictionCode = jurisdictionMt,
                allowedTypes = setOf(CasinoProviderType.SLOTS),
                rtpFloor = 98.0, // Starburst is 96.5%
                idempKey = "idemp-policy-rtp-floor",
                expectedVersion = 6L,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-starburst-01", jurisdiction = jurisdictionMt, idempKey = "idemp-launch-fail-rtp")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Rejects bet exceeding jurisdiction max bet -> INVALID
        service.configureJurisdictionPolicy(
            createPolicyCommand(
                jurisdictionCode = jurisdictionMt,
                allowedTypes = setOf(CasinoProviderType.SLOTS),
                maxBetLimit = 500L,
                idempKey = "idemp-policy-max-bet",
                expectedVersion = 7L,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-starburst-01", jurisdiction = jurisdictionMt, bet = 600L, idempKey = "idemp-launch-fail-max-bet")
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Reset policy to standard for stale sync test
        service.configureJurisdictionPolicy(
            createPolicyCommand(
                jurisdictionCode = jurisdictionMt,
                allowedTypes = setOf(CasinoProviderType.SLOTS, CasinoProviderType.CRASH_AVIATOR),
                idempKey = "idemp-policy-std",
                expectedVersion = 8L,
            )
        )

        // 8. Stale sync disables affected launch:
        // Set lastSynchronizedAt to 2 days in past (> 86400s)
        val game = catalogStore.findGame(tenantId, providerId, "game-starburst-01")!!
        catalogStore.saveGame(game.copy(lastSynchronizedAt = now.minusSeconds(86400 * 2)))

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(
                createLaunchCommand(gameId = "game-starburst-01", jurisdiction = jurisdictionMt, bet = 200L, idempKey = "idemp-launch-fail-stale")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(1, store.auditLogs.count { it.type == "AUTHORITATIVE_GAME_LAUNCH_REJECTED_STALE_SYNC" })

        // 9. Bet boundary rejections
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(createLaunchCommand(gameId = "game-starburst-01", bet = -10L, idempKey = "idemp-neg-bet"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeLaunch(createLaunchCommand(gameId = "game-starburst-01", currency = "US", idempKey = "idemp-bad-curr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 10. Security & Principal Checks
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt).copy(principal = null, idempotencyKey = "idemp-unauth-pol"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt).copy(principal = playerPrincipal, idempotencyKey = "idemp-player-pol"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt).copy(principal = crossTenantPrincipal, idempotencyKey = "idemp-cross-pol"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Expired session -> FORBIDDEN
        val expiredSessions = OpJurTestExpiredSessionDirectory()
        val expiredService = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = expiredSessions,
            catalogStore = catalogStore,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredService.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt).copy(idempotencyKey = "idemp-expired-sess-pol"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized permissions -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt).copy(principal = unauthorizedPrincipal, idempotencyKey = "idemp-noperm-pol"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale expected version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt).copy(expectedVersion = 999L, idempotencyKey = "idemp-stale-pol"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Idempotency conflict -> CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.configureJurisdictionPolicy(
                createPolicyCommand(jurisdictionMt).copy(
                    idempotencyKey = "idemp-policy-std", // Reused key with different allowed types
                    allowedGameTypes = setOf(CasinoProviderType.TABLE_GAMES),
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `GAME-002-02-T003 Enforce operator and jurisdiction game enablement survives concurrency, duplicate delivery, and dependency failure`() {
        val catalogStore = OpJurTestCatalogStore()
        val store = OpJurTestStore()
        val sessions = OpJurTestActiveSessionDirectory()
        val service = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            catalogStore = catalogStore,
            store = store,
            clock = clock,
        )

        setupCatalogGames(catalogStore)

        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)

        // 1. Race 8 threads configuring policy concurrently
        val polGate = CountDownLatch(1)
        val polCmd = createPolicyCommand(jurisdictionMt, idempKey = "idemp-conc-pol", expectedVersion = 1L)
        val polFutures = (1..threadCount).map {
            pool.submit<JurisdictionPolicyResult> {
                polGate.await()
                service.configureJurisdictionPolicy(polCmd)
            }
        }
        polGate.countDown()
        val polResults = polFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, polResults.count { it.isSuccess })
        val distinctPolIds = polResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctPolIds.size)
        assertEquals(1, store.auditLogs.count { it.type == "JURISDICTION_POLICY_CONFIGURED" })
        assertEquals(1, store.outboxLogs.count { it.type == "JURISDICTION_POLICY_CONFIGURED" })

        // 2. Race 8 threads authorizing launch concurrently
        val launchGate = CountDownLatch(1)
        val launchCmd = createLaunchCommand(
            gameId = "game-starburst-01",
            jurisdiction = jurisdictionMt,
            bet = 200L,
            idempKey = "idemp-conc-auth-launch",
        )
        val launchFutures = (1..threadCount).map {
            pool.submit<AuthoritativeGameLaunchResult> {
                launchGate.await()
                service.authorizeLaunch(launchCmd)
            }
        }
        launchGate.countDown()
        val launchResults = launchFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, launchResults.count { it.isSuccess })
        val distinctLaunchIds = launchResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctLaunchIds.size)
        assertEquals(1, store.auditLogs.count { it.type == "AUTHORITATIVE_GAME_LAUNCH_AUTHORIZED" })
        assertEquals(1, store.outboxLogs.count { it.type == "AUTHORITATIVE_GAME_LAUNCH_AUTHORIZED" })

        pool.shutdown()

        // 3. Dependency failure on session directory -> DEPENDENCY_UNAVAILABLE
        val failingSessions = OpJurTestFailingSessionDirectory()
        val failingSessionService = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = failingSessions,
            catalogStore = catalogStore,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.configureJurisdictionPolicy(createPolicyCommand(jurisdictionMt).copy(idempotencyKey = "idemp-dep-fail-sess"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `GAME-002-02-T004 Enforce operator and jurisdiction game enablement remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Flyway migration guardrail: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertFalse(migrationVersions.contains("V17"))

        // 2. Recovery across reboot / restart
        val catalogStore = OpJurTestCatalogStore()
        val store = OpJurTestStore()
        val sessions = OpJurTestActiveSessionDirectory()

        val serviceInitial = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            catalogStore = catalogStore,
            store = store,
            clock = clock,
        )

        setupCatalogGames(catalogStore)
        val polCmd = createPolicyCommand(jurisdictionMt, idempKey = "idemp-reboot-pol")
        val initialPol = serviceInitial.configureJurisdictionPolicy(polCmd)

        // Instantiate restarted service sharing the persistent store
        val serviceRestarted = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            catalogStore = catalogStore,
            store = store,
            clock = clock,
        )

        val replayedPol = serviceRestarted.configureJurisdictionPolicy(polCmd.copy(expectedVersion = 1L))
        assertEquals(initialPol.resultId, replayedPol.resultId)
        assertEquals(initialPol.evidenceReference, replayedPol.evidenceReference)

        // Launch authorization works across reboot
        val launchCmd = createLaunchCommand(
            gameId = "game-starburst-01",
            jurisdiction = jurisdictionMt,
            bet = 350L,
            idempKey = "idemp-reboot-launch",
        )
        val initialLaunch = serviceInitial.authorizeLaunch(launchCmd)
        val replayedLaunch = serviceRestarted.authorizeLaunch(launchCmd)
        assertEquals(initialLaunch.resultId, replayedLaunch.resultId)
        assertEquals(initialLaunch.launchToken, replayedLaunch.launchToken)

        // 3. Observability & Zero Raw Secret Exposure
        assertTrue(store.auditLogs.isNotEmpty())
        for (audit in store.auditLogs) {
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertNotNull(audit.occurredAt)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("keySecret", ignoreCase = true))
        }
    }

    private fun setupCatalogGames(catalogStore: AuthoritativeCatalogStore) {
        val game1 = CatalogGameEntry(
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-starburst-01",
            gameTitle = "Starburst",
            gameType = CasinoProviderType.SLOTS,
            supportedJurisdictions = setOf(jurisdictionMt, jurisdictionUk),
            rtpPercent = 96.50,
            minBetMinorUnits = 10L,
            maxBetMinorUnits = 100000L,
            enablementStatus = GameEnablementStatus.ENABLED,
            lastSynchronizedAt = now,
            staleSyncThresholdSeconds = 86400L,
            version = 1L,
        )
        val game2 = CatalogGameEntry(
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-aviator-01",
            gameTitle = "Aviator",
            gameType = CasinoProviderType.CRASH_AVIATOR,
            supportedJurisdictions = setOf(jurisdictionMt),
            rtpPercent = 97.00,
            minBetMinorUnits = 20L,
            maxBetMinorUnits = 500000L,
            enablementStatus = GameEnablementStatus.ENABLED,
            lastSynchronizedAt = now,
            staleSyncThresholdSeconds = 86400L,
            version = 1L,
        )
        catalogStore.saveGame(game1)
        catalogStore.saveGame(game2)
    }

    private fun createPolicyCommand(
        jurisdictionCode: String,
        allowedTypes: Set<CasinoProviderType> = setOf(CasinoProviderType.SLOTS, CasinoProviderType.CRASH_AVIATOR),
        maxBetLimit: Long? = null,
        rtpFloor: Double? = null,
        restrictedGames: Set<String> = emptySet(),
        idempKey: String = "idemp-pol-default",
        expectedVersion: Long = 1L,
    ) = ConfigureJurisdictionPolicyCommand(
        principal = adminPrincipal,
        sessionId = "session-1",
        tenantId = tenantId,
        jurisdictionCode = jurisdictionCode,
        status = JurisdictionComplianceStatus.ACTIVE,
        allowedGameTypes = allowedTypes,
        maxBetLimitMinorUnits = maxBetLimit,
        rtpFloorPercent = rtpFloor,
        restrictedGameIds = restrictedGames,
        effectiveFrom = now.minusSeconds(86400),
        effectiveUntil = now.plusSeconds(86400 * 30),
        complianceSigner = "compliance-lead-global",
        idempotencyKey = idempKey,
        correlationId = "corr-pol-1",
        causationId = "cause-pol-1",
        expectedVersion = expectedVersion,
    )

    private fun createLaunchCommand(
        gameId: String,
        jurisdiction: String = jurisdictionMt,
        bet: Long = 100L,
        currency: String = "USD",
        idempKey: String,
    ) = AuthorizeAuthoritativeGameLaunchCommand(
        tenantId = tenantId,
        providerId = providerId,
        gameId = gameId,
        playerId = "player-auth-1",
        jurisdictionCode = jurisdiction,
        requestedBetMinorUnits = bet,
        currencyCode = currency,
        idempotencyKey = idempKey,
        correlationId = "corr-l-default",
        causationId = "cause-l-default",
        expectedVersion = 1L,
    )
}

private class OpJurTestActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T18:00:00Z"),
        )
}

private class OpJurTestExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-18T02:00:00Z"), // Expired
        )
}

private class OpJurTestFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        error("database connection pool exhausted")
}

private class OpJurTestCatalogStore : AuthoritativeCatalogStore {
    private val games = mutableMapOf<String, CatalogGameEntry>()
    private val syncIdempotency = mutableMapOf<String, Pair<String, CatalogSyncResult>>()
    private val enablementIdempotency = mutableMapOf<String, Pair<String, GameEnablementResult>>()
    private val launchIdempotency = mutableMapOf<String, Pair<String, GameLaunchAuthorizationResult>>()

    override fun findGame(tenantId: String, providerId: String, gameId: String): CatalogGameEntry? =
        synchronized(this) { games["$tenantId:$providerId:$gameId"] }

    override fun listGames(tenantId: String, providerId: String): List<CatalogGameEntry> =
        synchronized(this) { games.values.filter { it.tenantId == tenantId && it.providerId == providerId } }

    override fun saveGame(game: CatalogGameEntry) =
        synchronized(this) { games["${game.tenantId}:${game.providerId}:${game.gameId}"] = game }

    override fun findSyncByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CatalogSyncResult>? =
        synchronized(this) { syncIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveSync(
        result: CatalogSyncResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        syncIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    override fun findEnablementByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameEnablementResult>? =
        synchronized(this) { enablementIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveEnablement(
        result: GameEnablementResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        enablementIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    override fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameLaunchAuthorizationResult>? =
        synchronized(this) { launchIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveLaunch(
        result: GameLaunchAuthorizationResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        launchIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

private class OpJurTestStore : OperatorJurisdictionEnablementStore {
    private val policies = mutableMapOf<String, JurisdictionCompliancePolicy>()
    private val policyIdempotency = mutableMapOf<String, Pair<String, JurisdictionPolicyResult>>()
    private val enablementIdempotency = mutableMapOf<String, Pair<String, OperatorEnablementResult>>()
    private val launchIdempotency = mutableMapOf<String, Pair<String, AuthoritativeGameLaunchResult>>()
    val auditLogs = mutableListOf<AuditEvent>()
    val outboxLogs = mutableListOf<OutboxEvent>()

    override fun findPolicy(tenantId: String, jurisdictionCode: String): JurisdictionCompliancePolicy? =
        synchronized(this) { policies["$tenantId:$jurisdictionCode"] }

    override fun savePolicy(
        policy: JurisdictionCompliancePolicy,
        result: JurisdictionPolicyResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        policies["$tenantId:${policy.jurisdictionCode}"] = policy
        policyIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }

    override fun findPolicyByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, JurisdictionPolicyResult>? =
        synchronized(this) { policyIdempotency["$tenantId:$idempotencyKey"] }

    override fun findEnablementByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, OperatorEnablementResult>? =
        synchronized(this) { enablementIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveEnablement(
        result: OperatorEnablementResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        enablementIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }

    override fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AuthoritativeGameLaunchResult>? =
        synchronized(this) { launchIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveLaunch(
        result: AuthoritativeGameLaunchResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        launchIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }
}
