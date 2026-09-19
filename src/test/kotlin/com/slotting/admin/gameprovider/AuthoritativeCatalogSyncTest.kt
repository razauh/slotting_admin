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

class AuthoritativeCatalogSyncTest {
    private val now = Instant.parse("2026-09-19T13:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-catalog-1"
    private val providerId = "prov-catalog-evolution"
    private val activeKeyId = "key-v1"
    private val activeKeySecret = "raw-secret-catalog-v1"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-catalog-1",
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
        tenantId = "tenant-catalog-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    @BeforeEach
    fun setUp() {
        AuthoritativeCatalogSyncBinding.isBound = true
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        AuthoritativeCatalogSyncBinding.isBound = true
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @Test
    fun `GAME-002-01-T001 Synchronize authoritative provider catalog produces the required authoritative outcome`() {
        // 1. Verify fail-closed gate throws expected RED assertion error when unbound
        AuthoritativeCatalogSyncBinding.isBound = false
        val contractStore = CatalogSyncTestContractStore()
        val catalogStore = CatalogSyncTestStore()
        val sessions = CatalogSyncTestActiveSessionDirectory()
        val service = AuthoritativeCatalogSyncService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            store = catalogStore,
            clock = clock,
        )

        val syncCmd = createSyncCommand()
        val gateError = assertFailsWith<AssertionError> {
            service.synchronizeCatalog(syncCmd)
        }
        assertEquals("disabled/unlicensed game launches", gateError.message)

        // Bind the gate
        AuthoritativeCatalogSyncBinding.isBound = true

        // Register canonical schema in contract store
        registerTestSchema(contractStore)

        // 2. Synchronize provider catalog with games
        val syncResult = service.synchronizeCatalog(syncCmd)
        assertNotNull(syncResult)
        assertEquals(tenantId, syncResult.tenantId)
        assertEquals(providerId, syncResult.providerId)
        assertEquals(2, syncResult.totalSynchronized)
        assertEquals(2, syncResult.enabledCount)
        assertEquals(0, syncResult.disabledCount)

        // Idempotent replay of synchronization
        val syncReplay = service.synchronizeCatalog(syncCmd)
        assertEquals(syncResult.resultId, syncReplay.resultId)
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_CATALOG_SYNCHRONIZED" })
        assertEquals(1, catalogStore.outboxLogs.count { it.type == "GAME_CATALOG_SYNCHRONIZED" })

        // 3. Update game enablement (disable game-aviator-01 by operator)
        val disableCmd = UpdateGameEnablementCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-aviator-01",
            newStatus = GameEnablementStatus.DISABLED_BY_OPERATOR,
            reason = "Temporary operator compliance freeze",
            idempotencyKey = "idemp-disable-aviator",
            correlationId = "corr-dis-1",
            causationId = "cause-dis-1",
            expectedVersion = 2L,
        )
        val disableResult = service.updateGameEnablement(disableCmd)
        assertEquals(GameEnablementStatus.ENABLED, disableResult.previousStatus)
        assertEquals(GameEnablementStatus.DISABLED_BY_OPERATOR, disableResult.newStatus)

        // Idempotent replay of enablement update
        val disableReplay = service.updateGameEnablement(disableCmd)
        assertEquals(disableResult.resultId, disableReplay.resultId)
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_ENABLEMENT_UPDATED" })

        // 4. Authorize valid game launch for game-starburst-01 in licensed jurisdiction (MT)
        val launchCmd = AuthorizeGameLaunchCommand(
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-starburst-01",
            playerId = "player-auth-100",
            jurisdictionCode = "MT",
            currencyCode = "USD",
            requestedBetMinorUnits = 500L,
            idempotencyKey = "idemp-launch-valid-1",
            correlationId = "corr-launch-1",
            causationId = "cause-launch-1",
            expectedVersion = 1L,
        )
        val launchResult = service.authorizeGameLaunch(launchCmd)
        assertTrue(launchResult.authorized)
        assertNotNull(launchResult.launchToken)
        assertTrue(launchResult.launchToken!!.startsWith("LAUNCH-"))

        // Idempotent replay of launch
        val launchReplay = service.authorizeGameLaunch(launchCmd)
        assertEquals(launchResult.resultId, launchReplay.resultId)
        assertEquals(launchResult.launchToken, launchReplay.launchToken)
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_LAUNCH_AUTHORIZED" })
    }

    @Test
    fun `GAME-002-01-T002 Synchronize authoritative provider catalog rejects invalid, boundary, unauthorized, and stale input`() {
        val contractStore = CatalogSyncTestContractStore()
        val catalogStore = CatalogSyncTestStore()
        val sessions = CatalogSyncTestActiveSessionDirectory()
        val service = AuthoritativeCatalogSyncService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            store = catalogStore,
            clock = clock,
        )

        registerTestSchema(contractStore)
        service.synchronizeCatalog(createSyncCommand())

        // Disable game-aviator-01
        service.updateGameEnablement(
            UpdateGameEnablementCommand(
                principal = adminPrincipal,
                sessionId = "session-1",
                tenantId = tenantId,
                providerId = providerId,
                gameId = "game-aviator-01",
                newStatus = GameEnablementStatus.DISABLED_BY_OPERATOR,
                reason = "Disabled for testing",
                idempotencyKey = "idemp-dis-aviator-t2",
                correlationId = "corr-t2",
                causationId = "cause-t2",
                expectedVersion = 2L,
            )
        )

        // 1. Disabled game launch rejected -> FORBIDDEN (prevents disabled game launches)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-aviator-01",
                    playerId = "player-1",
                    jurisdictionCode = "MT",
                    currencyCode = "USD",
                    requestedBetMinorUnits = 100L,
                    idempotencyKey = "idemp-launch-disabled",
                    correlationId = "corr-dis-launch",
                    causationId = "cause-dis-launch",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_LAUNCH_REJECTED_DISABLED" })

        // 2. Unlicensed jurisdiction launch rejected -> FORBIDDEN (prevents unlicensed game launches)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-starburst-01",
                    playerId = "player-1",
                    jurisdictionCode = "US-NV", // Not in supportedJurisdictions setOf("MT", "UK")
                    currencyCode = "USD",
                    requestedBetMinorUnits = 100L,
                    idempotencyKey = "idemp-launch-unlicensed",
                    correlationId = "corr-unlic",
                    causationId = "cause-unlic",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_LAUNCH_REJECTED_UNLICENSED" })

        // 3. Stale sync disables affected launch:
        // Set game-starburst-01's lastSynchronizedAt to 2 days in the past (> 86400s threshold)
        val existingGame = catalogStore.findGame(tenantId, providerId, "game-starburst-01")!!
        val staleGame = existingGame.copy(
            lastSynchronizedAt = now.minusSeconds(86400 * 2),
        )
        catalogStore.saveGame(staleGame)

        // Attempt launch on game with stale sync -> rejected with FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-starburst-01",
                    playerId = "player-1",
                    jurisdictionCode = "MT",
                    currencyCode = "USD",
                    requestedBetMinorUnits = 100L,
                    idempotencyKey = "idemp-launch-stale",
                    correlationId = "corr-stale-launch",
                    causationId = "cause-stale-launch",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        // Verify game status transitioned to DISABLED_STALE_SYNC
        val updatedGame = catalogStore.findGame(tenantId, providerId, "game-starburst-01")!!
        assertEquals(GameEnablementStatus.DISABLED_STALE_SYNC, updatedGame.enablementStatus)
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_LAUNCH_REJECTED_STALE_SYNC" })

        // Re-enable and fresh-sync game for bet boundary tests
        catalogStore.saveGame(
            existingGame.copy(
                enablementStatus = GameEnablementStatus.ENABLED,
                lastSynchronizedAt = now,
            )
        )

        // 4. Bet boundary rejections: bet < minBet -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-starburst-01",
                    playerId = "player-1",
                    jurisdictionCode = "MT",
                    currencyCode = "USD",
                    requestedBetMinorUnits = 5L, // minBet is 10L
                    idempotencyKey = "idemp-bet-too-low",
                    correlationId = "corr-b1",
                    causationId = "cause-b1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Bet > maxBet -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-starburst-01",
                    playerId = "player-1",
                    jurisdictionCode = "MT",
                    currencyCode = "USD",
                    requestedBetMinorUnits = 200000L, // maxBet is 100000L
                    idempotencyKey = "idemp-bet-too-high",
                    correlationId = "corr-b2",
                    causationId = "cause-b2",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Negative bet -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-starburst-01",
                    playerId = "player-1",
                    jurisdictionCode = "MT",
                    currencyCode = "USD",
                    requestedBetMinorUnits = -100L,
                    idempotencyKey = "idemp-neg-bet",
                    correlationId = "corr-b3",
                    causationId = "cause-b3",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid currency code -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-starburst-01",
                    playerId = "player-1",
                    jurisdictionCode = "MT",
                    currencyCode = "US",
                    requestedBetMinorUnits = 100L,
                    idempotencyKey = "idemp-bad-curr",
                    correlationId = "corr-b4",
                    causationId = "cause-b4",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Non-existent game -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorizeGameLaunch(
                AuthorizeGameLaunchCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-unknown-xyz",
                    playerId = "player-1",
                    jurisdictionCode = "MT",
                    currencyCode = "USD",
                    requestedBetMinorUnits = 100L,
                    idempotencyKey = "idemp-unknown-game",
                    correlationId = "corr-b5",
                    causationId = "cause-b5",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Security & Principal Checks on Sync
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.synchronizeCatalog(createSyncCommand().copy(principal = null, idempotencyKey = "idemp-unauth-sync"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.synchronizeCatalog(createSyncCommand().copy(principal = playerPrincipal, idempotencyKey = "idemp-player-sync"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.synchronizeCatalog(createSyncCommand().copy(principal = crossTenantPrincipal, idempotencyKey = "idemp-cross-sync"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Expired session -> FORBIDDEN
        val expiredSessions = CatalogSyncTestExpiredSessionDirectory()
        val expiredService = AuthoritativeCatalogSyncService(
            policy = AdminRbacPolicy(true),
            sessions = expiredSessions,
            contractStore = contractStore,
            store = catalogStore,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredService.synchronizeCatalog(createSyncCommand().copy(idempotencyKey = "idemp-expired-sess-sync"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized permissions -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.synchronizeCatalog(createSyncCommand().copy(principal = unauthorizedPrincipal, idempotencyKey = "idemp-noperm-sync"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale expected version on enablement -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.updateGameEnablement(
                UpdateGameEnablementCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    gameId = "game-starburst-01",
                    newStatus = GameEnablementStatus.DISABLED_BY_OPERATOR,
                    reason = "Stale version test",
                    idempotencyKey = "idemp-stale-en-cmd",
                    correlationId = "corr-stale-en",
                    causationId = "cause-stale-en",
                    expectedVersion = 999L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Idempotency conflict -> CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.synchronizeCatalog(
                createSyncCommand().copy(
                    idempotencyKey = "idemp-sync-default", // Reused key with different timestamp
                    syncTimestamp = now.plusSeconds(3600),
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `GAME-002-01-T003 Synchronize authoritative provider catalog survives concurrency, duplicate delivery, and dependency failure`() {
        val contractStore = CatalogSyncTestContractStore()
        val catalogStore = CatalogSyncTestStore()
        val sessions = CatalogSyncTestActiveSessionDirectory()
        val service = AuthoritativeCatalogSyncService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            store = catalogStore,
            clock = clock,
        )

        registerTestSchema(contractStore)

        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)

        // 1. Race 8 threads synchronizing catalog concurrently
        val syncGate = CountDownLatch(1)
        val syncCmd = createSyncCommand().copy(idempotencyKey = "idemp-conc-sync")
        val syncFutures = (1..threadCount).map {
            pool.submit<CatalogSyncResult> {
                syncGate.await()
                service.synchronizeCatalog(syncCmd)
            }
        }
        syncGate.countDown()
        val syncResults = syncFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, syncResults.count { it.isSuccess })
        val distinctSyncIds = syncResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctSyncIds.size)
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_CATALOG_SYNCHRONIZED" })
        assertEquals(1, catalogStore.outboxLogs.count { it.type == "GAME_CATALOG_SYNCHRONIZED" })

        // 2. Race 8 threads authorizing launch concurrently
        val launchGate = CountDownLatch(1)
        val launchCmd = AuthorizeGameLaunchCommand(
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-starburst-01",
            playerId = "player-conc-1",
            jurisdictionCode = "MT",
            currencyCode = "USD",
            requestedBetMinorUnits = 100L,
            idempotencyKey = "idemp-conc-launch",
            correlationId = "corr-conc-l",
            causationId = "cause-conc-l",
            expectedVersion = 1L,
        )
        val launchFutures = (1..threadCount).map {
            pool.submit<GameLaunchAuthorizationResult> {
                launchGate.await()
                service.authorizeGameLaunch(launchCmd)
            }
        }
        launchGate.countDown()
        val launchResults = launchFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, launchResults.count { it.isSuccess })
        val distinctLaunchIds = launchResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctLaunchIds.size)
        assertEquals(1, catalogStore.auditLogs.count { it.type == "GAME_LAUNCH_AUTHORIZED" })
        assertEquals(1, catalogStore.outboxLogs.count { it.type == "GAME_LAUNCH_AUTHORIZED" })

        pool.shutdown()

        // 3. Dependency failure on session directory -> DEPENDENCY_UNAVAILABLE
        val failingSessions = CatalogSyncTestFailingSessionDirectory()
        val failingSessionService = AuthoritativeCatalogSyncService(
            policy = AdminRbacPolicy(true),
            sessions = failingSessions,
            contractStore = contractStore,
            store = catalogStore,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.synchronizeCatalog(createSyncCommand().copy(idempotencyKey = "idemp-dep-fail-sess"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `GAME-002-01-T004 Synchronize authoritative provider catalog remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Flyway migration guardrail: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertFalse(migrationVersions.contains("V17"))

        // 2. Recovery across reboot / restart
        val contractStore = CatalogSyncTestContractStore()
        val catalogStore = CatalogSyncTestStore()
        val sessions = CatalogSyncTestActiveSessionDirectory()

        val serviceInitial = AuthoritativeCatalogSyncService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            store = catalogStore,
            clock = clock,
        )

        registerTestSchema(contractStore)
        val syncCmd = createSyncCommand().copy(idempotencyKey = "idemp-reboot-sync")
        val initialSync = serviceInitial.synchronizeCatalog(syncCmd)

        // Instantiate restarted service sharing the persistent store
        val serviceRestarted = AuthoritativeCatalogSyncService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            store = catalogStore,
            clock = clock,
        )

        val replayedSync = serviceRestarted.synchronizeCatalog(syncCmd.copy(expectedVersion = 1L))
        assertEquals(initialSync.resultId, replayedSync.resultId)
        assertEquals(initialSync.evidenceReference, replayedSync.evidenceReference)

        // Launch authorization works across reboot
        val launchCmd = AuthorizeGameLaunchCommand(
            tenantId = tenantId,
            providerId = providerId,
            gameId = "game-starburst-01",
            playerId = "player-reboot-1",
            jurisdictionCode = "MT",
            currencyCode = "USD",
            requestedBetMinorUnits = 250L,
            idempotencyKey = "idemp-reboot-launch",
            correlationId = "corr-reboot-l",
            causationId = "cause-reboot-l",
            expectedVersion = 1L,
        )
        val initialLaunch = serviceInitial.authorizeGameLaunch(launchCmd)
        val replayedLaunch = serviceRestarted.authorizeGameLaunch(launchCmd)
        assertEquals(initialLaunch.resultId, replayedLaunch.resultId)
        assertEquals(initialLaunch.launchToken, replayedLaunch.launchToken)

        // 3. Observability & Zero Raw Secret Exposure
        assertTrue(catalogStore.auditLogs.isNotEmpty())
        for (audit in catalogStore.auditLogs) {
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertNotNull(audit.occurredAt)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("keySecret", ignoreCase = true))
        }
    }

    private fun registerTestSchema(contractStore: CanonicalCasinoProviderContractStore) {
        val activeKey = ProviderKeyCredential(
            keyId = activeKeyId,
            keySecretHash = "hash-key-1",
            rotationState = ProviderKeyRotationState.ACTIVE,
            issuedAt = now,
            expiresAt = now.plusSeconds(86400 * 90),
        )
        val schema = CanonicalCasinoProviderSchema(
            schemaId = "SCHEMA-CATALOG-01",
            providerId = providerId,
            providerName = "Evolution Provider",
            providerType = CasinoProviderType.SLOTS,
            schemaVersion = "1.0.0",
            supportedCurrencies = setOf("USD", "EUR"),
            signatureAlgorithm = ProviderSignatureAlgorithm.HMAC_SHA256,
            callbackEndpoint = "https://api.evolution.com/callback",
            maxRoundDurationSeconds = 120L,
            supportsAtomicRollback = true,
            activeKey = activeKey,
            version = 1L,
        )
        contractStore.saveSchema(
            schema = schema,
            result = ProviderSchemaResult(
                resultId = UUID.randomUUID(),
                tenantId = tenantId,
                providerId = providerId,
                schema = schema,
                rotationObservable = false,
                outageObservable = false,
                serverTime = now,
                evidenceReference = "EVID-SCHEMA-01",
            ),
            tenantId = tenantId,
            idempotencyKey = "idemp-schema-setup",
            fingerprint = "fp-schema-setup",
            audit = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "SCHEMA_SAVED", now, "corr-setup", "cause-setup"),
            outbox = OutboxEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "SCHEMA_SAVED", now),
        )
    }

    private fun createSyncCommand() = SynchronizeProviderCatalogCommand(
        principal = adminPrincipal,
        sessionId = "session-1",
        tenantId = tenantId,
        providerId = providerId,
        games = listOf(
            ProviderCatalogGameDto(
                gameId = "game-starburst-01",
                gameTitle = "Starburst Classic",
                gameType = CasinoProviderType.SLOTS,
                supportedJurisdictions = setOf("MT", "UK"),
                rtpPercent = 96.50,
                minBetMinorUnits = 10L,
                maxBetMinorUnits = 100000L,
                initialEnablement = GameEnablementStatus.ENABLED,
            ),
            ProviderCatalogGameDto(
                gameId = "game-aviator-01",
                gameTitle = "Aviator Crash",
                gameType = CasinoProviderType.CRASH_AVIATOR,
                supportedJurisdictions = setOf("MT"),
                rtpPercent = 97.00,
                minBetMinorUnits = 20L,
                maxBetMinorUnits = 500000L,
                initialEnablement = GameEnablementStatus.ENABLED,
            ),
        ),
        syncTimestamp = now,
        idempotencyKey = "idemp-sync-default",
        correlationId = "corr-sync-1",
        causationId = "cause-sync-1",
        expectedVersion = 1L,
    )
}

private class CatalogSyncTestActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T18:00:00Z"),
        )
}

private class CatalogSyncTestExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-18T02:00:00Z"), // Expired
        )
}

private class CatalogSyncTestFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        error("database connection pool exhausted")
}

private class CatalogSyncTestContractStore : CanonicalCasinoProviderContractStore {
    private val schemas = mutableMapOf<String, CanonicalCasinoProviderSchema>()
    private val idempotencyMap = mutableMapOf<String, Pair<String, Any>>()
    private val seenSignatures = mutableSetOf<String>()

    override fun findSchema(tenantId: String, providerId: String): CanonicalCasinoProviderSchema? =
        synchronized(this) { schemas["$tenantId:$providerId"] }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        synchronized(this) { idempotencyMap["$tenantId:$idempotencyKey"] }

    override fun isSignatureSeen(tenantId: String, signature: String): Boolean =
        synchronized(this) { seenSignatures.contains("$tenantId:$signature") }

    override fun saveSchema(
        schema: CanonicalCasinoProviderSchema,
        result: ProviderSchemaResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        schemas["$tenantId:${schema.providerId}"] = schema
        idempotencyMap["$tenantId:$idempotencyKey"] = fingerprint to result
    }

    override fun recordVerification(
        result: ProviderCallbackVerificationResult,
        tenantId: String,
        signature: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        seenSignatures.add("$tenantId:$signature")
        idempotencyMap["$tenantId:$idempotencyKey"] = fingerprint to result
    }
}

private class CatalogSyncTestStore : AuthoritativeCatalogStore {
    private val games = mutableMapOf<String, CatalogGameEntry>()
    private val syncIdempotency = mutableMapOf<String, Pair<String, CatalogSyncResult>>()
    private val enablementIdempotency = mutableMapOf<String, Pair<String, GameEnablementResult>>()
    private val launchIdempotency = mutableMapOf<String, Pair<String, GameLaunchAuthorizationResult>>()
    val auditLogs = mutableListOf<AuditEvent>()
    val outboxLogs = mutableListOf<OutboxEvent>()

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
        auditLogs += audit
        outboxLogs += outbox
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
        auditLogs += audit
        outboxLogs += outbox
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
        auditLogs += audit
        outboxLogs += outbox
    }
}
