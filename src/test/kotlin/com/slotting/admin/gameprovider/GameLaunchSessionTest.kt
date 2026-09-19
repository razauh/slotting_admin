package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import com.slotting.admin.identity.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class GameLaunchSessionTest {

    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-casino-launch"
    private val providerId = "prov-pragmatic"
    private val gameId = "game-gates-of-olympus"
    private val jurisdictionMt = "MT"
    private val currencyUsd = "USD"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-game-lead",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPPORT),
    )

    private lateinit var regStore: InMemoryPlayerRegistrationStore
    private lateinit var eligStore: InMemoryServerEligibilityStore
    private lateinit var catalogStore: LaunchTestCatalogStore
    private lateinit var jurStore: LaunchTestJurisdictionStore
    private lateinit var launchStore: InMemoryGameLaunchSessionStore
    private lateinit var alertSink: InMemoryGameLaunchAlertSink
    private lateinit var sessionDirectory: LaunchTestSessionDirectory
    private lateinit var operatorService: OperatorJurisdictionEnablementService
    private lateinit var launchService: GameLaunchSessionService

    @BeforeEach
    fun setUp() {
        GameLaunchTokenBinding.isBound = true
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true
        ServerEligibilityBinding.isBound = true

        regStore = InMemoryPlayerRegistrationStore()
        eligStore = InMemoryServerEligibilityStore()
        catalogStore = LaunchTestCatalogStore()
        jurStore = LaunchTestJurisdictionStore()
        launchStore = InMemoryGameLaunchSessionStore()
        alertSink = InMemoryGameLaunchAlertSink()
        sessionDirectory = LaunchTestSessionDirectory()

        operatorService = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory,
            catalogStore = catalogStore,
            store = jurStore,
            clock = clock,
        )

        launchService = GameLaunchSessionService(
            operatorEnablementService = operatorService,
            registrationStore = regStore,
            eligibilityStore = eligStore,
            launchStore = launchStore,
            alertSink = alertSink,
            clock = clock,
            tokenTtlSeconds = 120L,
            sessionTtlSeconds = 7200L,
        )

        setupCatalogAndJurisdiction()
    }

    @AfterEach
    fun tearDown() {
        GameLaunchTokenBinding.isBound = true
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true
        ServerEligibilityBinding.isBound = true
    }

    private fun setupCatalogAndJurisdiction() {
        val game = CatalogGameEntry(
            tenantId = tenantId,
            providerId = providerId,
            gameId = gameId,
            gameTitle = "Gates of Olympus",
            gameType = CasinoProviderType.SLOTS,
            supportedJurisdictions = setOf(jurisdictionMt, "UK", "NV"),
            rtpPercent = 96.5,
            minBetMinorUnits = 20L,
            maxBetMinorUnits = 10000L,
            enablementStatus = GameEnablementStatus.ENABLED,
            lastSynchronizedAt = now,
            staleSyncThresholdSeconds = 86400L,
            version = 1L,
        )
        catalogStore.saveGame(game)

        operatorService.configureJurisdictionPolicy(
            ConfigureJurisdictionPolicyCommand(
                principal = adminPrincipal,
                sessionId = "admin-sess-1",
                tenantId = tenantId,
                jurisdictionCode = jurisdictionMt,
                status = JurisdictionComplianceStatus.ACTIVE,
                allowedGameTypes = setOf(CasinoProviderType.SLOTS),
                maxBetLimitMinorUnits = 50000L,
                rtpFloorPercent = 90.0,
                restrictedGameIds = emptySet(),
                effectiveFrom = now.minusSeconds(86400),
                effectiveUntil = now.plusSeconds(86400 * 365),
                complianceSigner = "MGA-REG-OFFICER-7",
                idempotencyKey = "pol-idemp-mt",
                correlationId = "corr-pol",
                causationId = "cause-pol",
                expectedVersion = 1L,
            )
        )
    }

    private fun registerActiveEligiblePlayer(
        playerId: UUID = UUID.randomUUID(),
        selfExcluded: Boolean = false,
        kycStatus: KycComplianceStatus = KycComplianceStatus.VERIFIED,
        coolOffUntil: Instant? = null,
        ageYears: Int = 25,
    ): UUID {
        regStore.players[playerId] = PlayerRegistrationRecord(
            playerId = playerId,
            tenantId = tenantId,
            emailHash = "email-$playerId",
            phoneHash = "phone-$playerId",
            maskedEmail = "player-$playerId@example.com",
            maskedPhone = "+1555123456",
            jurisdiction = jurisdictionMt,
            riskScore = 10.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            emailVerified = true,
            phoneVerified = true,
            createdAt = now.minusSeconds(86400 * 30),
            updatedAt = now.minusSeconds(86400 * 30),
        )

        eligStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerId,
                tenantId = tenantId,
                dateOfBirth = LocalDate.ofInstant(now, ZoneOffset.UTC).minusYears(ageYears.toLong()),
                kycStatus = kycStatus,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = jurisdictionMt,
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerId,
                    selfExcluded = selfExcluded,
                    coolOffUntil = coolOffUntil,
                ),
            )
        )

        eligStore.saveVerdict(
            ServerEligibilityVerdict(
                decisionId = UUID.randomUUID(),
                version = 1L,
                tenantId = tenantId,
                playerId = playerId,
                eligible = !selfExcluded && kycStatus == KycComplianceStatus.VERIFIED && (coolOffUntil == null || coolOffUntil.isBefore(now)),
                accountStatus = PlayerAccountStatus.ACTIVE,
                kycStatus = kycStatus,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = jurisdictionMt,
                ageVerified = true,
                calculatedAge = ageYears,
                minAgeRequired = 21,
                selfExcluded = selfExcluded,
                coolOffUntil = coolOffUntil,
                dailyWagerLimitMinor = null,
                currentDailyWagerMinor = 0L,
                singleWagerLimitMinor = null,
                denialReasons = if (selfExcluded) listOf("SELF_EXCLUDED") else emptyList(),
                evaluatedAt = now,
                expiresAt = now.plusSeconds(3600),
                evidenceReference = "ev-verdict-$playerId",
                auditEvent = AuditEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "ELIGIBILITY_EVALUATED", now, "c", "c"),
                outboxEvent = OutboxEvent(UUID.randomUUID(), UUID.randomUUID(), tenantId, "ELIGIBILITY_EVALUATED", now),
            )
        )

        return playerId
    }

    // =========================================================================
    // GAME-003-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `GAME-003-T001 Launch sessions and tokens produces the required authoritative outcome`() {
        // 1. Verify fail-closed gate throws expected RED assertion error when unbound
        GameLaunchTokenBinding.isBound = false
        val playerId = registerActiveEligiblePlayer()

        val requestCmd = RequestGameLaunchSessionCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            jurisdictionCode = jurisdictionMt,
            currencyCode = currencyUsd,
            requestedBetMinorUnits = 100L,
            idempotencyKey = "launch-idemp-1",
            correlationId = "corr-launch-1",
            causationId = "cause-launch-1",
        )

        val redError = assertFailsWith<AssertionError> {
            launchService.requestLaunchSession(requestCmd)
        }
        assertEquals("replay/expired/wrong-player token", redError.message)

        // Bind the gate
        GameLaunchTokenBinding.isBound = true

        // 2. Perform authoritative launch session request
        val launchResult = launchService.requestLaunchSession(requestCmd)

        // Assert: Launch rechecks jurisdiction/account/game and emits session correlation.
        assertNotNull(launchResult)
        assertEquals(tenantId, launchResult.tenantId)
        assertEquals(playerId, launchResult.playerId)
        assertEquals(providerId, launchResult.providerId)
        assertEquals(gameId, launchResult.gameId)
        assertEquals(jurisdictionMt, launchResult.jurisdictionCode)
        assertEquals(currencyUsd, launchResult.currencyCode)
        assertEquals(GameLaunchSessionStatus.ISSUED, launchResult.status)
        assertTrue(launchResult.sessionCorrelationId.startsWith("sess-corr-"))
        assertTrue(launchResult.launchToken.startsWith("launch_tok_"))
        assertTrue(launchResult.launchUrl.contains("sessionCorrelationId=${launchResult.sessionCorrelationId}"))
        assertTrue(launchResult.launchUrl.contains("launchToken=${launchResult.launchToken}"))
        assertEquals(now.plusSeconds(120L), launchResult.tokenExpiresAt)
        assertEquals(now.plusSeconds(7200L), launchResult.sessionExpiresAt)

        // Verify stored session and audit/outbox events
        val storedSession = launchStore.findSession(tenantId, launchResult.sessionId)
        assertNotNull(storedSession)
        assertEquals(LaunchTokenStatus.ACTIVE, storedSession.tokenStatus)
        assertEquals(GameLaunchSessionStatus.ISSUED, storedSession.status)

        val issuedAudit = launchStore.auditEvents.find { it.type == "GAME_LAUNCH_SESSION_ISSUED" }
        assertNotNull(issuedAudit)
        assertEquals("corr-launch-1", issuedAudit.correlationId)
        assertEquals("cause-launch-1", issuedAudit.causationId)

        // Verify that raw secrets (launchToken) are never leaked into audit or outbox
        assertFalse(issuedAudit.toString().contains(launchResult.launchToken))
        val issuedOutbox = launchStore.outboxEvents.find { it.type == "GAME_LAUNCH_SESSION_ISSUED" }
        assertNotNull(issuedOutbox)
        assertFalse(issuedOutbox.toString().contains(launchResult.launchToken))

        // 3. Consume/validate launch token by provider/client boundary
        val validateCmd = ValidateLaunchTokenCommand(
            tenantId = tenantId,
            sessionId = launchResult.sessionId,
            launchToken = launchResult.launchToken,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            correlationId = "corr-validate-1",
            causationId = "cause-validate-1",
        )

        val validateResult = launchService.validateOrConsumeLaunchToken(validateCmd)
        assertNotNull(validateResult)
        assertTrue(validateResult.authorized)
        assertEquals(GameLaunchSessionStatus.ACTIVE, validateResult.sessionStatus)
        assertEquals(launchResult.sessionCorrelationId, validateResult.sessionCorrelationId)
        assertEquals(playerId, validateResult.playerId)

        // Verify session transitioned to ACTIVE and token to CONSUMED
        val consumedSession = launchStore.findSession(tenantId, launchResult.sessionId)
        assertNotNull(consumedSession)
        assertEquals(LaunchTokenStatus.CONSUMED, consumedSession.tokenStatus)
        assertEquals(GameLaunchSessionStatus.ACTIVE, consumedSession.status)
        assertEquals(now, consumedSession.consumedAt)

        val consumedAudit = launchStore.auditEvents.find { it.type == "GAME_LAUNCH_TOKEN_CONSUMED" }
        assertNotNull(consumedAudit)
        assertEquals("corr-validate-1", consumedAudit.correlationId)
    }

    // =========================================================================
    // GAME-003-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `GAME-003-T002 Launch sessions and tokens rejects invalid, boundary, unauthorized, and stale input`() {
        val playerId = registerActiveEligiblePlayer()

        // 1. Invalid / blank input variants
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = "",
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = "INVALID_CURRENCY",
                    idempotencyKey = "k2",
                    correlationId = "c2",
                    causationId = "c2",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k3",
                    correlationId = "c3",
                    causationId = "c3",
                    expectedVersion = 2L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 3. Game disabled by operator
        operatorService.updateOperatorGameEnablement(
            EnforceOperatorGameEnablementCommand(
                principal = adminPrincipal,
                sessionId = "admin-sess-1",
                tenantId = tenantId,
                providerId = providerId,
                gameId = gameId,
                newStatus = GameEnablementStatus.DISABLED_BY_OPERATOR,
                reason = "Disabled for compliance review",
                idempotencyKey = "op-disable-1",
                correlationId = "corr-dis",
                causationId = "cause-dis",
                expectedVersion = 2L,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k-disabled",
                    correlationId = "c-dis",
                    causationId = "cause-dis",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Re-enable the game for subsequent tests
        operatorService.updateOperatorGameEnablement(
            EnforceOperatorGameEnablementCommand(
                principal = adminPrincipal,
                sessionId = "admin-sess-1",
                tenantId = tenantId,
                providerId = providerId,
                gameId = gameId,
                newStatus = GameEnablementStatus.ENABLED,
                reason = "Re-enabled",
                idempotencyKey = "op-enable-1",
                correlationId = "corr-en",
                causationId = "cause-en",
                expectedVersion = 3L,
            )
        )

        // 4. Ineligible account: Self-Excluded Player
        val selfExcludedPlayerId = registerActiveEligiblePlayer(selfExcluded = true)
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = tenantId,
                    playerId = selfExcludedPlayerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k-self-ex",
                    correlationId = "c-se",
                    causationId = "cause-se",
                )
            )
        }.also {
            assertEquals(AuthErrorCode.FORBIDDEN, it.code)
            assertTrue(alertSink.alerts.any { a -> a.contains("SELF_EXCLUDED_LAUNCH_ATTEMPT") })
        }

        // 5. Ineligible account: Cool-off period active
        val coolOffPlayerId = registerActiveEligiblePlayer(coolOffUntil = now.plusSeconds(3600))
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = tenantId,
                    playerId = coolOffPlayerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k-cool-off",
                    correlationId = "c-co",
                    causationId = "cause-co",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Ineligible account: Underage (< 21)
        val underagePlayerId = registerActiveEligiblePlayer(ageYears = 19)
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = tenantId,
                    playerId = underagePlayerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k-underage",
                    correlationId = "c-ua",
                    causationId = "cause-ua",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Issue valid launch session for token validation negative tests
        val validLaunch = launchService.requestLaunchSession(
            RequestGameLaunchSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                jurisdictionCode = jurisdictionMt,
                currencyCode = currencyUsd,
                idempotencyKey = "k-valid-session",
                correlationId = "c-vs",
                causationId = "cause-vs",
            )
        )

        // 7. Wrong-Player Token Exchange (Attempted token hijack)
        val attackerPlayerId = registerActiveEligiblePlayer()
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.validateOrConsumeLaunchToken(
                ValidateLaunchTokenCommand(
                    tenantId = tenantId,
                    sessionId = validLaunch.sessionId,
                    launchToken = validLaunch.launchToken,
                    playerId = attackerPlayerId, // Wrong player!
                    providerId = providerId,
                    gameId = gameId,
                    correlationId = "c-hijack",
                    causationId = "cause-hijack",
                )
            )
        }.also {
            assertEquals(AuthErrorCode.FORBIDDEN, it.code)
            assertTrue(alertSink.alerts.any { a -> a.contains("LAUNCH_TOKEN_WRONG_PLAYER_DETECTED") })
        }

        // 8. Wrong-Game / Wrong-Provider Token Exchange
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.validateOrConsumeLaunchToken(
                ValidateLaunchTokenCommand(
                    tenantId = tenantId,
                    sessionId = validLaunch.sessionId,
                    launchToken = validLaunch.launchToken,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = "game-wrong-game-id", // Wrong game!
                    correlationId = "c-wg",
                    causationId = "cause-wg",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 9. Expired Token Exchange
        val expiredClock = Clock.fixed(now.plusSeconds(130L), ZoneOffset.UTC) // Past 120s TTL
        val expiredLaunchService = GameLaunchSessionService(
            operatorEnablementService = operatorService,
            registrationStore = regStore,
            eligibilityStore = eligStore,
            launchStore = launchStore,
            alertSink = alertSink,
            clock = expiredClock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredLaunchService.validateOrConsumeLaunchToken(
                ValidateLaunchTokenCommand(
                    tenantId = tenantId,
                    sessionId = validLaunch.sessionId,
                    launchToken = validLaunch.launchToken,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    correlationId = "c-exp",
                    causationId = "cause-exp",
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 10. Replay of Already Consumed Token
        val freshLaunch = launchService.requestLaunchSession(
            RequestGameLaunchSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                jurisdictionCode = jurisdictionMt,
                currencyCode = currencyUsd,
                idempotencyKey = "k-fresh-replay-test",
                correlationId = "c-fr",
                causationId = "cause-fr",
            )
        )
        // First consume succeeds
        val firstConsume = launchService.validateOrConsumeLaunchToken(
            ValidateLaunchTokenCommand(
                tenantId = tenantId,
                sessionId = freshLaunch.sessionId,
                launchToken = freshLaunch.launchToken,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                correlationId = "c-consume-1",
                causationId = "cause-consume-1",
            )
        )
        assertTrue(firstConsume.authorized)

        // Second consume (replay) MUST fail closed with CONFLICT and alert
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.validateOrConsumeLaunchToken(
                ValidateLaunchTokenCommand(
                    tenantId = tenantId,
                    sessionId = freshLaunch.sessionId,
                    launchToken = freshLaunch.launchToken,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    correlationId = "c-replay",
                    causationId = "cause-replay",
                )
            )
        }.also {
            assertEquals(AuthErrorCode.CONFLICT, it.code)
            assertTrue(alertSink.alerts.any { a -> a.contains("LAUNCH_TOKEN_REPLAY_DETECTED") })
        }

        // 11. Invalid Token Hash Mismatch
        val freshLaunch2 = launchService.requestLaunchSession(
            RequestGameLaunchSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                jurisdictionCode = jurisdictionMt,
                currencyCode = currencyUsd,
                idempotencyKey = "k-tamper-token",
                correlationId = "c-tt",
                causationId = "cause-tt",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.validateOrConsumeLaunchToken(
                ValidateLaunchTokenCommand(
                    tenantId = tenantId,
                    sessionId = freshLaunch2.sessionId,
                    launchToken = "tampered_token_invalid_hash",
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    correlationId = "c-tamper",
                    causationId = "cause-tamper",
                )
            )
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }
    }

    // =========================================================================
    // GAME-003-T003: Concurrency, Duplicate Delivery, and Dependency Failure
    // =========================================================================

    @Test
    fun `GAME-003-T003 Launch sessions and tokens survives concurrency, duplicate delivery, and dependency failure`() {
        val playerId = registerActiveEligiblePlayer()

        // 1. Idempotent request replay (identical payload) returns identical result
        val reqCmd = RequestGameLaunchSessionCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameId,
            jurisdictionCode = jurisdictionMt,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-launch-concurrent-1",
            correlationId = "corr-concurrent-1",
            causationId = "cause-concurrent-1",
        )
        val initialResult = launchService.requestLaunchSession(reqCmd)
        val replayResult = launchService.requestLaunchSession(reqCmd)
        assertEquals(initialResult.sessionId, replayResult.sessionId)
        assertEquals(initialResult.launchToken, replayResult.launchToken)
        assertEquals(initialResult.sessionCorrelationId, replayResult.sessionCorrelationId)

        // 2. Changed payload with same idempotency key fails with CONFLICT
        val conflictingCmd = reqCmd.copy(currencyCode = "EUR")
        assertFailsWith<AuthenticationFailure.Rejected> {
            launchService.requestLaunchSession(conflictingCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrent single-use token consumption race
        val concurrentLaunch = launchService.requestLaunchSession(
            RequestGameLaunchSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                jurisdictionCode = jurisdictionMt,
                currencyCode = currencyUsd,
                idempotencyKey = "idemp-race-token",
                correlationId = "corr-race",
                causationId = "cause-race",
            )
        )

        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val successCount = AtomicInteger(0)
        val conflictCount = AtomicInteger(0)

        for (i in 1..threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = launchService.validateOrConsumeLaunchToken(
                        ValidateLaunchTokenCommand(
                            tenantId = tenantId,
                            sessionId = concurrentLaunch.sessionId,
                            launchToken = concurrentLaunch.launchToken,
                            playerId = playerId,
                            providerId = providerId,
                            gameId = gameId,
                            correlationId = "corr-race-$i",
                            causationId = "cause-race-$i",
                        )
                    )
                    if (res.authorized) {
                        successCount.incrementAndGet()
                    }
                } catch (e: AuthenticationFailure.Rejected) {
                    if (e.code == AuthErrorCode.CONFLICT) {
                        conflictCount.incrementAndGet()
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        // Exactly one thread must succeed and exactly 9 must fail with CONFLICT (replay detected)
        assertEquals(1, successCount.get(), "Only exactly one thread may consume single-use launch token")
        assertEquals(9, conflictCount.get(), "All other concurrent attempts must be rejected as replays")

        // 4. Dependency failure fails closed with DEPENDENCY_UNAVAILABLE
        val failingRegStore = LaunchFailingRegistrationStore()
        val failingLaunchService = GameLaunchSessionService(
            operatorEnablementService = operatorService,
            registrationStore = failingRegStore,
            eligibilityStore = eligStore,
            launchStore = launchStore,
            alertSink = alertSink,
            clock = clock,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            failingLaunchService.requestLaunchSession(
                RequestGameLaunchSessionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameId,
                    jurisdictionCode = jurisdictionMt,
                    currencyCode = currencyUsd,
                    idempotencyKey = "idemp-failing-dep",
                    correlationId = "corr-fail",
                    causationId = "cause-fail",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    // =========================================================================
    // GAME-003-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `GAME-003-T004 Launch sessions and tokens remains compatible, recoverable, observable, and lifecycle-safe`() {
        val playerId = registerActiveEligiblePlayer()

        // 1. Create a launch session
        val launchResult = launchService.requestLaunchSession(
            RequestGameLaunchSessionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                jurisdictionCode = jurisdictionMt,
                currencyCode = currencyUsd,
                idempotencyKey = "idemp-lifecycle-1",
                correlationId = "corr-lifecycle-1",
                causationId = "cause-lifecycle-1",
            )
        )

        // 2. Re-instantiate service (simulating application restart / migration)
        val restartedService = GameLaunchSessionService(
            operatorEnablementService = operatorService,
            registrationStore = regStore,
            eligibilityStore = eligStore,
            launchStore = launchStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Validate token against restarted service: state recovered accurately
        val validateResult = restartedService.validateOrConsumeLaunchToken(
            ValidateLaunchTokenCommand(
                tenantId = tenantId,
                sessionId = launchResult.sessionId,
                launchToken = launchResult.launchToken,
                playerId = playerId,
                providerId = providerId,
                gameId = gameId,
                correlationId = "corr-restart-val",
                causationId = "cause-restart-val",
            )
        )
        assertTrue(validateResult.authorized)
        assertEquals(GameLaunchSessionStatus.ACTIVE, validateResult.sessionStatus)

        // 3. Terminate launch session (lifecycle termination)
        val termCmd = TerminateLaunchSessionCommand(
            tenantId = tenantId,
            sessionId = launchResult.sessionId,
            playerId = playerId,
            reason = "Player exited game client",
            idempotencyKey = "idemp-term-1",
            correlationId = "corr-term-1",
            causationId = "cause-term-1",
        )
        val termResult = restartedService.terminateSession(termCmd)
        assertEquals(GameLaunchSessionStatus.TERMINATED, termResult.status)
        assertEquals(now, termResult.terminatedAt)

        // Idempotent replay of termination
        val termReplay = restartedService.terminateSession(termCmd)
        assertEquals(termResult.resultId, termReplay.resultId)
        assertEquals(termResult.status, termReplay.status)

        // 4. Observability & Redaction checks
        val auditEvents = launchStore.auditEvents
        val outboxEvents = launchStore.outboxEvents
        assertTrue(auditEvents.isNotEmpty(), "Audit events must be recorded")
        assertTrue(outboxEvents.isNotEmpty(), "Outbox events must be recorded")

        for (event in auditEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.occurredAt)
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
            // Verify zero raw secrets or unmasked PII in audit records
            assertFalse(event.toString().contains(launchResult.launchToken))
        }

        for (event in outboxEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.createdAt)
            assertFalse(event.toString().contains(launchResult.launchToken))
        }
    }
}

// =============================================================================
// Test Fakes & In-Memory Helpers (isolated to this test suite)
// =============================================================================

class LaunchTestSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T18:00:00Z"),
        )
}

class LaunchTestJurisdictionStore : OperatorJurisdictionEnablementStore {
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

class LaunchTestCatalogStore : AuthoritativeCatalogStore {
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

class LaunchFailingRegistrationStore : PlayerRegistrationStore {
    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? {
        throw RuntimeException("Database connection timeout")
    }

    override fun saveRegistration(
        command: RegisterPlayerCommand,
        result: RegisterPlayerResult,
        record: PlayerRegistrationRecord,
        verificationCodes: List<VerificationCodeRecord>
    ) {
        throw RuntimeException("Database connection timeout")
    }

    override fun saveVerification(
        command: VerifyContactCommand,
        result: VerifyContactResult,
        record: PlayerRegistrationRecord,
        verificationCode: VerificationCodeRecord
    ) {
        throw RuntimeException("Database connection timeout")
    }

    override fun findByEmailHash(tenantId: String, emailHash: String): PlayerRegistrationRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun findByPhoneHash(tenantId: String, phoneHash: String): PlayerRegistrationRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun findById(tenantId: String, playerId: UUID): PlayerRegistrationRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun findVerificationCode(tenantId: String, playerId: UUID, channel: ContactVerificationChannel): VerificationCodeRecord? {
        throw RuntimeException("Database connection timeout")
    }

    override fun currentVersion(tenantId: String, playerId: UUID): Long {
        throw RuntimeException("Database connection timeout")
    }
}
