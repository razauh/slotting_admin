package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import com.slotting.admin.geo.GeoVendorOutcome
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class JurisdictionRestrictionTest {

    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-casino-jur"
    private val providerId = "prov-netent"
    private val gameIdStarburst = "game-starburst"
    private val gameIdAviator = "game-aviator"
    private val jurisdictionMt = "MT"
    private val jurisdictionUk = "UK"
    private val jurisdictionNy = "US-NY"
    private val currencyUsd = "USD"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-compliance-lead",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPPORT),
    )

    private lateinit var catalogStore: JurResTestCatalogStore
    private lateinit var jurStore: JurResTestJurisdictionStore
    private lateinit var restrictionStore: InMemoryJurisdictionRestrictionStore
    private lateinit var alertSink: InMemoryJurisdictionAlertSink
    private lateinit var sessionDirectory: JurResTestSessionDirectory
    private lateinit var operatorService: OperatorJurisdictionEnablementService
    private lateinit var restrictionService: JurisdictionRestrictionService

    @BeforeEach
    fun setUp() {
        JurisdictionRestrictionBinding.isBound = true
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true

        catalogStore = JurResTestCatalogStore()
        jurStore = JurResTestJurisdictionStore()
        restrictionStore = InMemoryJurisdictionRestrictionStore()
        alertSink = InMemoryJurisdictionAlertSink()
        sessionDirectory = JurResTestSessionDirectory()

        operatorService = OperatorJurisdictionEnablementService(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory,
            catalogStore = catalogStore,
            store = jurStore,
            clock = clock,
        )

        restrictionService = JurisdictionRestrictionService(
            operatorJurisdictionService = operatorService,
            catalogStore = catalogStore,
            store = restrictionStore,
            alertSink = alertSink,
            clock = clock,
            maxLocationAgeSeconds = 900L,
            minimumConfidenceThreshold = 0.70,
        )

        setupCatalogAndPolicies()
    }

    @AfterEach
    fun tearDown() {
        JurisdictionRestrictionBinding.isBound = true
        OperatorJurisdictionEnablementBinding.isBound = true
        AuthoritativeCatalogSyncBinding.isBound = true
    }

    private fun setupCatalogAndPolicies() {
        // Setup catalog games
        val starburst = CatalogGameEntry(
            tenantId = tenantId,
            providerId = providerId,
            gameId = gameIdStarburst,
            gameTitle = "Starburst",
            gameType = CasinoProviderType.SLOTS,
            supportedJurisdictions = setOf(jurisdictionMt, jurisdictionUk),
            rtpPercent = 96.1,
            minBetMinorUnits = 10L,
            maxBetMinorUnits = 10000L,
            enablementStatus = GameEnablementStatus.ENABLED,
            lastSynchronizedAt = now,
            staleSyncThresholdSeconds = 86400L,
            version = 1L,
        )
        val aviator = CatalogGameEntry(
            tenantId = tenantId,
            providerId = providerId,
            gameId = gameIdAviator,
            gameTitle = "Aviator Crash",
            gameType = CasinoProviderType.CRASH_AVIATOR,
            supportedJurisdictions = setOf(jurisdictionMt),
            rtpPercent = 97.0,
            minBetMinorUnits = 20L,
            maxBetMinorUnits = 50000L,
            enablementStatus = GameEnablementStatus.ENABLED,
            lastSynchronizedAt = now,
            staleSyncThresholdSeconds = 86400L,
            version = 1L,
        )
        catalogStore.saveGame(starburst)
        catalogStore.saveGame(aviator)

        // Setup MT jurisdiction policy: allows SLOTS and CRASH_AVIATOR, maxBet 50000, rtpFloor 90.0
        operatorService.configureJurisdictionPolicy(
            ConfigureJurisdictionPolicyCommand(
                principal = adminPrincipal,
                sessionId = "admin-sess-1",
                tenantId = tenantId,
                jurisdictionCode = jurisdictionMt,
                status = JurisdictionComplianceStatus.ACTIVE,
                allowedGameTypes = setOf(CasinoProviderType.SLOTS, CasinoProviderType.CRASH_AVIATOR),
                maxBetLimitMinorUnits = 50000L,
                rtpFloorPercent = 90.0,
                restrictedGameIds = emptySet(),
                effectiveFrom = now.minusSeconds(86400),
                effectiveUntil = now.plusSeconds(86400 * 365),
                complianceSigner = "MGA-LEGAL-OFFICER-4",
                idempotencyKey = "pol-idemp-mt",
                correlationId = "corr-pol-mt",
                causationId = "cause-pol-mt",
                expectedVersion = 1L,
            )
        )

        // Setup UK jurisdiction policy: allows SLOTS only (disallows CRASH_AVIATOR), maxBet 2000
        operatorService.configureJurisdictionPolicy(
            ConfigureJurisdictionPolicyCommand(
                principal = adminPrincipal,
                sessionId = "admin-sess-1",
                tenantId = tenantId,
                jurisdictionCode = jurisdictionUk,
                status = JurisdictionComplianceStatus.ACTIVE,
                allowedGameTypes = setOf(CasinoProviderType.SLOTS),
                maxBetLimitMinorUnits = 2000L,
                rtpFloorPercent = 92.0,
                restrictedGameIds = emptySet(),
                effectiveFrom = now.minusSeconds(86400),
                effectiveUntil = now.plusSeconds(86400 * 365),
                complianceSigner = "UKGC-OFFICER-12",
                idempotencyKey = "pol-idemp-uk",
                correlationId = "corr-pol-uk",
                causationId = "cause-pol-uk",
                expectedVersion = 1L,
            )
        )
    }

    private fun createValidLocation(
        playerId: UUID,
        jurisdiction: String = jurisdictionMt,
        verifiedAgeSeconds: Long = 60L,
        expiresInSeconds: Long = 840L,
        isProxyOrVpn: Boolean = false,
        isMockLocation: Boolean = false,
        confidenceScore: Double = 0.98,
        vendorOutcome: GeoVendorOutcome = GeoVendorOutcome.PERMITTED_JURISDICTION,
    ) = LocationEvidence(
        evidenceId = UUID.randomUUID(),
        tenantId = tenantId,
        playerId = playerId,
        ipAddress = "185.12.34.56",
        countryCode = if (jurisdiction.startsWith("US")) "US" else jurisdiction,
        jurisdictionCode = jurisdiction,
        latitude = 35.8989,
        longitude = 14.5146,
        accuracyMeters = 15.0,
        isProxyOrVpn = isProxyOrVpn,
        isMockLocation = isMockLocation,
        confidenceScore = confidenceScore,
        vendorOutcome = vendorOutcome,
        verifiedAt = now.minusSeconds(verifiedAgeSeconds),
        expiresAt = now.plusSeconds(expiresInSeconds),
    )

    // =========================================================================
    // GAME-004-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `GAME-004-T001 Jurisdiction restrictions produces the required authoritative outcome`() {
        // 1. Prove fail-closed gate throws expected RED assertion error when unbound
        JurisdictionRestrictionBinding.isBound = false
        val playerId = UUID.randomUUID()
        val loc = createValidLocation(playerId, jurisdictionMt)

        val cmd = EvaluateJurisdictionRestrictionCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameIdStarburst,
            gameType = CasinoProviderType.SLOTS,
            locationEvidence = loc,
            requestedBetMinorUnits = 100L,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-jur-t001",
            correlationId = "corr-jur-1",
            causationId = "cause-jur-1",
        )

        val redError = assertFailsWith<AssertionError> {
            restrictionService.evaluateRestrictions(cmd)
        }
        assertEquals("location expiry/bypass", redError.message)

        // Bind the gate
        JurisdictionRestrictionBinding.isBound = true

        // 2. Perform authoritative restriction evaluation
        val result = restrictionService.evaluateRestrictions(cmd)

        // Assert: Fail closed, reason safe for player, full reason restricted to ops.
        assertNotNull(result)
        assertTrue(result.permitted)
        assertEquals(JurisdictionRestrictionDecision.PERMITTED, result.decision)
        assertEquals(tenantId, result.tenantId)
        assertEquals(playerId, result.playerId)
        assertEquals(gameIdStarburst, result.gameId)
        assertEquals(jurisdictionMt, result.evaluatedJurisdiction)
        assertNull(result.playerSafeReason, "PERMITTED outcome must not have a failure reason safe for player")
        assertNotNull(result.opsDetailedReason)
        assertTrue(result.opsDetailedReason!!.contains("Permitted: Verified location in jurisdiction MT"))

        // Assert durable store and audit/outbox persistence
        val saved = restrictionStore.findLatestDecision(tenantId, playerId, gameIdStarburst)
        assertNotNull(saved)
        assertEquals(result.resultId, saved.resultId)
        assertEquals(JurisdictionRestrictionDecision.PERMITTED, saved.decision)

        val audit = restrictionStore.auditEvents.find { it.type == "JURISDICTION_RESTRICTION_PERMITTED" }
        assertNotNull(audit)
        assertEquals("corr-jur-1", audit.correlationId)
        assertEquals("cause-jur-1", audit.causationId)

        val outbox = restrictionStore.outboxEvents.find { it.type == "JURISDICTION_RESTRICTION_PERMITTED" }
        assertNotNull(outbox)
        assertEquals(tenantId, outbox.tenantId)
    }

    // =========================================================================
    // GAME-004-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `GAME-004-T002 Jurisdiction restrictions rejects invalid, boundary, unauthorized, and stale input`() {
        val playerId = UUID.randomUUID()

        // 1. Invalid / malformed inputs
        assertFailsWith<AuthenticationFailure.Rejected> {
            restrictionService.evaluateRestrictions(
                EvaluateJurisdictionRestrictionCommand(
                    tenantId = "",
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameIdStarburst,
                    gameType = CasinoProviderType.SLOTS,
                    locationEvidence = createValidLocation(playerId),
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            restrictionService.evaluateRestrictions(
                EvaluateJurisdictionRestrictionCommand(
                    tenantId = tenantId,
                    playerId = playerId,
                    providerId = providerId,
                    gameId = gameIdStarburst,
                    gameType = CasinoProviderType.SLOTS,
                    locationEvidence = createValidLocation(playerId),
                    idempotencyKey = "k2",
                    correlationId = "c2",
                    causationId = "c2",
                    expectedVersion = 2L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 2. Missing / null location evidence -> Fails closed with safe reason for player and full reason for ops
        val nullLocResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = null,
                idempotencyKey = "k-null-loc",
                correlationId = "c-nl",
                causationId = "cause-nl",
            )
        )
        assertFalse(nullLocResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_INDETERMINATE_LOCATION, nullLocResult.decision)
        assertEquals("Unable to verify your location. Please check your device location settings.", nullLocResult.playerSafeReason)
        assertTrue(nullLocResult.opsDetailedReason!!.contains("Location evidence is missing or null"))

        // 3. Location Expiry (Protected Risk: location expiry)
        val expiredLoc = createValidLocation(
            playerId = playerId,
            verifiedAgeSeconds = 1200L, // 1200s > max 900s
            expiresInSeconds = -10L,     // Expired 10s ago
        )
        val expiredResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = expiredLoc,
                idempotencyKey = "k-exp-loc",
                correlationId = "c-el",
                causationId = "cause-el",
            )
        )
        assertFalse(expiredResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_LOCATION_EXPIRED, expiredResult.decision)
        assertEquals("Location verification expired. Please re-verify your location to continue.", expiredResult.playerSafeReason)
        assertTrue(expiredResult.opsDetailedReason!!.contains("Location evidence expired"))

        // 4. Location Bypass / Proxy or VPN detected (Protected Risk: location bypass)
        val vpnLoc = createValidLocation(
            playerId = playerId,
            isProxyOrVpn = true,
            vendorOutcome = GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN,
        )
        val vpnResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = vpnLoc,
                idempotencyKey = "k-vpn-loc",
                correlationId = "c-vpn",
                causationId = "cause-vpn",
            )
        )
        assertFalse(vpnResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_BYPASS_DETECTED, vpnResult.decision)
        assertEquals("Game is unavailable from your current network or location.", vpnResult.playerSafeReason)
        assertTrue(vpnResult.opsDetailedReason!!.contains("Proxy/VPN or mock location bypass detected"))
        assertTrue(alertSink.alerts.any { it.contains("GEO_LOCATION_BYPASS_ATTEMPT") })

        // 5. Location Bypass / Mock Location detected
        val mockLoc = createValidLocation(
            playerId = playerId,
            isMockLocation = true,
        )
        val mockResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = mockLoc,
                idempotencyKey = "k-mock-loc",
                correlationId = "c-mock",
                causationId = "cause-mock",
            )
        )
        assertFalse(mockResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_BYPASS_DETECTED, mockResult.decision)
        assertEquals("Game is unavailable from your current network or location.", mockResult.playerSafeReason)

        // 6. Cross-Player / Ownership Mismatch
        val hijackedLoc = createValidLocation(
            playerId = UUID.randomUUID(), // Different player ID
        )
        val mismatchResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = hijackedLoc,
                idempotencyKey = "k-mismatch-loc",
                correlationId = "c-mm",
                causationId = "cause-mm",
            )
        )
        assertFalse(mismatchResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_BYPASS_DETECTED, mismatchResult.decision)
        assertEquals("Location verification error. Please reconnect.", mismatchResult.playerSafeReason)
        assertTrue(alertSink.alerts.any { it.contains("LOCATION_EVIDENCE_MISMATCH") })

        // 7. Low Confidence / Indeterminate Location
        val lowConfLoc = createValidLocation(
            playerId = playerId,
            confidenceScore = 0.45, // Below 0.70 threshold
        )
        val lowConfResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = lowConfLoc,
                idempotencyKey = "k-low-conf",
                correlationId = "c-lc",
                causationId = "cause-lc",
            )
        )
        assertFalse(lowConfResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_INDETERMINATE_LOCATION, lowConfResult.decision)
        assertEquals("Unable to reliably verify your location. Please try again.", lowConfResult.playerSafeReason)

        // 8. Prohibited / Unlicensed Jurisdiction (NY not in game's supported jurisdictions)
        val nyLoc = createValidLocation(
            playerId = playerId,
            jurisdiction = jurisdictionNy,
        )
        val unlicensedResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = nyLoc,
                idempotencyKey = "k-unlicensed",
                correlationId = "c-un",
                causationId = "cause-un",
            )
        )
        assertFalse(unlicensedResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_UNLICENSED_JURISDICTION, unlicensedResult.decision)
        assertEquals("This game is not available in your region.", unlicensedResult.playerSafeReason)
        assertTrue(unlicensedResult.opsDetailedReason!!.contains("not in game supportedJurisdictions"))

        // 9. Game Type Prohibited in Jurisdiction (Aviator crash game disallowed in UK)
        val ukLoc = createValidLocation(
            playerId = playerId,
            jurisdiction = jurisdictionUk,
        )
        val typeDisallowedResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdAviator,
                gameType = CasinoProviderType.CRASH_AVIATOR,
                locationEvidence = ukLoc,
                idempotencyKey = "k-disallowed-type",
                correlationId = "c-dt",
                causationId = "cause-dt",
            )
        )
        assertFalse(typeDisallowedResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_UNLICENSED_JURISDICTION, typeDisallowedResult.decision)
        assertEquals("This game is not available in your region.", typeDisallowedResult.playerSafeReason)

        // 10. Bet Limit Exceeded in Jurisdiction (bet 5000 > UK maxBet 2000)
        val betExceededResult = restrictionService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = ukLoc,
                requestedBetMinorUnits = 5000L, // Exceeds UK 2000 limit
                idempotencyKey = "k-bet-exceeded",
                correlationId = "c-be",
                causationId = "cause-be",
            )
        )
        assertFalse(betExceededResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_BET_LIMIT_EXCEEDED, betExceededResult.decision)
        assertEquals("Requested bet exceeds regulatory limit for your region.", betExceededResult.playerSafeReason)
        assertTrue(betExceededResult.opsDetailedReason!!.contains("Bet limit or RTP compliance check failed"))
    }

    // =========================================================================
    // GAME-004-T003: Concurrency, Duplicate Delivery, and Dependency Failure
    // =========================================================================

    @Test
    fun `GAME-004-T003 Jurisdiction restrictions survives concurrency, duplicate delivery, and dependency failure`() {
        val playerId = UUID.randomUUID()
        val loc = createValidLocation(playerId, jurisdictionMt)

        // 1. Idempotent request replay (identical payload) returns identical result
        val cmd = EvaluateJurisdictionRestrictionCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameIdStarburst,
            gameType = CasinoProviderType.SLOTS,
            locationEvidence = loc,
            requestedBetMinorUnits = 100L,
            idempotencyKey = "idemp-jur-concurrent-1",
            correlationId = "corr-c1",
            causationId = "cause-c1",
        )
        val initialResult = restrictionService.evaluateRestrictions(cmd)
        val replayResult = restrictionService.evaluateRestrictions(cmd)
        assertEquals(initialResult.resultId, replayResult.resultId)
        assertEquals(initialResult.decision, replayResult.decision)
        assertEquals(initialResult.permitted, replayResult.permitted)

        // 2. Changed payload with same idempotency key fails with CONFLICT
        val conflictingCmd = cmd.copy(requestedBetMinorUnits = 500L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            restrictionService.evaluateRestrictions(conflictingCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrent evaluation under high thread load
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val successCount = AtomicInteger(0)

        for (i in 1..threadCount) {
            val threadPlayerId = UUID.randomUUID()
            val threadLoc = createValidLocation(threadPlayerId, jurisdictionMt)
            executor.submit {
                try {
                    startLatch.await()
                    val res = restrictionService.evaluateRestrictions(
                        EvaluateJurisdictionRestrictionCommand(
                            tenantId = tenantId,
                            playerId = threadPlayerId,
                            providerId = providerId,
                            gameId = gameIdStarburst,
                            gameType = CasinoProviderType.SLOTS,
                            locationEvidence = threadLoc,
                            requestedBetMinorUnits = 100L,
                            idempotencyKey = "idemp-race-jur-$i",
                            correlationId = "corr-race-$i",
                            causationId = "cause-race-$i",
                        )
                    )
                    if (res.permitted) {
                        successCount.incrementAndGet()
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertEquals(threadCount, successCount.get(), "All parallel permitted evaluations must succeed without race conditions")

        // 4. Dependency failure fails closed with RESTRICTED_DEPENDENCY_FAILURE
        val failingCatalogStore = JurResFailingCatalogStore()
        val failingService = JurisdictionRestrictionService(
            operatorJurisdictionService = operatorService,
            catalogStore = failingCatalogStore,
            store = restrictionStore,
            alertSink = alertSink,
            clock = clock,
        )

        val depFailResult = failingService.evaluateRestrictions(
            EvaluateJurisdictionRestrictionCommand(
                tenantId = tenantId,
                playerId = playerId,
                providerId = providerId,
                gameId = gameIdStarburst,
                gameType = CasinoProviderType.SLOTS,
                locationEvidence = loc,
                idempotencyKey = "idemp-dep-fail",
                correlationId = "corr-df",
                causationId = "cause-df",
            )
        )
        assertFalse(depFailResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_DEPENDENCY_FAILURE, depFailResult.decision)
        assertEquals("Game service is temporarily unavailable. Please try again later.", depFailResult.playerSafeReason)
        assertTrue(depFailResult.opsDetailedReason!!.contains("Catalog lookup dependency failed"))
    }

    // =========================================================================
    // GAME-004-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `GAME-004-T004 Jurisdiction restrictions remains compatible, recoverable, observable, and lifecycle-safe`() {
        val playerId = UUID.randomUUID()
        val loc = createValidLocation(playerId, jurisdictionMt)

        // 1. Initial permitted evaluation
        val cmd = EvaluateJurisdictionRestrictionCommand(
            tenantId = tenantId,
            playerId = playerId,
            providerId = providerId,
            gameId = gameIdStarburst,
            gameType = CasinoProviderType.SLOTS,
            locationEvidence = loc,
            idempotencyKey = "idemp-lifecycle-t004",
            correlationId = "corr-lifecycle-1",
            causationId = "cause-lifecycle-1",
        )
        val initialResult = restrictionService.evaluateRestrictions(cmd)
        assertTrue(initialResult.permitted)

        // 2. Re-instantiate service (simulating application restart / migration)
        val restartedService = JurisdictionRestrictionService(
            operatorJurisdictionService = operatorService,
            catalogStore = catalogStore,
            store = restrictionStore,
            alertSink = alertSink,
            clock = clock,
        )

        // State recovered accurately from store
        val latest = restrictionStore.findLatestDecision(tenantId, playerId, gameIdStarburst)
        assertNotNull(latest)
        assertEquals(initialResult.resultId, latest.resultId)
        assertEquals(JurisdictionRestrictionDecision.PERMITTED, latest.decision)

        // 3. Operational Policy Change: Disable Starburst by Operator
        operatorService.updateOperatorGameEnablement(
            EnforceOperatorGameEnablementCommand(
                principal = adminPrincipal,
                sessionId = "admin-sess-1",
                tenantId = tenantId,
                providerId = providerId,
                gameId = gameIdStarburst,
                newStatus = GameEnablementStatus.DISABLED_BY_OPERATOR,
                reason = "Emergency regulatory disablement",
                idempotencyKey = "idemp-op-disable-lifecycle",
                correlationId = "corr-dis-lc",
                causationId = "cause-dis-lc",
                expectedVersion = 2L,
            )
        )

        // Subsequent evaluation must immediately fail closed without modifying historical records
        val disabledResult = restartedService.evaluateRestrictions(
            cmd.copy(idempotencyKey = "idemp-after-disable")
        )
        assertFalse(disabledResult.permitted)
        assertEquals(JurisdictionRestrictionDecision.RESTRICTED_GAME_TYPE_PROHIBITED, disabledResult.decision)
        assertEquals("This game is currently disabled.", disabledResult.playerSafeReason)
        assertTrue(disabledResult.opsDetailedReason!!.contains("Game disabled by operator or regulatory policy"))

        // Historical initialResult remains immutable in audit logs
        val auditEvents = restrictionStore.auditEvents
        val outboxEvents = restrictionStore.outboxEvents
        assertTrue(auditEvents.any { it.type == "JURISDICTION_RESTRICTION_PERMITTED" })
        assertTrue(auditEvents.any { it.type == "JURISDICTION_RESTRICTION_ENFORCED" })

        for (event in auditEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.occurredAt)
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
        }

        for (event in outboxEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.createdAt)
        }
    }
}

// =============================================================================
// Test Fakes & In-Memory Helpers (isolated to this test suite)
// =============================================================================

class JurResTestSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T18:00:00Z"),
        )
}

class JurResTestJurisdictionStore : OperatorJurisdictionEnablementStore {
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

class JurResTestCatalogStore : AuthoritativeCatalogStore {
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

class JurResFailingCatalogStore : AuthoritativeCatalogStore {
    override fun findGame(tenantId: String, providerId: String, gameId: String): CatalogGameEntry? {
        throw RuntimeException("Catalog database query failure")
    }

    override fun listGames(tenantId: String, providerId: String): List<CatalogGameEntry> {
        throw RuntimeException("Catalog database query failure")
    }

    override fun saveGame(game: CatalogGameEntry) {
        throw RuntimeException("Catalog database query failure")
    }

    override fun findSyncByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CatalogSyncResult>? {
        throw RuntimeException("Catalog database query failure")
    }

    override fun saveSync(result: CatalogSyncResult, tenantId: String, idempotencyKey: String, fingerprint: String, audit: AuditEvent, outbox: OutboxEvent) {
        throw RuntimeException("Catalog database query failure")
    }

    override fun findEnablementByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameEnablementResult>? {
        throw RuntimeException("Catalog database query failure")
    }

    override fun saveEnablement(result: GameEnablementResult, tenantId: String, idempotencyKey: String, fingerprint: String, audit: AuditEvent, outbox: OutboxEvent) {
        throw RuntimeException("Catalog database query failure")
    }

    override fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameLaunchAuthorizationResult>? {
        throw RuntimeException("Catalog database query failure")
    }

    override fun saveLaunch(result: GameLaunchAuthorizationResult, tenantId: String, idempotencyKey: String, fingerprint: String, audit: AuditEvent, outbox: OutboxEvent) {
        throw RuntimeException("Catalog database query failure")
    }
}
