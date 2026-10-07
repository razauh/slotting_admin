package com.slotting.admin.gameprovider

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.InMemoryDurableAuthStore
import com.slotting.admin.auth.PlayerSessionRecord
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.auth.SessionState
import com.slotting.admin.contract.auth.TokenResponseDto
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.security.SecurityAuthenticationFilter
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AviatorSecurityFilterContractTest {

    private val objectMapper: ObjectMapper = ObjectMapper()
        .findAndRegisterModules()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    private val converter = MappingJackson2HttpMessageConverter(objectMapper)

    private val now = Instant.parse("2026-10-01T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-filter-001"
    private val otherTenantId = "tenant-filter-002"

    private val playerUuid = UUID.fromString("33333333-3333-3333-3333-333333333333")
    private val playerIdStr = playerUuid.toString()

    private lateinit var authStore: InMemoryDurableAuthStore
    private lateinit var authService: DurableAuthService
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService
    private lateinit var controller: AviatorGameRestController
    private lateinit var securityFilter: SecurityAuthenticationFilter
    private lateinit var mockMvc: MockMvc

    private val fakeAdminSessionDirectory = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? = null
    }

    @BeforeEach
    fun setUp() {
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)
        val registrationStore = InMemoryPlayerRegistrationStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()

        val adminPrincipal = AuthenticatedPrincipal(
            id = "admin-sys-01",
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )

        val gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
        )

        val fairnessStore = InMemoryFairnessEvidenceStore()
        val fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
        val eventJournalStore = InMemoryGameEventJournalStore()

        authStore = InMemoryDurableAuthStore()
        authService = DurableAuthService(store = authStore, clock = clock)

        snapshotAndEventService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
            authService = authService,
        )

        controller = AviatorGameRestController(
            snapshotAndEventService = snapshotAndEventService,
            gameService = gameService,
        )

        securityFilter = SecurityAuthenticationFilter(
            authService = authService,
            adminSessionDirectory = fakeAdminSessionDirectory,
        )

        val builder = MockMvcBuilders.standaloneSetup(controller).setMessageConverters(converter)
        builder.addFilters<StandaloneMockMvcBuilder>(securityFilter)
        mockMvc = builder.build()

        registrationStore.players[playerUuid] = PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "filter-hash",
            phoneHash = "filter-phone",
            maskedEmail = "filter@test.internal",
            maskedPhone = "+1***3333",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )
    }

    private fun mintToken(targetTenant: String = tenantId, player: UUID = playerUuid): TokenResponseDto {
        val authCode = authService.createAuthorizationCode(
            clientId = "slotting-android",
            redirectUri = "https://app.slotting.internal/auth/callback",
            scope = "openid profile",
            state = "state-123",
            nonce = "nonce-123",
            codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            codeChallengeMethod = "S256",
            tenantId = targetTenant,
            playerId = player,
        )
        return authService.exchangeAuthorizationCode(
            grantType = "authorization_code",
            code = authCode.code,
            codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            codeChallengeMethod = "S256",
            state = "state-123",
            redirectUri = "https://app.slotting.internal/auth/callback",
            clientId = "slotting-android",
        )
    }

    @Test
    fun `GivenNoCredential_WhenAnyProtectedRouteCalled_Then401FromFilter`() {
        val routes = listOf(
            get("/api/bootstrap").param("gameId", "AVIATOR"),
            get("/api/my-info"),
            post("/api/my-info").content("{}"),
            get("/api/get-day-history"),
            get("/api/get-month-history"),
            get("/api/get-year-history"),
            get("/api/snapshot").param("gameId", "AVIATOR"),
            get("/api/round-history").param("gameId", "AVIATOR"),
            post("/api/command").content("{}"),
            get("/api/command-result").param("roundId", "r1").param("commandId", "c1"),
        )

        for (request in routes) {
            mockMvc.perform(request)
                .andExpect(status().isUnauthorized)
        }
    }

    @Test
    fun `GivenForgedUuid_WhenAnyProtectedRouteCalled_Then401FromFilter`() {
        val victimUuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
        val victimIdStr = victimUuid.toString()

        val routes = listOf(
            get("/api/bootstrap").param("gameId", "AVIATOR").header("X-Session-Token", victimIdStr),
            get("/api/my-info").header("X-Session-Token", victimIdStr),
            post("/api/my-info").header("X-Session-Token", victimIdStr).content("{}"),
            get("/api/get-day-history").header("X-Session-Token", victimIdStr),
            get("/api/snapshot").param("gameId", "AVIATOR").header("X-Session-Token", victimIdStr),
            get("/api/round-history").param("gameId", "AVIATOR").header("X-Session-Token", victimIdStr),
            post("/api/command").header("X-Session-Token", victimIdStr).content("{}"),
            get("/api/command-result").param("roundId", "r1").param("commandId", "c1").header("X-Session-Token", victimIdStr),
            get("/api/bootstrap").param("gameId", "AVIATOR").header("Authorization", "Bearer $victimIdStr"),
            get("/api/my-info").header("Authorization", "Bearer $victimIdStr"),
            post("/api/command").header("Authorization", "Bearer $victimIdStr").content("{}"),
        )

        for (request in routes) {
            val result = mockMvc.perform(request)
                .andExpect(status().isUnauthorized)
                .andReturn()
            assertTrue(!result.response.contentAsString.contains(victimIdStr))
        }
    }

    @Test
    fun `GivenArbitraryText_WhenAnyProtectedRouteCalled_Then401FromFilter`() {
        val arbitraryTokens = listOf(
            "arbitrary-attacker-string",
            "not-a-uuid",
            "expired-session-12345",
        )

        for (token in arbitraryTokens) {
            mockMvc.perform(get("/api/my-info").header("X-Session-Token", token))
                .andExpect(status().isUnauthorized)

            mockMvc.perform(get("/api/my-info").header("Authorization", "Bearer $token"))
                .andExpect(status().isUnauthorized)

            mockMvc.perform(get("/api/bootstrap").param("gameId", "AVIATOR").header("Authorization", "Bearer $token"))
                .andExpect(status().isUnauthorized)
        }
    }

    @Test
    fun `GivenUuidSessionId_WhenProtectedRouteCalled_Then401FromFilterBecauseNotBearerCredential`() {
        val sessionId = UUID.randomUUID()
        authStore.createSession(
            PlayerSessionRecord(
                sessionId = sessionId,
                tenantId = tenantId,
                playerId = playerUuid,
                state = SessionState.ACTIVE,
                createdAt = now,
                expiresAt = now.plusSeconds(2592000),
            )
        )

        mockMvc.perform(get("/api/my-info").header("X-Session-Token", sessionId.toString()))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `GivenPublicBetLimits_WhenCalledWithoutCredentials_ThenOnlyGeneralLimitsAreReturned`() {
        assertNull(gameStore.findLatestRound(tenantId, "AVIATOR"))

        val anonymous = mockMvc.perform(get("/api/bet-limits").param("gameId", "AVIATOR"))
            .andExpect(status().isOk)
            .andReturn()
        val anonymousBody = anonymous.response.contentAsString
        assertTrue(anonymousBody.contains("minWagerMinor"))
        assertTrue(!anonymousBody.contains(playerIdStr))
        assertTrue(!anonymousBody.contains(tenantId))
        val cacheControl = anonymous.response.getHeader("Cache-Control")
        assertTrue(cacheControl != null && cacheControl.contains("public"))

        val otherTenant = mockMvc.perform(
            get("/api/bet-limits").param("gameId", "AVIATOR").header("X-Tenant-Id", otherTenantId)
        ).andExpect(status().isOk).andReturn()
        assertTrue(otherTenant.response.contentAsString == anonymousBody)

        val forgedToken = "attacker-token-xyz"
        val forged = mockMvc.perform(
            get("/api/bet-limits").param("gameId", "AVIATOR").header("X-Session-Token", forgedToken)
        ).andExpect(status().isOk).andReturn()
        assertTrue(!forged.response.contentAsString.contains(forgedToken))

        mockMvc.perform(post("/api/bet-limits").param("gameId", "AVIATOR"))
            .andExpect(status().isMethodNotAllowed)

        mockMvc.perform(get("/api/bet-limits/extra").param("gameId", "AVIATOR"))
            .andExpect(status().isUnauthorized)

        mockMvc.perform(get("/api/round-history").param("gameId", "AVIATOR"))
            .andExpect(status().isUnauthorized)

        assertNull(gameStore.findLatestRound(tenantId, "AVIATOR"))
    }

    @Test
    fun `GivenValidAccessToken_WhenProtectedRouteCalled_ThenFilterInstallsVerifiedPrincipal`() {
        val token = mintToken()

        val headerResult = mockMvc.perform(
            get("/api/my-info")
                .header("X-Tenant-Id", tenantId)
                .header("Authorization", "Bearer ${token.accessToken}")
        ).andExpect(status().isOk).andReturn()
        assertTrue(headerResult.response.contentAsString.contains(playerIdStr))
        assertTrue(!headerResult.response.contentAsString.contains(token.accessToken))

        mockMvc.perform(
            get("/api/my-info")
                .header("X-Tenant-Id", tenantId)
                .header("X-Session-Token", token.accessToken)
        ).andExpect(status().isOk)
    }

    @Test
    fun `GivenTenantAAccessToken_WhenRequestingTenantB_Then403FromController`() {
        val token = mintToken(targetTenant = tenantId)

        mockMvc.perform(
            get("/api/my-info")
                .header("X-Tenant-Id", otherTenantId)
                .header("Authorization", "Bearer ${token.accessToken}")
        ).andExpect(status().isForbidden)
    }

    @Test
    fun `GivenTerminatedSession_WhenAccessTokenPresented_Then401FromFilter`() {
        val token = mintToken()
        authStore.terminateSession(UUID.fromString(token.sessionId), now)

        mockMvc.perform(get("/api/my-info").header("Authorization", "Bearer ${token.accessToken}"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `GivenPublicRoute_WhenNoCredential_ThenFilterPasses`() {
        mockMvc.perform(get("/auth/token"))
            .andExpect(status().isNotFound)
    }
}
