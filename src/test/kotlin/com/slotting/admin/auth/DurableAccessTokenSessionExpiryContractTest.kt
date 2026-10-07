package com.slotting.admin.auth

import com.slotting.admin.contract.auth.TokenResponseDto
import com.slotting.admin.gameprovider.AuthoritativeGameSnapshotAndEventService
import com.slotting.admin.gameprovider.AviatorGameRestController
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementService
import com.slotting.admin.gameprovider.InMemoryDurableGameWagerAndSettlementStore
import com.slotting.admin.gameprovider.InMemoryFairnessEvidenceStore
import com.slotting.admin.gameprovider.InMemoryGameEventJournalStore
import com.slotting.admin.gameprovider.SessionStoreOutageException
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DurableAccessTokenSessionExpiryContractTest {

    private val now = Instant.parse("2026-10-01T12:00:00Z")
    private val tenantId = "tenant-expiry-001"
    private val otherTenantId = "tenant-expiry-002"
    private val playerUuid = UUID.fromString("44444444-4444-4444-4444-444444444444")

    private lateinit var clock: MutableClock
    private lateinit var baseStore: InMemoryDurableAuthStore
    private lateinit var authService: DurableAuthService

    private class MutableClock(private var current: Instant) : Clock() {
        override fun getZone(): ZoneOffset = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = current
        fun advanceTo(instant: Instant) { current = instant }
    }

    @BeforeEach
    fun setUp() {
        clock = MutableClock(now)
        baseStore = InMemoryDurableAuthStore()
        authService = DurableAuthService(store = baseStore, clock = clock)
    }

    private fun mintToken(
        service: DurableAuthService = authService,
        targetTenant: String = tenantId,
        player: UUID = playerUuid,
    ): TokenResponseDto {
        val authCode = service.createAuthorizationCode(
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
        return service.exchangeAuthorizationCode(
            grantType = "authorization_code",
            code = authCode.code,
            codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            codeChallengeMethod = "S256",
            state = "state-123",
            redirectUri = "https://app.slotting.internal/auth/callback",
            clientId = "slotting-android",
        )
    }

    private fun setSessionExpiry(sessionId: UUID, expiresAt: Instant) {
        val existing = assertNotNull(baseStore.sessions[sessionId])
        baseStore.sessions[sessionId] = existing.copy(expiresAt = expiresAt)
    }

    private fun buildSnapshotService(service: DurableAuthService): AuthoritativeGameSnapshotAndEventService {
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        val walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        val walletService = AuthoritativeWalletService(store = walletStore, clock = clock)
        val registrationStore = InMemoryPlayerRegistrationStore()
        val eligibilityStore = InMemoryServerEligibilityStore()
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
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
        return AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = InMemoryFairnessEvidenceStore(),
            eventJournalStore = InMemoryGameEventJournalStore(),
            registrationStore = registrationStore,
            clock = clock,
            authService = service,
        )
    }

    private fun buildController(snapshotService: AuthoritativeGameSnapshotAndEventService): AviatorGameRestController {
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        val ledgerStore = InMemoryLedgerJournalStore()
        val gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = LedgerPostingService(store = ledgerStore, clock = clock),
            registrationStore = InMemoryPlayerRegistrationStore(),
            eligibilityStore = InMemoryServerEligibilityStore(),
            adminPrincipal = AuthenticatedPrincipal(
                id = "admin-sys-01",
                tenantId = tenantId,
                kind = PrincipalKind.ADMIN,
                roles = setOf(AdminRole.SUPER_ADMIN),
            ),
            clock = clock,
        )
        return AviatorGameRestController(
            snapshotAndEventService = snapshotService,
            gameService = gameService,
        )
    }

    @Test
    fun `GivenActiveUnexpiredSession_WhenTokenValidated_ThenAccepted`() {
        val token = mintToken()
        val principal = authService.validateAccessToken(token.accessToken)
        assertNotNull(principal)
        assertEquals(playerUuid.toString(), principal.id)
        assertEquals(tenantId, principal.tenantId)
    }

    @Test
    fun `GivenExpiredSession_WhenTokenValidated_ThenRejected`() {
        val token = mintToken()
        setSessionExpiry(UUID.fromString(token.sessionId), now.minus(Duration.ofSeconds(1)))
        assertNull(authService.validateAccessToken(token.accessToken))
    }

    @Test
    fun `GivenSessionExpiryBoundary_WhenJustBeforeExpiry_ThenAccepted_AndAtExpiry_ThenRejected`() {
        val token = mintToken()
        val sessionId = UUID.fromString(token.sessionId)
        val sessionExpiry = now.plus(Duration.ofMinutes(5))
        setSessionExpiry(sessionId, sessionExpiry)

        clock.advanceTo(sessionExpiry.minus(Duration.ofSeconds(1)))
        assertNotNull(authService.validateAccessToken(token.accessToken))

        clock.advanceTo(sessionExpiry)
        assertNull(authService.validateAccessToken(token.accessToken))
    }

    @Test
    fun `GivenAccessTokenExpiryBoundary_WhenJustBeforeExpiry_ThenAccepted_AndAtExpiry_ThenRejected`() {
        val token = mintToken()
        val tokenExpiry = now.plus(DurableAuthService.ACCESS_TOKEN_TTL)

        clock.advanceTo(tokenExpiry.minus(Duration.ofSeconds(1)))
        assertNotNull(authService.validateAccessToken(token.accessToken))

        clock.advanceTo(tokenExpiry)
        assertNull(authService.validateAccessToken(token.accessToken))
    }

    @Test
    fun `GivenRevokedSession_WhenTokenValidated_ThenRejected`() {
        val token = mintToken()
        baseStore.terminateSession(UUID.fromString(token.sessionId), clock.instant())
        assertNull(authService.validateAccessToken(token.accessToken))
    }

    @Test
    fun `GivenMissingSession_WhenTokenValidated_ThenRejected`() {
        val token = mintToken()
        baseStore.sessions.remove(UUID.fromString(token.sessionId))
        assertNull(authService.validateAccessToken(token.accessToken))
    }

    @Test
    fun `GivenSessionBelongingToDifferentTenant_WhenTokenValidated_ThenRejected`() {
        val token = mintToken()
        val sessionId = UUID.fromString(token.sessionId)
        val existing = baseStore.sessions[sessionId]!!
        baseStore.sessions[sessionId] = existing.copy(tenantId = otherTenantId)
        assertNull(authService.validateAccessToken(token.accessToken))
    }

    @Test
    fun `GivenSessionStoreUnavailable_WhenTokenValidated_ThenFailsClosed`() {
        val outageStore = object : DurableAuthStore by baseStore {
            override fun findSession(sessionId: UUID): PlayerSessionRecord? {
                throw SessionStoreOutageException("Database connection failure")
            }
        }
        val outageService = DurableAuthService(store = outageStore, clock = clock)
        val token = mintToken(outageService)
        assertFailsWith<SessionStoreOutageException> {
            outageService.validateAccessToken(token.accessToken)
        }
    }

    @Test
    fun `GivenExpiredSession_WhenRestOrSocketAuthenticates_ThenRejected`() {
        val token = mintToken()
        setSessionExpiry(UUID.fromString(token.sessionId), now.minus(Duration.ofSeconds(1)))

        val snapshotService = buildSnapshotService(authService)
        val socketEx = assertFailsWith<AuthenticationFailure.Rejected> {
            snapshotService.authenticateSession(tenantId, token.accessToken)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, socketEx.code)

        val controller = buildController(snapshotService)
        assertEquals(HttpStatus.UNAUTHORIZED, controller.getMyInfo(
            tenantIdHeader = tenantId,
            sessionToken = null,
            authHeader = "Bearer ${token.accessToken}",
            principalAttr = null,
        ).statusCode)
    }

    @Test
    fun `GivenWrongTenantRequest_WhenRestAuthenticates_ThenForbidden`() {
        val token = mintToken()
        val snapshotService = buildSnapshotService(authService)
        val controller = buildController(snapshotService)
        assertEquals(HttpStatus.FORBIDDEN, controller.getMyInfo(
            tenantIdHeader = otherTenantId,
            sessionToken = null,
            authHeader = "Bearer ${token.accessToken}",
            principalAttr = null,
        ).statusCode)
    }
}
