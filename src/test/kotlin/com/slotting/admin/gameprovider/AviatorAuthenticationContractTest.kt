package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import com.slotting.admin.auth.SessionState
import com.slotting.admin.identity.*
import com.slotting.admin.ledger.*
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import java.math.BigDecimal
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*

class AviatorAuthenticationContractTest {

    private val now = Instant.parse("2026-10-01T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-pilot-001"
    private val otherTenantId = "tenant-other-999"

    private val victimPlayerUuid = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val victimPlayerId = victimPlayerUuid.toString()

    private val attackerPlayerUuid = UUID.fromString("99999999-9999-9999-9999-999999999999")
    private val attackerPlayerId = attackerPlayerUuid.toString()

    private val verifiedPlayerUuid = UUID.fromString("33333333-3333-3333-3333-333333333333")
    private val verifiedPlayerId = verifiedPlayerUuid.toString()

    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var walletStore: InMemoryAuthoritativeWalletStore
    private lateinit var walletService: AuthoritativeWalletService
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var fairnessStore: InMemoryFairnessEvidenceStore
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var eventJournalStore: InMemoryGameEventJournalStore
    private lateinit var authStore: InMemoryDurableAuthStore
    private lateinit var authService: DurableAuthService
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService
    private lateinit var controller: AviatorGameRestController

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    @BeforeEach
    fun setUp() {
        ledgerStore = InMemoryLedgerJournalStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        walletStore = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock)
        walletService = AuthoritativeWalletService(store = walletStore, clock = clock)
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        gameStore = InMemoryDurableGameWagerAndSettlementStore()

        authStore = InMemoryDurableAuthStore()
        authService = DurableAuthService(store = authStore, clock = clock)

        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
        )

        fairnessStore = InMemoryFairnessEvidenceStore()
        fairnessAuthority = ProvablyFairOutcomeAuthority(store = fairnessStore, clock = clock)
        eventJournalStore = InMemoryGameEventJournalStore()

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
            authStore = authStore,
        )

        controller = AviatorGameRestController(
            snapshotAndEventService = snapshotAndEventService,
            gameService = gameService,
        )

        registrationStore.players[victimPlayerUuid] = PlayerRegistrationRecord(
            playerId = victimPlayerUuid,
            tenantId = tenantId,
            emailHash = "victim-hash",
            phoneHash = "victim-phone",
            maskedEmail = "victim@test.internal",
            maskedPhone = "+1***0000",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )

        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = victimPlayerUuid,
                tenantId = tenantId,
                dateOfBirth = java.time.LocalDate.of(1990, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = victimPlayerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 500000L,
                    dailyWagerLimitMinor = 2000000L,
                ),
            )
        )

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-VICTIM-01",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("SYSTEM:CASH", JournalEntryDirection.DEBIT, 100000L, "INR"),
                    JournalEntryDraft("PLAYER:$victimPlayerId", JournalEntryDirection.CREDIT, 100000L, "INR"),
                ),
                idempotencyKey = "IDEM-SEED-VICTIM-01",
                correlationId = "corr-seed-victim",
                causationId = "caus-seed-victim",
            )
        )

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = "AVIATOR",
                roundId = "rnd-auth-test-01",
                phase = GameRoundPhase.BET_COUNTDOWN,
            )
        )
    }

    @Test
    fun `GivenForgedUuidToken_WhenProtectedEndpointsCalled_Then401AndNoAuthorityCalls`() {
        val initialVictimBalance = ledgerStore.findBalance(tenantId, "PLAYER:$victimPlayerId", "INR")
        assertEquals(100000L, initialVictimBalance)

        val tokenHeaders = listOf(
            Pair("X-Session-Token", victimPlayerId),
            Pair("Authorization", "Bearer $victimPlayerId"),
        )

        for ((headerName, headerVal) in tokenHeaders) {
            val sessionToken = if (headerName == "X-Session-Token") headerVal else null
            val authHeader = if (headerName == "Authorization") headerVal else null

            val myInfoGet = controller.getMyInfo(
                tenantIdHeader = tenantId,
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, myInfoGet.statusCode)
            assertFalse(myInfoGet.body?.toString()?.contains(victimPlayerId) ?: false)

            val myInfoPost = controller.postMyInfo(
                tenantIdHeader = tenantId,
                body = mapOf("limit" to 10),
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, myInfoPost.statusCode)

            val topHistory = controller.getTopHistory(
                tenantIdHeader = tenantId,
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, topHistory.statusCode)

            val snapshot = controller.getSnapshot(
                tenantIdHeader = tenantId,
                gameId = "AVIATOR",
                roundId = "rnd-auth-test-01",
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, snapshot.statusCode)

            val placeBetCommand = controller.postCommand(
                tenantIdHeader = tenantId,
                request = GameCommandRequest(
                    commandId = "cmd-forged-bet-${UUID.randomUUID()}",
                    roundId = "rnd-auth-test-01",
                    handId = "hand_primary",
                    action = "PLACE_BET",
                    wagerMinorUnits = 5000L,
                    currencyCode = "INR",
                ),
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, placeBetCommand.statusCode)

            val cancelBetCommand = controller.postCommand(
                tenantIdHeader = tenantId,
                request = GameCommandRequest(
                    commandId = "cmd-forged-cancel-${UUID.randomUUID()}",
                    roundId = "rnd-auth-test-01",
                    handId = "hand_primary",
                    action = "CANCEL_BET",
                ),
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, cancelBetCommand.statusCode)

            val cashOutCommand = controller.postCommand(
                tenantIdHeader = tenantId,
                request = GameCommandRequest(
                    commandId = "cmd-forged-cashout-${UUID.randomUUID()}",
                    roundId = "rnd-auth-test-01",
                    handId = "hand_primary",
                    action = "CASH_OUT",
                ),
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, cashOutCommand.statusCode)

            val commandResult = controller.getCommandResult(
                tenantIdHeader = tenantId,
                gameId = "AVIATOR",
                roundId = "rnd-auth-test-01",
                commandId = "cmd-forged-bet-1",
                sessionToken = sessionToken,
                authHeader = authHeader,
                principalAttr = null,
            )
            assertEquals(HttpStatus.UNAUTHORIZED, commandResult.statusCode)
        }

        val finalVictimBalance = ledgerStore.findBalance(tenantId, "PLAYER:$victimPlayerId", "INR")
        assertEquals(initialVictimBalance, finalVictimBalance)
        assertTrue(gameStore.findBetsForRound(tenantId, "AVIATOR", "rnd-auth-test-01").isEmpty())
    }

    @Test
    fun `GivenBadSessions_WhenRestOrSocketAuthenticates_ThenFailClosed`() {
        val expiredSessionId = UUID.randomUUID()
        authStore.createSession(
            PlayerSessionRecord(
                sessionId = expiredSessionId,
                tenantId = tenantId,
                playerId = verifiedPlayerUuid,
                state = SessionState.ACTIVE,
                createdAt = now.minus(Duration.ofDays(31)),
                expiresAt = now.minus(Duration.ofMinutes(1)),
            )
        )

        val revokedSessionId = UUID.randomUUID()
        authStore.createSession(
            PlayerSessionRecord(
                sessionId = revokedSessionId,
                tenantId = tenantId,
                playerId = verifiedPlayerUuid,
                state = SessionState.TERMINATED,
                createdAt = now.minus(Duration.ofDays(1)),
                expiresAt = now.plus(Duration.ofDays(29)),
                terminatedAt = now.minus(Duration.ofMinutes(10)),
            )
        )

        val tenantASessionId = UUID.randomUUID()
        authStore.createSession(
            PlayerSessionRecord(
                sessionId = tenantASessionId,
                tenantId = tenantId,
                playerId = verifiedPlayerUuid,
                state = SessionState.ACTIVE,
                createdAt = now,
                expiresAt = now.plus(Duration.ofDays(30)),
            )
        )

        val badTokens = listOf(
            "" to HttpStatus.UNAUTHORIZED,
            "arbitrary-attacker-string" to HttpStatus.UNAUTHORIZED,
            "expired-session-12345" to HttpStatus.UNAUTHORIZED,
            "invalid-session-99999" to HttpStatus.UNAUTHORIZED,
            expiredSessionId.toString() to HttpStatus.UNAUTHORIZED,
            revokedSessionId.toString() to HttpStatus.UNAUTHORIZED,
        )

        for ((badToken, expectedStatus) in badTokens) {
            val response = controller.getMyInfo(
                tenantIdHeader = tenantId,
                sessionToken = badToken.ifBlank { null },
                authHeader = if (badToken.isNotBlank()) "Bearer $badToken" else null,
                principalAttr = null,
            )
            assertEquals(expectedStatus, response.statusCode)

            val ex = assertFailsWith<AuthenticationFailure.Rejected> {
                snapshotAndEventService.authenticateSession(tenantId, badToken)
            }
            assertEquals(AuthErrorCode.UNAUTHENTICATED, ex.code)
        }

        val crossTenantResponse = controller.getMyInfo(
            tenantIdHeader = otherTenantId,
            sessionToken = tenantASessionId.toString(),
            authHeader = null,
            principalAttr = null,
        )
        assertEquals(HttpStatus.FORBIDDEN, crossTenantResponse.statusCode)

        val crossTenantSocketEx = assertFailsWith<AuthenticationFailure.Rejected> {
            snapshotAndEventService.authenticateSession(otherTenantId, tenantASessionId.toString())
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantSocketEx.code)

        val nonPlayerResponse = controller.getMyInfo(
            tenantIdHeader = tenantId,
            sessionToken = null,
            authHeader = null,
            principalAttr = adminPrincipal,
        )
        assertEquals(HttpStatus.FORBIDDEN, nonPlayerResponse.statusCode)

        val outageSessionId = UUID.randomUUID()
        val outageAuthStore = object : DurableAuthStore by authStore {
            override fun findSession(sessionId: UUID): PlayerSessionRecord? {
                throw SessionStoreOutageException("Database connection failure")
            }
        }
        val outageStoreService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
            authStore = outageAuthStore,
        )
        val outageController = AviatorGameRestController(
            snapshotAndEventService = outageStoreService,
            gameService = gameService,
        )
        val outageResponse = outageController.getMyInfo(
            tenantIdHeader = tenantId,
            sessionToken = outageSessionId.toString(),
            authHeader = null,
            principalAttr = null,
        )
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, outageResponse.statusCode)
        assertFailsWith<SessionStoreOutageException> {
            outageStoreService.authenticateSession(tenantId, outageSessionId.toString())
        }
    }

    @Test
    fun `GivenVerifiedSession_WhenRestAndSocketCalled_ThenSubjectAndTenantMatch`() {
        val validSessionId = UUID.randomUUID()
        authStore.createSession(
            PlayerSessionRecord(
                sessionId = validSessionId,
                tenantId = tenantId,
                playerId = verifiedPlayerUuid,
                state = SessionState.ACTIVE,
                createdAt = now,
                expiresAt = now.plus(Duration.ofDays(30)),
            )
        )

        registrationStore.players[verifiedPlayerUuid] = PlayerRegistrationRecord(
            playerId = verifiedPlayerUuid,
            tenantId = tenantId,
            emailHash = "verified-hash",
            phoneHash = "verified-phone",
            maskedEmail = "verified@test.internal",
            maskedPhone = "+1***3333",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )

        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-SEED-VERIFIED-01",
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("SYSTEM:CASH", JournalEntryDirection.DEBIT, 75000L, "INR"),
                    JournalEntryDraft("PLAYER:$verifiedPlayerId", JournalEntryDirection.CREDIT, 75000L, "INR"),
                ),
                idempotencyKey = "IDEM-SEED-VERIFIED-01",
                correlationId = "corr-seed-verified",
                causationId = "caus-seed-verified",
            )
        )

        val socketPrincipal = snapshotAndEventService.authenticateSession(tenantId, validSessionId.toString())
        assertEquals(verifiedPlayerId, socketPrincipal.id)
        assertNotEquals(validSessionId.toString(), socketPrincipal.id)
        assertEquals(tenantId, socketPrincipal.tenantId)
        assertEquals(PrincipalKind.PLAYER, socketPrincipal.kind)

        val restResponse = controller.getMyInfo(
            tenantIdHeader = tenantId,
            sessionToken = validSessionId.toString(),
            authHeader = null,
            principalAttr = null,
        )
        assertEquals(HttpStatus.OK, restResponse.statusCode)
        val body = restResponse.body as SnapshotUser
        assertEquals(verifiedPlayerId, body.userId)
        assertNotEquals(validSessionId.toString(), body.userId)
        assertEquals(75000L, body.balanceMinor)

        val trustedPrincipal = AuthenticatedPrincipal(
            id = verifiedPlayerId,
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        val filterResponse = controller.getMyInfo(
            tenantIdHeader = tenantId,
            sessionToken = null,
            authHeader = null,
            principalAttr = trustedPrincipal,
        )
        assertEquals(HttpStatus.OK, filterResponse.statusCode)
        val filterBody = filterResponse.body as SnapshotUser
        assertEquals(verifiedPlayerId, filterBody.userId)
    }
}
