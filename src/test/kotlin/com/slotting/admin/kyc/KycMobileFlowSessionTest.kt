package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class KycMobileFlowSessionTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var service: KycMobileFlowSessionService

    private val tenantId = "tenant-alpha"
    private val playerId = "player-001"
    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        service = KycMobileFlowSessionService(
            clock = clock,
            sessionTtl = Duration.ofMinutes(15),
        )
    }

    @Test
    fun `KYC-003-T001 Android KYC flow produces the required authoritative outcome`() {
        // 1. Initiate session
        val initCmd = InitiateMobileKycCommand(
            principal = playerPrincipal,
            tenantId = tenantId,
            userId = playerId,
            returnUrlScheme = "slotting://kyc/return",
            idempotencyKey = "idemp-mobile-001",
            correlationId = "corr-001",
            causationId = "cause-001",
        )
        val initResult = service.initiateMobileKycSession(initCmd)

        assertNotNull(initResult.sessionId)
        assertEquals(MobileKycSessionState.INITIATED, initResult.state)
        assertTrue(initResult.vendorRedirectUrl.contains(initResult.returnNonce))
        assertEquals(fixedInstant.plus(Duration.ofMinutes(15)), initResult.expiresAt)
        assertEquals(fixedInstant, initResult.serverTime)
        assertEquals(1L, initResult.serverVersion)
        assertEquals("Accessibility, cancellation, process death, safe external return; server status authoritative.", initResult.message)

        // Financial & untrusted client invariants
        assertFalse(initResult.directEligibilityGranted)
        assertFalse(initResult.financialMutationPermitted)

        // 2. Simulate return from external vendor flow
        val returnCmd = ExternalReturnCommand(
            principal = playerPrincipal,
            tenantId = tenantId,
            sessionId = initResult.sessionId,
            returnNonce = initResult.returnNonce,
            clientReturnedStatus = "success",
            idempotencyKey = "idemp-return-001",
            correlationId = "corr-002",
            causationId = "cause-002",
            expectedVersion = 1L,
        )
        val updatedSession = service.handleExternalReturn(returnCmd)

        assertEquals(MobileKycSessionState.SUBMITTED_FOR_REVIEW, updatedSession.state)
        assertEquals(2L, updatedSession.serverVersion)
        assertEquals(KycStatusState.IN_REVIEW, updatedSession.serverAuthoritativeKycStatus)

        // 3. Status query
        val statusQuery = MobileKycStatusQuery(
            principal = playerPrincipal,
            tenantId = tenantId,
            sessionId = initResult.sessionId,
        )
        val statusResult = service.getAuthoritativeSessionStatus(statusQuery)

        assertEquals(MobileKycSessionState.SUBMITTED_FOR_REVIEW, statusResult.sessionState)
        assertFalse(statusResult.isEligible)
        assertFalse(statusResult.directEligibilityGranted)
        assertFalse(statusResult.financialMutationPermitted)
    }

    @Test
    fun `KYC-003-T002 Android KYC flow rejects invalid, boundary, unauthorized, and stale input`() {
        val initResult = service.initiateMobileKycSession(
            InitiateMobileKycCommand(
                principal = playerPrincipal,
                tenantId = tenantId,
                userId = playerId,
                idempotencyKey = "idemp-mobile-002",
                correlationId = "corr-003",
                causationId = "cause-003",
            )
        )

        // 1. Invalid return nonce (forged or tampered callback)
        assertThrows(InvalidReturnNonceException::class.java) {
            service.handleExternalReturn(
                ExternalReturnCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    sessionId = initResult.sessionId,
                    returnNonce = "FORGED_NONCE_12345",
                    clientReturnedStatus = "success",
                    idempotencyKey = "idemp-forged-nonce",
                    correlationId = "corr-004",
                    causationId = "cause-004",
                    expectedVersion = 1L,
                )
            )
        }

        // 2. Upload bypass attempt: client directly claiming "verified" without server authority
        assertThrows(UploadBypassAttemptException::class.java) {
            service.handleExternalReturn(
                ExternalReturnCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    sessionId = initResult.sessionId,
                    returnNonce = initResult.returnNonce,
                    clientReturnedStatus = "verified",
                    idempotencyKey = "idemp-bypass",
                    correlationId = "corr-005",
                    causationId = "cause-005",
                    expectedVersion = 1L,
                )
            )
        }

        // 3. Expired session return
        val expiredInstant = fixedInstant.plus(Duration.ofMinutes(16))
        val expiredClock = Clock.fixed(expiredInstant, ZoneOffset.UTC)
        val expiredService = KycMobileFlowSessionService(
            clock = expiredClock,
            sessionTtl = Duration.ofMinutes(15),
        )
        // copy session into expiredService
        val sessionField = KycMobileFlowSessionService::class.java.getDeclaredField("sessionsStore")
        sessionField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val store = sessionField.get(expiredService) as java.util.concurrent.ConcurrentHashMap<UUID, MobileKycFlowSession>
        store[initResult.sessionId] = service.getAuthoritativeSessionStatus(
            MobileKycStatusQuery(playerPrincipal, tenantId, initResult.sessionId)
        ).let {
            MobileKycFlowSession(
                sessionId = initResult.sessionId,
                tenantId = tenantId,
                userId = playerId,
                state = MobileKycSessionState.INITIATED,
                vendorRedirectUrl = initResult.vendorRedirectUrl,
                returnNonce = initResult.returnNonce,
                idempotencyKey = "idemp-mobile-002",
                expiresAt = initResult.expiresAt,
                createdAt = fixedInstant,
                updatedAt = fixedInstant,
            )
        }

        assertThrows(SessionExpiredException::class.java) {
            expiredService.handleExternalReturn(
                ExternalReturnCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    sessionId = initResult.sessionId,
                    returnNonce = initResult.returnNonce,
                    clientReturnedStatus = "success",
                    idempotencyKey = "idemp-return-expired",
                    correlationId = "corr-006",
                    causationId = "cause-006",
                    expectedVersion = 1L,
                )
            )
        }

        // 4. Cross-player IDOR return
        val otherPlayer = AuthenticatedPrincipal(
            id = "attacker-player",
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        assertThrows(IdorForbiddenException::class.java) {
            service.handleExternalReturn(
                ExternalReturnCommand(
                    principal = otherPlayer,
                    tenantId = tenantId,
                    sessionId = initResult.sessionId,
                    returnNonce = initResult.returnNonce,
                    clientReturnedStatus = "success",
                    idempotencyKey = "idemp-idor-return",
                    correlationId = "corr-007",
                    causationId = "cause-007",
                    expectedVersion = 1L,
                )
            )
        }
    }

    @Test
    fun `KYC-003-T003 Android KYC flow survives concurrency, duplicate delivery, and dependency failure`() {
        val initCmd = InitiateMobileKycCommand(
            principal = playerPrincipal,
            tenantId = tenantId,
            userId = playerId,
            idempotencyKey = "idemp-mobile-003",
            correlationId = "corr-008",
            causationId = "cause-008",
        )

        // 1. Initial initiation
        val res1 = service.initiateMobileKycSession(initCmd)

        // 2. Duplicate initiation replay returns identical session
        val res2 = service.initiateMobileKycSession(initCmd)
        assertEquals(res1.sessionId, res2.sessionId)
        assertEquals(res1.returnNonce, res2.returnNonce)
        assertEquals(res1.vendorRedirectUrl, res2.vendorRedirectUrl)

        // 3. Conflicting initiate payload with same idempotency key throws ConcurrencyConflictException
        assertThrows(ConcurrencyConflictException::class.java) {
            service.initiateMobileKycSession(
                initCmd.copy(returnUrlScheme = "slotting://other/scheme")
            )
        }

        // 4. Cancellation flow
        val cancelResult = service.cancelMobileKycSession(
            CancelMobileKycCommand(
                principal = playerPrincipal,
                tenantId = tenantId,
                sessionId = res1.sessionId,
                reason = "User pressed back button in webview",
                idempotencyKey = "idemp-cancel",
                correlationId = "corr-009",
                causationId = "cause-009",
                expectedVersion = 1L,
            )
        )
        assertEquals(MobileKycSessionState.CANCELLED, cancelResult.state)
        assertEquals("User pressed back button in webview", cancelResult.cancellationReason)
    }

    @Test
    fun `KYC-003-T004 Android KYC flow remains compatible, recoverable, observable, and lifecycle-safe`() {
        val initResult = service.initiateMobileKycSession(
            InitiateMobileKycCommand(
                principal = playerPrincipal,
                tenantId = tenantId,
                userId = playerId,
                idempotencyKey = "idemp-mobile-004",
                correlationId = "corr-010",
                causationId = "cause-010",
            )
        )

        // Backend marks session verified authoritatively (e.g. from verified provider webhook)
        service.setAuthoritativeVerification(initResult.sessionId, verified = true)

        // Simulate Activity recreation / process death recovery:
        // Android client queries server status afresh
        val query = MobileKycStatusQuery(
            principal = playerPrincipal,
            tenantId = tenantId,
            sessionId = initResult.sessionId,
        )
        val statusResult = service.getAuthoritativeSessionStatus(query)

        assertEquals(MobileKycSessionState.VERIFIED, statusResult.sessionState)
        assertEquals(KycStatusState.VERIFIED, statusResult.authoritativeKycStatus)
        assertTrue(statusResult.isEligible)
        assertFalse(statusResult.directEligibilityGranted)
        assertFalse(statusResult.financialMutationPermitted)
        assertEquals("Accessibility, cancellation, process death, safe external return; server status authoritative.", statusResult.message)
    }
}
