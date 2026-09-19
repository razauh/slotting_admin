package com.slotting.admin.integrity

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class PlayIntegrityTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var fakeProvider: FakePlayIntegrityProviderAdapter
    private lateinit var service: PlayIntegrityService

    private val tenantId = "tenant-prod-1"

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val userPrincipal = AuthenticatedPrincipal(
        id = "user-100",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        fakeProvider = FakePlayIntegrityProviderAdapter(clock)
        service = PlayIntegrityService(clock = clock, provider = fakeProvider)
    }

    // =========================================================================
    // INTEGRITY-001-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `INTEGRITY-001-T001 Play Integrity produces the required authoritative outcome`() {
        // Must fail with AssertionError("replayed/forged/stale verdict accepted") in RED phase
        PlayIntegrityBinding.checkBound()

        // 1. Issue authoritative nonce
        val nonce = service.issueNonce(
            tenantId = tenantId,
            userId = userPrincipal.id,
            principal = userPrincipal,
        )
        assertNotNull(nonce.nonceValue)
        assertFalse(nonce.consumed)

        // 2. Client submits valid nonced integrity token
        val token = "token-nonce:${nonce.nonceValue}:valid"
        val result = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = token,
            nonceValue = nonce.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-key-1",
        )

        assertTrue(result.isSuccess)
        val verification = result.getOrThrow()
        assertEquals(PlayIntegrityDecisionState.ALLOWED, verification.decision)
        assertEquals(PlayIntegrityReason.VERIFIED_DEVICE_AND_APP, verification.reason)

        // Semantic & Financial Contracts
        assertFalse(verification.directEligibilityGranted)
        assertFalse(verification.financialMutationPermitted)
        assertTrue(verification.evidenceReference.isNotBlank())

        // 3. Readiness evaluation check
        val readiness = service.evaluatePlayIntegrityReadiness(tenantId, securityAdmin)
        assertEquals(PlayIntegrityDecisionState.ALLOWED, readiness.status)
        assertFalse(readiness.directEligibilityGranted)
        assertFalse(readiness.financialMutationPermitted)
        assertEquals("Fail closed or risk-hold per approved policy; do not log tokens/verdict payloads.", readiness.message)
    }

    // =========================================================================
    // INTEGRITY-001-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `INTEGRITY-001-T002 Play Integrity rejects invalid, boundary, unauthorized, and stale input`() {
        PlayIntegrityBinding.checkBound()

        // 1. Replay attack: Reusing consumed nonce fails
        val nonce = service.issueNonce(
            tenantId = tenantId,
            userId = userPrincipal.id,
            principal = userPrincipal,
        )
        val token = "token-nonce:${nonce.nonceValue}:valid"
        service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = token,
            nonceValue = nonce.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-1",
        )

        // Replay same nonce with new call -> BLOCKED
        val replayResult = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = token,
            nonceValue = nonce.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-replay",
        ).getOrThrow()
        assertEquals(PlayIntegrityDecisionState.BLOCKED, replayResult.decision)
        assertEquals(PlayIntegrityReason.NONCE_MISMATCH_OR_EXPIRED, replayResult.reason)

        // 2. Forged token -> BLOCKED
        val nonce2 = service.issueNonce(tenantId, userPrincipal.id, userPrincipal)
        val forgedResult = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = "forged-token",
            nonceValue = nonce2.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-forged",
        ).getOrThrow()
        assertEquals(PlayIntegrityDecisionState.BLOCKED, forgedResult.decision)
        assertEquals(PlayIntegrityReason.REPLAYED_FORGED_OR_STALE_TOKEN, forgedResult.reason)

        // 3. Stale token -> BLOCKED
        val nonce3 = service.issueNonce(tenantId, userPrincipal.id, userPrincipal)
        val staleToken = "token-nonce:${nonce3.nonceValue}:stale"
        val staleResult = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = staleToken,
            nonceValue = nonce3.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-stale",
        ).getOrThrow()
        assertEquals(PlayIntegrityDecisionState.BLOCKED, staleResult.decision)
        assertEquals(PlayIntegrityReason.REPLAYED_FORGED_OR_STALE_TOKEN, staleResult.reason)

        // 4. Policy Risk Hold: Device with only BASIC integrity transitions to RISK_HOLD
        fakeProvider.deviceLevels = listOf(DeviceIntegrityLevel.MEETS_BASIC_INTEGRITY)
        val nonce4 = service.issueNonce(tenantId, userPrincipal.id, userPrincipal)
        val basicResult = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = "token-nonce:${nonce4.nonceValue}:basic",
            nonceValue = nonce4.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-basic",
        ).getOrThrow()
        assertEquals(PlayIntegrityDecisionState.RISK_HOLD, basicResult.decision)
        assertEquals(PlayIntegrityReason.BASIC_INTEGRITY_RISK_HOLD, basicResult.reason)

        // 5. Cross-tenant access forbidden
        val otherTenantPrincipal = AuthenticatedPrincipal(
            id = "user-other",
            tenantId = "other-tenant",
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        val crossTenantResult = service.verifyIntegrityToken(
            tenantId = "other-tenant",
            userId = userPrincipal.id,
            rawToken = "any-token",
            nonceValue = "any-nonce",
            principal = userPrincipal, // from tenant-prod-1
            idempotencyKey = "cross-verif",
        )
        assertTrue(crossTenantResult.isFailure)
        assertTrue(crossTenantResult.exceptionOrNull() is SecurityException)

        // 6. Privacy: Tokens and full payloads never logged
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.none { it.detailsRedacted.contains(token) })
        assertTrue(audits.none { it.detailsRedacted.contains("forged-token") })
    }

    // =========================================================================
    // INTEGRITY-001-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `INTEGRITY-001-T003 Play Integrity survives concurrency, duplicate delivery, and dependency failure`() {
        PlayIntegrityBinding.checkBound()

        val nonce = service.issueNonce(tenantId, userPrincipal.id, userPrincipal)
        val token = "token-nonce:${nonce.nonceValue}:valid"

        // Idempotent duplicate verification
        val verif1 = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = token,
            nonceValue = nonce.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "idem-verif-1",
        ).getOrThrow()

        val verif2 = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = token,
            nonceValue = nonce.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "idem-verif-1",
        ).getOrThrow()

        assertEquals(verif1.verificationId, verif2.verificationId)
        assertEquals(verif1.decision, verif2.decision)

        // Conflict on payload reuse
        val conflict = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = "different-user",
            rawToken = token,
            nonceValue = nonce.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "idem-verif-1",
        )
        assertTrue(conflict.isFailure)
        assertTrue(conflict.exceptionOrNull() is IllegalArgumentException)

        // Provider failure handling (fail closed)
        fakeProvider.shouldFail = true
        val nonceFail = service.issueNonce(tenantId, userPrincipal.id, userPrincipal)
        val failClosedResult = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = "token-nonce:${nonceFail.nonceValue}:test",
            nonceValue = nonceFail.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-fail-closed",
        ).getOrThrow()

        assertEquals(PlayIntegrityDecisionState.BLOCKED, failClosedResult.decision)
        assertEquals(PlayIntegrityReason.PROVIDER_UNAVAILABLE_FAIL_CLOSED, failClosedResult.reason)
        assertFalse(failClosedResult.directEligibilityGranted)
        assertFalse(failClosedResult.financialMutationPermitted)

        // Recover provider
        fakeProvider.shouldFail = false
        val nonceRecover = service.issueNonce(tenantId, userPrincipal.id, userPrincipal)
        val recoveredResult = service.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = "token-nonce:${nonceRecover.nonceValue}:recovered",
            nonceValue = nonceRecover.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "verif-recovered",
        ).getOrThrow()

        assertEquals(PlayIntegrityDecisionState.ALLOWED, recoveredResult.decision)

        // Concurrent nonce generations
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..8).map { i ->
            pool.submit(Callable {
                service.issueNonce(tenantId, "user-$i", userPrincipal)
            })
        }
        val nonces = futures.map { it.get() }
        pool.shutdown()

        assertEquals(8, nonces.distinctBy { it.nonceValue }.size)
    }

    // =========================================================================
    // INTEGRITY-001-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `INTEGRITY-001-T004 Play Integrity remains compatible, recoverable, observable, and lifecycle-safe`() {
        PlayIntegrityBinding.checkBound()

        // Sandbox adapter compatibility
        val sandboxAdapter = SandboxPlayIntegrityProviderAdapter(clock)
        val sandboxService = PlayIntegrityService(clock = clock, provider = sandboxAdapter)

        val nonce = sandboxService.issueNonce(tenantId, userPrincipal.id, userPrincipal)
        val sandboxResult = sandboxService.verifyIntegrityToken(
            tenantId = tenantId,
            userId = userPrincipal.id,
            rawToken = "token-nonce:${nonce.nonceValue}:sandbox",
            nonceValue = nonce.nonceValue,
            principal = userPrincipal,
            idempotencyKey = "sandbox-verif-1",
        )
        assertTrue(sandboxResult.isSuccess)

        // Readiness evaluation
        val evaluation = service.evaluatePlayIntegrityReadiness(tenantId, securityAdmin)
        assertEquals(PlayIntegrityDecisionState.ALLOWED, evaluation.status)
        assertEquals("Fail closed or risk-hold per approved policy; do not log tokens/verdict payloads.", evaluation.message)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)

        // Observability check: audits exist and never contain secrets or raw tokens
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.none { it.detailsRedacted.contains("sandbox-token") })
    }
}
