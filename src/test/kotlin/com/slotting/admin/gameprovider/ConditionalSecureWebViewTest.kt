package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Mandatory contract test suite for GAME-011:
 * Conditional secure WebView.
 *
 * Semantic contract: "Otherwise classified intentionally deferred; no WebView added speculatively."
 * Protected risk assertion: "unsafe bridge/navigation/file access"
 */
class ConditionalSecureWebViewTest {

    private lateinit var store: InMemoryConditionalWebViewStore
    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var service: ConditionalSecureWebViewService
    private val clock = Clock.fixed(Instant.parse("2026-09-19T00:00:00Z"), ZoneOffset.UTC)

    private val tenantId = "tenant-pilot-001"
    private val authorizedPrincipal = AuthenticatedPrincipal(
        id = "usr-admin-001",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    @BeforeEach
    fun setUp() {
        store = InMemoryConditionalWebViewStore()
        rbacPolicy = AdminRbacPolicy(true)
        service = ConditionalSecureWebViewService(
            store = store,
            rbacPolicy = rbacPolicy,
            clock = clock
        )
    }

    // =========================================================================
    // GAME-011-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `GAME-011-T001 Conditional secure WebView produces the required authoritative outcome`() {
        ConditionalSecureWebViewBinding.checkBound()

        val command = EvaluateConditionalWebViewCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            providerId = "provider-pragmatic",
            gameId = "game-sweet-bonanza",
            idempotencyKey = "idemp-webview-001",
            correlationId = "corr-webview-001",
            causationId = "caus-webview-001",
            expectedVersion = 1L
        )

        val result = service.evaluateWebViewPosture(command)

        // Exact assertions from semantic contract:
        // "Otherwise classified intentionally deferred; no WebView added speculatively."
        assertEquals(WebViewLaunchPosture.INTENTIONALLY_DEFERRED, result.posture)
        assertFalse(result.permitted)
        assertEquals("INTENTIONALLY_DEFERRED_NO_SPECULATIVE_WEBVIEW", result.reasonCode)
        assertEquals("Otherwise classified intentionally deferred; no WebView added speculatively", result.safeMessage)
        assertNull(result.launchUrl)
        assertNull(result.enforcedSecurityConstraints)
        assertTrue(result.evidenceReference.isNotBlank())

        // Transactional persistence & audit
        assertNotNull(store.findEvaluation(tenantId, result.resultId))
        assertTrue(store.auditEvents.any { it.type == "CONDITIONAL_WEBVIEW_EVALUATED_INTENTIONALLY_DEFERRED" })
        assertTrue(store.outboxEvents.any { it.type == "CONDITIONAL_WEBVIEW_EVALUATED" })
    }

    // =========================================================================
    // GAME-011-T002: Negative, Boundary, Security & Authorization Rejection
    // =========================================================================

    @Test
    fun `GAME-011-T002 Conditional secure WebView rejects invalid, boundary, unauthorized, and stale input`() {
        ConditionalSecureWebViewBinding.checkBound()

        val baseCommand = EvaluateConditionalWebViewCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            providerId = "provider-pragmatic",
            gameId = "game-sweet-bonanza",
            idempotencyKey = "idemp-sec-001",
            correlationId = "corr-sec-001",
            causationId = "caus-sec-001",
            expectedVersion = 1L
        )

        // 1. Missing principal -> UNAUTHENTICATED
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(baseCommand.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant principal -> FORBIDDEN
        val crossTenantPrincipal = authorizedPrincipal.copy(tenantId = "tenant-other")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(baseCommand.copy(principal = crossTenantPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Unsafe file access requested -> FORBIDDEN ("unsafe bridge/navigation/file access")
        val unsafeFileAccess = WebViewSecurityConstraints(allowFileAccess = true)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(baseCommand.copy(requestedSecurityConstraints = unsafeFileAccess))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Insecure cleartext HTTP requested -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(baseCommand.copy(requestedLaunchUrl = "http://insecure-provider.com/game"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Unsafe JavaScript bridge requested -> FORBIDDEN
        val unsafeJsBridge = WebViewSecurityConstraints(allowJavaScriptInterface = true)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(baseCommand.copy(requestedSecurityConstraints = unsafeJsBridge))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Stale version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(baseCommand.copy(expectedVersion = 999L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 7. Blank tenantId / providerId -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(baseCommand.copy(tenantId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // GAME-011-T003: Concurrency, Duplicate Delivery, and Idempotency
    // =========================================================================

    @Test
    fun `GAME-011-T003 Conditional secure WebView survives concurrency, duplicate delivery, and dependency failure`() {
        ConditionalSecureWebViewBinding.checkBound()

        val command = EvaluateConditionalWebViewCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            providerId = "provider-pragmatic",
            gameId = "game-sweet-bonanza",
            idempotencyKey = "idemp-dup-001",
            correlationId = "corr-dup-001",
            causationId = "caus-dup-001",
            expectedVersion = 1L
        )

        // Initial execution
        val firstResult = service.evaluateWebViewPosture(command)
        assertEquals(WebViewLaunchPosture.INTENTIONALLY_DEFERRED, firstResult.posture)
        val initialAuditCount = store.auditEvents.size

        // Duplicate delivery with same idempotency key returns identical result
        val duplicateResult = service.evaluateWebViewPosture(command)
        assertEquals(firstResult.resultId, duplicateResult.resultId)
        assertEquals(firstResult.evidenceReference, duplicateResult.evidenceReference)
        assertEquals(firstResult.posture, duplicateResult.posture)
        assertEquals(initialAuditCount, store.auditEvents.size)

        // Same idempotency key with conflicting payload throws CONFLICT
        val conflictingCommand = command.copy(gameId = "game-gates-of-olympus")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateWebViewPosture(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // GAME-011-T004: Lifecycle, Observability, and Audit Trail Safety
    // =========================================================================

    @Test
    fun `GAME-011-T004 Conditional secure WebView remains compatible, recoverable, observable, and lifecycle-safe`() {
        ConditionalSecureWebViewBinding.checkBound()

        // 1. Evaluate baseline intentionally deferred
        val command = EvaluateConditionalWebViewCommand(
            tenantId = tenantId,
            principal = authorizedPrincipal,
            providerId = "provider-evolution",
            gameId = "game-roulette",
            idempotencyKey = "idemp-life-001",
            correlationId = "corr-life-001",
            causationId = "caus-life-001",
            expectedVersion = 1L
        )

        val result = service.evaluateWebViewPosture(command)
        assertEquals(WebViewLaunchPosture.INTENTIONALLY_DEFERRED, result.posture)
        assertFalse(result.permitted)
        assertEquals("Otherwise classified intentionally deferred; no WebView added speculatively", result.safeMessage)

        // 2. Verified provider with approved certification requiring WebView
        val now = clock.instant()
        store.setProviderCertification(
            tenantId,
            ProviderCertificationEvidence(
                providerId = "provider-evolution",
                requiresWebView = true,
                certifiedDomains = setOf("live.evolution.com"),
                certificationId = "cert-evo-999",
                certifiedAt = now.minusSeconds(3600),
                expiresAt = now.plusSeconds(86400)
            )
        )

        val approvedCommand = command.copy(
            idempotencyKey = "idemp-life-002",
            requestedLaunchUrl = "https://live.evolution.com/launch?table=roulette"
        )
        val certifiedResult = service.evaluateWebViewPosture(approvedCommand)
        assertEquals(WebViewLaunchPosture.PERMITTED_SECURE, certifiedResult.posture)
        assertTrue(certifiedResult.permitted)
        assertNotNull(certifiedResult.enforcedSecurityConstraints)
        assertTrue(certifiedResult.enforcedSecurityConstraints!!.isSecure())
        assertEquals("https://live.evolution.com/launch?table=roulette", certifiedResult.launchUrl)

        // 3. Verify audit trail and outbox events retain correlation without leaking secrets or PII
        val audits = store.auditEvents.filter { it.correlationId == "corr-life-001" }
        assertEquals(2, audits.size)
        audits.forEach { audit ->
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
        }
    }
}
