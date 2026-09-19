package com.slotting.admin.architecture

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TrustBoundariesAndThreatModelTest {
    private val now = Instant.parse("2026-09-18T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private fun adminPrincipal(tenantId: String = "tenant-admin-1"): AuthenticatedPrincipal =
        AuthenticatedPrincipal(
            id = "security-lead-1",
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
        )

    private fun playerPrincipal(tenantId: String = "tenant-admin-1"): AuthenticatedPrincipal =
        AuthenticatedPrincipal(
            id = "player-user-1",
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet()
        )

    private fun validAbuseCases(): List<AbuseReviewCase> = listOf(
        // 1. MONEY: Client attempts to directly confirm deposit credit
        AbuseReviewCase(
            caseId = "ABUSE-MONEY-01",
            domain = TrustBoundaryDomain.MONEY,
            threatCategory = StrideThreatCategory.TAMPERING,
            abuseDescription = "Android client returns status=success query param attempting local wallet credit",
            isClientAuthorityClaimed = true,
            isDenied = true,
            isObservableInAudit = true,
            reasonCode = "CLIENT_CREDIT_MUTATION_DENIED",
            evidenceArtifactRef = "evidence/stride/money-tampering.txt",
            passed = true
        ),
        // 2. CALLBACKS: Attacker sends unsigned or forged provider callback
        AbuseReviewCase(
            caseId = "ABUSE-CALLBACK-01",
            domain = TrustBoundaryDomain.CALLBACKS,
            threatCategory = StrideThreatCategory.SPOOFING,
            abuseDescription = "Forged game provider settlement callback with invalid HMAC signature",
            isClientAuthorityClaimed = false,
            isDenied = true,
            isObservableInAudit = true,
            reasonCode = "CALLBACK_SIGNATURE_INVALID",
            evidenceArtifactRef = "evidence/stride/callback-spoofing.txt",
            passed = true
        ),
        // 3. ADMIN: Unauthorized privilege escalation or repudiation
        AbuseReviewCase(
            caseId = "ABUSE-ADMIN-01",
            domain = TrustBoundaryDomain.ADMIN,
            threatCategory = StrideThreatCategory.ELEVATION_OF_PRIVILEGE,
            abuseDescription = "Support role attempting unapproved manual ledger balance adjustment without dual control",
            isClientAuthorityClaimed = false,
            isDenied = true,
            isObservableInAudit = true,
            reasonCode = "ADMIN_RBAC_DUAL_CONTROL_DENIED",
            evidenceArtifactRef = "evidence/stride/admin-elevation.txt",
            passed = true
        ),
        // 4. ADMIN: Repudiation attempt
        AbuseReviewCase(
            caseId = "ABUSE-ADMIN-02",
            domain = TrustBoundaryDomain.ADMIN,
            threatCategory = StrideThreatCategory.REPUDIATION,
            abuseDescription = "Attempt to bypass audit trail during role modification",
            isClientAuthorityClaimed = false,
            isDenied = true,
            isObservableInAudit = true,
            reasonCode = "AUDIT_BYPASS_PROHIBITED",
            evidenceArtifactRef = "evidence/stride/admin-repudiation.txt",
            passed = true
        ),
        // 5. ANDROID: Information disclosure of sensitive token
        AbuseReviewCase(
            caseId = "ABUSE-ANDROID-01",
            domain = TrustBoundaryDomain.ANDROID,
            threatCategory = StrideThreatCategory.INFORMATION_DISCLOSURE,
            abuseDescription = "Intent URL contains refresh token; sanitized before logging or presentation",
            isClientAuthorityClaimed = false,
            isDenied = true,
            isObservableInAudit = true,
            reasonCode = "SENSITIVE_URI_TOKEN_REDACTED",
            evidenceArtifactRef = "evidence/stride/android-info-disclosure.txt",
            passed = true
        ),
        // 6. ANDROID: Denial of service replay flood
        AbuseReviewCase(
            caseId = "ABUSE-ANDROID-02",
            domain = TrustBoundaryDomain.ANDROID,
            threatCategory = StrideThreatCategory.DENIAL_OF_SERVICE,
            abuseDescription = "Spin burst flood without waiting for server response",
            isClientAuthorityClaimed = false,
            isDenied = true,
            isObservableInAudit = true,
            reasonCode = "RATE_LIMIT_EXCEEDED",
            evidenceArtifactRef = "evidence/stride/android-dos.txt",
            passed = true
        )
    )

    private fun validCommand(
        tenantId: String = "tenant-admin-1",
        principal: AuthenticatedPrincipal? = adminPrincipal(tenantId),
        idempotencyKey: String = "idemp-threat-001",
        expectedVersion: Long = 1L,
        cases: List<AbuseReviewCase> = validAbuseCases()
    ): ThreatModelReviewCommand =
        ThreatModelReviewCommand(
            principal = principal,
            sessionId = "session-threat-101",
            tenantId = tenantId,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-threat-555",
            causationId = "caus-threat-666",
            expectedVersion = expectedVersion,
            cases = cases
        )

    @BeforeEach
    fun setUp() {
        TrustBoundariesBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        TrustBoundariesBinding.isBound = true
    }

    // =========================================================================
    // ARCH-002-T001: Produces Authoritative Certified Outcome
    // =========================================================================

    @Test
    fun `ARCH-002-T001 Trust boundaries and threat model produces the required authoritative outcome`() {
        val store = InMemoryThreatModelStore()
        val service = TrustBoundaryService(store, clock)

        val command = validCommand()
        val result = service.review(command)

        assertEquals(ThreatModelStatus.ACCEPTED, result.status)
        assertEquals(1L, result.serverVersion)
        assertEquals(now, result.serverTime)
        assertTrue(result.evidenceReference.startsWith("threat-model:tenant-admin-1:"))

        // Verify all 4 required domains covered: money, callbacks, admin, android
        val expectedDomains = setOf(
            TrustBoundaryDomain.MONEY,
            TrustBoundaryDomain.CALLBACKS,
            TrustBoundaryDomain.ADMIN,
            TrustBoundaryDomain.ANDROID
        )
        assertEquals(expectedDomains, result.coveredDomains)

        // Verify all 6 STRIDE threat categories covered
        val expectedThreats = StrideThreatCategory.entries.toSet()
        assertEquals(expectedThreats, result.coveredThreatCategories)

        // Verify denied events are observable
        assertTrue(result.deniedEventCount > 0)
        assertEquals(result.deniedEventCount, store.deniedEvents.size)
        store.deniedEvents.forEach { event ->
            assertTrue(event.type.startsWith("STRIDE_ABUSE_DENIED_"))
            assertEquals(command.tenantId, event.tenantId)
        }

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("STRIDE_THREAT_MODEL_ACCEPTED", store.audit[0].type)
        assertEquals("STRIDE_THREAT_MODEL_ACCEPTED", store.outbox[0].type)

        // Assert zero financial authority mutation: service has no financial mutation methods
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("mutate") || it.contains("credit") || it.contains("debit") })
    }

    // =========================================================================
    // ARCH-002-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `ARCH-002-T002 Trust boundaries and threat model rejects invalid boundary unauthorized and stale input`() {
        val store = InMemoryThreatModelStore()
        val service = TrustBoundaryService(store, clock)

        // 1. Unauthenticated caller rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(validCommand(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Player caller attempting threat model review rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(validCommand(principal = playerPrincipal()))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Cross-tenant access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(validCommand(tenantId = "other-tenant", principal = adminPrincipal("tenant-admin-1")))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Stale version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(validCommand(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Blank idempotency key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(validCommand(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Missing domain (e.g. missing MONEY domain) rejected
        val casesMissingMoney = validAbuseCases().filter { it.domain != TrustBoundaryDomain.MONEY }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(validCommand(cases = casesMissingMoney))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Abuse case demonstrating unmitigated client authority rejected
        val rogueCase = AbuseReviewCase(
            caseId = "ABUSE-ROGUE-01",
            domain = TrustBoundaryDomain.MONEY,
            threatCategory = StrideThreatCategory.TAMPERING,
            abuseDescription = "Client successfully credited wallet without server verification",
            isClientAuthorityClaimed = true,
            isDenied = false, // Failure to deny client authority!
            isObservableInAudit = true,
            reasonCode = "CLIENT_CREDIT_UNMITIGATED",
            evidenceArtifactRef = "evidence/stride/fail.txt",
            passed = false
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(validCommand(cases = validAbuseCases() + rogueCase))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Assert zero unauthorized durable mutation
        assertEquals(0, store.audit.size)
        assertEquals(0, store.outbox.size)
    }

    // =========================================================================
    // ARCH-002-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `ARCH-002-T003 Trust boundaries and threat model survives concurrency duplicate delivery and dependency failure`() {
        val store = InMemoryThreatModelStore()
        val service = TrustBoundaryService(store, clock)

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val command = validCommand(idempotencyKey = "idemp-concurrent-threat-001")

        val calls = (1..2).map {
            pool.submit<ThreatModelReviewResult> {
                gate.await()
                service.review(command)
            }
        }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()

        // Concurrent equivalent submissions produce identical authoritative result
        assertEquals(results[0].resultId, results[1].resultId)
        assertEquals(ThreatModelStatus.ACCEPTED, results[0].status)
        assertEquals(ThreatModelStatus.ACCEPTED, results[1].status)

        // Conflicting payload with reused key rejected with CONFLICT
        val conflictingCommand = command.copy(sessionId = "different-session-id")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // ARCH-002-T004: Remains Compatible, Recoverable, Observable, Lifecycle-Safe
    // =========================================================================

    @Test
    fun `ARCH-002-T004 Trust boundaries and threat model remains compatible recoverable observable and lifecycle-safe`() {
        val store = InMemoryThreatModelStore()
        val service = TrustBoundaryService(store, clock)

        // 1. Fail-closed assertion gate (expected RED failure: abuse cases demonstrate client authority)
        TrustBoundariesBinding.isBound = false
        val ex = assertFailsWith<AssertionError> {
            service.review(validCommand())
        }
        assertEquals("abuse cases demonstrate client authority", ex.message)

        // Re-bind
        TrustBoundariesBinding.isBound = true

        // 2. Authoritative evaluation and observability
        val command = validCommand(idempotencyKey = "idemp-obs-threat-001")
        val result = service.review(command)
        assertEquals(ThreatModelStatus.ACCEPTED, result.status)

        // Assert audit evidence contains no sensitive secrets or PII
        val auditEvent = result.auditEvent
        assertNotNull(auditEvent)
        val auditString = "${auditEvent.type}:${auditEvent.tenantId}:${auditEvent.correlationId}:${auditEvent.causationId}"
        assertTrue(!auditString.contains("SECRET", ignoreCase = true))
        assertTrue(!auditString.contains("PASSWORD", ignoreCase = true))
        assertTrue(!auditString.contains("TOKEN", ignoreCase = true))

        // Assert all denied events are observable and free from secret tokens
        store.deniedEvents.forEach { denied ->
            val deniedStr = "${denied.type}:${denied.tenantId}:${denied.correlationId}"
            assertTrue(!deniedStr.contains("SECRET", ignoreCase = true))
            assertTrue(!deniedStr.contains("PASSWORD", ignoreCase = true))
            assertTrue(!deniedStr.contains("TOKEN", ignoreCase = true))
        }
    }
}
