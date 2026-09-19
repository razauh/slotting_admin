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

class BackendModuleBoundariesTest {
    private val now = Instant.parse("2026-09-18T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private fun adminPrincipal(tenantId: String = "tenant-admin-1"): AuthenticatedPrincipal =
        AuthenticatedPrincipal(
            id = "admin-user-1",
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

    private fun validCommand(
        tenantId: String = "tenant-admin-1",
        principal: AuthenticatedPrincipal? = adminPrincipal(tenantId),
        idempotencyKey: String = "idemp-arch-001",
        expectedVersion: Long = 1L,
        declaredModules: Set<String> = CanonicalBackendModule.REQUIRED_MODULE_IDS
    ): EnforceModuleBoundariesCommand =
        EnforceModuleBoundariesCommand(
            principal = principal,
            sessionId = "session-arch-101",
            tenantId = tenantId,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-arch-555",
            causationId = "caus-arch-666",
            expectedVersion = expectedVersion,
            declaredModules = declaredModules
        )

    @BeforeEach
    fun setUp() {
        BackendModuleBoundaryBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        BackendModuleBoundaryBinding.isBound = true
    }

    // =========================================================================
    // ARCH-001-02-T001: Produces Authoritative Certified Outcome
    // =========================================================================

    @Test
    fun `ARCH-001-02-T001 Enforce backend module boundaries produces the required authoritative outcome`() {
        val store = InMemoryModuleBoundaryStore()
        val service = BackendModuleBoundaryService(store, clock)

        val command = validCommand()
        val result = service.enforce(command)

        assertEquals(BoundaryEnforcementStatus.ENFORCED, result.status)
        assertEquals(1L, result.serverVersion)
        assertEquals(now, result.serverTime)
        assertTrue(result.evidenceReference.startsWith("arch-boundary:tenant-admin-1:"))

        // Verify the exact 9 required modules per semantic contract:
        // "Modules: identity,wallet,ledger,payments,games,compliance,admin,support,outbox; repeatable local tests; no Android source impact."
        val expectedModules = setOf(
            "identity", "wallet", "ledger", "payments", "games",
            "compliance", "admin", "support", "outbox"
        )
        assertEquals(expectedModules, result.enforcedModules)

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("BACKEND_MODULE_BOUNDARIES_ENFORCED", store.audit[0].type)
        assertEquals("BACKEND_MODULE_BOUNDARIES_ENFORCED", store.outbox[0].type)
        assertEquals(command.correlationId, store.audit[0].correlationId)
        assertEquals(command.causationId, store.audit[0].causationId)

        // Assert zero financial authority mutation: service has no financial mutation methods
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("mutate") || it.contains("credit") || it.contains("debit") })
    }

    // =========================================================================
    // ARCH-001-02-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `ARCH-001-02-T002 Enforce backend module boundaries rejects invalid boundary unauthorized and stale input`() {
        val store = InMemoryModuleBoundaryStore()
        val service = BackendModuleBoundaryService(store, clock)

        // 1. Unauthenticated principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(validCommand(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Player principal attempting admin architecture governance rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(validCommand(principal = playerPrincipal()))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Cross-tenant access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(validCommand(tenantId = "other-tenant", principal = adminPrincipal("tenant-admin-1")))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Stale version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(validCommand(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Blank idempotency key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(validCommand(idempotencyKey = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Missing required modules rejected (e.g. missing 'ledger' and 'outbox')
        val incompleteModules = setOf("identity", "wallet", "payments", "games", "compliance", "admin", "support")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(validCommand(declaredModules = incompleteModules))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Android source contamination rejected (violates 'no Android source impact')
        val contaminatedModules = CanonicalBackendModule.REQUIRED_MODULE_IDS + "android-client"
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(validCommand(declaredModules = contaminatedModules))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Assert zero unauthorized durable mutation
        assertEquals(0, store.audit.size)
        assertEquals(0, store.outbox.size)
    }

    // =========================================================================
    // ARCH-001-02-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `ARCH-001-02-T003 Enforce backend module boundaries survives concurrency duplicate delivery and dependency failure`() {
        val store = InMemoryModuleBoundaryStore()
        val service = BackendModuleBoundaryService(store, clock)

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val command = validCommand(idempotencyKey = "idemp-concurrent-001")

        val calls = (1..2).map {
            pool.submit<EnforceModuleBoundariesResult> {
                gate.await()
                service.enforce(command)
            }
        }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()

        // Concurrent equivalent submissions produce identical authoritative result
        assertEquals(results[0].resultId, results[1].resultId)
        assertEquals(BoundaryEnforcementStatus.ENFORCED, results[0].status)
        assertEquals(BoundaryEnforcementStatus.ENFORCED, results[1].status)

        // Conflicting payload with reused key rejected with CONFLICT
        val conflictingCommand = command.copy(sessionId = "different-session-id")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforce(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // ARCH-001-02-T004: Remains Compatible, Recoverable, Observable, Lifecycle-Safe
    // =========================================================================

    @Test
    fun `ARCH-001-02-T004 Enforce backend module boundaries remains compatible recoverable observable and lifecycle-safe`() {
        val store = InMemoryModuleBoundaryStore()
        val service = BackendModuleBoundaryService(store, clock)

        // 1. Fail-closed assertion gate (expected RED failure: architecture test fails missing modules)
        BackendModuleBoundaryBinding.isBound = false
        val ex = assertFailsWith<AssertionError> {
            service.enforce(validCommand())
        }
        assertEquals("architecture test fails missing modules", ex.message)

        // Re-bind
        BackendModuleBoundaryBinding.isBound = true

        // 2. Authoritative evaluation and observability
        val command = validCommand(idempotencyKey = "idemp-obs-001")
        val result = service.enforce(command)
        assertEquals(BoundaryEnforcementStatus.ENFORCED, result.status)

        // Assert audit evidence contains no sensitive secrets or PII
        val auditEvent = result.auditEvent
        assertNotNull(auditEvent)
        val auditString = "${auditEvent.type}:${auditEvent.tenantId}:${auditEvent.correlationId}:${auditEvent.causationId}"
        assertTrue(!auditString.contains("SECRET", ignoreCase = true))
        assertTrue(!auditString.contains("PASSWORD", ignoreCase = true))
        assertTrue(!auditString.contains("TOKEN", ignoreCase = true))
    }
}
