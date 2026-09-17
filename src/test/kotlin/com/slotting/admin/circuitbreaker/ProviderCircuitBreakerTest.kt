package com.slotting.admin.circuitbreaker

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class ProviderCircuitBreakerTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-005-03-T001 Operate provider circuit breakers produces the required authoritative outcome`() {
        val store = CircuitBreakerMemoryStore()
        val service = service(store)

        // 1. Initial configuration of circuit breaker (CLOSED = traffic flowing)
        val configured = service.operate(
            command(
                action = CircuitBreakerAction.CONFIGURE,
                providerId = "stripe-eu",
                providerType = ProviderType.PAYMENT,
                failureThreshold = 5,
                cooldownSeconds = 60,
            )
        )
        assertFalse(configured.circuitBreaker.toString().contains("secret"))
        assertEquals("****", configured.circuitBreaker.maskedSecretPreview)
        assertEquals(CircuitBreakerState.CLOSED, configured.circuitBreaker.state)
        assertEquals(5, configured.circuitBreaker.failureThreshold)
        assertEquals(60, configured.circuitBreaker.cooldownSeconds)

        // 2. Trip circuit breaker (disable traffic) correlating to incident
        val tripped = service.operate(
            command(
                action = CircuitBreakerAction.TRIP,
                providerId = "stripe-eu",
                expectedVersion = configured.circuitBreaker.serverVersion,
                incidentReference = "INC-CB-701",
                idempotencyKey = "key-trip-cb",
            )
        )
        assertEquals(CircuitBreakerState.OPEN, tripped.circuitBreaker.state)
        assertEquals("INC-CB-701", tripped.circuitBreaker.incidentReference)

        // 3. Disable is reversible: reset circuit breaker (resume traffic) correlating to resolution
        val reset = service.operate(
            command(
                action = CircuitBreakerAction.RESET,
                providerId = "stripe-eu",
                expectedVersion = tripped.circuitBreaker.serverVersion,
                incidentReference = "INC-CB-701-RESOLVED",
                idempotencyKey = "key-reset-cb",
            )
        )
        assertEquals(CircuitBreakerState.CLOSED, reset.circuitBreaker.state)
        assertEquals("INC-CB-701-RESOLVED", reset.circuitBreaker.incidentReference)

        // Verify audit and outbox
        assertEquals(3, store.audit.size)
        assertEquals(3, store.outbox.size)
        assertEquals("CIRCUIT_BREAKER_CONFIGURE", store.audit[0].type)
        assertEquals("CIRCUIT_BREAKER_TRIP", store.audit[1].type)
        assertEquals("CIRCUIT_BREAKER_RESET", store.audit[2].type)
        assertEquals("corr-cb-1", store.audit[0].correlationId)
        assertEquals("cause-cb-1", store.audit[0].causationId)
    }

    @Test
    fun `ADMIN-005-03-T002 Operate provider circuit breakers rejects invalid, boundary, unauthorized, and stale input`() {
        val store = CircuitBreakerMemoryStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = null)) }
            .also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = admin(tenantId = "tenant-other"))) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unsafe enable/input validations
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(providerId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(failureThreshold = 0)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(cooldownSeconds = -1)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(sessionId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unknown provider on trip
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = CircuitBreakerAction.TRIP, providerId = "unknown-prov"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        val configured = service.operate(command(action = CircuitBreakerAction.CONFIGURE))

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = CircuitBreakerAction.TRIP, expectedVersion = 99))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Unsafe disable/enable: tripping or resetting without incident reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = CircuitBreakerAction.TRIP,
                    expectedVersion = configured.circuitBreaker.serverVersion,
                    incidentReference = null,
                    idempotencyKey = "trip-fail-no-inc",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val tripped = service.operate(
            command(
                action = CircuitBreakerAction.TRIP,
                expectedVersion = configured.circuitBreaker.serverVersion,
                incidentReference = "INC-1",
                idempotencyKey = "trip-ok",
            )
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = CircuitBreakerAction.RESET,
                    expectedVersion = tripped.circuitBreaker.serverVersion,
                    incidentReference = "   ",
                    idempotencyKey = "reset-fail-blank-inc",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `ADMIN-005-03-T003 Operate provider circuit breakers survives concurrency, duplicate delivery, and dependency failure`() {
        val store = CircuitBreakerMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<ProviderCircuitBreakerResult> {
                gate.await()
                service.operate(command(action = CircuitBreakerAction.CONFIGURE, idempotencyKey = "race-reg-cb"))
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }
        pool.shutdown()

        assertEquals(2, outcomes.count { it.isSuccess })
        assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // Conflicting replay with different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = CircuitBreakerAction.CONFIGURE,
                    failureThreshold = 99,
                    idempotencyKey = "race-reg-cb",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = CircuitBreakerAction.TRIP, expectedVersion = 0, idempotencyKey = "stale-trip-cb"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(command(action = CircuitBreakerAction.TRIP, expectedVersion = 1, idempotencyKey = "dep-trip-cb"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-005-03-T004 Operate provider circuit breakers remains compatible, recoverable, observable, and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V13__provider_circuit_breaker.sql").readText()
        assertTrue(migration.contains("admin_provider_circuit_breaker"))
        assertTrue(migration.contains("admin_provider_circuit_breaker_result"))
        assertTrue(migration.contains("failure_threshold"))
        assertTrue(migration.contains("cooldown_seconds"))
        assertTrue(migration.contains("incident_reference"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: CircuitBreakerMemoryStore) =
        ProviderCircuitBreakerService(AdminRbacPolicy(true), ActiveCircuitBreakerSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: CircuitBreakerMemoryStore) =
        ProviderCircuitBreakerService(AdminRbacPolicy(true), FailingCircuitBreakerSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        providerId: String = "stripe-eu",
        providerType: ProviderType = ProviderType.PAYMENT,
        action: CircuitBreakerAction = CircuitBreakerAction.CONFIGURE,
        failureThreshold: Int = 5,
        cooldownSeconds: Long = 60,
        incidentReference: String? = null,
        expectedVersion: Long = 0L,
        idempotencyKey: String = "key-cb-${action.name}",
        sessionId: String = "session-cb-1",
        correlationId: String = "corr-cb-1",
        causationId: String = "cause-cb-1",
    ) = ProviderCircuitBreakerCommand(
        principal,
        sessionId,
        "tenant-1",
        providerId,
        providerType,
        action,
        incidentReference,
        failureThreshold,
        cooldownSeconds,
        idempotencyKey,
        correlationId,
        causationId,
        expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveCircuitBreakerSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-cb-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingCircuitBreakerSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class CircuitBreakerMemoryStore : ProviderCircuitBreakerStore {
    val items = mutableMapOf<String, ProviderCircuitBreaker>()
    val results = mutableMapOf<String, Pair<String, ProviderCircuitBreakerResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findBreaker(tenantId: String, providerId: String) = synchronized(this) { items["$tenantId:$providerId"] }
    override fun save(
        result: ProviderCircuitBreakerResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        items["$tenantId:${result.circuitBreaker.providerId}"] = result.circuitBreaker
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
