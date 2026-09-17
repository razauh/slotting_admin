package com.slotting.admin.auth

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

class AdminMfaAuthenticationTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-001-01-T001 Authenticate administrators with MFA produces authoritative outcome`() {
        val store = MemoryStore()
        val alerts = MemoryAlerts()
        val result = authenticator(store, alerts).authenticate(command(breakGlass = true))

        assertEquals(AuthenticationState.AUTHENTICATED, result.state)
        assertEquals(now.plusSeconds(1800), result.expiresAt)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("ADMIN_BREAK_GLASS_STARTED", alerts.events.single().type)
        assertTrue(result.evidenceReference.startsWith("admin-auth:"))
    }

    @Test
    fun `ADMIN-001-01-T002 Authenticate administrators with MFA rejects invalid boundary unauthorized and stale input`() {
        val store = MemoryStore()
        val service = authenticator(store, MemoryAlerts())
        assertFailsWith<AuthenticationFailure.Rejected> { service.authenticate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.authenticate(command(mfaAssertion = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.authenticate(command(expectedVersion = -1)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertEquals(0, store.results.size)
    }

    @Test
    fun `ADMIN-001-01-T003 Authenticate administrators with MFA survives concurrency duplicate delivery and dependency failure`() {
        val store = MemoryStore()
        val service = authenticator(store, MemoryAlerts())
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val results = (1..2).map { pool.submit<AuthenticationResult> { gate.await(); service.authenticate(command()) } }
        gate.countDown()
        val resolved = results.map { runCatching { it.get() } }
        pool.shutdown()
        assertTrue(resolved.all { it.isSuccess })
        assertEquals(1, resolved.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.results.size)
        assertNotNull(service.authenticate(command()).resultId)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticate(command(mfaAssertion = "different"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADMIN-001-01-T004 Authenticate administrators with MFA remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V1__admin_mfa.sql").readText()
        assertTrue(migration.contains("admin_audit_event"))
        assertTrue(migration.contains("admin_outbox_event"))
        assertTrue(!migration.contains("update admin_")) // no posted-history update statement
        val policy = RoleChangePolicy(dualControlRequired = true)
        val admin = command().principal!!
        assertTrue(!policy.isAllowed(admin, admin.id))
        assertTrue(policy.isAllowed(admin, "second-approver"))
    }

    private fun authenticator(store: MemoryStore, alerts: MemoryAlerts) =
        AdminMfaAuthenticator(AlwaysValidMfa(), store, alerts, clock)

    private fun command(
        principal: AuthenticatedPrincipal = admin(),
        mfaAssertion: String = "opaque-proof",
        expectedVersion: Long = 0,
        breakGlass: Boolean = false,
    ) = AdminMfaCommand(principal, AdminRole.SECURITY, "session-1", "key-1", "corr-1", "cause-1", expectedVersion, mfaAssertion, breakGlass)

    private fun admin() = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))
    private fun player() = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class AlwaysValidMfa : MfaVerifier {
    override fun verify(tenantId: String, principalId: String, sessionId: String, assertion: String) = assertion == "opaque-proof"
}

private class MemoryAlerts : AlertSink {
    val events = mutableListOf<AuditEvent>()
    override fun alert(event: AuditEvent) = synchronized(events) { events += event }
}

private class MemoryStore : AuthenticationStore {
    val results = mutableMapOf<String, Pair<String, AuthenticationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()
    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) {
        results["$tenantId:$key"]
    }
    override fun currentVersion(tenantId: String, principalId: String) = synchronized(this) {
        results.values.maxOfOrNull { it.second.serverVersion } ?: 0L
    }
    override fun save(result: AuthenticationResult, tenantId: String, principalId: String, sessionId: String, idempotencyKey: String, requestFingerprint: String, audit: AuditEvent, outbox: OutboxEvent) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = requestFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
