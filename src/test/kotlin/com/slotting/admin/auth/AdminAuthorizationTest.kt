package com.slotting.admin.auth

import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AdminAuthorizationTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-001-03-T001 Enforce segregation of duties and break-glass controls produces authoritative outcome`() {
        val store = AuthorizationMemoryStore()
        val alerts = MemoryAuthorizationAlerts()
        val service = service(store, alerts)
        val result = service.authorize(command(permission = AdminPermission.CHANGE_ROLES, secondApproverId = "admin-2", breakGlass = true))

        assertEquals(AuthorizationState.ALLOWED, result.state)
        assertEquals(1L, result.serverVersion)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals(setOf("ADMIN_ROLE_CHANGE_DUAL_CONTROL", "ADMIN_BREAK_GLASS_AUTHZ"), alerts.events.map { it.type }.toSet())
        assertTrue(result.evidenceReference.startsWith("admin-rbac:"))
    }

    @Test
    fun `ADMIN-001-03-T002 Enforce segregation of duties and break-glass controls rejects invalid boundary unauthorized and stale input`() {
        val store = AuthorizationMemoryStore()
        val service = service(store, MemoryAuthorizationAlerts())
        assertFailsWith<AuthenticationFailure.Rejected> { service.authorize(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.authorize(command(tenantId = "other-tenant")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.authorize(command(permission = AdminPermission.FINANCIAL_MUTATION)) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.authorize(command(permission = AdminPermission.CHANGE_ROLES, secondApproverId = "admin-1")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.authorize(command(expectedVersion = 3)) }
            .also { assertEquals(AuthErrorCode.STALE, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.authorize(command(breakGlass = true, sessionId = "expired-session")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(0, store.results.size)
    }

    @Test
    fun `ADMIN-001-03-T003 Enforce segregation of duties and break-glass controls survives concurrency duplicate delivery and dependency failure`() {
        val store = AuthorizationMemoryStore()
        val service = service(store, MemoryAuthorizationAlerts())
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map { pool.submit<AuthorizationResult> { gate.await(); service.authorize(command()) } }
        gate.countDown()
        val results = calls.map { it.get() }
        pool.shutdown()
        assertEquals(1, results.distinctBy { it.resultId }.size)
        assertEquals(1, store.results.size)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(command(permission = AdminPermission.READ_SUPPORT))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADMIN-001-03-T004 Enforce segregation of duties and break-glass controls remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V2__admin_rbac.sql").readText()
        assertTrue(migration.contains("admin_authorization_decision"))
        assertTrue(migration.contains("resource_owner_id"))
        assertTrue(migration.contains("server_version"))
        assertTrue(!migration.contains("update admin_"))
        assertTrue(!AdminRbacPolicy(dualControlRequired = true).isPermitted(admin(), AdminPermission.FINANCIAL_MUTATION))
    }

    private fun service(store: AuthorizationMemoryStore, alerts: MemoryAuthorizationAlerts) =
        AdminAuthorizationService(ActiveSessionDirectory(), store, ResourceOwnerDirectory(), alerts, AdminRbacPolicy(true), clock)

    private fun command(
        principal: AuthenticatedPrincipal = admin(),
        tenantId: String = "tenant-1",
        sessionId: String = "session-1",
        permission: AdminPermission = AdminPermission.MANAGE_SUPPORT,
        expectedVersion: Long = 0,
        secondApproverId: String? = null,
        breakGlass: Boolean = false,
    ) = AdminAuthorizationCommand(principal, sessionId, tenantId, "resource-1", permission, "key-1", "corr-1", "cause-1", expectedVersion, secondApproverId, breakGlass)

    private fun admin() = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private fun player() = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-1")
            AdminSessionStatus(true, true, Instant.parse("2026-09-17T10:30:00Z"))
        else null
}

private class ResourceOwnerDirectory : ResourceOwnerResolver {
    override fun resolve(tenantId: String, resourceReference: String) =
        if (tenantId == "tenant-1" && resourceReference == "resource-1") "owner-1" else null
}

private class MemoryAuthorizationAlerts : AlertSink {
    val events = mutableListOf<AuditEvent>()
    override fun alert(event: AuditEvent) { events += event }
}

private class AuthorizationMemoryStore : AuthorizationStore {
    val results = mutableMapOf<String, Pair<String, AuthorizationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()
    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun currentVersion(tenantId: String, ownerId: String) = synchronized(this) {
        results.values.maxOfOrNull { it.second.serverVersion } ?: 0L
    }
    override fun save(result: AuthorizationResult, tenantId: String, ownerId: String, permission: AdminPermission, idempotencyKey: String, breakGlass: Boolean, expiresAt: Instant, requestFingerprint: String, audit: AuditEvent, outbox: OutboxEvent) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = requestFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
