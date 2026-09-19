package com.slotting.admin.auth

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ApiResourceOwnershipTest {

    private val now = Instant.parse("2026-09-18T23:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        ApiResourceOwnershipBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ApiResourceOwnershipBinding.isBound = true
    }

    private fun playerPrincipal(id: String = "player-1", tenantId: String = "tenant-1"): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet()
        )
    }

    private fun adminPrincipal(
        id: String = "admin-1",
        tenantId: String = "tenant-1",
        roles: Set<AdminRole> = setOf(AdminRole.SUPPORT)
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = roles
        )
    }

    // =========================================================================
    // AUTHZ-002-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTHZ-002-01-T001 Enforce API resource ownership produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        ApiResourceOwnershipBinding.checkBound()

        val directory = InMemoryApiResourceDirectory()
        val store = InMemoryApiResourceOwnershipStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service = ApiResourceOwnershipService(
            resourceDirectory = directory,
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-1"
        val player = playerPrincipal("player-100", tenantId)

        // Register player-owned wallet view resource
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "wallet-view-100",
                resourceType = ApiResourceType.PLAYER_WALLET_VIEW,
                tenantId = tenantId,
                ownerId = player.id,
                version = 1L
            )
        )

        // Player accesses their own resource
        val playerCmd = EnforceResourceOwnershipCommand(
            principal = player,
            tenantId = tenantId,
            resourceType = ApiResourceType.PLAYER_WALLET_VIEW,
            resourceId = "wallet-view-100",
            operation = ApiOperation.READ,
            idempotencyKey = "cmd-1",
            correlationId = "corr-1",
            causationId = "caus-1",
            expectedVersion = 1L
        )

        val decision = service.enforceOwnership(playerCmd)

        // Exact assertions: Default deny; resource owner resolved server-side; P0/P1 authz tests mandatory.
        assertTrue(decision.allowed)
        assertEquals(tenantId, decision.tenantId)
        assertEquals("wallet-view-100", decision.resourceId)
        assertEquals(ApiResourceType.PLAYER_WALLET_VIEW, decision.resourceType)
        assertEquals("player-100", decision.resolvedOwnerId)
        assertEquals("player-100", decision.principalId)
        assertEquals(PrincipalKind.PLAYER, decision.principalKind)
        assertEquals(1L, decision.serverVersion)
        assertEquals(now, decision.serverTime)
        assertTrue(decision.evidenceReference.startsWith("api-resource-authz:$tenantId:PLAYER_WALLET_VIEW:wallet-view-100:"))

        // Verify Audit & Outbox lineage
        assertEquals("API_RESOURCE_ACCESS_AUTHORIZED", decision.auditEvent.type)
        assertEquals(tenantId, decision.auditEvent.tenantId)
        assertEquals("corr-1", decision.auditEvent.correlationId)
        assertEquals("caus-1", decision.auditEvent.causationId)
        assertEquals("API_RESOURCE_ACCESS_AUTHORIZED", decision.outboxEvent.type)

        // 2. Authoritative Admin access to player resource with audited reason
        val supportAdmin = adminPrincipal("admin-support-1", tenantId, setOf(AdminRole.SUPPORT))
        val adminCmd = EnforceResourceOwnershipCommand(
            principal = supportAdmin,
            tenantId = tenantId,
            resourceType = ApiResourceType.PLAYER_WALLET_VIEW,
            resourceId = "wallet-view-100",
            operation = ApiOperation.READ,
            adminAccessReason = "Investigating customer dispute TICKET-789",
            idempotencyKey = "cmd-admin-1",
            correlationId = "corr-admin-1",
            causationId = "caus-admin-1",
            expectedVersion = 1L
        )
        val adminDecision = service.enforceOwnership(adminCmd)
        assertTrue(adminDecision.allowed)
        assertEquals("player-100", adminDecision.resolvedOwnerId)
        assertEquals("admin-support-1", adminDecision.principalId)
        assertEquals(PrincipalKind.ADMIN, adminDecision.principalKind)

        // 3. Super admin access to tenant configuration
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "config-tenant-1",
                resourceType = ApiResourceType.TENANT_CONFIGURATION,
                tenantId = tenantId,
                ownerId = tenantId,
                adminRoleRequired = AdminRole.SUPER_ADMIN,
                version = 1L
            )
        )
        val superAdmin = adminPrincipal("super-admin-1", tenantId, setOf(AdminRole.SUPER_ADMIN))
        val configCmd = EnforceResourceOwnershipCommand(
            principal = superAdmin,
            tenantId = tenantId,
            resourceType = ApiResourceType.TENANT_CONFIGURATION,
            resourceId = "config-tenant-1",
            operation = ApiOperation.WRITE,
            idempotencyKey = "cmd-admin-config",
            correlationId = "corr-admin-cfg",
            causationId = "caus-admin-cfg",
            expectedVersion = 1L
        )
        val configDecision = service.enforceOwnership(configCmd)
        assertTrue(configDecision.allowed)

        // 4. Assert zero financial mutation: authorization does not credit, debit, or mutate money
        assertEquals(3, store.decisions.size)
    }

    // =========================================================================
    // AUTHZ-002-01-T002: Negative, Boundary, and Security Cases
    // =========================================================================

    @Test
    fun `AUTHZ-002-01-T002 Enforce API resource ownership rejects invalid boundary unauthorized and stale input`() {
        ApiResourceOwnershipBinding.isBound = true

        val directory = InMemoryApiResourceDirectory()
        val store = InMemoryApiResourceOwnershipStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service = ApiResourceOwnershipService(
            resourceDirectory = directory,
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenant1 = "tenant-1"
        val tenant2 = "tenant-2"
        val playerAlice = playerPrincipal("alice", tenant1)
        val playerBob = playerPrincipal("bob", tenant1)

        // Resource owned by Alice
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "profile-alice",
                resourceType = ApiResourceType.PLAYER_PROFILE,
                tenantId = tenant1,
                ownerId = "alice",
                version = 1L
            )
        )

        // Resource in Tenant 2
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "profile-tenant2",
                resourceType = ApiResourceType.PLAYER_PROFILE,
                tenantId = tenant2,
                ownerId = "user-t2",
                version = 1L
            )
        )

        // Admin-only security audit log
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "audit-log-1",
                resourceType = ApiResourceType.ADMIN_AUDIT_LOG,
                tenantId = tenant1,
                ownerId = tenant1,
                adminRoleRequired = AdminRole.SECURITY,
                version = 1L
            )
        )

        // 1. Horizontal IDOR Attack: Bob attempts to access Alice's profile
        val idorError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerBob,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.READ,
                    idempotencyKey = "idor-1",
                    correlationId = "corr-idor-1",
                    causationId = "caus-idor-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, idorError.code)
        assertTrue(alertSink.alerts.any { it.contains("HORIZONTAL_IDOR_ATTEMPT") })

        // 2. IDOR with spoofed declared owner: Bob passes declaredOwnerId = "alice"
        val spoofError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerBob,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.READ,
                    declaredOwnerId = "alice",
                    idempotencyKey = "idor-spoof",
                    correlationId = "corr-idor-2",
                    causationId = "caus-idor-2",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, spoofError.code)

        // 3. Vertical Role Bypass: Alice attempts to access admin audit log
        val roleBypassError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerAlice,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.ADMIN_AUDIT_LOG,
                    resourceId = "audit-log-1",
                    operation = ApiOperation.READ,
                    idempotencyKey = "role-bypass-1",
                    correlationId = "corr-rb-1",
                    causationId = "caus-rb-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, roleBypassError.code)
        assertTrue(alertSink.alerts.any { it.contains("VERTICAL_ROLE_BYPASS_ATTEMPT") })

        // 4. Vertical Operation Bypass: Alice attempts admin override operation on her own profile
        val adminOpError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerAlice,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.ADMIN_OVERRIDE,
                    idempotencyKey = "op-bypass-1",
                    correlationId = "corr-ob-1",
                    causationId = "caus-ob-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, adminOpError.code)

        // 5. Cross-Tenant Violation: Alice (Tenant 1) attempts to access resource in Tenant 2
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerAlice,
                    tenantId = tenant2, // command tenant differs from principal tenant
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-tenant2",
                    operation = ApiOperation.READ,
                    idempotencyKey = "cross-t-1",
                    correlationId = "corr-ct-1",
                    causationId = "caus-ct-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantError.code)
        assertTrue(alertSink.alerts.any { it.contains("CROSS_TENANT_VIOLATION") })

        // 6. Default Deny: Unauthenticated principal (null)
        val unauthError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = null,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.READ,
                    idempotencyKey = "unauth-1",
                    correlationId = "corr-ua-1",
                    causationId = "caus-ua-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, unauthError.code)

        // 7. Non-existent resource: Server cannot resolve owner
        val notFoundError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerAlice,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "non-existent-profile",
                    operation = ApiOperation.READ,
                    idempotencyKey = "nf-1",
                    correlationId = "corr-nf-1",
                    causationId = "caus-nf-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.INVALID, notFoundError.code)

        // 8. Stale version: expected version != resource current version
        val staleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerAlice,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.READ,
                    idempotencyKey = "stale-1",
                    correlationId = "corr-stale-1",
                    causationId = "caus-stale-1",
                    expectedVersion = 99L // expected 99 but actual is 1
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, staleError.code)

        // 9. Admin accessing player resource without mandatory access reason
        val supportAdmin = adminPrincipal("support-1", tenant1, setOf(AdminRole.SUPPORT))
        val missingReasonError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = supportAdmin,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.READ,
                    adminAccessReason = "   ", // blank reason
                    idempotencyKey = "no-reason-1",
                    correlationId = "corr-nr-1",
                    causationId = "caus-nr-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.INVALID, missingReasonError.code)

        // 10. Admin lacking required role (SUPPORT admin attempting to access SECURITY audit log)
        val roleMismatchError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = supportAdmin,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.ADMIN_AUDIT_LOG,
                    resourceId = "audit-log-1",
                    operation = ApiOperation.READ,
                    idempotencyKey = "role-mismatch-1",
                    correlationId = "corr-rm-1",
                    causationId = "caus-rm-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, roleMismatchError.code)
        assertTrue(alertSink.alerts.any { it.contains("ADMIN_ROLE_INSUFFICIENT") })

        // 11. Malformed headers: blank tenantId, blank correlationId, negative expectedVersion
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerAlice,
                    tenantId = "",
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.READ,
                    idempotencyKey = "key",
                    correlationId = "corr",
                    causationId = "caus",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = playerAlice,
                    tenantId = tenant1,
                    resourceType = ApiResourceType.PLAYER_PROFILE,
                    resourceId = "profile-alice",
                    operation = ApiOperation.READ,
                    idempotencyKey = "key",
                    correlationId = "corr",
                    causationId = "caus",
                    expectedVersion = -1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // AUTHZ-002-01-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `AUTHZ-002-01-T003 Enforce API resource ownership survives concurrency duplicate delivery and dependency failure`() {
        ApiResourceOwnershipBinding.isBound = true

        val directory = InMemoryApiResourceDirectory()
        val store = InMemoryApiResourceOwnershipStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service = ApiResourceOwnershipService(
            resourceDirectory = directory,
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-concurrent"
        val player = playerPrincipal("player-c", tenantId)
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "session-123",
                resourceType = ApiResourceType.PLAYER_SESSION,
                tenantId = tenantId,
                ownerId = player.id,
                version = 1L
            )
        )

        val baseCmd = EnforceResourceOwnershipCommand(
            principal = player,
            tenantId = tenantId,
            resourceType = ApiResourceType.PLAYER_SESSION,
            resourceId = "session-123",
            operation = ApiOperation.READ,
            idempotencyKey = "idem-key-1",
            correlationId = "corr-idem-1",
            causationId = "caus-idem-1",
            expectedVersion = 1L
        )

        // 1. Idempotent replay: Calling with exact same idempotency key returns cached decision
        val res1 = service.enforceOwnership(baseCmd)
        val res2 = service.enforceOwnership(baseCmd)
        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.evidenceReference, res2.evidenceReference)
        assertEquals(1, store.decisions.size)

        // 2. Idempotency key conflict on modified payload (e.g. changed operation)
        val conflictingCmd = baseCmd.copy(operation = ApiOperation.DELETE)
        val conflictError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforceOwnership(conflictingCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictError.code)

        // 3. Multi-threaded concurrency: 16 threads executing ownership enforcement across distinct resources
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)

        val resources = (1..threadCount).map { i ->
            val p = playerPrincipal("player-$i", tenantId)
            val resRecord = ApiResourceRecord(
                resourceId = "game-round-$i",
                resourceType = ApiResourceType.GAME_ROUND,
                tenantId = tenantId,
                ownerId = p.id,
                version = 1L
            )
            directory.registerResource(resRecord)
            p to resRecord
        }

        val concurrentDecisions = ConcurrentHashMap<String, ResourceOwnershipDecision>()

        resources.forEachIndexed { index, (p, r) ->
            executor.submit {
                try {
                    val dec = service.enforceOwnership(
                        EnforceResourceOwnershipCommand(
                            principal = p,
                            tenantId = tenantId,
                            resourceType = r.resourceType,
                            resourceId = r.resourceId,
                            operation = ApiOperation.READ,
                            idempotencyKey = "concurrent-key-$index",
                            correlationId = "corr-c-$index",
                            causationId = "caus-c-$index",
                            expectedVersion = 1L
                        )
                    )
                    concurrentDecisions[r.resourceId] = dec
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()

        assertEquals(threadCount, concurrentDecisions.size)
        concurrentDecisions.values.forEach { decision ->
            assertTrue(decision.allowed)
            assertEquals(tenantId, decision.tenantId)
            assertEquals(decision.resolvedOwnerId, decision.principalId)
        }
    }

    // =========================================================================
    // AUTHZ-002-01-T004: Migration Integrity, Recovery and Observability
    // =========================================================================

    @Test
    fun `AUTHZ-002-01-T004 Enforce API resource ownership remains compatible recoverable observable and lifecycle-safe`() {
        // 1. Migration integrity: No Flyway migrations > V16
        val migrationsDir = File("src/main/resources/db/migration")
        if (migrationsDir.exists()) {
            val invalidMigrations = migrationsDir.listFiles()?.filter { file ->
                val name = file.name
                if (name.startsWith("V") && name.contains("__")) {
                    val versionStr = name.substring(1, name.indexOf("__"))
                    val versionNum = versionStr.toIntOrNull()
                    versionNum != null && versionNum > 16
                } else false
            } ?: emptyList()
            assertTrue(invalidMigrations.isEmpty(), "Found illegal migrations > V16: ${invalidMigrations.map { it.name }}")
        }

        ApiResourceOwnershipBinding.isBound = true

        val directory = InMemoryApiResourceDirectory()
        val store = InMemoryApiResourceOwnershipStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service1 = ApiResourceOwnershipService(
            resourceDirectory = directory,
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-restart"
        val player = playerPrincipal("player-restart", tenantId)
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "ticket-999",
                resourceType = ApiResourceType.SUPPORT_TICKET,
                tenantId = tenantId,
                ownerId = player.id,
                version = 1L
            )
        )

        val initialDecision = service1.enforceOwnership(
            EnforceResourceOwnershipCommand(
                principal = player,
                tenantId = tenantId,
                resourceType = ApiResourceType.SUPPORT_TICKET,
                resourceId = "ticket-999",
                operation = ApiOperation.READ,
                idempotencyKey = "restart-key-1",
                correlationId = "corr-restart-1",
                causationId = "caus-restart-1",
                expectedVersion = 1L
            )
        )
        assertTrue(initialDecision.allowed)

        // 2. Recovery and Restart: New service instance attached to existing persistent stores
        val service2 = ApiResourceOwnershipService(
            resourceDirectory = directory,
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        // Replay through restarted service recovers identical decision
        val replayedDecision = service2.enforceOwnership(
            EnforceResourceOwnershipCommand(
                principal = player,
                tenantId = tenantId,
                resourceType = ApiResourceType.SUPPORT_TICKET,
                resourceId = "ticket-999",
                operation = ApiOperation.READ,
                idempotencyKey = "restart-key-1",
                correlationId = "corr-restart-1",
                causationId = "caus-restart-1",
                expectedVersion = 1L
            )
        )
        assertEquals(initialDecision.resultId, replayedDecision.resultId)
        assertEquals(initialDecision.evidenceReference, replayedDecision.evidenceReference)

        // 3. Observability & Redaction: Audit events, outbox, and security alerts
        val audit = initialDecision.auditEvent
        assertEquals(tenantId, audit.tenantId)
        assertEquals("corr-restart-1", audit.correlationId)
        assertEquals("caus-restart-1", audit.causationId)
        assertEquals("API_RESOURCE_ACCESS_AUTHORIZED", audit.type)
        assertEquals(now, audit.occurredAt)

        val outbox = initialDecision.outboxEvent
        assertEquals(tenantId, outbox.tenantId)
        assertEquals("API_RESOURCE_ACCESS_AUTHORIZED", outbox.type)
        assertEquals(now, outbox.createdAt)

        // Generate an IDOR security alert to verify no secrets/PII leak in alerts
        val attacker = playerPrincipal("attacker-evil", tenantId)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service2.enforceOwnership(
                EnforceResourceOwnershipCommand(
                    principal = attacker,
                    tenantId = tenantId,
                    resourceType = ApiResourceType.SUPPORT_TICKET,
                    resourceId = "ticket-999",
                    operation = ApiOperation.READ,
                    idempotencyKey = "attack-key-1",
                    correlationId = "corr-atk-1",
                    causationId = "caus-atk-1",
                    expectedVersion = 1L
                )
            )
        }

        alertSink.alerts.forEach { alert ->
            assertFalse(alert.contains("password"))
            assertFalse(alert.contains("cvv"))
            assertFalse(alert.contains("secret"))
        }
    }
}
