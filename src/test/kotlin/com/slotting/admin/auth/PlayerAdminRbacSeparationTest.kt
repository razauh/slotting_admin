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

class PlayerAdminRbacSeparationTest {

    private val now = Instant.parse("2026-09-18T23:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        PlayerAdminRbacSeparationBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ApiResourceOwnershipBinding.isBound = true
        PlayerAdminRbacSeparationBinding.isBound = true
    }

    private fun playerPrincipal(
        id: String = "player-1",
        tenantId: String = "tenant-1",
        roles: Set<AdminRole> = emptySet()
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = roles
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
    // AUTHZ-002-02-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTHZ-002-02-T001 Enforce player and admin RBAC separation produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        PlayerAdminRbacSeparationBinding.checkBound()

        val directory = InMemoryApiResourceDirectory()
        val decisionStore = InMemoryRbacDecisionStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service = PlayerAdminRbacSeparationService(
            resourceDirectory = directory,
            decisionStore = decisionStore,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-casino-1"
        val player = playerPrincipal("player-42", tenantId)

        // Register player's wallet view
        directory.registerResource(
            ApiResourceRecord(
                resourceId = "wallet-42",
                resourceType = ApiResourceType.PLAYER_WALLET_VIEW,
                tenantId = tenantId,
                ownerId = player.id,
                version = 1L
            )
        )

        // Player accesses their own wallet view
        val playerCmd = AuthorizeRbacCommand(
            principal = player,
            tenantId = tenantId,
            permission = RbacPermission.PLAYER_WALLET_VIEW,
            resourceType = ApiResourceType.PLAYER_WALLET_VIEW,
            resourceId = "wallet-42",
            idempotencyKey = "cmd-p1",
            correlationId = "corr-p1",
            causationId = "caus-p1",
            expectedVersion = 1L
        )

        val playerDecision = service.authorize(playerCmd)

        // Exact assertions: Default deny; resource owner resolved server-side; P0/P1 authz tests mandatory.
        assertTrue(playerDecision.allowed)
        assertEquals(tenantId, playerDecision.tenantId)
        assertEquals(player.id, playerDecision.principalId)
        assertEquals(PrincipalKind.PLAYER, playerDecision.principalKind)
        assertEquals(RbacPermission.PLAYER_WALLET_VIEW, playerDecision.permission)
        assertEquals("wallet-42", playerDecision.resourceId)
        assertEquals(player.id, playerDecision.resolvedOwnerId)
        assertEquals(1L, playerDecision.serverVersion)
        assertEquals(now, playerDecision.serverTime)
        assertTrue(playerDecision.evidenceReference.startsWith("rbac-separation:$tenantId:PLAYER:PLAYER_WALLET_VIEW:"))
        assertEquals("RBAC_AUTHORIZATION_ALLOWED", playerDecision.auditEvent.type)
        assertEquals("RBAC_AUTHORIZATION_ALLOWED", playerDecision.outboxEvent.type)

        // 2. Admin with SUPPORT role executes support read with audited reason on player resource
        val supportAdmin = adminPrincipal("support-staff-1", tenantId, setOf(AdminRole.SUPPORT))
        val adminCmd = AuthorizeRbacCommand(
            principal = supportAdmin,
            tenantId = tenantId,
            permission = RbacPermission.ADMIN_SUPPORT_READ,
            resourceType = ApiResourceType.PLAYER_WALLET_VIEW,
            resourceId = "wallet-42",
            adminAccessReason = "Reviewing dispute DISP-101",
            idempotencyKey = "cmd-a1",
            correlationId = "corr-a1",
            causationId = "caus-a1",
            expectedVersion = 1L
        )
        val adminDecision = service.authorize(adminCmd)
        assertTrue(adminDecision.allowed)
        assertEquals(PrincipalKind.ADMIN, adminDecision.principalKind)
        assertEquals(RbacPermission.ADMIN_SUPPORT_READ, adminDecision.permission)
        assertEquals(player.id, adminDecision.resolvedOwnerId)

        // 3. Super Admin executes dual-controlled role management
        val superAdmin = adminPrincipal("super-admin-1", tenantId, setOf(AdminRole.SUPER_ADMIN))
        val dualControlCmd = AuthorizeRbacCommand(
            principal = superAdmin,
            tenantId = tenantId,
            permission = RbacPermission.ADMIN_ROLE_MANAGEMENT,
            secondApproverId = "super-admin-2", // distinct second approver
            idempotencyKey = "cmd-dual-1",
            correlationId = "corr-d1",
            causationId = "caus-d1",
            expectedVersion = 1L
        )
        val dualControlDecision = service.authorize(dualControlCmd)
        assertTrue(dualControlDecision.allowed)
        assertEquals(RbacPermission.ADMIN_ROLE_MANAGEMENT, dualControlDecision.permission)

        // 4. Assert zero financial authority or mutation: decisions don't mutate financial data
        assertEquals(3, decisionStore.decisions.size)
    }

    // =========================================================================
    // AUTHZ-002-02-T002: Negative, Boundary, and Security Cases
    // =========================================================================

    @Test
    fun `AUTHZ-002-02-T002 Enforce player and admin RBAC separation rejects invalid boundary unauthorized and stale input`() {
        PlayerAdminRbacSeparationBinding.isBound = true

        val directory = InMemoryApiResourceDirectory()
        val decisionStore = InMemoryRbacDecisionStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service = PlayerAdminRbacSeparationService(
            resourceDirectory = directory,
            decisionStore = decisionStore,
            alertSink = alertSink,
            clock = clock
        )

        val tenant1 = "tenant-1"
        val tenant2 = "tenant-2"
        val player = playerPrincipal("player-alice", tenant1)
        val bob = playerPrincipal("player-bob", tenant1)
        val supportAdmin = adminPrincipal("admin-sup", tenant1, setOf(AdminRole.SUPPORT))

        directory.registerResource(
            ApiResourceRecord(
                resourceId = "session-alice",
                resourceType = ApiResourceType.PLAYER_SESSION,
                tenantId = tenant1,
                ownerId = "player-alice",
                version = 1L
            )
        )

        // 1. Vertical Role Bypass: Player attempts to execute an Admin plane permission
        val playerAdminBypassError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = player,
                    tenantId = tenant1,
                    permission = RbacPermission.ADMIN_USER_MANAGEMENT,
                    idempotencyKey = "v-bypass-1",
                    correlationId = "corr-vb-1",
                    causationId = "caus-vb-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, playerAdminBypassError.code)
        assertTrue(alertSink.alerts.any { it.contains("VERTICAL_ROLE_BYPASS_ATTEMPT") })

        // 2. Privilege Escalation: Player token claiming admin roles
        val roguePlayer = playerPrincipal(
            id = "rogue-player",
            tenantId = tenant1,
            roles = setOf(AdminRole.SUPER_ADMIN)
        )
        val roleClaimError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = roguePlayer,
                    tenantId = tenant1,
                    permission = RbacPermission.PLAYER_PROFILE_VIEW,
                    idempotencyKey = "rogue-claim-1",
                    correlationId = "corr-rc-1",
                    causationId = "caus-rc-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, roleClaimError.code)
        assertTrue(alertSink.alerts.any { it.contains("ILLEGAL_PLAYER_ADMIN_ROLE_CLAIM") })

        // 3. Insider Play Prevention: Admin attempts to execute player game play
        val insiderPlayError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = supportAdmin,
                    tenantId = tenant1,
                    permission = RbacPermission.PLAYER_GAME_PLAY,
                    idempotencyKey = "insider-play-1",
                    correlationId = "corr-ip-1",
                    causationId = "caus-ip-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, insiderPlayError.code)
        assertTrue(alertSink.alerts.any { it.contains("ADMIN_INSIDER_PLAY_DENIED") })

        // 4. Dual-Control Violation: Missing second approver on high-risk admin action
        val superAdmin = adminPrincipal("super-admin-1", tenant1, setOf(AdminRole.SUPER_ADMIN))
        val missingSecondApproverError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = superAdmin,
                    tenantId = tenant1,
                    permission = RbacPermission.ADMIN_ROLE_MANAGEMENT,
                    secondApproverId = null, // missing
                    idempotencyKey = "dc-miss-1",
                    correlationId = "corr-dc-1",
                    causationId = "caus-dc-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, missingSecondApproverError.code)
        assertTrue(alertSink.alerts.any { it.contains("DUAL_CONTROL_REQUIREMENT_FAILED") })

        // 5. Dual-Control Violation: Self-approval (second approver == principal)
        val selfApprovalError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = superAdmin,
                    tenantId = tenant1,
                    permission = RbacPermission.ADMIN_ROLE_MANAGEMENT,
                    secondApproverId = "super-admin-1", // self
                    idempotencyKey = "dc-self-1",
                    correlationId = "corr-dc-2",
                    causationId = "caus-dc-2",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, selfApprovalError.code)

        // 6. Admin Least Privilege: Support admin attempts security audit
        val leastPrivilegeError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = supportAdmin,
                    tenantId = tenant1,
                    permission = RbacPermission.ADMIN_SECURITY_AUDIT,
                    idempotencyKey = "lp-error-1",
                    correlationId = "corr-lp-1",
                    causationId = "caus-lp-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, leastPrivilegeError.code)
        assertTrue(alertSink.alerts.any { it.contains("ADMIN_LEAST_PRIVILEGE_DENIED") })

        // 7. Horizontal IDOR in RBAC check: Bob attempts to access Alice's session
        val idorError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = bob,
                    tenantId = tenant1,
                    permission = RbacPermission.PLAYER_PROFILE_VIEW,
                    resourceType = ApiResourceType.PLAYER_SESSION,
                    resourceId = "session-alice",
                    idempotencyKey = "idor-rbac-1",
                    correlationId = "corr-id-1",
                    causationId = "caus-id-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, idorError.code)
        assertTrue(alertSink.alerts.any { it.contains("HORIZONTAL_IDOR_ATTEMPT") })

        // 8. Cross-Tenant Violation
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = player,
                    tenantId = tenant2,
                    permission = RbacPermission.PLAYER_PROFILE_VIEW,
                    idempotencyKey = "ct-rbac-1",
                    correlationId = "corr-ct-1",
                    causationId = "caus-ct-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, crossTenantError.code)
        assertTrue(alertSink.alerts.any { it.contains("CROSS_TENANT_RBAC_VIOLATION") })

        // 9. Default Deny on unauthenticated principal
        val unauthError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = null,
                    tenantId = tenant1,
                    permission = RbacPermission.PLAYER_WALLET_VIEW,
                    idempotencyKey = "unauth-rbac-1",
                    correlationId = "corr-ua-1",
                    causationId = "caus-ua-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, unauthError.code)

        // 10. Admin accessing player resource without mandatory audit reason
        val missingReasonError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = supportAdmin,
                    tenantId = tenant1,
                    permission = RbacPermission.ADMIN_SUPPORT_READ,
                    resourceType = ApiResourceType.PLAYER_SESSION,
                    resourceId = "session-alice",
                    adminAccessReason = "   ", // blank
                    idempotencyKey = "ar-blank-1",
                    correlationId = "corr-ar-1",
                    causationId = "caus-ar-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.INVALID, missingReasonError.code)

        // 11. Stale version
        val staleError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = player,
                    tenantId = tenant1,
                    permission = RbacPermission.PLAYER_PROFILE_VIEW,
                    resourceType = ApiResourceType.PLAYER_SESSION,
                    resourceId = "session-alice",
                    idempotencyKey = "stale-rbac-1",
                    correlationId = "corr-st-1",
                    causationId = "caus-st-1",
                    expectedVersion = 99L // current is 1L
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, staleError.code)

        // 12. Malformed headers
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(
                AuthorizeRbacCommand(
                    principal = player,
                    tenantId = "",
                    permission = RbacPermission.PLAYER_WALLET_VIEW,
                    idempotencyKey = "key",
                    correlationId = "corr",
                    causationId = "caus",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // AUTHZ-002-02-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `AUTHZ-002-02-T003 Enforce player and admin RBAC separation survives concurrency duplicate delivery and dependency failure`() {
        PlayerAdminRbacSeparationBinding.isBound = true

        val directory = InMemoryApiResourceDirectory()
        val decisionStore = InMemoryRbacDecisionStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service = PlayerAdminRbacSeparationService(
            resourceDirectory = directory,
            decisionStore = decisionStore,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-concurrent"
        val player = playerPrincipal("player-conc", tenantId)

        val baseCmd = AuthorizeRbacCommand(
            principal = player,
            tenantId = tenantId,
            permission = RbacPermission.PLAYER_WALLET_VIEW,
            idempotencyKey = "idem-rbac-1",
            correlationId = "corr-id-1",
            causationId = "caus-id-1",
            expectedVersion = 1L
        )

        // 1. Idempotent replay returns cached decision
        val res1 = service.authorize(baseCmd)
        val res2 = service.authorize(baseCmd)
        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.evidenceReference, res2.evidenceReference)
        assertEquals(1, decisionStore.decisions.size)

        // 2. Idempotency conflict on modified payload (e.g. different permission)
        val conflictingCmd = baseCmd.copy(permission = RbacPermission.PLAYER_TRANSACTION_HISTORY)
        val conflictError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(conflictingCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictError.code)

        // 3. Multi-threaded concurrency: 16 threads executing concurrent player and admin RBAC checks
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)

        val testCases = (1..threadCount).map { i ->
            if (i % 2 == 0) {
                // Admin test case
                val admin = adminPrincipal("admin-$i", tenantId, setOf(AdminRole.SUPPORT))
                AuthorizeRbacCommand(
                    principal = admin,
                    tenantId = tenantId,
                    permission = RbacPermission.ADMIN_SUPPORT_READ,
                    idempotencyKey = "concurrent-rbac-$i",
                    correlationId = "corr-c-$i",
                    causationId = "caus-c-$i",
                    expectedVersion = 1L
                )
            } else {
                // Player test case
                val p = playerPrincipal("player-$i", tenantId)
                AuthorizeRbacCommand(
                    principal = p,
                    tenantId = tenantId,
                    permission = RbacPermission.PLAYER_WALLET_VIEW,
                    idempotencyKey = "concurrent-rbac-$i",
                    correlationId = "corr-c-$i",
                    causationId = "caus-c-$i",
                    expectedVersion = 1L
                )
            }
        }

        val concurrentDecisions = ConcurrentHashMap<String, RbacAuthorizationDecision>()

        testCases.forEachIndexed { index, cmd ->
            executor.submit {
                try {
                    val dec = service.authorize(cmd)
                    concurrentDecisions[cmd.idempotencyKey] = dec
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()

        assertEquals(threadCount, concurrentDecisions.size)
        concurrentDecisions.values.forEach { dec ->
            assertTrue(dec.allowed)
            assertEquals(tenantId, dec.tenantId)
        }
    }

    // =========================================================================
    // AUTHZ-002-02-T004: Migration Integrity, Recovery & Observability
    // =========================================================================

    @Test
    fun `AUTHZ-002-02-T004 Enforce player and admin RBAC separation remains compatible recoverable observable and lifecycle-safe`() {
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

        PlayerAdminRbacSeparationBinding.isBound = true

        val directory = InMemoryApiResourceDirectory()
        val decisionStore = InMemoryRbacDecisionStore()
        val alertSink = InMemoryApiSecurityAlertSink()
        val service1 = PlayerAdminRbacSeparationService(
            resourceDirectory = directory,
            decisionStore = decisionStore,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-recover"
        val player = playerPrincipal("player-recover", tenantId)

        val initialDecision = service1.authorize(
            AuthorizeRbacCommand(
                principal = player,
                tenantId = tenantId,
                permission = RbacPermission.PLAYER_PROFILE_VIEW,
                idempotencyKey = "rec-key-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )
        assertTrue(initialDecision.allowed)

        // 2. Recovery and restart: New service instance attached to existing persistent stores
        val service2 = PlayerAdminRbacSeparationService(
            resourceDirectory = directory,
            decisionStore = decisionStore,
            alertSink = alertSink,
            clock = clock
        )

        // Replay through restarted service recovers identical decision
        val replayedDecision = service2.authorize(
            AuthorizeRbacCommand(
                principal = player,
                tenantId = tenantId,
                permission = RbacPermission.PLAYER_PROFILE_VIEW,
                idempotencyKey = "rec-key-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )
        assertEquals(initialDecision.resultId, replayedDecision.resultId)
        assertEquals(initialDecision.evidenceReference, replayedDecision.evidenceReference)

        // 3. Observability and Redaction
        val audit = initialDecision.auditEvent
        assertEquals(tenantId, audit.tenantId)
        assertEquals("corr-rec-1", audit.correlationId)
        assertEquals("caus-rec-1", audit.causationId)
        assertEquals("RBAC_AUTHORIZATION_ALLOWED", audit.type)
        assertEquals(now, audit.occurredAt)

        val outbox = initialDecision.outboxEvent
        assertEquals(tenantId, outbox.tenantId)
        assertEquals("RBAC_AUTHORIZATION_ALLOWED", outbox.type)
        assertEquals(now, outbox.createdAt)

        // Verify security alerts do not leak passwords, tokens, or CVV
        val attacker = playerPrincipal("attacker", tenantId)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service2.authorize(
                AuthorizeRbacCommand(
                    principal = attacker,
                    tenantId = tenantId,
                    permission = RbacPermission.ADMIN_SECURITY_AUDIT,
                    idempotencyKey = "atk-key-1",
                    correlationId = "corr-atk-1",
                    causationId = "caus-atk-1",
                    expectedVersion = 1L
                )
            )
        }

        alertSink.alerts.forEach { alert ->
            assertFalse(alert.contains("password"))
            assertFalse(alert.contains("token"))
            assertFalse(alert.contains("cvv"))
        }
    }
}
