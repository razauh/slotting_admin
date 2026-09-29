package com.slotting.admin.auth

import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * TC-006: Enforce authorization-before-replay and authenticated dual control.
 *
 * Verifies:
 * 1. Authorization-before-replay across unauthenticated, wrong tenant, expired MFA, revoked role, expired session.
 * 2. Independent maker/checker dual control rejecting self-approval, payload change, stale version, duplicate decision, and concurrency races.
 * 3. Least-privilege permissions for payment config, restrictions, fraud, analytics, financials, and operations.
 */
class AuthorizationBeforeReplayAndDualControlContractTest {

    private val now = Instant.parse("2026-09-24T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val makerPrincipal = AuthenticatedPrincipal(
        id = "admin-maker-1",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private val checkerPrincipal = AuthenticatedPrincipal(
        id = "admin-checker-2",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "admin-support-3",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-9",
        tenantId = "tenant-foreign-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    // =========================================================================
    // 1. Authorization Before Replay Tests (BE-012)
    // =========================================================================

    @Test
    fun `test01 unauthenticated caller cannot replay existing cached result`() {
        val store = ContractAuthMemoryStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val service = createAuthService(store, sessions, alerts)

        // 1. Legitimate admin executes command and result is cached under idempotency key
        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = true, mfaVerified = true)
        val initialCmd = AdminAuthorizationCommand(
            principal = makerPrincipal,
            sessionId = "session-valid",
            tenantId = "tenant-prod-1",
            resourceReference = "resource-1",
            permission = AdminPermission.MANAGE_SUPPORT,
            idempotencyKey = "idemp-cache-001",
            correlationId = "corr-1",
            causationId = "cause-1",
            expectedVersion = 0L
        )
        val initialResult = service.authorize(initialCmd)
        assertEquals(AuthorizationState.ALLOWED, initialResult.state)

        // 2. Unauthenticated caller attempts to replay the same idempotency key
        val unauthenticatedCmd = initialCmd.copy(principal = null)
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(unauthenticatedCmd)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, failure.code)
    }

    @Test
    fun `test02 wrong tenant caller cannot replay existing cached result`() {
        val store = ContractAuthMemoryStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val service = createAuthService(store, sessions, alerts)

        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = true, mfaVerified = true)
        val initialCmd = AdminAuthorizationCommand(
            principal = makerPrincipal,
            sessionId = "session-valid",
            tenantId = "tenant-prod-1",
            resourceReference = "resource-1",
            permission = AdminPermission.MANAGE_SUPPORT,
            idempotencyKey = "idemp-tenant-002",
            correlationId = "corr-2",
            causationId = "cause-2",
            expectedVersion = 0L
        )
        service.authorize(initialCmd)

        // Foreign admin attempts to replay the same idempotency key
        sessions.register("tenant-foreign-2", "admin-foreign-9", "session-foreign", active = true, mfaVerified = true)
        val foreignCmd = initialCmd.copy(
            principal = foreignAdminPrincipal,
            sessionId = "session-foreign"
        )
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(foreignCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, failure.code)
    }

    @Test
    fun `test03 expired MFA cannot replay existing cached result`() {
        val store = ContractAuthMemoryStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val service = createAuthService(store, sessions, alerts)

        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = true, mfaVerified = true)
        val initialCmd = AdminAuthorizationCommand(
            principal = makerPrincipal,
            sessionId = "session-valid",
            tenantId = "tenant-prod-1",
            resourceReference = "resource-1",
            permission = AdminPermission.MANAGE_SUPPORT,
            idempotencyKey = "idemp-mfa-003",
            correlationId = "corr-3",
            causationId = "cause-3",
            expectedVersion = 0L
        )
        service.authorize(initialCmd)

        // Admin's MFA expires
        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = true, mfaVerified = false)
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(initialCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, failure.code)
    }

    @Test
    fun `test04 role revoked after first call cannot replay existing cached result`() {
        val store = ContractAuthMemoryStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val service = createAuthService(store, sessions, alerts)

        // Admin has SUPER_ADMIN role initially
        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = true, mfaVerified = true)
        val initialCmd = AdminAuthorizationCommand(
            principal = makerPrincipal,
            sessionId = "session-valid",
            tenantId = "tenant-prod-1",
            resourceReference = "resource-1",
            permission = AdminPermission.MANAGE_SECURITY,
            idempotencyKey = "idemp-role-004",
            correlationId = "corr-4",
            causationId = "cause-4",
            expectedVersion = 0L
        )
        service.authorize(initialCmd)

        // Admin's role is demoted to SUPPORT (which lacks MANAGE_SECURITY)
        val demotedPrincipal = makerPrincipal.copy(roles = setOf(AdminRole.SUPPORT))
        val demotedCmd = initialCmd.copy(principal = demotedPrincipal)

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(demotedCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, failure.code)
    }

    @Test
    fun `test05 expired or terminated session cannot replay existing cached result`() {
        val store = ContractAuthMemoryStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val service = createAuthService(store, sessions, alerts)

        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = true, mfaVerified = true)
        val initialCmd = AdminAuthorizationCommand(
            principal = makerPrincipal,
            sessionId = "session-valid",
            tenantId = "tenant-prod-1",
            resourceReference = "resource-1",
            permission = AdminPermission.MANAGE_SUPPORT,
            idempotencyKey = "idemp-sess-005",
            correlationId = "corr-5",
            causationId = "cause-5",
            expectedVersion = 0L
        )
        service.authorize(initialCmd)

        // Session terminated
        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = false, mfaVerified = true)
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(initialCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, failure.code)
    }

    // =========================================================================
    // 2. Dual Control / Maker-Checker Contract Tests (BE-013)
    // =========================================================================

    @Test
    fun `test06 maker proposes and checker approves producing immutable receipt and audit`() {
        val dualStore = InMemoryDualControlStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)
        val service = DualControlApprovalService(sessions, dualStore, policy, alerts, clock)

        sessions.register("tenant-prod-1", "admin-maker-1", "sess-maker", active = true, mfaVerified = true)
        sessions.register("tenant-prod-1", "admin-checker-2", "sess-checker", active = true, mfaVerified = true)

        val payload = """{"role":"SUPER_ADMIN","targetUserId":"user_target_42"}"""
        val payloadDigest = sha256(payload)

        // 1. Maker proposes
        val proposeCmd = ProposeDualControlCommand(
            principal = makerPrincipal,
            sessionId = "sess-maker",
            tenantId = "tenant-prod-1",
            operationId = "op-role-change-101",
            operationType = "CHANGE_ROLES",
            resourceReference = "user_target_42",
            payloadDigest = payloadDigest,
            requiredPermission = AdminPermission.CHANGE_ROLES,
            targetVersion = 3L,
            idempotencyKey = "idemp-prop-101",
            correlationId = "corr-101",
            causationId = "cause-101",
            notes = "Promoting user 42 to SUPER_ADMIN"
        )
        val proposal = service.propose(proposeCmd)
        assertEquals(DualControlStatus.PENDING_CHECKER, proposal.status)
        assertEquals("admin-maker-1", proposal.maker.principalId)
        assertEquals(payloadDigest, proposal.payloadDigest)
        assertEquals(3L, proposal.targetVersion)

        // 2. Checker reviews and approves
        val reviewCmd = ReviewDualControlCommand(
            principal = checkerPrincipal,
            sessionId = "sess-checker",
            tenantId = "tenant-prod-1",
            operationId = "op-role-change-101",
            action = DualControlAction.APPROVE,
            payloadDigest = payloadDigest,
            expectedTargetVersion = 3L,
            idempotencyKey = "idemp-rev-101",
            correlationId = "corr-102",
            causationId = "cause-102",
            notes = "Independently verified and approved"
        )
        val receipt = service.review(reviewCmd)
        assertEquals(DualControlStatus.APPROVED, receipt.status)
        assertEquals("admin-maker-1", receipt.maker.principalId)
        assertEquals("admin-checker-2", receipt.checker.principalId)
        assertEquals(payloadDigest, receipt.payloadDigest)
        assertEquals(3L, receipt.targetVersion)

        // Verify receipt validation helper
        assertTrue(service.validateReceipt(receipt, "tenant-prod-1", "op-role-change-101", payloadDigest, 3L))

        // Verify audit log captured both actors and exact change
        val auditEvents = dualStore.auditEvents
        assertEquals(2, auditEvents.size)
        assertTrue(auditEvents.any { it.type == "DUAL_CONTROL_PROPOSED" })
        assertTrue(auditEvents.any { it.type == "DUAL_CONTROL_APPROVED" })
    }

    @Test
    fun `test07 same actor twice is rejected as self-approval`() {
        val dualStore = InMemoryDualControlStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)
        val service = DualControlApprovalService(sessions, dualStore, policy, alerts, clock)

        sessions.register("tenant-prod-1", "admin-maker-1", "sess-maker", active = true, mfaVerified = true)

        val payloadDigest = sha256("payload-data")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker",
                tenantId = "tenant-prod-1",
                operationId = "op-self-approval",
                operationType = "CHANGE_ROLES",
                resourceReference = "res-1",
                payloadDigest = payloadDigest,
                requiredPermission = AdminPermission.CHANGE_ROLES,
                targetVersion = 1L,
                idempotencyKey = "idemp-self-1",
                correlationId = "corr-s",
                causationId = "cause-s"
            )
        )

        // Maker attempts to approve their own proposal
        val selfReviewCmd = ReviewDualControlCommand(
            principal = makerPrincipal,
            sessionId = "sess-maker",
            tenantId = "tenant-prod-1",
            operationId = "op-self-approval",
            action = DualControlAction.APPROVE,
            payloadDigest = payloadDigest,
            expectedTargetVersion = 1L,
            idempotencyKey = "idemp-self-2",
            correlationId = "corr-s2",
            causationId = "cause-s2"
        )

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(selfReviewCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, failure.code)
        // Alert emitted on self-approval attempt
        assertTrue(alerts.events.any { it.type == "DUAL_CONTROL_SELF_APPROVAL_ATTEMPT" })
    }

    @Test
    fun `test08 proposal changed payload digest mismatch is rejected`() {
        val dualStore = InMemoryDualControlStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)
        val service = DualControlApprovalService(sessions, dualStore, policy, alerts, clock)

        sessions.register("tenant-prod-1", "admin-maker-1", "sess-maker", active = true, mfaVerified = true)
        sessions.register("tenant-prod-1", "admin-checker-2", "sess-checker", active = true, mfaVerified = true)

        val originalDigest = sha256("original-payload")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker",
                tenantId = "tenant-prod-1",
                operationId = "op-changed-payload",
                operationType = "PAYMENT_CONFIGURATION",
                resourceReference = "provider-gateway-1",
                payloadDigest = originalDigest,
                requiredPermission = AdminPermission.PAYMENT_CONFIGURATION,
                targetVersion = 1L,
                idempotencyKey = "idemp-cp-1",
                correlationId = "corr-cp1",
                causationId = "cause-cp1"
            )
        )

        // Checker attempts to approve a different payload digest
        val tamperedDigest = sha256("tampered-payload")
        val reviewCmd = ReviewDualControlCommand(
            principal = checkerPrincipal,
            sessionId = "sess-checker",
            tenantId = "tenant-prod-1",
            operationId = "op-changed-payload",
            action = DualControlAction.APPROVE,
            payloadDigest = tamperedDigest,
            expectedTargetVersion = 1L,
            idempotencyKey = "idemp-cp-2",
            correlationId = "corr-cp2",
            causationId = "cause-cp2"
        )

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(reviewCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, failure.code)
        assertTrue(alerts.events.any { it.type == "DUAL_CONTROL_PAYLOAD_MISMATCH" })
    }

    @Test
    fun `test09 stale target version is rejected`() {
        val dualStore = InMemoryDualControlStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)
        val service = DualControlApprovalService(sessions, dualStore, policy, alerts, clock)

        sessions.register("tenant-prod-1", "admin-maker-1", "sess-maker", active = true, mfaVerified = true)
        sessions.register("tenant-prod-1", "admin-checker-2", "sess-checker", active = true, mfaVerified = true)

        val digest = sha256("config-data")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker",
                tenantId = "tenant-prod-1",
                operationId = "op-stale-version",
                operationType = "PAYMENT_CONFIGURATION",
                resourceReference = "provider-gateway-1",
                payloadDigest = digest,
                requiredPermission = AdminPermission.PAYMENT_CONFIGURATION,
                targetVersion = 5L,
                idempotencyKey = "idemp-sv-1",
                correlationId = "corr-sv1",
                causationId = "cause-sv1"
            )
        )

        // Checker passes outdated version (4L instead of 5L)
        val reviewCmd = ReviewDualControlCommand(
            principal = checkerPrincipal,
            sessionId = "sess-checker",
            tenantId = "tenant-prod-1",
            operationId = "op-stale-version",
            action = DualControlAction.APPROVE,
            payloadDigest = digest,
            expectedTargetVersion = 4L,
            idempotencyKey = "idemp-sv-2",
            correlationId = "corr-sv2",
            causationId = "cause-sv2"
        )

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(reviewCmd)
        }
        assertEquals(AuthErrorCode.STALE, failure.code)
    }

    @Test
    fun `test10 duplicate decision on already finalized proposal is rejected`() {
        val dualStore = InMemoryDualControlStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)
        val service = DualControlApprovalService(sessions, dualStore, policy, alerts, clock)

        sessions.register("tenant-prod-1", "admin-maker-1", "sess-maker", active = true, mfaVerified = true)
        sessions.register("tenant-prod-1", "admin-checker-2", "sess-checker", active = true, mfaVerified = true)

        val digest = sha256("config-data")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker",
                tenantId = "tenant-prod-1",
                operationId = "op-dup-dec",
                operationType = "PAYMENT_CONFIGURATION",
                resourceReference = "provider-gateway-1",
                payloadDigest = digest,
                requiredPermission = AdminPermission.PAYMENT_CONFIGURATION,
                targetVersion = 1L,
                idempotencyKey = "idemp-dd-1",
                correlationId = "corr-dd1",
                causationId = "cause-dd1"
            )
        )

        // First approval succeeds
        service.review(
            ReviewDualControlCommand(
                principal = checkerPrincipal,
                sessionId = "sess-checker",
                tenantId = "tenant-prod-1",
                operationId = "op-dup-dec",
                action = DualControlAction.APPROVE,
                payloadDigest = digest,
                expectedTargetVersion = 1L,
                idempotencyKey = "idemp-dd-2",
                correlationId = "corr-dd2",
                causationId = "cause-dd2"
            )
        )

        // Second review attempt under new idempotency key on already finalized proposal fails
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(
                ReviewDualControlCommand(
                    principal = checkerPrincipal,
                    sessionId = "sess-checker",
                    tenantId = "tenant-prod-1",
                    operationId = "op-dup-dec",
                    action = DualControlAction.REJECT,
                    payloadDigest = digest,
                    expectedTargetVersion = 1L,
                    idempotencyKey = "idemp-dd-3",
                    correlationId = "corr-dd3",
                    causationId = "cause-dd3"
                )
            )
        }
        assertEquals(AuthErrorCode.CONFLICT, failure.code)
    }

    @Test
    fun `test11 concurrent approvers race and exactly one succeeds`() {
        val dualStore = InMemoryDualControlStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)
        val service = DualControlApprovalService(sessions, dualStore, policy, alerts, clock)

        sessions.register("tenant-prod-1", "admin-maker-1", "sess-maker", active = true, mfaVerified = true)
        sessions.register("tenant-prod-1", "admin-checker-2", "sess-checker-2", active = true, mfaVerified = true)
        sessions.register("tenant-prod-1", "admin-checker-3", "sess-checker-3", active = true, mfaVerified = true)

        val digest = sha256("concurrent-payload")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker",
                tenantId = "tenant-prod-1",
                operationId = "op-concurrent-race",
                operationType = "PAYMENT_CONFIGURATION",
                resourceReference = "provider-gateway-1",
                payloadDigest = digest,
                requiredPermission = AdminPermission.PAYMENT_CONFIGURATION,
                targetVersion = 1L,
                idempotencyKey = "idemp-cr-1",
                correlationId = "corr-cr1",
                causationId = "cause-cr1"
            )
        )

        val checker3Principal = AuthenticatedPrincipal(
            id = "admin-checker-3",
            tenantId = "tenant-prod-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN)
        )

        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)

        val callA = pool.submit(Callable<DualControlReceipt> {
            gate.await()
            service.review(
                ReviewDualControlCommand(
                    principal = checkerPrincipal,
                    sessionId = "sess-checker-2",
                    tenantId = "tenant-prod-1",
                    operationId = "op-concurrent-race",
                    action = DualControlAction.APPROVE,
                    payloadDigest = digest,
                    expectedTargetVersion = 1L,
                    idempotencyKey = "idemp-race-a",
                    correlationId = "corr-ra",
                    causationId = "cause-ra"
                )
            )
        })

        val callB = pool.submit(Callable<DualControlReceipt> {
            gate.await()
            service.review(
                ReviewDualControlCommand(
                    principal = checker3Principal,
                    sessionId = "sess-checker-3",
                    tenantId = "tenant-prod-1",
                    operationId = "op-concurrent-race",
                    action = DualControlAction.APPROVE,
                    payloadDigest = digest,
                    expectedTargetVersion = 1L,
                    idempotencyKey = "idemp-race-b",
                    correlationId = "corr-rb",
                    causationId = "cause-rb"
                )
            )
        })

        gate.countDown()
        val resultA = runCatching { callA.get(5, TimeUnit.SECONDS) }
        val resultB = runCatching { callB.get(5, TimeUnit.SECONDS) }
        pool.shutdown()

        val successes = listOf(resultA, resultB).count { it.isSuccess }
        val failures = listOf(resultA, resultB).count { it.isFailure }

        assertEquals(1, successes, "Exactly one concurrent approver must succeed")
        assertEquals(1, failures, "The losing concurrent approver must fail")
    }

    @Test
    fun `test12 checker lacking required permission is rejected`() {
        val dualStore = InMemoryDualControlStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)
        val service = DualControlApprovalService(sessions, dualStore, policy, alerts, clock)

        sessions.register("tenant-prod-1", "admin-maker-1", "sess-maker", active = true, mfaVerified = true)
        sessions.register("tenant-prod-1", "admin-support-3", "sess-support", active = true, mfaVerified = true)

        val digest = sha256("security-config")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker",
                tenantId = "tenant-prod-1",
                operationId = "op-perm-check",
                operationType = "PAYMENT_CONFIGURATION",
                resourceReference = "provider-gateway-1",
                payloadDigest = digest,
                requiredPermission = AdminPermission.PAYMENT_CONFIGURATION,
                targetVersion = 1L,
                idempotencyKey = "idemp-pc-1",
                correlationId = "corr-pc1",
                causationId = "cause-pc1"
            )
        )

        // Support role lacks PAYMENT_CONFIGURATION permission
        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.review(
                ReviewDualControlCommand(
                    principal = supportPrincipal,
                    sessionId = "sess-support",
                    tenantId = "tenant-prod-1",
                    operationId = "op-perm-check",
                    action = DualControlAction.APPROVE,
                    payloadDigest = digest,
                    expectedTargetVersion = 1L,
                    idempotencyKey = "idemp-pc-2",
                    correlationId = "corr-pc2",
                    causationId = "cause-pc2"
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, failure.code)
    }

    @Test
    fun `test13 caller-supplied ID without authenticated decision record is rejected in protected commands`() {
        val store = ContractAuthMemoryStore()
        val sessions = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val service = createAuthService(store, sessions, alerts)

        sessions.register("tenant-prod-1", "admin-maker-1", "session-valid", active = true, mfaVerified = true)

        // A high-risk command requiring dual control (e.g. CHANGE_ROLES or PAYMENT_CONFIGURATION)
        // caller supplies secondApproverId = "admin-checker-2" as text without a valid dualControlReceipt
        val legacyTextCommand = AdminAuthorizationCommand(
            principal = makerPrincipal,
            sessionId = "session-valid",
            tenantId = "tenant-prod-1",
            resourceReference = "resource-1",
            permission = AdminPermission.CHANGE_ROLES,
            idempotencyKey = "idemp-text-second-approver",
            correlationId = "corr-txt",
            causationId = "cause-txt",
            expectedVersion = 0L,
            secondApproverId = "admin-checker-2", // Text only!
            dualControlReceipt = null
        )

        val failure = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authorize(legacyTextCommand)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, failure.code)
    }

    @Test
    fun `test14 least privilege permissions defined and segregated across roles`() {
        val policy = AdminRbacPolicy(dualControlRequired = true)

        val support = AuthenticatedPrincipal("s1", "t1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        val security = AuthenticatedPrincipal("sec1", "t1", PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))
        val auditor = AuthenticatedPrincipal("aud1", "t1", PrincipalKind.ADMIN, setOf(AdminRole.AUDITOR))
        val superAdmin = AuthenticatedPrincipal("sa1", "t1", PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

        // Support has READ_SUPPORT, MANAGE_SUPPORT, RESTRICTIONS_MANAGE but NOT PAYMENT_CONFIGURATION or FRAUD_CASE_MANAGE
        assertTrue(policy.isPermitted(support, AdminPermission.READ_SUPPORT))
        assertTrue(policy.isPermitted(support, AdminPermission.MANAGE_SUPPORT))
        assertTrue(policy.isPermitted(support, AdminPermission.RESTRICTIONS_MANAGE))
        kotlin.test.assertFalse(policy.isPermitted(support, AdminPermission.PAYMENT_CONFIGURATION))
        kotlin.test.assertFalse(policy.isPermitted(support, AdminPermission.FRAUD_CASE_MANAGE))

        // Security has FRAUD_CASE_MANAGE, OPERATIONS_MANAGE, MANAGE_SECURITY but NOT PAYMENT_CONFIGURATION or FINANCIAL_REVIEW
        assertTrue(policy.isPermitted(security, AdminPermission.FRAUD_CASE_MANAGE))
        assertTrue(policy.isPermitted(security, AdminPermission.OPERATIONS_MANAGE))
        assertTrue(policy.isPermitted(security, AdminPermission.MANAGE_SECURITY))
        kotlin.test.assertFalse(policy.isPermitted(security, AdminPermission.PAYMENT_CONFIGURATION))
        kotlin.test.assertFalse(policy.isPermitted(security, AdminPermission.FINANCIAL_REVIEW))

        // Auditor has READ_ANALYTICS, FINANCIAL_REVIEW, READ_AUDIT, READ_SUPPORT but NOT mutations
        assertTrue(policy.isPermitted(auditor, AdminPermission.ANALYTICS_READ))
        assertTrue(policy.isPermitted(auditor, AdminPermission.FINANCIAL_REVIEW))
        assertTrue(policy.isPermitted(auditor, AdminPermission.READ_AUDIT))
        kotlin.test.assertFalse(policy.isPermitted(auditor, AdminPermission.CHANGE_ROLES))
        kotlin.test.assertFalse(policy.isPermitted(auditor, AdminPermission.MANAGE_SUPPORT))

        // Super Admin has all administrative permissions, but never direct FINANCIAL_MUTATION
        assertTrue(policy.isPermitted(superAdmin, AdminPermission.PAYMENT_CONFIGURATION))
        assertTrue(policy.isPermitted(superAdmin, AdminPermission.CHANGE_ROLES))
        assertTrue(policy.isPermitted(superAdmin, AdminPermission.WITHDRAWAL_REVIEW))
        kotlin.test.assertFalse(policy.isPermitted(superAdmin, AdminPermission.FINANCIAL_MUTATION))
    }

    @Test
    fun `test15 restart node recovery preserves valid decisions and rejects unapproved in-flight proposals`() {
        val persistentDualStore = InMemoryDualControlStore()
        val sessionsBeforeRestart = MutableSessionDirectory()
        val alerts = ContractMemoryAlerts()
        val policy = AdminRbacPolicy(dualControlRequired = true)

        var service = DualControlApprovalService(sessionsBeforeRestart, persistentDualStore, policy, alerts, clock)

        sessionsBeforeRestart.register("tenant-prod-1", "admin-maker-1", "sess-maker-pre", active = true, mfaVerified = true)
        sessionsBeforeRestart.register("tenant-prod-1", "admin-checker-2", "sess-checker-pre", active = true, mfaVerified = true)

        val digest1 = sha256("config-1")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker-pre",
                tenantId = "tenant-prod-1",
                operationId = "op-approved-pre-restart",
                operationType = "PAYMENT_CONFIGURATION",
                resourceReference = "gateway-1",
                payloadDigest = digest1,
                requiredPermission = AdminPermission.PAYMENT_CONFIGURATION,
                targetVersion = 1L,
                idempotencyKey = "idemp-prop-pre-1",
                correlationId = "corr-pre1",
                causationId = "cause-pre1"
            )
        )
        val validReceipt = service.review(
            ReviewDualControlCommand(
                principal = checkerPrincipal,
                sessionId = "sess-checker-pre",
                tenantId = "tenant-prod-1",
                operationId = "op-approved-pre-restart",
                action = DualControlAction.APPROVE,
                payloadDigest = digest1,
                expectedTargetVersion = 1L,
                idempotencyKey = "idemp-rev-pre-1",
                correlationId = "corr-rev-pre1",
                causationId = "cause-rev-pre1"
            )
        )

        // Proposal 2 is left in-flight
        val digest2 = sha256("config-2")
        service.propose(
            ProposeDualControlCommand(
                principal = makerPrincipal,
                sessionId = "sess-maker-pre",
                tenantId = "tenant-prod-1",
                operationId = "op-inflight-pre-restart",
                operationType = "PAYMENT_CONFIGURATION",
                resourceReference = "gateway-2",
                payloadDigest = digest2,
                requiredPermission = AdminPermission.PAYMENT_CONFIGURATION,
                targetVersion = 1L,
                idempotencyKey = "idemp-prop-pre-2",
                correlationId = "corr-pre2",
                causationId = "cause-pre2"
            )
        )

        // --- Node Restart Event ---
        // New service instance simulates node recovery: new session directory, but same persistent store
        val sessionsAfterRestart = MutableSessionDirectory()
        val restartedService = DualControlApprovalService(sessionsAfterRestart, persistentDualStore, policy, alerts, clock)

        // 1. Preserved decision: Previously approved receipt is preserved and verified
        val recoveredReceipt = persistentDualStore.findReceiptByIdempotency("tenant-prod-1", "idemp-rev-pre-1")?.second
        assertNotNull(recoveredReceipt)
        assertEquals(DualControlStatus.APPROVED, recoveredReceipt.status)
        assertTrue(restartedService.validateReceipt(recoveredReceipt, "tenant-prod-1", "op-approved-pre-restart", digest1, 1L))

        // 2. In-flight proposal without valid active session after restart is rejected
        val restartFailure = assertFailsWith<AuthenticationFailure.Rejected> {
            restartedService.review(
                ReviewDualControlCommand(
                    principal = checkerPrincipal,
                    sessionId = "sess-checker-pre", // Lost/unregistered session on recovered node
                    tenantId = "tenant-prod-1",
                    operationId = "op-inflight-pre-restart",
                    action = DualControlAction.APPROVE,
                    payloadDigest = digest2,
                    expectedTargetVersion = 1L,
                    idempotencyKey = "idemp-rev-post-2",
                    correlationId = "corr-post2",
                    causationId = "cause-post2"
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, restartFailure.code)
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun createAuthService(
        store: AuthorizationStore,
        sessions: AdminSessionDirectory,
        alerts: AlertSink
    ): AdminAuthorizationService = AdminAuthorizationService(
        sessions = sessions,
        store = store,
        owners = object : ResourceOwnerResolver {
            override fun resolve(tenantId: String, resourceReference: String): String? =
                if (resourceReference == "unknown") null else "owner-1"
        },
        alerts = alerts,
        policy = AdminRbacPolicy(dualControlRequired = true),
        clock = clock
    )

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}

class MutableSessionDirectory : AdminSessionDirectory {
    private val sessions = mutableMapOf<String, AdminSessionStatus>()

    fun register(
        tenantId: String,
        principalId: String,
        sessionId: String,
        active: Boolean = true,
        breakGlass: Boolean = false,
        expiresAt: Instant = Instant.parse("2026-09-24T18:00:00Z"),
        mfaVerified: Boolean = true,
        mfaExpiresAt: Instant? = Instant.parse("2026-09-24T18:00:00Z")
    ) {
        sessions["$tenantId:$principalId:$sessionId"] = AdminSessionStatus(
            active = active,
            breakGlass = breakGlass,
            expiresAt = expiresAt,
            mfaVerified = mfaVerified,
            mfaExpiresAt = mfaExpiresAt
        )
    }

    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        sessions["$tenantId:$principalId:$sessionId"]
}

class ContractMemoryAlerts : AlertSink {
    val events = mutableListOf<AuditEvent>()
    override fun alert(event: AuditEvent) {
        events += event
    }
}

class ContractAuthMemoryStore : AuthorizationStore {
    val results = mutableMapOf<String, Pair<String, AuthorizationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<String, AuthorizationResult>? = synchronized(this) {
        results["$tenantId:$key"]
    }

    override fun currentVersion(tenantId: String, ownerId: String): Long = synchronized(this) {
        results.values.maxOfOrNull { it.second.serverVersion } ?: 0L
    }

    override fun save(
        result: AuthorizationResult,
        tenantId: String,
        ownerId: String,
        permission: AdminPermission,
        idempotencyKey: String,
        breakGlass: Boolean,
        expiresAt: Instant,
        requestFingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = requestFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
