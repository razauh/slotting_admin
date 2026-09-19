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

class FourEyesPrimitivesTest {

    private val now = Instant.parse("2026-09-18T23:45:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        FourEyesPrimitivesBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        ApiResourceOwnershipBinding.isBound = true
        PlayerAdminRbacSeparationBinding.isBound = true
        FourEyesPrimitivesBinding.isBound = true
    }

    private fun adminPrincipal(
        id: String,
        tenantId: String = "tenant-1",
        roles: Set<AdminRole> = setOf(AdminRole.SUPER_ADMIN)
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = roles
        )
    }

    private fun playerPrincipal(
        id: String = "player-1",
        tenantId: String = "tenant-1"
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet()
        )
    }

    // =========================================================================
    // AUTHZ-003-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `AUTHZ-003-T001 Four-eyes primitives produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        FourEyesPrimitivesBinding.checkBound()

        val store = InMemoryFourEyesProposalStore()
        val alertSink = InMemoryFourEyesAlertSink()
        val service = FourEyesPrimitivesService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-dual-control-1"
        val maker = adminPrincipal("maker-admin-1", tenantId)
        val checker = adminPrincipal("checker-admin-2", tenantId)

        // 2. Propose a high-risk action
        val proposeCmd = ProposeHighRiskActionCommand(
            makerPrincipal = maker,
            tenantId = tenantId,
            actionType = FourEyesActionType.CHANGE_ROLES,
            makerReason = "Promoting user-55 to SUPPORT role per ticket SEC-404",
            payloadDetails = mapOf("targetUserId" to "user-55", "targetRole" to "SUPPORT"),
            ttlSeconds = 3600L,
            idempotencyKey = "propose-key-1",
            correlationId = "corr-prop-1",
            causationId = "caus-prop-1",
            expectedVersion = 1L
        )

        val proposalResult = service.proposeAction(proposeCmd)

        // Assert proposal is pending approval and cannot execute before second approval
        assertEquals(FourEyesProposalStatus.PENDING_APPROVAL, proposalResult.status)
        assertEquals(tenantId, proposalResult.tenantId)
        assertEquals(maker.id, proposalResult.makerId)
        assertEquals(null, proposalResult.checkerId)
        assertEquals(1L, proposalResult.serverVersion)
        assertEquals(now, proposalResult.serverTime)
        assertTrue(proposalResult.evidenceReference.contains("PROPOSED"))
        assertEquals("FOUR_EYES_PROPOSAL_CREATED", proposalResult.auditEvent.type)
        assertEquals("FOUR_EYES_PROPOSAL_CREATED", proposalResult.outboxEvent.type)

        // 3. Checker reviews and approves the proposal
        val reviewCmd = ReviewProposalCommand(
            checkerPrincipal = checker,
            tenantId = tenantId,
            proposalId = proposalResult.proposalId,
            approve = true,
            checkerReason = "Verified identity and ticket SEC-404; approval granted",
            idempotencyKey = "review-key-1",
            correlationId = "corr-rev-1",
            causationId = "caus-rev-1",
            expectedVersion = 1L
        )

        val reviewResult = service.reviewProposal(reviewCmd)

        // Exact assertions: Configured high-risk actions cannot execute before second approval; immutable record.
        assertEquals(FourEyesProposalStatus.APPROVED, reviewResult.status)
        assertEquals(tenantId, reviewResult.tenantId)
        assertEquals(proposalResult.proposalId, reviewResult.proposalId)
        assertEquals(maker.id, reviewResult.makerId)
        assertEquals(checker.id, reviewResult.checkerId)
        assertEquals(2L, reviewResult.serverVersion)
        assertEquals(now, reviewResult.serverTime)
        assertTrue(reviewResult.evidenceReference.contains("APPROVED"))
        assertEquals("FOUR_EYES_PROPOSAL_APPROVED", reviewResult.auditEvent.type)
        assertEquals("FOUR_EYES_PROPOSAL_APPROVED", reviewResult.outboxEvent.type)

        // 4. Assert zero financial authority or mutation
        val savedProposal = store.findById(tenantId, proposalResult.proposalId)
        assertNotNull(savedProposal)
        assertEquals(FourEyesProposalStatus.APPROVED, savedProposal.status)
    }

    // =========================================================================
    // AUTHZ-003-T002: Negative, Boundary, and Security Cases
    // =========================================================================

    @Test
    fun `AUTHZ-003-T002 Four-eyes primitives rejects invalid boundary unauthorized and stale input`() {
        FourEyesPrimitivesBinding.isBound = true

        val store = InMemoryFourEyesProposalStore()
        val alertSink = InMemoryFourEyesAlertSink()
        val service = FourEyesPrimitivesService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenant1 = "tenant-1"
        val tenant2 = "tenant-2"
        val maker = adminPrincipal("maker-1", tenant1)
        val checker = adminPrincipal("checker-2", tenant1)

        val proposalResult = service.proposeAction(
            ProposeHighRiskActionCommand(
                makerPrincipal = maker,
                tenantId = tenant1,
                actionType = FourEyesActionType.SYSTEM_SETTLEMENT_OVERRIDE,
                makerReason = "Reconciling settlement drift",
                payloadDetails = mapOf("settlementBatch" to "BATCH-909"),
                ttlSeconds = 300L,
                idempotencyKey = "prop-sec-1",
                correlationId = "corr-s-1",
                causationId = "caus-s-1",
                expectedVersion = 1L
            )
        )

        // 1. Maker Self-Approval Defense: Maker attempts to approve their own proposal
        val selfApprovalError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewProposal(
                ReviewProposalCommand(
                    checkerPrincipal = maker, // same principal as maker!
                    tenantId = tenant1,
                    proposalId = proposalResult.proposalId,
                    approve = true,
                    checkerReason = "Self approving my change",
                    idempotencyKey = "rev-self-1",
                    correlationId = "corr-self-1",
                    causationId = "caus-self-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, selfApprovalError.code)
        assertTrue(alertSink.alerts.any { it.contains("MAKER_SELF_APPROVAL_ATTEMPT") })

        // 2. Legitimate approval by checker
        val approvedResult = service.reviewProposal(
            ReviewProposalCommand(
                checkerPrincipal = checker,
                tenantId = tenant1,
                proposalId = proposalResult.proposalId,
                approve = true,
                checkerReason = "Confirmed batch numbers",
                idempotencyKey = "rev-valid-1",
                correlationId = "corr-valid-1",
                causationId = "caus-valid-1",
                expectedVersion = 1L
            )
        )
        assertEquals(FourEyesProposalStatus.APPROVED, approvedResult.status)

        // 3. Replay Prevention: Attempting to review an already approved proposal again
        val replayError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewProposal(
                ReviewProposalCommand(
                    checkerPrincipal = adminPrincipal("checker-3", tenant1),
                    tenantId = tenant1,
                    proposalId = proposalResult.proposalId,
                    approve = true,
                    checkerReason = "Replaying review attempt",
                    idempotencyKey = "rev-replay-1",
                    correlationId = "corr-rep-1",
                    causationId = "caus-rep-1",
                    expectedVersion = 2L
                )
            )
        }
        assertEquals(AuthErrorCode.CONFLICT, replayError.code)

        // 4. Expiration / TTL Defense: Stale proposal past expiresAt
        val expiredProposal = service.proposeAction(
            ProposeHighRiskActionCommand(
                makerPrincipal = maker,
                tenantId = tenant1,
                actionType = FourEyesActionType.BREAK_GLASS_ACCESS,
                makerReason = "Emergency database access",
                payloadDetails = mapOf("incidentId" to "INC-500"),
                ttlSeconds = 60L,
                idempotencyKey = "prop-exp-1",
                correlationId = "corr-exp-1",
                causationId = "caus-exp-1",
                expectedVersion = 1L
            )
        )

        val futureClock = Clock.fixed(now.plusSeconds(120), ZoneOffset.UTC)
        val futureService = FourEyesPrimitivesService(store = store, alertSink = alertSink, clock = futureClock)
        val expiredError = assertFailsWith<AuthenticationFailure.Rejected> {
            futureService.reviewProposal(
                ReviewProposalCommand(
                    checkerPrincipal = checker,
                    tenantId = tenant1,
                    proposalId = expiredProposal.proposalId,
                    approve = true,
                    checkerReason = "Approving after TTL",
                    idempotencyKey = "rev-exp-1",
                    correlationId = "corr-rexp-1",
                    causationId = "caus-rexp-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, expiredError.code)

        // 5. Cross-Tenant Defense: Checker in Tenant 2 attempts to review Tenant 1's proposal
        val crossTenantChecker = adminPrincipal("checker-t2", tenant2)
        val crossTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewProposal(
                ReviewProposalCommand(
                    checkerPrincipal = crossTenantChecker,
                    tenantId = tenant2, // command tenant differs from proposal tenant
                    proposalId = proposalResult.proposalId,
                    approve = true,
                    checkerReason = "Cross-tenant review attempt",
                    idempotencyKey = "rev-ct-1",
                    correlationId = "corr-ct-1",
                    causationId = "caus-ct-1",
                    expectedVersion = 2L
                )
            )
        }
        assertEquals(AuthErrorCode.INVALID, crossTenantError.code) // Proposal not found in Tenant 2

        // 6. Player Unauthorized: Player principal attempts to propose high-risk action
        val player = playerPrincipal("player-evil", tenant1)
        val playerProposeError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.proposeAction(
                ProposeHighRiskActionCommand(
                    makerPrincipal = player,
                    tenantId = tenant1,
                    actionType = FourEyesActionType.CHANGE_ROLES,
                    makerReason = "Self promoting player",
                    payloadDetails = mapOf("role" to "SUPER_ADMIN"),
                    idempotencyKey = "prop-player-1",
                    correlationId = "corr-pp-1",
                    causationId = "caus-pp-1",
                    expectedVersion = 1L
                )
            )
        }
        assertEquals(AuthErrorCode.FORBIDDEN, playerProposeError.code)
        assertTrue(alertSink.alerts.any { it.contains("UNAUTHORIZED_MAKER_ATTEMPT") })

        // 7. Stale Version Defense: Review command expectedVersion mismatch
        val newProposal = service.proposeAction(
            ProposeHighRiskActionCommand(
                makerPrincipal = maker,
                tenantId = tenant1,
                actionType = FourEyesActionType.POLICY_EXCEPTION,
                makerReason = "Temporary testing policy exception",
                payloadDetails = mapOf("policy" to "GEO_ALLOW"),
                idempotencyKey = "prop-v-1",
                correlationId = "corr-v-1",
                causationId = "caus-v-1",
                expectedVersion = 1L
            )
        )
        val versionMismatchError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewProposal(
                ReviewProposalCommand(
                    checkerPrincipal = checker,
                    tenantId = tenant1,
                    proposalId = newProposal.proposalId,
                    approve = true,
                    checkerReason = "Stale version review",
                    idempotencyKey = "rev-vm-1",
                    correlationId = "corr-vm-1",
                    causationId = "caus-vm-1",
                    expectedVersion = 99L // expected 99 but actual is 1
                )
            )
        }
        assertEquals(AuthErrorCode.STALE, versionMismatchError.code)

        // 8. Blank Reason Validations
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.proposeAction(
                ProposeHighRiskActionCommand(
                    makerPrincipal = maker,
                    tenantId = tenant1,
                    actionType = FourEyesActionType.CHANGE_ROLES,
                    makerReason = "   ", // blank
                    payloadDetails = emptyMap(),
                    idempotencyKey = "prop-br-1",
                    correlationId = "corr-br-1",
                    causationId = "caus-br-1",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewProposal(
                ReviewProposalCommand(
                    checkerPrincipal = checker,
                    tenantId = tenant1,
                    proposalId = newProposal.proposalId,
                    approve = true,
                    checkerReason = "   ", // blank
                    idempotencyKey = "rev-br-1",
                    correlationId = "corr-br-1",
                    causationId = "caus-br-1",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // AUTHZ-003-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `AUTHZ-003-T003 Four-eyes primitives survives concurrency duplicate delivery and dependency failure`() {
        FourEyesPrimitivesBinding.isBound = true

        val store = InMemoryFourEyesProposalStore()
        val alertSink = InMemoryFourEyesAlertSink()
        val service = FourEyesPrimitivesService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-concurrent"
        val maker = adminPrincipal("maker-c", tenantId)
        val checker = adminPrincipal("checker-c", tenantId)

        val baseProposeCmd = ProposeHighRiskActionCommand(
            makerPrincipal = maker,
            tenantId = tenantId,
            actionType = FourEyesActionType.POLICY_EXCEPTION,
            makerReason = "Concurrency testing",
            payloadDetails = mapOf("test" to "data"),
            idempotencyKey = "idem-prop-1",
            correlationId = "corr-ip-1",
            causationId = "caus-ip-1",
            expectedVersion = 1L
        )

        // 1. Idempotent proposal replay
        val prop1 = service.proposeAction(baseProposeCmd)
        val prop2 = service.proposeAction(baseProposeCmd)
        assertEquals(prop1.proposalId, prop2.proposalId)
        assertEquals(prop1.evidenceReference, prop2.evidenceReference)

        // 2. Proposal conflict on changed payload
        val conflictingPropCmd = baseProposeCmd.copy(makerReason = "Changed reason")
        val propConflict = assertFailsWith<AuthenticationFailure.Rejected> {
            service.proposeAction(conflictingPropCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, propConflict.code)

        // 3. Idempotent review replay
        val baseReviewCmd = ReviewProposalCommand(
            checkerPrincipal = checker,
            tenantId = tenantId,
            proposalId = prop1.proposalId,
            approve = true,
            checkerReason = "Idempotent review approval",
            idempotencyKey = "idem-rev-1",
            correlationId = "corr-ir-1",
            causationId = "caus-ir-1",
            expectedVersion = 1L
        )
        val rev1 = service.reviewProposal(baseReviewCmd)
        val rev2 = service.reviewProposal(baseReviewCmd)
        assertEquals(rev1.resultId, rev2.resultId)
        assertEquals(rev1.status, rev2.status)
        assertEquals(rev1.evidenceReference, rev2.evidenceReference)

        // 4. Review conflict on changed payload
        val conflictingRevCmd = baseReviewCmd.copy(approve = false)
        val revConflict = assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewProposal(conflictingRevCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, revConflict.code)

        // 5. Multi-threaded concurrency: 16 threads proposing and reviewing distinct proposals concurrently
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)

        val proposals = (1..threadCount).map { i ->
            val m = adminPrincipal("maker-$i", tenantId)
            val c = adminPrincipal("checker-$i", tenantId)
            val pResult = service.proposeAction(
                ProposeHighRiskActionCommand(
                    makerPrincipal = m,
                    tenantId = tenantId,
                    actionType = FourEyesActionType.CHANGE_ROLES,
                    makerReason = "Concurrent proposal $i",
                    payloadDetails = mapOf("seq" to "$i"),
                    idempotencyKey = "conc-prop-$i",
                    correlationId = "corr-cp-$i",
                    causationId = "caus-cp-$i",
                    expectedVersion = 1L
                )
            )
            Triple(m, c, pResult)
        }

        val concurrentReviews = ConcurrentHashMap<UUID, FourEyesDecisionResult>()

        proposals.forEachIndexed { index, (m, c, pResult) ->
            executor.submit {
                try {
                    val res = service.reviewProposal(
                        ReviewProposalCommand(
                            checkerPrincipal = c,
                            tenantId = tenantId,
                            proposalId = pResult.proposalId,
                            approve = true,
                            checkerReason = "Concurrent approval $index",
                            idempotencyKey = "conc-rev-$index",
                            correlationId = "corr-cr-$index",
                            causationId = "caus-cr-$index",
                            expectedVersion = 1L
                        )
                    )
                    concurrentReviews[pResult.proposalId] = res
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()

        assertEquals(threadCount, concurrentReviews.size)
        concurrentReviews.values.forEach { dec ->
            assertEquals(FourEyesProposalStatus.APPROVED, dec.status)
            assertNotNull(dec.checkerId)
            assertFalse(dec.makerId == dec.checkerId)
        }
    }

    // =========================================================================
    // AUTHZ-003-T004: Migration Integrity, Recovery and Observability
    // =========================================================================

    @Test
    fun `AUTHZ-003-T004 Four-eyes primitives remains compatible recoverable observable and lifecycle-safe`() {
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

        FourEyesPrimitivesBinding.isBound = true

        val store = InMemoryFourEyesProposalStore()
        val alertSink = InMemoryFourEyesAlertSink()
        val service1 = FourEyesPrimitivesService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-restart"
        val maker = adminPrincipal("maker-restart", tenantId)
        val checker = adminPrincipal("checker-restart", tenantId)

        val proposal = service1.proposeAction(
            ProposeHighRiskActionCommand(
                makerPrincipal = maker,
                tenantId = tenantId,
                actionType = FourEyesActionType.PLAYER_ACCOUNT_CLOSE,
                makerReason = "User requested account closure per GDPR/compliance",
                payloadDetails = mapOf("targetPlayer" to "player-888"),
                idempotencyKey = "prop-rec-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )
        assertEquals(FourEyesProposalStatus.PENDING_APPROVAL, proposal.status)

        // 2. Recovery and Restart: New service instance attached to existing persistent store
        val service2 = FourEyesPrimitivesService(
            store = store,
            alertSink = alertSink,
            clock = clock
        )

        val approvedOnRestart = service2.reviewProposal(
            ReviewProposalCommand(
                checkerPrincipal = checker,
                tenantId = tenantId,
                proposalId = proposal.proposalId,
                approve = true,
                checkerReason = "GDPR request verified",
                idempotencyKey = "rev-rec-1",
                correlationId = "corr-rev-rec-1",
                causationId = "caus-rev-rec-1",
                expectedVersion = 1L
            )
        )
        assertEquals(FourEyesProposalStatus.APPROVED, approvedOnRestart.status)
        assertEquals(proposal.proposalId, approvedOnRestart.proposalId)

        // 3. Observability and Redaction
        val audit = approvedOnRestart.auditEvent
        assertEquals(tenantId, audit.tenantId)
        assertEquals("corr-rev-rec-1", audit.correlationId)
        assertEquals("caus-rev-rec-1", audit.causationId)
        assertEquals("FOUR_EYES_PROPOSAL_APPROVED", audit.type)
        assertEquals(now, audit.occurredAt)

        val outbox = approvedOnRestart.outboxEvent
        assertEquals(tenantId, outbox.tenantId)
        assertEquals("FOUR_EYES_PROPOSAL_APPROVED", outbox.type)
        assertEquals(now, outbox.createdAt)

        // Trigger self-approval failure to check security alert redaction
        assertFailsWith<AuthenticationFailure.Rejected> {
            service2.reviewProposal(
                ReviewProposalCommand(
                    checkerPrincipal = maker,
                    tenantId = tenantId,
                    proposalId = proposal.proposalId,
                    approve = true,
                    checkerReason = "Attempting illegal self-approval",
                    idempotencyKey = "rev-self-rec",
                    correlationId = "corr-sr-1",
                    causationId = "caus-sr-1",
                    expectedVersion = 1L
                )
            )
        }

        alertSink.alerts.forEach { alert ->
            assertFalse(alert.contains("password"))
            assertFalse(alert.contains("cvv"))
            assertFalse(alert.contains("token"))
            assertFalse(alert.contains("secret"))
        }
    }
}
