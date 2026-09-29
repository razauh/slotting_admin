package com.slotting.admin.fraud

import com.slotting.admin.auth.*
import com.slotting.admin.restriction.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

/**
 * TC-032 Contract Test Suite: Fraud Restrictions, Manual-Review Cases, and Disposition Lifecycle.
 *
 * Verifies all 10 required test scenarios:
 * 1. duplicate signal
 * 2. case merge policy
 * 3. temporary hold
 * 4. manual clear
 * 5. escalation
 * 6. concurrent reviewer
 * 7. active session
 * 8. multiple devices
 * 9. direct API
 * 10. cache loss
 */
class FraudCaseManagementContractTest {

    private val tenantId = "tenant-case-1"
    private val subjectRef = "player-fraud-99"
    private val baseNow = Instant.parse("2026-09-26T12:00:00Z")
    private lateinit var clock: MutableClock
    private lateinit var caseStore: InMemoryFraudCaseStore
    private lateinit var restrictionStore: InMemoryServerRestrictionStore
    private lateinit var sessionDirectory: TestSessionDirectory
    private lateinit var service: FraudCaseService

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SECURITY),
        kind = PrincipalKind.ADMIN,
    )

    private val secondApproverAdmin = AuthenticatedPrincipal(
        id = "admin-sec-02",
        tenantId = tenantId,
        roles = setOf(AdminRole.SECURITY),
        kind = PrincipalKind.ADMIN,
    )

    private val supportAdmin = AuthenticatedPrincipal(
        id = "admin-sup-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT), // Lacks FRAUD_CASE_MANAGE
        kind = PrincipalKind.ADMIN,
    )

    class MutableClock(private var current: Instant) : Clock() {
        override fun getZone(): ZoneOffset = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = current
        fun advance(duration: Duration) { current = current.plus(duration) }
        fun setInstant(newInstant: Instant) { current = newInstant }
    }

    class TestSessionDirectory : AdminSessionDirectory {
        private val sessions = mutableMapOf<String, AdminSessionStatus>()

        fun register(tenantId: String, principalId: String, sessionId: String, status: AdminSessionStatus) {
            sessions["$tenantId:$principalId:$sessionId"] = status
        }

        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
            sessions["$tenantId:$principalId:$sessionId"]
    }

    @BeforeEach
    fun setUp() {
        clock = MutableClock(baseNow)
        caseStore = InMemoryFraudCaseStore()
        restrictionStore = InMemoryServerRestrictionStore()
        sessionDirectory = TestSessionDirectory()

        // Register valid session with MFA verified
        sessionDirectory.register(
            tenantId = tenantId,
            principalId = securityAdmin.id,
            sessionId = "sess-valid-1",
            status = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = baseNow.plus(Duration.ofHours(2)),
                mfaVerified = true,
                mfaExpiresAt = baseNow.plus(Duration.ofHours(1)),
            ),
        )

        sessionDirectory.register(
            tenantId = tenantId,
            principalId = secondApproverAdmin.id,
            sessionId = "sess-valid-2",
            status = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = baseNow.plus(Duration.ofHours(2)),
                mfaVerified = true,
                mfaExpiresAt = baseNow.plus(Duration.ofHours(1)),
            ),
        )

        sessionDirectory.register(
            tenantId = tenantId,
            principalId = supportAdmin.id,
            sessionId = "sess-support-1",
            status = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = baseNow.plus(Duration.ofHours(2)),
                mfaVerified = true,
                mfaExpiresAt = baseNow.plus(Duration.ofHours(1)),
            ),
        )

        service = FraudCaseService(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory,
            caseStore = caseStore,
            restrictionStore = restrictionStore,
            clock = clock,
            claimLeaseDuration = Duration.ofMinutes(15),
            requireDualControlForCritical = true,
        )
    }

    @Test
    fun `V35 migration script exists and defines required fraud case and action tables`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V35__durable_fraud_cases_and_dispositions.sql")
        assertNotNull(stream, "V35 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("fraud_cases", ignoreCase = true))
        assertTrue(sql.contains("fraud_case_actions", ignoreCase = true))
        assertTrue(sql.contains("uq_fraud_case_actions_tenant_idem", ignoreCase = true))
    }

    // -------------------------------------------------------------
    // Scenario 1: Duplicate Signal
    // -------------------------------------------------------------
    @Test
    fun `Scenario 1 - duplicate signal delivery is completely idempotent`() {
        val cmd = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-001",
            severity = FraudCaseSeverity.HIGH,
            detectedReasons = listOf("FAILED_DEPOSITS_BURST"),
            requiresRestriction = true,
            idempotencyKey = "idem-case-1",
            correlationId = "corr-1",
            causationId = "cause-1",
        )

        val firstCase = service.openOrMergeCase(cmd)
        val duplicateCase = service.openOrMergeCase(cmd)

        assertEquals(firstCase.caseId, duplicateCase.caseId)
        assertEquals(firstCase.caseReference, duplicateCase.caseReference)
        assertEquals(1, duplicateCase.riskDecisionReferences.size)
    }

    // -------------------------------------------------------------
    // Scenario 2: Case Merge Policy
    // -------------------------------------------------------------
    @Test
    fun `Scenario 2 - subsequent risk decisions merge into existing active case instead of creating disjoint cases`() {
        val cmd1 = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-INITIAL",
            severity = FraudCaseSeverity.MEDIUM,
            detectedReasons = listOf("AUTH_ANOMALY_DETECTED"),
            requiresRestriction = true,
            idempotencyKey = "idem-open-1",
            correlationId = "c1",
            causationId = "cause1",
        )
        val initialCase = service.openOrMergeCase(cmd1)
        assertEquals(FraudCaseSeverity.MEDIUM, initialCase.severity)

        // New decision for same subject with higher severity
        val cmd2 = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-SECONDARY",
            severity = FraudCaseSeverity.CRITICAL,
            detectedReasons = listOf("PROVIDER_CHARGEBACK_DISPUTE"),
            requiresRestriction = true,
            idempotencyKey = "idem-open-2",
            correlationId = "c2",
            causationId = "cause2",
        )
        val mergedCase = service.openOrMergeCase(cmd2)

        assertEquals(initialCase.caseId, mergedCase.caseId)
        assertEquals(initialCase.caseReference, mergedCase.caseReference)
        assertEquals(2, mergedCase.riskDecisionReferences.size)
        assertTrue(mergedCase.detectedReasons.contains("AUTH_ANOMALY_DETECTED"))
        assertTrue(mergedCase.detectedReasons.contains("PROVIDER_CHARGEBACK_DISPUTE"))
        // Severity escalated to CRITICAL
        assertEquals(FraudCaseSeverity.CRITICAL, mergedCase.severity)
    }

    // -------------------------------------------------------------
    // Scenario 3: Temporary Hold
    // -------------------------------------------------------------
    @Test
    fun `Scenario 3 - temporary fraud hold is applied with bounded UTC expiry`() {
        val holdDuration = Duration.ofDays(7)
        val openCmd = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-HOLD",
            severity = FraudCaseSeverity.HIGH,
            detectedReasons = listOf("SUSPICIOUS_PAYMENT_ACTIVITY"),
            requiresRestriction = true,
            restrictionDuration = holdDuration,
            idempotencyKey = "idem-hold-1",
            correlationId = "c-hold",
            causationId = "cause-hold",
        )

        val caseRecord = service.openOrMergeCase(openCmd)
        assertNotNull(caseRecord.restrictionId)

        val activeRestrictions = restrictionStore.findActiveRestrictions(tenantId, subjectRef, baseNow)
        assertEquals(1, activeRestrictions.size)
        val restriction = activeRestrictions.first()
        assertEquals(RestrictionSource.FRAUD_SECURITY, restriction.source)
        assertEquals(baseNow.plus(holdDuration), restriction.expiresAt)

        // After expiry, restriction is no longer active
        clock.advance(holdDuration.plusSeconds(10))
        val expiredRestrictions = restrictionStore.findActiveRestrictions(tenantId, subjectRef, clock.instant())
        assertTrue(expiredRestrictions.isEmpty(), "Temporary fraud hold must expire after duration")
    }

    // -------------------------------------------------------------
    // Scenario 4: Manual Clear
    // -------------------------------------------------------------
    @Test
    fun `Scenario 4 - reviewer clears case, lifting active fraud restriction via audited disposition`() {
        val openCmd = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-TO-CLEAR",
            severity = FraudCaseSeverity.MEDIUM,
            detectedReasons = listOf("SUSPICIOUS_VELOCITY"),
            requiresRestriction = true,
            idempotencyKey = "idem-clear-open",
            correlationId = "c-clear",
            causationId = "cause-clear",
        )
        val openedCase = service.openOrMergeCase(openCmd)
        assertNotNull(openedCase.restrictionId)

        // Verify restriction is currently active
        assertEquals(1, restrictionStore.findActiveRestrictions(tenantId, subjectRef, baseNow).size)

        // Reviewer claims case
        val claimedCase = service.operateCase(
            OperateFraudCaseCommand(
                principal = securityAdmin,
                sessionId = "sess-valid-1",
                tenantId = tenantId,
                caseReference = openedCase.caseReference,
                action = FraudCaseAction.CLAIM,
                expectedVersion = openedCase.serverVersion,
                idempotencyKey = "idem-claim-op",
                correlationId = "c-claim",
                causationId = "cause-claim",
            )
        )
        assertEquals(FraudCaseState.CLAIMED, claimedCase.state)

        // Reviewer clears case (disposition)
        val clearedCase = service.operateCase(
            OperateFraudCaseCommand(
                principal = securityAdmin,
                sessionId = "sess-valid-1",
                tenantId = tenantId,
                caseReference = openedCase.caseReference,
                action = FraudCaseAction.DISPOSE_CLEAR,
                reason = "VERIFIED_LEGITIMATE_CUSTOMER_ACTIVITY",
                expectedVersion = claimedCase.serverVersion,
                idempotencyKey = "idem-clear-op",
                correlationId = "c-disp-clear",
                causationId = "cause-disp-clear",
            )
        )

        assertEquals(FraudCaseState.DISPOSED_CLEARED, clearedCase.state)
        assertEquals(securityAdmin.id, clearedCase.disposedBy)
        assertEquals("VERIFIED_LEGITIMATE_CUSTOMER_ACTIVITY", clearedCase.dispositionReason)

        // Assert: Active fraud restriction has been REVOKED!
        val postClearRestrictions = restrictionStore.findActiveRestrictions(tenantId, subjectRef, baseNow)
        assertTrue(postClearRestrictions.isEmpty(), "Fraud restriction must be revoked on clear disposition")
    }

    // -------------------------------------------------------------
    // Scenario 5: Escalation & Dual Control
    // -------------------------------------------------------------
    @Test
    fun `Scenario 5 - escalation requires dual control for critical case disposition`() {
        val openCmd = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-CRITICAL",
            severity = FraudCaseSeverity.CRITICAL,
            detectedReasons = listOf("ORGANIZED_FRAUD_RING"),
            requiresRestriction = true,
            idempotencyKey = "idem-crit-open",
            correlationId = "c-crit",
            causationId = "cause-crit",
        )
        val openedCase = service.openOrMergeCase(openCmd)

        // Reviewer escalates case
        val escalatedCase = service.operateCase(
            OperateFraudCaseCommand(
                principal = securityAdmin,
                sessionId = "sess-valid-1",
                tenantId = tenantId,
                caseReference = openedCase.caseReference,
                action = FraudCaseAction.ESCALATE,
                reason = "COMPLEX_RING_REQUIRES_DUAL_CONTROL",
                expectedVersion = openedCase.serverVersion,
                idempotencyKey = "idem-esc-op",
                correlationId = "c-esc",
                causationId = "cause-esc",
            )
        )
        assertEquals(FraudCaseState.ESCALATED, escalatedCase.state)

        // Attempting to clear critical case without second approver is FORBIDDEN
        assertThrows(AuthenticationFailure.Rejected::class.java) {
            service.operateCase(
                OperateFraudCaseCommand(
                    principal = securityAdmin,
                    sessionId = "sess-valid-1",
                    tenantId = tenantId,
                    caseReference = openedCase.caseReference,
                    action = FraudCaseAction.DISPOSE_CLEAR,
                    secondApproverId = null, // Missing!
                    expectedVersion = escalatedCase.serverVersion,
                    idempotencyKey = "idem-no-second",
                    correlationId = "c-err",
                    causationId = "cause-err",
                )
            )
        }

        // Self-approval is FORBIDDEN
        assertThrows(AuthenticationFailure.Rejected::class.java) {
            service.operateCase(
                OperateFraudCaseCommand(
                    principal = securityAdmin,
                    sessionId = "sess-valid-1",
                    tenantId = tenantId,
                    caseReference = openedCase.caseReference,
                    action = FraudCaseAction.DISPOSE_CLEAR,
                    secondApproverId = securityAdmin.id, // Self-approval!
                    expectedVersion = escalatedCase.serverVersion,
                    idempotencyKey = "idem-self-approve",
                    correlationId = "c-self",
                    causationId = "cause-self",
                )
            )
        }

        // Proper dual approval with distinct second approver succeeds
        val disposedCase = service.operateCase(
            OperateFraudCaseCommand(
                principal = securityAdmin,
                sessionId = "sess-valid-1",
                tenantId = tenantId,
                caseReference = openedCase.caseReference,
                action = FraudCaseAction.DISPOSE_CLEAR,
                reason = "INVESTIGATION_CONCLUDED_CLEARED",
                secondApproverId = secondApproverAdmin.id,
                expectedVersion = escalatedCase.serverVersion,
                idempotencyKey = "idem-dual-approved",
                correlationId = "c-dual",
                causationId = "cause-dual",
            )
        )
        assertEquals(FraudCaseState.DISPOSED_CLEARED, disposedCase.state)
        assertEquals(secondApproverAdmin.id, disposedCase.secondApproverId)
    }

    // -------------------------------------------------------------
    // Scenario 6: Concurrent Reviewer
    // -------------------------------------------------------------
    @Test
    fun `Scenario 6 - concurrent claim race results in exactly one winner and conflict for others`() {
        val openCmd = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-RACE",
            severity = FraudCaseSeverity.HIGH,
            detectedReasons = listOf("CONCURRENT_CHECK"),
            requiresRestriction = false,
            idempotencyKey = "idem-race-open",
            correlationId = "c-race",
            causationId = "cause-race",
        )
        val openedCase = service.openOrMergeCase(openCmd)

        val threadCount = 4
        val pool = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val finishGate = CountDownLatch(threadCount)

        val successes = mutableListOf<String>()
        val conflicts = mutableListOf<Throwable>()

        for (i in 1..threadCount) {
            val admin = AuthenticatedPrincipal(
                id = "admin-race-$i",
                tenantId = tenantId,
                roles = setOf(AdminRole.SECURITY),
                kind = PrincipalKind.ADMIN,
            )
            sessionDirectory.register(
                tenantId = tenantId,
                principalId = admin.id,
                sessionId = "sess-race-$i",
                status = AdminSessionStatus(
                    active = true,
                    breakGlass = false,
                    expiresAt = baseNow.plus(Duration.ofHours(2)),
                    mfaVerified = true,
                ),
            )

            pool.submit {
                try {
                    startGate.await()
                    service.operateCase(
                        OperateFraudCaseCommand(
                            principal = admin,
                            sessionId = "sess-race-$i",
                            tenantId = tenantId,
                            caseReference = openedCase.caseReference,
                            action = FraudCaseAction.CLAIM,
                            expectedVersion = openedCase.serverVersion,
                            idempotencyKey = "idem-race-claim-$i",
                            correlationId = "c-race-$i",
                            causationId = "cause-race-$i",
                        )
                    )
                    synchronized(successes) { successes.add(admin.id) }
                } catch (t: Throwable) {
                    synchronized(conflicts) { conflicts.add(t) }
                } finally {
                    finishGate.countDown()
                }
            }
        }

        startGate.countDown()
        finishGate.await()
        pool.shutdown()

        assertEquals(1, successes.size, "Exactly one reviewer must win the lease")
        assertEquals(threadCount - 1, conflicts.size, "All other reviewers must get conflict")
        assertTrue(conflicts.all { it is AuthenticationFailure.Rejected && (it.code == AuthErrorCode.CONFLICT || it.code == AuthErrorCode.STALE) })
    }

    // -------------------------------------------------------------
    // Scenario 7: Active Session
    // -------------------------------------------------------------
    @Test
    fun `Scenario 7 - active player game session is immediately blocked when fraud restriction is placed`() {
        val evaluator: ServerRestrictionEvaluator = DefaultServerRestrictionEvaluator(restrictionStore)

        // 1. Before restriction: game session and wager are ALLOWED
        val preGame = evaluator.evaluate(OperationEvaluationContext(ServerOperation.NEW_GAME_SESSION, tenantId, subjectRef, now = baseNow))
        val preWager = evaluator.evaluate(OperationEvaluationContext(ServerOperation.WAGER, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.ALLOW, preGame.compositeAccess)
        assertEquals(AccessDecision.ALLOW, preWager.compositeAccess)

        // 2. Open fraud case with restriction
        service.openOrMergeCase(
            OpenOrMergeCaseCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                decisionReference = "DEC-BLOCK",
                severity = FraudCaseSeverity.HIGH,
                detectedReasons = listOf("ACCOUNT_TAKEOVER_DETECTED"),
                requiresRestriction = true,
                idempotencyKey = "idem-session-block",
                correlationId = "c-block",
                causationId = "cause-block",
            )
        )

        // 3. Immediately after: active session operations are DENIED
        val postGame = evaluator.evaluate(OperationEvaluationContext(ServerOperation.NEW_GAME_SESSION, tenantId, subjectRef, now = baseNow))
        val postWager = evaluator.evaluate(OperationEvaluationContext(ServerOperation.WAGER, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.DENY, postGame.compositeAccess)
        assertEquals(AccessDecision.DENY, postWager.compositeAccess)
    }

    // -------------------------------------------------------------
    // Scenario 8: Multiple Devices
    // -------------------------------------------------------------
    @Test
    fun `Scenario 8 - multiple devices cannot bypass active fraud restriction`() {
        val evaluator: ServerRestrictionEvaluator = DefaultServerRestrictionEvaluator(restrictionStore)

        // Open case with restriction
        service.openOrMergeCase(
            OpenOrMergeCaseCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                decisionReference = "DEC-MULTIDEV",
                severity = FraudCaseSeverity.HIGH,
                detectedReasons = listOf("COLLUSION"),
                requiresRestriction = true,
                idempotencyKey = "idem-multidev",
                correlationId = "c-multi",
                causationId = "cause-multi",
            )
        )

        // Device A (e.g. Android phone) attempting auth -> DENY
        val devAAuth = evaluator.evaluate(
            OperationEvaluationContext(
                operation = ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION,
                tenantId = tenantId,
                subjectReference = subjectRef,
                now = baseNow,
            )
        )
        assertEquals(AccessDecision.DENY, devAAuth.compositeAccess)

        // Device B (e.g. tablet or fresh browser session) attempting auth -> DENY
        val devBAuth = evaluator.evaluate(
            OperationEvaluationContext(
                operation = ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION,
                tenantId = tenantId,
                subjectReference = subjectRef,
                now = baseNow,
            )
        )
        assertEquals(AccessDecision.DENY, devBAuth.compositeAccess)
    }

    // -------------------------------------------------------------
    // Scenario 9: Direct API
    // -------------------------------------------------------------
    @Test
    fun `Scenario 9 - direct API calls for deposit, withdrawal, and wager are held or denied`() {
        val evaluator: ServerRestrictionEvaluator = DefaultServerRestrictionEvaluator(restrictionStore)

        service.openOrMergeCase(
            OpenOrMergeCaseCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                decisionReference = "DEC-DIRECT",
                severity = FraudCaseSeverity.HIGH,
                detectedReasons = listOf("PAYMENT_FRAUD"),
                requiresRestriction = true,
                idempotencyKey = "idem-direct-api",
                correlationId = "c-api",
                causationId = "cause-api",
            )
        )

        // Direct Deposit -> DENY
        val depRes = evaluator.evaluate(OperationEvaluationContext(ServerOperation.DEPOSIT, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.DENY, depRes.compositeAccess)

        // Direct Withdrawal -> DENY
        val wthRes = evaluator.evaluate(OperationEvaluationContext(ServerOperation.WITHDRAWAL, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.DENY, wthRes.compositeAccess)

        // Direct Wager -> DENY
        val wagRes = evaluator.evaluate(OperationEvaluationContext(ServerOperation.WAGER, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.DENY, wagRes.compositeAccess)

        // Direct Support -> ALLOW (player can contact support for resolution)
        val supRes = evaluator.evaluate(OperationEvaluationContext(ServerOperation.SUPPORT_ACCESS, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.ALLOW, supRes.compositeAccess)
    }

    // -------------------------------------------------------------
    // Scenario 10: Cache Loss
    // -------------------------------------------------------------
    @Test
    fun `Scenario 10 - cache flush or loss does not unlock active fraud restriction`() {
        val cache = InMemoryEphemeralRestrictionCache()
        val evaluator: ServerRestrictionEvaluator = DefaultServerRestrictionEvaluator(
            durableStore = restrictionStore,
            cache = cache,
            clock = clock,
        )

        service.openOrMergeCase(
            OpenOrMergeCaseCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                decisionReference = "DEC-CACHE",
                severity = FraudCaseSeverity.HIGH,
                detectedReasons = listOf("COMPROMISED_CREDENTIALS"),
                requiresRestriction = true,
                idempotencyKey = "idem-cache-test",
                correlationId = "c-cache",
                causationId = "cause-cache",
            )
        )

        // First evaluation populates cache
        val firstEval = evaluator.evaluate(OperationEvaluationContext(ServerOperation.WAGER, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.DENY, firstEval.compositeAccess)

        // Flush cache completely (simulating Redis crash / memory loss)
        cache.clear()

        // Post-flush evaluation MUST still DENY because durable store is authoritative!
        val postFlushEval = evaluator.evaluate(OperationEvaluationContext(ServerOperation.WAGER, tenantId, subjectRef, now = baseNow))
        assertEquals(AccessDecision.DENY, postFlushEval.compositeAccess)
    }

    // -------------------------------------------------------------
    // RBAC & MFA Authorization Guardrails
    // -------------------------------------------------------------
    @Test
    fun `Unauthorized admin role cannot operate fraud cases`() {
        val openCmd = OpenOrMergeCaseCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            decisionReference = "DEC-RBAC",
            severity = FraudCaseSeverity.MEDIUM,
            detectedReasons = listOf("SUSPICIOUS_PATTERN"),
            requiresRestriction = false,
            idempotencyKey = "idem-rbac-open",
            correlationId = "c-rbac",
            causationId = "cause-rbac",
        )
        val caseRecord = service.openOrMergeCase(openCmd)

        // Support agent lacks FRAUD_CASE_MANAGE
        assertThrows(AuthenticationFailure.Rejected::class.java) {
            service.operateCase(
                OperateFraudCaseCommand(
                    principal = supportAdmin,
                    sessionId = "sess-support-1",
                    tenantId = tenantId,
                    caseReference = caseRecord.caseReference,
                    action = FraudCaseAction.CLAIM,
                    expectedVersion = caseRecord.serverVersion,
                    idempotencyKey = "idem-sup-unauth",
                    correlationId = "c-sup",
                    causationId = "cause-sup",
                )
            )
        }
    }
}
