package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class FinancialRiskMonitoringTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `AML-001-02-T001 Monitor configurable financial risk rules produces the required authoritative outcome`() {
        val store = FinancialRiskMonitoringMemoryStore()
        val service = service(store)

        // 1. Single transaction limit breach -> must hold and queue AML review (HIGH_RISK_ACTION)
        val highRiskCmd = command(
            transactionReference = "tx-high-risk-001",
            amountMinorUnits = 1_500_000L, // 15,000 EUR > 10,000 EUR threshold
            idempotencyKey = "key-risk-eval-001",
            correlationId = "corr-risk-1",
            causationId = "cause-risk-1",
        )
        val highRiskRes = service.evaluateTransaction(highRiskCmd)

        // Assert: Thresholds are approved config; fail closed/hold policy explicit; decision provenance retained
        assertEquals(RuleEvaluationOutcome.BREACH_DETECTED, highRiskRes.outcome)
        assertEquals(RiskDecisionStatus.HOLD, highRiskRes.status)
        assertEquals(AmlReviewReason.HIGH_RISK_ACTION, highRiskRes.amlReason)
        assertNotNull(highRiskRes.amlCaseReference)
        assertFalse(highRiskRes.financialAuthorityCreated) // Outcome cannot create financial authority
        assertFalse(highRiskRes.moneyMutated)             // Cannot mutate money
        assertEquals("EVID-RISK-tx-high-risk-001", highRiskRes.evidenceReference)

        // Provenance assertions
        assertEquals(1L, highRiskRes.provenance.configVersion)
        assertEquals(1_500_000L, highRiskRes.provenance.evaluatedAmountMinorUnits)
        assertTrue(highRiskRes.provenance.breachedRules.contains("SINGLE_TRANSACTION_LIMIT_EXCEEDED"))

        // Assert: Atomic queue item in store
        val highRiskQueueItem = store.queuedItems[highRiskRes.amlCaseReference]
        assertNotNull(highRiskQueueItem)
        assertEquals(AmlReviewState.QUEUED, highRiskQueueItem.state)

        // 2. Structuring detection -> must hold and queue AML review (STRUCTURING_ALERT)
        val structuringCmd = command(
            transactionReference = "tx-structuring-001",
            amountMinorUnits = 950_000L, // 9,500 EUR in structuring window (9,000..9,999 EUR)
            idempotencyKey = "key-risk-struct-001",
        )
        val structRes = service.evaluateTransaction(structuringCmd)
        assertEquals(RuleEvaluationOutcome.BREACH_DETECTED, structRes.outcome)
        assertEquals(RiskDecisionStatus.HOLD, structRes.status)
        assertEquals(AmlReviewReason.STRUCTURING_ALERT, structRes.amlReason)
        assertTrue(structRes.provenance.breachedRules.contains("POTENTIAL_STRUCTURING_DETECTED"))

        // 3. Velocity limit breach -> must hold and queue AML review (SUSPICIOUS_ACTIVITY)
        val velocityCmd = command(
            transactionReference = "tx-velocity-001",
            amountMinorUnits = 100_000L,
            historicalCountInWindow = 6, // 6 transactions in window > 5 threshold
            idempotencyKey = "key-risk-vel-001",
        )
        val velRes = service.evaluateTransaction(velocityCmd)
        assertEquals(RuleEvaluationOutcome.BREACH_DETECTED, velRes.outcome)
        assertEquals(RiskDecisionStatus.HOLD, velRes.status)
        assertEquals(AmlReviewReason.SUSPICIOUS_ACTIVITY, velRes.amlReason)
        assertTrue(velRes.provenance.breachedRules.contains("VELOCITY_LIMIT_EXCEEDED"))

        // 4. Clean transaction within approved thresholds -> must be APPROVED with no case queued
        val cleanCmd = command(
            transactionReference = "tx-clean-001",
            amountMinorUnits = 50_000L,
            historicalCountInWindow = 1,
            historicalVolumeInWindowMinorUnits = 50_000L,
            idempotencyKey = "key-risk-clean-001",
        )
        val cleanRes = service.evaluateTransaction(cleanCmd)
        assertEquals(RuleEvaluationOutcome.CLEARED, cleanRes.outcome)
        assertEquals(RiskDecisionStatus.APPROVED, cleanRes.status)
        assertNull(cleanRes.amlCaseReference)

        // 5. Replay with identical idempotency key returns identical authoritative result
        val replay = service.evaluateTransaction(highRiskCmd)
        assertEquals(highRiskRes.resultId, replay.resultId)
        assertEquals(highRiskRes.evidenceReference, replay.evidenceReference)

        // Observability check
        assertEquals(4, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-risk-1", store.audit[0].correlationId)
        assertEquals("cause-risk-1", store.audit[0].causationId)
    }

    @Test
    fun `AML-001-02-T002 Monitor configurable financial risk rules rejects invalid, boundary, unauthorized, and stale input`() {
        val store = FinancialRiskMonitoringMemoryStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized role lacking MANAGE_SECURITY
        val supportAdmin = AuthenticatedPrincipal("admin-support", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(principal = supportAdmin, idempotencyKey = "key-support-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = FinancialRiskMonitoringService(AdminRbacPolicy(true), TestFinancialRiskExpiredSessionDirectory(), store, FinancialRiskRuleConfig(), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.evaluateTransaction(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(subjectReference = "   ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank transaction reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(transactionReference = "   ", idempotencyKey = "key-blank-tx"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Non-positive amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(amountMinorUnits = 0L, idempotencyKey = "key-zero-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid currency code
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(currencyCode = "US", idempotencyKey = "key-bad-curr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(expectedVersion = 3L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.evaluateTransaction(command(idempotencyKey = "key-conflict-risk"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateTransaction(command(amountMinorUnits = 888L, idempotencyKey = "key-conflict-risk"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `AML-001-02-T003 Monitor configurable financial risk rules survives concurrency, duplicate delivery, and dependency failure`() {
        val store = FinancialRiskMonitoringMemoryStore()
        val service = service(store)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-risk-001")
        val calls = (1..4).map {
            pool.submit<FinancialRiskEvaluationResult> {
                gate.await()
                service.evaluateTransaction(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingService = FinancialRiskMonitoringService(AdminRbacPolicy(true), TestFinancialRiskFailingSessionDirectory(), store, FinancialRiskRuleConfig(), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.evaluateTransaction(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `AML-001-02-T004 Monitor configurable financial risk rules remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: committed rows/constraints on admin_aml_review_queue in V8
        val migration = File("src/main/resources/db/migration/V8__aml_review_queue.sql").readText()
        assertTrue(migration.contains("admin_aml_review_queue"))
        assertTrue(migration.contains("admin_aml_review_result"))
        assertTrue(migration.contains("check (state in ('QUEUED','CLAIMED','APPROVED','REJECTED'))"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("balance"))

        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = FinancialRiskMonitoringMemoryStore()
        val service = service(store)

        val cmd = command(
            transactionReference = "tx-reboot-risk-001",
            amountMinorUnits = 1_200_000L,
            idempotencyKey = "key-reboot-risk",
            correlationId = "corr-reboot-risk-1",
            causationId = "cause-reboot-risk-1",
        )
        val first = service.evaluateTransaction(cmd)

        val restartedService = service(store)
        val second = restartedService.evaluateTransaction(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.financialAuthorityCreated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_FINANCIAL_RISK_EVALUATION", store.audit[0].type)
        assertEquals("corr-reboot-risk-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-risk-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: FinancialRiskMonitoringStore) =
        FinancialRiskMonitoringService(AdminRbacPolicy(true), TestFinancialRiskActiveSessionDirectory(), store, FinancialRiskRuleConfig(), clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-aml-risk-001",
        transactionReference: String = "tx-aml-risk-001",
        transactionType: RiskTransactionType = RiskTransactionType.DEPOSIT,
        amountMinorUnits: Long = 100_000L,
        currencyCode: String = "EUR",
        historicalCountInWindow: Int = 0,
        historicalVolumeInWindowMinorUnits: Long = 0L,
        idempotencyKey: String = "key-risk-cmd-001",
        correlationId: String = "corr-risk-default",
        causationId: String = "cause-risk-default",
        expectedVersion: Long = 1L,
    ) = FinancialRiskEvaluationCommand(
        principal = principal,
        sessionId = "session-risk-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        transactionReference = transactionReference,
        transactionType = transactionType,
        amountMinorUnits = amountMinorUnits,
        currencyCode = currencyCode,
        historicalCountInWindow = historicalCountInWindow,
        historicalVolumeInWindowMinorUnits = historicalVolumeInWindowMinorUnits,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-aml-risk-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-aml-risk-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestFinancialRiskActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-risk-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:00:00Z"))
        else null
}

private class TestFinancialRiskExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:00:00Z"))
}

private class TestFinancialRiskFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class FinancialRiskMonitoringMemoryStore : FinancialRiskMonitoringStore {
    val results = mutableMapOf<String, Pair<String, FinancialRiskEvaluationResult>>()
    val queuedItems = mutableMapOf<String, AmlQueueItem>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: FinancialRiskEvaluationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queuedAmlItem: AmlQueueItem?,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        queuedAmlItem?.let { queuedItems[it.caseReference] = it }
        this.audit += audit
        this.outbox += outbox
    }
}
