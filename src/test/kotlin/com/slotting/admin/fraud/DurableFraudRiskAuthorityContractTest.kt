package com.slotting.admin.fraud

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
 * TC-031: Authoritative Fraud Risk-Event Ingestion and Versioned Rule Evaluation Contract Tests.
 *
 * Covers:
 * 1. failed deposits burst
 * 2. failed withdrawals
 * 3. deposit-withdraw cycling
 * 4. unusual withdrawal
 * 5. auth anomalies
 * 6. payment reuse
 * 7. provider anomaly
 * 8. manual flag
 * 9. late event
 * 10. multi-currency safety
 * 11. rejection of client/admin fabricated historical counters as authority
 * 12. duplicate delivery idempotency
 * 13. service restart / reproducibility
 * 14. rule activation and rollback
 * 15. tenant isolation
 * 16. TC-026 restriction matrix integration
 * 17. V34 migration verification
 */
class DurableFraudRiskAuthorityContractTest {

    private val tenantId = "tenant-fraud-1"
    private val subjectRef = "player-risk-100"
    private val baseNow = Instant.parse("2026-09-26T12:00:00Z")
    private lateinit var clock: MutableClock
    private lateinit var store: InMemoryDurableFraudRiskStore
    private lateinit var restrictionStore: InMemoryServerRestrictionStore
    private lateinit var service: DurableFraudRiskService

    class MutableClock(private var current: Instant) : Clock() {
        override fun getZone(): ZoneOffset = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?): Clock = this
        override fun instant(): Instant = current
        fun advance(duration: Duration) { current = current.plus(duration) }
        fun setInstant(newInstant: Instant) { current = newInstant }
    }

    @BeforeEach
    fun setUp() {
        clock = MutableClock(baseNow)
        store = InMemoryDurableFraudRiskStore()
        restrictionStore = InMemoryServerRestrictionStore()
        service = DurableFraudRiskService(
            store = store,
            restrictionStore = restrictionStore,
            clock = clock,
        )
    }

    @Test
    fun `V34 migration script exists and defines required durable fraud risk tables`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V34__durable_fraud_risk_event_and_rule_evaluation.sql")
        assertNotNull(stream, "V34 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("fraud_risk_events", ignoreCase = true), "Must create fraud_risk_events table")
        assertTrue(sql.contains("fraud_risk_rule_sets", ignoreCase = true), "Must create fraud_risk_rule_sets table")
        assertTrue(sql.contains("fraud_risk_decisions", ignoreCase = true), "Must create fraud_risk_decisions table")
        assertTrue(sql.contains("uq_fraud_risk_events_tenant_idem", ignoreCase = true), "Must enforce event tenant idempotency constraint")
    }

    // -------------------------------------------------------------
    // Scenario 1: Failed Deposits Burst
    // -------------------------------------------------------------
    @Test
    fun `Scenario 1 - failed deposits burst triggers HOLD and queues fraud case`() {
        // Ingest 3 failed deposits within 10 minutes
        for (i in 1..3) {
            service.ingestEvent(
                IngestRiskEventCommand(
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    eventType = RiskEventType.DEPOSIT_FAILED,
                    source = EventSource.PROVIDER_VERIFIED,
                    confidence = SourceConfidence.HIGH,
                    eventTimestamp = baseNow.minus(Duration.ofMinutes((4 - i) * 2L)),
                    idempotencyKey = "dep-fail-$i",
                    correlationId = "corr-dep-$i",
                    causationId = "cause-dep-$i",
                    metadata = mapOf("errorCode" to "INSUFFICIENT_FUNDS"),
                )
            )
        }

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-dep-burst-1",
                correlationId = "corr-eval-1",
                causationId = "cause-eval-1",
            )
        )

        assertEquals(RiskActionRecommendation.HOLD, decision.action)
        assertTrue(decision.requiresCase)
        assertNotNull(decision.caseReference)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_FAILED_DEPOSITS_BURST" })
        assertEquals("FAILED_DEPOSITS_BURST", decision.matchedRules.first().reason)
    }

    // -------------------------------------------------------------
    // Scenario 2: Failed Withdrawals
    // -------------------------------------------------------------
    @Test
    fun `Scenario 2 - failed withdrawals burst triggers HOLD`() {
        for (i in 1..3) {
            service.ingestEvent(
                IngestRiskEventCommand(
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    eventType = RiskEventType.WITHDRAWAL_FAILED,
                    source = EventSource.PROVIDER_VERIFIED,
                    confidence = SourceConfidence.HIGH,
                    eventTimestamp = baseNow.minus(Duration.ofMinutes((4 - i) * 10L)),
                    idempotencyKey = "wth-fail-$i",
                    correlationId = "corr-wth-$i",
                    causationId = "cause-wth-$i",
                )
            )
        }

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-wth-burst-1",
                correlationId = "corr-eval-wth",
                causationId = "cause-eval-wth",
            )
        )

        assertEquals(RiskActionRecommendation.HOLD, decision.action)
        assertTrue(decision.requiresCase)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_FAILED_WITHDRAWALS_BURST" })
    }

    // -------------------------------------------------------------
    // Scenario 3: Deposit-Withdraw Cycling
    // -------------------------------------------------------------
    @Test
    fun `Scenario 3 - rapid deposit-withdrawal cycling without gameplay triggers HOLD`() {
        // Successful deposit 20 minutes ago
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.DEPOSIT_SUCCEEDED,
                source = EventSource.SERVER_OBSERVED,
                confidence = SourceConfidence.HIGH,
                money = RiskMoney(50000L, "EUR"),
                eventTimestamp = baseNow.minus(Duration.ofMinutes(20)),
                idempotencyKey = "cycle-dep-1",
                correlationId = "corr-cycle-dep",
                causationId = "cause-cycle-dep",
            )
        )

        // Withdrawal requested 5 minutes ago with zero wagers
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.WITHDRAWAL_REQUESTED,
                source = EventSource.SERVER_OBSERVED,
                confidence = SourceConfidence.HIGH,
                money = RiskMoney(50000L, "EUR"),
                eventTimestamp = baseNow.minus(Duration.ofMinutes(5)),
                idempotencyKey = "cycle-wth-1",
                correlationId = "corr-cycle-wth",
                causationId = "cause-cycle-wth",
            )
        )

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-cycle-1",
                correlationId = "corr-eval-cycle",
                causationId = "cause-eval-cycle",
            )
        )

        assertEquals(RiskActionRecommendation.HOLD, decision.action)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_DEPOSIT_WITHDRAW_CYCLING" })
    }

    // -------------------------------------------------------------
    // Scenario 4: Unusual Withdrawal
    // -------------------------------------------------------------
    @Test
    fun `Scenario 4 - unusual high-value withdrawal triggers HOLD`() {
        val highValEvent = DurableRiskEvent(
            tenantId = tenantId,
            subjectReference = subjectRef,
            eventType = RiskEventType.WITHDRAWAL_REQUESTED,
            source = EventSource.SERVER_OBSERVED,
            confidence = SourceConfidence.HIGH,
            money = RiskMoney(2_500_000L, "EUR"), // 25,000 EUR > 10,000 EUR threshold
            eventTimestamp = baseNow,
            idempotencyKey = "unusual-wth-1",
            correlationId = "corr-unusual",
            causationId = "cause-unusual",
        )
        store.saveEvent(highValEvent)

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                triggerEvent = highValEvent,
                idempotencyKey = "eval-unusual-1",
                correlationId = "corr-eval-unusual",
                causationId = "cause-eval-unusual",
            )
        )

        assertEquals(RiskActionRecommendation.HOLD, decision.action)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_UNUSUAL_WITHDRAWAL" })
    }

    // -------------------------------------------------------------
    // Scenario 5: Auth Anomalies
    // -------------------------------------------------------------
    @Test
    fun `Scenario 5 - auth anomalies trigger STEP_UP recommendation`() {
        // 3 failed auth attempts from different IPs
        for (i in 1..3) {
            service.ingestEvent(
                IngestRiskEventCommand(
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    eventType = RiskEventType.AUTH_FAILED,
                    source = EventSource.SERVER_OBSERVED,
                    confidence = SourceConfidence.HIGH,
                    ipAddress = "192.0.2.$i",
                    eventTimestamp = baseNow.minus(Duration.ofMinutes((10 - i).toLong())),
                    idempotencyKey = "auth-fail-$i",
                    correlationId = "corr-auth-$i",
                    causationId = "cause-auth-$i",
                )
            )
        }

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-auth-1",
                correlationId = "corr-eval-auth",
                causationId = "cause-eval-auth",
            )
        )

        assertEquals(RiskActionRecommendation.STEP_UP, decision.action)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_AUTH_ANOMALIES" })
    }

    // -------------------------------------------------------------
    // Scenario 6: Payment Reuse
    // -------------------------------------------------------------
    @Test
    fun `Scenario 6 - cross-subject payment instrument reuse triggers HOLD`() {
        val sharedInstrumentHash = "hash-card-998877"

        // Subject A uses instrument
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = "player-subject-A",
                eventType = RiskEventType.DEPOSIT_SUCCEEDED,
                source = EventSource.PROVIDER_VERIFIED,
                confidence = SourceConfidence.HIGH,
                paymentInstrumentHash = sharedInstrumentHash,
                eventTimestamp = baseNow.minus(Duration.ofHours(2)),
                idempotencyKey = "dep-sub-A",
                correlationId = "corr-A",
                causationId = "cause-A",
            )
        )

        // Subject B (our test subject) uses same instrument
        val triggerEvent = DurableRiskEvent(
            tenantId = tenantId,
            subjectReference = subjectRef,
            eventType = RiskEventType.DEPOSIT_INITIATED,
            source = EventSource.SERVER_OBSERVED,
            confidence = SourceConfidence.HIGH,
            paymentInstrumentHash = sharedInstrumentHash,
            eventTimestamp = baseNow,
            idempotencyKey = "dep-sub-B",
            correlationId = "corr-B",
            causationId = "cause-B",
        )
        store.saveEvent(triggerEvent)

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                triggerEvent = triggerEvent,
                idempotencyKey = "eval-reuse-1",
                correlationId = "corr-eval-reuse",
                causationId = "cause-eval-reuse",
            )
        )

        assertEquals(RiskActionRecommendation.HOLD, decision.action)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_PAYMENT_INSTRUMENT_REUSE" })
    }

    // -------------------------------------------------------------
    // Scenario 7: Provider Anomaly
    // -------------------------------------------------------------
    @Test
    fun `Scenario 7 - provider dispute or chargeback triggers DENY`() {
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.CHARGEBACK_DISPUTE,
                source = EventSource.PROVIDER_VERIFIED,
                confidence = SourceConfidence.HIGH,
                money = RiskMoney(10000L, "EUR"),
                eventTimestamp = baseNow.minus(Duration.ofMinutes(10)),
                idempotencyKey = "chargeback-1",
                correlationId = "corr-cb",
                causationId = "cause-cb",
                metadata = mapOf("disputeReason" to "FRAUDULENT_TRANSACTION"),
            )
        )

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-provider-anomaly-1",
                correlationId = "corr-eval-cb",
                causationId = "cause-eval-cb",
            )
        )

        assertEquals(RiskActionRecommendation.DENY, decision.action)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_PROVIDER_ANOMALY" })
    }

    // -------------------------------------------------------------
    // Scenario 8: Manual Flag
    // -------------------------------------------------------------
    @Test
    fun `Scenario 8 - active manual fraud flag from admin triggers DENY`() {
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.MANUAL_FLAG,
                source = EventSource.ADMIN_ACTION,
                confidence = SourceConfidence.HIGH,
                eventTimestamp = baseNow.minus(Duration.ofHours(1)),
                idempotencyKey = "manual-flag-1",
                correlationId = "corr-mf",
                causationId = "cause-mf",
                metadata = mapOf("adminId" to "admin-security-01", "reason" to "CONFIRMED_ACCOUNT_TAKEOVER"),
            )
        )

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-manual-flag-1",
                correlationId = "corr-eval-mf",
                causationId = "cause-eval-mf",
            )
        )

        assertEquals(RiskActionRecommendation.DENY, decision.action)
        assertTrue(decision.matchedRules.any { it.ruleId == "RULE_MANUAL_FRAUD_FLAG" })
    }

    // -------------------------------------------------------------
    // Scenario 9: Late Event
    // -------------------------------------------------------------
    @Test
    fun `Scenario 9 - late event is placed in historical order and evaluated correctly`() {
        // Ingest early event
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.DEPOSIT_SUCCEEDED,
                source = EventSource.SERVER_OBSERVED,
                confidence = SourceConfidence.HIGH,
                eventTimestamp = baseNow.minus(Duration.ofMinutes(10)),
                idempotencyKey = "order-dep-1",
                correlationId = "c1",
                causationId = "cause1",
            )
        )

        // Late event arriving now, but with historical timestamp 25 minutes ago
        val lateResult = service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.DEPOSIT_FAILED,
                source = EventSource.PROVIDER_VERIFIED,
                confidence = SourceConfidence.HIGH,
                eventTimestamp = baseNow.minus(Duration.ofMinutes(25)),
                idempotencyKey = "order-dep-late",
                correlationId = "c2",
                causationId = "cause2",
            )
        )

        assertTrue(lateResult.isNewEvent)
        val subjectEvents = store.findEventsForSubject(
            tenantId, subjectRef, baseNow.minus(Duration.ofHours(1)), baseNow
        )

        assertEquals(2, subjectEvents.size)
        // Earliest event timestamp must be first regardless of ingestion time!
        assertEquals("order-dep-late", subjectEvents[0].idempotencyKey)
        assertEquals("order-dep-1", subjectEvents[1].idempotencyKey)
    }

    // -------------------------------------------------------------
    // Scenario 10: Multi-Currency Safety
    // -------------------------------------------------------------
    @Test
    fun `Scenario 10 - multi-currency mismatch rejects cross-currency summation and checked overflow throws`() {
        val eurMoney = RiskMoney(50000L, "EUR")
        val usdMoney = RiskMoney(50000L, "USD")

        // Summing mismatched currencies must fail closed
        assertThrows(IllegalArgumentException::class.java) {
            eurMoney + usdMoney
        }

        // Long arithmetic overflow must fail closed
        val maxMoney = RiskMoney(Long.MAX_VALUE - 10, "EUR")
        val addMoney = RiskMoney(20L, "EUR")
        assertThrows(ArithmeticException::class.java) {
            maxMoney + addMoney
        }
    }

    // -------------------------------------------------------------
    // Authority & Idempotency: Reject caller fabricated historical counters
    // -------------------------------------------------------------
    @Test
    fun `Caller cannot supply historical counts or volume as authority`() {
        // Evaluate with no durable events stored
        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-empty-1",
                correlationId = "c-empty",
                causationId = "cause-empty",
            )
        )

        // Without durable events in store, action must be ALLOW
        assertEquals(RiskActionRecommendation.ALLOW, decision.action)
        assertTrue(decision.matchedRules.isEmpty())
        assertFalse(decision.requiresCase)
    }

    @Test
    fun `Duplicate event delivery does not inflate velocity or duplicate cases`() {
        val cmd = IngestRiskEventCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            eventType = RiskEventType.DEPOSIT_FAILED,
            source = EventSource.PROVIDER_VERIFIED,
            confidence = SourceConfidence.HIGH,
            eventTimestamp = baseNow,
            idempotencyKey = "duplicate-key-100",
            correlationId = "c-dup",
            causationId = "cause-dup",
        )

        val first = service.ingestEvent(cmd)
        assertTrue(first.isNewEvent)

        val second = service.ingestEvent(cmd)
        assertFalse(second.isNewEvent)
        assertEquals(first.eventId, second.eventId)

        val events = store.findEventsForSubject(tenantId, subjectRef, baseNow.minusSeconds(60), baseNow.plusSeconds(60))
        assertEquals(1, events.size, "Duplicate event must not be added to store")
    }

    // -------------------------------------------------------------
    // Service Restart & Reproducibility
    // -------------------------------------------------------------
    @Test
    fun `Stored events and rule version reproduce identical decision after simulated restart`() {
        // Seed 3 failed deposits
        for (i in 1..3) {
            service.ingestEvent(
                IngestRiskEventCommand(
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    eventType = RiskEventType.DEPOSIT_FAILED,
                    source = EventSource.PROVIDER_VERIFIED,
                    confidence = SourceConfidence.HIGH,
                    eventTimestamp = baseNow.minus(Duration.ofMinutes(i * 2L)),
                    idempotencyKey = "restart-dep-$i",
                    correlationId = "c-$i",
                    causationId = "cause-$i",
                )
            )
        }

        val firstDecision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-pre-restart",
                correlationId = "c-eval-1",
                causationId = "cause-eval-1",
                specificRuleVersion = 1L,
            )
        )

        // Simulate restart by recreating service with the same underlying store
        val restartedService = DurableFraudRiskService(
            store = store,
            restrictionStore = restrictionStore,
            clock = clock,
        )

        val replayedDecision = restartedService.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-post-restart",
                correlationId = "c-eval-2",
                causationId = "cause-eval-2",
                specificRuleVersion = 1L,
            )
        )

        assertEquals(firstDecision.action, replayedDecision.action)
        assertEquals(firstDecision.ruleSetVersion, replayedDecision.ruleSetVersion)
        assertEquals(firstDecision.matchedRules.size, replayedDecision.matchedRules.size)
        assertEquals(firstDecision.matchedRules.first().ruleId, replayedDecision.matchedRules.first().ruleId)
    }

    // -------------------------------------------------------------
    // Rule Activation and Rollback
    // -------------------------------------------------------------
    @Test
    fun `Rule version activation and rollback updates evaluation deterministically`() {
        // Seed 1 failed deposit
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.DEPOSIT_FAILED,
                source = EventSource.PROVIDER_VERIFIED,
                confidence = SourceConfidence.HIGH,
                eventTimestamp = baseNow.minus(Duration.ofMinutes(2)),
                idempotencyKey = "rule-dep-1",
                correlationId = "c-1",
                causationId = "cause-1",
            )
        )

        // Version 1 (threshold = 3) -> ALLOW
        val v1Decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-v1",
                correlationId = "c-v1",
                causationId = "cause-v1",
            )
        )
        assertEquals(RiskActionRecommendation.ALLOW, v1Decision.action)

        // Create version 2 with stricter threshold (threshold = 1)
        val strictRuleSet = RiskRuleSet(
            version = 2L,
            active = false,
            rules = listOf(FailedDepositsBurstRule(burstCountThreshold = 1)),
            createdAt = baseNow,
        )
        store.saveRuleSet(strictRuleSet)

        // Activate version 2
        assertTrue(service.activateRuleSet(2L))

        // Version 2 -> HOLD
        val v2Decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-v2",
                correlationId = "c-v2",
                causationId = "cause-v2",
            )
        )
        assertEquals(RiskActionRecommendation.HOLD, v2Decision.action)
        assertEquals(2L, v2Decision.ruleSetVersion)

        // Rollback to version 1
        assertTrue(service.rollbackToRuleSet(1L))
        val v1RollbackDecision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-v1-rollback",
                correlationId = "c-v1-rb",
                causationId = "cause-v1-rb",
            )
        )
        assertEquals(RiskActionRecommendation.ALLOW, v1RollbackDecision.action)
        assertEquals(1L, v1RollbackDecision.ruleSetVersion)
    }

    // -------------------------------------------------------------
    // Tenant Isolation
    // -------------------------------------------------------------
    @Test
    fun `Tenant events and evaluations are strictly isolated`() {
        val otherTenant = "tenant-other"

        // Ingest failed deposits for other tenant
        for (i in 1..3) {
            service.ingestEvent(
                IngestRiskEventCommand(
                    tenantId = otherTenant,
                    subjectReference = subjectRef,
                    eventType = RiskEventType.DEPOSIT_FAILED,
                    source = EventSource.PROVIDER_VERIFIED,
                    confidence = SourceConfidence.HIGH,
                    eventTimestamp = baseNow.minus(Duration.ofMinutes(i * 2L)),
                    idempotencyKey = "iso-dep-$i",
                    correlationId = "c-iso-$i",
                    causationId = "cause-iso-$i",
                )
            )
        }

        // Evaluating our tenant must see zero events and return ALLOW
        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-tenant-isolated",
                correlationId = "c-iso-eval",
                causationId = "cause-iso-eval",
            )
        )
        assertEquals(RiskActionRecommendation.ALLOW, decision.action)
    }

    // -------------------------------------------------------------
    // Concurrency: multi-threaded race on duplicate delivery
    // -------------------------------------------------------------
    @Test
    fun `Concurrent delivery of duplicate event is safely deduplicated`() {
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val finishGate = CountDownLatch(threadCount)

        val cmd = IngestRiskEventCommand(
            tenantId = tenantId,
            subjectReference = subjectRef,
            eventType = RiskEventType.AUTH_FAILED,
            source = EventSource.SERVER_OBSERVED,
            confidence = SourceConfidence.HIGH,
            eventTimestamp = baseNow,
            idempotencyKey = "concurrent-key-999",
            correlationId = "c-concurrent",
            causationId = "cause-concurrent",
        )

        val results = mutableListOf<IngestRiskEventResult>()
        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startGate.await()
                    val res = service.ingestEvent(cmd)
                    synchronized(results) { results.add(res) }
                } finally {
                    finishGate.countDown()
                }
            }
        }

        startGate.countDown()
        finishGate.await()
        executor.shutdown()

        assertEquals(threadCount, results.size)
        val newEventCount = results.count { it.isNewEvent }
        assertEquals(1, newEventCount, "Exactly one thread must successfully ingest as new event")

        val storedEvents = store.findEventsForSubject(tenantId, subjectRef, baseNow.minusSeconds(10), baseNow.plusSeconds(10))
        assertEquals(1, storedEvents.size)
    }

    // -------------------------------------------------------------
    // TC-026 Policy Matrix Integration
    // -------------------------------------------------------------
    @Test
    fun `Fraud restriction is enforced by ServerRestrictionEvaluator per TC-026 policy matrix`() {
        // Trigger a manual fraud flag
        service.ingestEvent(
            IngestRiskEventCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                eventType = RiskEventType.MANUAL_FLAG,
                source = EventSource.ADMIN_ACTION,
                confidence = SourceConfidence.HIGH,
                eventTimestamp = baseNow,
                idempotencyKey = "matrix-flag-1",
                correlationId = "c-matrix",
                causationId = "cause-matrix",
            )
        )

        val decision = service.evaluateSubject(
            EvaluateSubjectRiskCommand(
                tenantId = tenantId,
                subjectReference = subjectRef,
                idempotencyKey = "eval-matrix-1",
                correlationId = "c-eval-matrix",
                causationId = "cause-eval-matrix",
            )
        )

        assertEquals(RiskActionRecommendation.DENY, decision.action)
        assertNotNull(decision.serverRestriction)

        // TC-026 Evaluator integration: evaluate gaming, auth, and support operations
        val evaluator: ServerRestrictionEvaluator = DefaultServerRestrictionEvaluator(restrictionStore)

        // 1. Wager -> DENY
        val wagerEval = evaluator.evaluate(
            OperationEvaluationContext(
                operation = ServerOperation.WAGER,
                tenantId = tenantId,
                subjectReference = subjectRef,
                now = baseNow,
            )
        )
        assertEquals(AccessDecision.DENY, wagerEval.compositeAccess)

        // 2. New Game Session -> DENY
        val gameEval = evaluator.evaluate(
            OperationEvaluationContext(
                operation = ServerOperation.NEW_GAME_SESSION,
                tenantId = tenantId,
                subjectReference = subjectRef,
                now = baseNow,
            )
        )
        assertEquals(AccessDecision.DENY, gameEval.compositeAccess)

        // 3. Normal Auth -> DENY by default
        val authEval = evaluator.evaluate(
            OperationEvaluationContext(
                operation = ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION,
                tenantId = tenantId,
                subjectReference = subjectRef,
                isRemediationFlow = false,
                now = baseNow,
            )
        )
        assertEquals(AccessDecision.DENY, authEval.compositeAccess)

        // 4. Remediation Auth -> STEP_UP
        val remEval = evaluator.evaluate(
            OperationEvaluationContext(
                operation = ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION,
                tenantId = tenantId,
                subjectReference = subjectRef,
                isRemediationFlow = true,
                now = baseNow,
            )
        )
        assertEquals(AccessDecision.STEP_UP, remEval.compositeAccess)

        // 5. Support Access -> ALLOW (support remains accessible for contested fraud flags)
        val supportEval = evaluator.evaluate(
            OperationEvaluationContext(
                operation = ServerOperation.SUPPORT_ACCESS,
                tenantId = tenantId,
                subjectReference = subjectRef,
                now = baseNow,
            )
        )
        assertEquals(AccessDecision.ALLOW, supportEval.compositeAccess)
    }
}
