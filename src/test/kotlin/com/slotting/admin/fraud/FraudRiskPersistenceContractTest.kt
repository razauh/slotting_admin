package com.slotting.admin.fraud

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * Verifies V34 migration script and basic store contracts for durable fraud risk subsystem.
 */
class FraudRiskPersistenceContractTest {

    @Test
    fun `V34 migration script defines all required schema objects and idempotency constraints`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V34__durable_fraud_risk_event_and_rule_evaluation.sql")
        assertNotNull(stream, "V34 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("fraud_risk_events", ignoreCase = true))
        assertTrue(sql.contains("fraud_risk_rule_sets", ignoreCase = true))
        assertTrue(sql.contains("fraud_risk_decisions", ignoreCase = true))
        assertTrue(sql.contains("uq_fraud_risk_events_tenant_idem", ignoreCase = true))
        assertTrue(sql.contains("uq_fraud_risk_decisions_tenant_idem", ignoreCase = true))
        assertTrue(sql.contains("idx_fraud_risk_events_subject_time", ignoreCase = true))
        assertTrue(sql.contains("idx_fraud_risk_events_payment_instrument", ignoreCase = true))
    }

    @Test
    fun `Durable fraud store handles event, decision, and rule set CRUD`() {
        val store: DurableFraudRiskStore = InMemoryDurableFraudRiskStore()
        val now = Instant.parse("2026-09-26T12:00:00Z")
        val tenantId = "tenant-persist-1"
        val subject = "player-persist-1"

        // 1. Save and retrieve event
        val event = DurableRiskEvent(
            eventId = UUID.randomUUID(),
            tenantId = tenantId,
            subjectReference = subject,
            eventType = RiskEventType.DEPOSIT_SUCCEEDED,
            source = EventSource.SERVER_OBSERVED,
            confidence = SourceConfidence.HIGH,
            money = RiskMoney(10000L, "EUR"),
            eventTimestamp = now.minus(5, ChronoUnit.MINUTES),
            idempotencyKey = "idem-event-1",
            correlationId = "corr-1",
            causationId = "cause-1",
        )
        assertTrue(store.saveEvent(event))

        // Idempotency: duplicate save returns false
        assertFalse(store.saveEvent(event))

        val fetchedEvent = store.findEventByIdempotency(tenantId, "idem-event-1")
        assertNotNull(fetchedEvent)
        assertEquals(event.eventId, fetchedEvent?.eventId)

        // Find events in window
        val eventsInWindow = store.findEventsForSubject(
            tenantId, subject, now.minus(10, ChronoUnit.MINUTES), now
        )
        assertEquals(1, eventsInWindow.size)

        // 2. Save and retrieve decision
        val decision = RiskEvaluationDecision(
            decisionId = UUID.randomUUID(),
            tenantId = tenantId,
            subjectReference = subject,
            ruleSetVersion = 1L,
            action = RiskActionRecommendation.ALLOW,
            matchedRules = emptyList(),
            evidenceReference = "EVID-1",
            evaluatedAt = now,
            idempotencyKey = "idem-decision-1",
        )
        assertTrue(store.saveDecision(decision))
        assertFalse(store.saveDecision(decision))

        val fetchedDecision = store.findDecisionByIdempotency(tenantId, "idem-decision-1")
        assertNotNull(fetchedDecision)
        assertEquals(decision.decisionId, fetchedDecision?.decisionId)

        // 3. Rule set versioning and activation
        val ruleSetV1 = RiskRuleSet(
            version = 1L,
            active = true,
            rules = listOf(FailedDepositsBurstRule()),
            createdAt = now,
            activatedAt = now,
        )
        val ruleSetV2 = RiskRuleSet(
            version = 2L,
            active = false,
            rules = listOf(FailedDepositsBurstRule(burstCountThreshold = 1)),
            createdAt = now,
        )
        assertTrue(store.saveRuleSet(ruleSetV1))
        assertTrue(store.saveRuleSet(ruleSetV2))

        assertEquals(1L, store.findActiveRuleSet()?.version)

        assertTrue(store.activateRuleSet(2L, now.plus(1, ChronoUnit.MINUTES)))
        assertEquals(2L, store.findActiveRuleSet()?.version)
    }
}
