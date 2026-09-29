package com.slotting.admin.fraud

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

interface DurableFraudRiskStore {
    fun saveEvent(event: DurableRiskEvent): Boolean
    fun findEventByIdempotency(tenantId: String, idempotencyKey: String): DurableRiskEvent?
    fun findEventsForSubject(tenantId: String, subjectReference: String, fromTime: Instant, toTime: Instant): List<DurableRiskEvent>
    fun findEventsByPaymentInstrument(tenantId: String, paymentInstrumentHash: String, fromTime: Instant): List<DurableRiskEvent>
    fun saveDecision(decision: RiskEvaluationDecision): Boolean
    fun findDecisionByIdempotency(tenantId: String, idempotencyKey: String): RiskEvaluationDecision?
    fun saveRuleSet(ruleSet: RiskRuleSet): Boolean
    fun findRuleSet(version: Long): RiskRuleSet?
    fun findActiveRuleSet(): RiskRuleSet?
    fun activateRuleSet(version: Long, activatedAt: Instant): Boolean
}

class InMemoryDurableFraudRiskStore : DurableFraudRiskStore {
    val eventsByIdempotency = ConcurrentHashMap<String, DurableRiskEvent>()
    val events = mutableListOf<DurableRiskEvent>()
    val decisionsByIdempotency = ConcurrentHashMap<String, RiskEvaluationDecision>()
    val ruleSets = ConcurrentHashMap<Long, RiskRuleSet>()

    @Synchronized
    override fun saveEvent(event: DurableRiskEvent): Boolean {
        val key = "${event.tenantId}:${event.idempotencyKey}"
        if (eventsByIdempotency.putIfAbsent(key, event) != null) {
            return false
        }
        events.add(event)
        return true
    }

    override fun findEventByIdempotency(tenantId: String, idempotencyKey: String): DurableRiskEvent? =
        eventsByIdempotency["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun findEventsForSubject(
        tenantId: String,
        subjectReference: String,
        fromTime: Instant,
        toTime: Instant
    ): List<DurableRiskEvent> {
        return events.filter {
            it.tenantId == tenantId &&
                it.subjectReference == subjectReference &&
                !it.eventTimestamp.isBefore(fromTime) &&
                !it.eventTimestamp.isAfter(toTime)
        }.sortedBy { it.eventTimestamp }
    }

    @Synchronized
    override fun findEventsByPaymentInstrument(
        tenantId: String,
        paymentInstrumentHash: String,
        fromTime: Instant
    ): List<DurableRiskEvent> {
        return events.filter {
            it.tenantId == tenantId &&
                it.paymentInstrumentHash == paymentInstrumentHash &&
                !it.eventTimestamp.isBefore(fromTime)
        }.sortedBy { it.eventTimestamp }
    }

    @Synchronized
    override fun saveDecision(decision: RiskEvaluationDecision): Boolean {
        val key = "${decision.tenantId}:${decision.idempotencyKey}"
        return decisionsByIdempotency.putIfAbsent(key, decision) == null
    }

    override fun findDecisionByIdempotency(tenantId: String, idempotencyKey: String): RiskEvaluationDecision? =
        decisionsByIdempotency["$tenantId:$idempotencyKey"]

    @Synchronized
    override fun saveRuleSet(ruleSet: RiskRuleSet): Boolean {
        ruleSets[ruleSet.version] = ruleSet
        return true
    }

    override fun findRuleSet(version: Long): RiskRuleSet? = ruleSets[version]

    @Synchronized
    override fun findActiveRuleSet(): RiskRuleSet? =
        ruleSets.values.filter { it.active }.maxByOrNull { it.version }

    @Synchronized
    override fun activateRuleSet(version: Long, activatedAt: Instant): Boolean {
        val target = ruleSets[version] ?: return false
        // Deactivate all others
        ruleSets.keys.forEach { v ->
            val rs = ruleSets[v]!!
            ruleSets[v] = rs.copy(active = (v == version), activatedAt = if (v == version) activatedAt else rs.activatedAt)
        }
        return true
    }
}
