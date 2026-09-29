package com.slotting.admin.fraud

import java.util.concurrent.ConcurrentHashMap

interface FraudCaseStore {
    fun saveCase(caseRecord: FraudCaseRecord): Boolean
    fun findCaseByReference(tenantId: String, caseReference: String): FraudCaseRecord?
    fun findActiveCaseForSubject(tenantId: String, subjectReference: String): FraudCaseRecord?
    fun updateCaseWithCas(caseRecord: FraudCaseRecord, expectedVersion: Long): Boolean
    fun recordAction(actionRecord: FraudCaseActionRecord): Boolean
    fun findActionByIdempotency(tenantId: String, idempotencyKey: String): FraudCaseActionRecord?
    fun countActiveCases(tenantId: String): Long = 0L
}

class InMemoryFraudCaseStore : FraudCaseStore {
    val casesByRef = ConcurrentHashMap<String, FraudCaseRecord>()
    val actionsByIdempotency = ConcurrentHashMap<String, FraudCaseActionRecord>()

    override fun countActiveCases(tenantId: String): Long {
        val activeStates = setOf(
            FraudCaseState.OPEN,
            FraudCaseState.CLAIMED,
            FraudCaseState.EVIDENCE_REQUESTED,
            FraudCaseState.ESCALATED,
        )
        return casesByRef.values.count { it.tenantId == tenantId && it.state in activeStates }.toLong()
    }

    @Synchronized
    override fun saveCase(caseRecord: FraudCaseRecord): Boolean {
        val key = "${caseRecord.tenantId}:${caseRecord.caseReference}"
        if (casesByRef.putIfAbsent(key, caseRecord) != null) {
            return false
        }
        return true
    }

    override fun findCaseByReference(tenantId: String, caseReference: String): FraudCaseRecord? =
        casesByRef["$tenantId:$caseReference"]

    @Synchronized
    override fun findActiveCaseForSubject(tenantId: String, subjectReference: String): FraudCaseRecord? {
        val activeStates = setOf(
            FraudCaseState.OPEN,
            FraudCaseState.CLAIMED,
            FraudCaseState.EVIDENCE_REQUESTED,
            FraudCaseState.ESCALATED,
        )
        return casesByRef.values.find {
            it.tenantId == tenantId &&
                it.subjectReference == subjectReference &&
                it.state in activeStates
        }
    }

    @Synchronized
    override fun updateCaseWithCas(caseRecord: FraudCaseRecord, expectedVersion: Long): Boolean {
        val key = "${caseRecord.tenantId}:${caseRecord.caseReference}"
        val existing = casesByRef[key] ?: return false
        if (existing.serverVersion != expectedVersion) {
            return false
        }
        casesByRef[key] = caseRecord.copy(serverVersion = expectedVersion + 1)
        return true
    }

    @Synchronized
    override fun recordAction(actionRecord: FraudCaseActionRecord): Boolean {
        val key = "${actionRecord.tenantId}:${actionRecord.idempotencyKey}"
        return actionsByIdempotency.putIfAbsent(key, actionRecord) == null
    }

    override fun findActionByIdempotency(tenantId: String, idempotencyKey: String): FraudCaseActionRecord? =
        actionsByIdempotency["$tenantId:$idempotencyKey"]
}
