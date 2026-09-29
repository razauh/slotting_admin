package com.slotting.admin.fraud

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * Verifies V35 migration script and persistence contracts for durable fraud cases, actions, and dispositions (TC-032).
 */
class FraudCasePersistenceContractTest {

    @Test
    fun `V35 migration script defines all required schema objects, indexes, and idempotency constraints`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V35__durable_fraud_cases_and_dispositions.sql")
        assertNotNull(stream, "V35 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("fraud_cases", ignoreCase = true))
        assertTrue(sql.contains("fraud_case_actions", ignoreCase = true))
        assertTrue(sql.contains("uq_fraud_case_actions_tenant_idem", ignoreCase = true))
        assertTrue(sql.contains("idx_fraud_cases_subject_state", ignoreCase = true))
        assertTrue(sql.contains("idx_fraud_case_actions_case", ignoreCase = true))
        assertTrue(sql.contains("second_approver_id", ignoreCase = true))
        assertTrue(sql.contains("server_version", ignoreCase = true))
    }

    @Test
    fun `InMemoryFraudCaseStore satisfies case lifecycle, CAS versioning, and action idempotency contracts`() {
        val store: FraudCaseStore = InMemoryFraudCaseStore()
        val now = Instant.parse("2026-09-26T12:00:00Z")
        val tenantId = "tenant-persist-case"
        val subject = "player-persist-case-1"
        val caseRef = "CASE-PERSIST-001"

        // 1. Save and retrieve case
        val caseRecord = FraudCaseRecord(
            caseId = UUID.randomUUID(),
            tenantId = tenantId,
            subjectReference = subject,
            caseReference = caseRef,
            state = FraudCaseState.OPEN,
            severity = FraudCaseSeverity.HIGH,
            riskDecisionReferences = listOf("DEC-001"),
            detectedReasons = listOf("CHARGEBACK_ALERT"),
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )
        assertTrue(store.saveCase(caseRecord), "Initial save must succeed")
        assertFalse(store.saveCase(caseRecord), "Duplicate save must fail (idempotent / unique caseReference)")

        val fetchedCase = store.findCaseByReference(tenantId, caseRef)
        assertNotNull(fetchedCase)
        assertEquals(caseRecord.caseId, fetchedCase?.caseId)
        assertEquals(FraudCaseState.OPEN, fetchedCase?.state)
        assertEquals(1L, fetchedCase?.serverVersion)

        // Find active case for subject
        val activeCase = store.findActiveCaseForSubject(tenantId, subject)
        assertNotNull(activeCase)
        assertEquals(caseRef, activeCase?.caseReference)

        // 2. CAS Versioning Update
        // Wrong expectedVersion fails
        assertFalse(store.updateCaseWithCas(caseRecord.copy(state = FraudCaseState.CLAIMED), 999L), "Stale CAS update must fail")

        // Correct expectedVersion succeeds and increments version
        val updated = caseRecord.copy(
            state = FraudCaseState.CLAIMED,
            claimedBy = "admin-1",
            claimExpiresAt = now.plus(15, ChronoUnit.MINUTES),
            updatedAt = now.plus(1, ChronoUnit.SECONDS),
        )
        assertTrue(store.updateCaseWithCas(updated, 1L), "Valid CAS update must succeed")

        val postUpdate = store.findCaseByReference(tenantId, caseRef)
        assertNotNull(postUpdate)
        assertEquals(FraudCaseState.CLAIMED, postUpdate?.state)
        assertEquals("admin-1", postUpdate?.claimedBy)
        assertEquals(2L, postUpdate?.serverVersion, "CAS update must advance serverVersion to 2")

        // 3. Action recording and idempotency
        val action = FraudCaseActionRecord(
            actionId = UUID.randomUUID(),
            caseId = caseRecord.caseId,
            tenantId = tenantId,
            caseReference = caseRef,
            action = FraudCaseAction.CLAIM,
            actorId = "admin-1",
            fromState = FraudCaseState.OPEN,
            toState = FraudCaseState.CLAIMED,
            reason = "Claiming case for investigation",
            occurredAt = now.plus(1, ChronoUnit.SECONDS),
            idempotencyKey = "idem-action-claim-1",
            correlationId = "corr-claim-1",
            causationId = "cause-claim-1",
        )
        assertTrue(store.recordAction(action), "Initial action record must succeed")
        assertFalse(store.recordAction(action), "Duplicate action record with same idempotency key must fail")

        val fetchedAction = store.findActionByIdempotency(tenantId, "idem-action-claim-1")
        assertNotNull(fetchedAction)
        assertEquals(action.actionId, fetchedAction?.actionId)
        assertEquals(FraudCaseAction.CLAIM, fetchedAction?.action)
    }
}
