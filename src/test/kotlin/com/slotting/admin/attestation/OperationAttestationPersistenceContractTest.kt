package com.slotting.admin.attestation

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * Verifies V36 migration script and persistence contracts for operation-bound attestation challenges (TC-033).
 */
class OperationAttestationPersistenceContractTest {

    @Test
    fun `V36 migration script defines all required schema objects, indexes, and idempotency constraints`() {
        val stream = javaClass.classLoader.getResourceAsStream("db/migration/V36__operation_bound_attestation_challenges.sql")
        assertNotNull(stream, "V36 migration must exist on classpath")

        val sql = stream!!.bufferedReader().use { it.readText() }
        assertTrue(sql.contains("operation_attestation_challenges", ignoreCase = true))
        assertTrue(sql.contains("operation_attestation_audits", ignoreCase = true))
        assertTrue(sql.contains("uq_attestation_audits_tenant_idem", ignoreCase = true))
        assertTrue(sql.contains("idx_attestation_challenges_lookup", ignoreCase = true))
        assertTrue(sql.contains("idx_attestation_challenges_active", ignoreCase = true))
        assertTrue(sql.contains("nonce_value", ignoreCase = true))
        assertTrue(sql.contains("consumed", ignoreCase = true))
    }

    @Test
    fun `InMemoryOperationChallengeStore satisfies challenge saving, consumption, and audit idempotency contracts`() {
        val store: DurableOperationChallengeStore = InMemoryOperationChallengeStore()
        val now = Instant.parse("2026-09-26T12:00:00Z")
        val tenantId = "tenant-persist-chal"
        val userId = "user-persist-1"
        val sessionId = "session-persist-1"
        val nonce = "nonce-persist-xyz-1"

        // 1. Save and retrieve challenge
        val challenge = OperationChallengeRecord(
            challengeId = UUID.randomUUID(),
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = ProtectedOperation.WAGER,
            nonceValue = nonce,
            issuedAt = now,
            expiresAt = now.plus(5, ChronoUnit.MINUTES),
            consumed = false,
        )

        assertTrue(store.saveChallenge(challenge), "Initial challenge save must succeed")
        assertFalse(store.saveChallenge(challenge), "Duplicate challenge save with same nonce must fail")

        val fetched = store.findChallenge(tenantId, nonce)
        assertNotNull(fetched)
        assertEquals(challenge.challengeId, fetched?.challengeId)
        assertFalse(fetched!!.consumed)

        val fetchedByNonce = store.findChallengeByNonce(nonce)
        assertNotNull(fetchedByNonce)
        assertEquals(tenantId, fetchedByNonce?.tenantId)

        // 2. Active count check
        assertEquals(1, store.countActiveChallenges(tenantId, userId, sessionId, now))

        // 3. Atomic consumption
        assertTrue(store.consumeChallenge(tenantId, nonce, "op-ref-1", now.plusSeconds(1)), "First consumption must succeed")
        assertFalse(store.consumeChallenge(tenantId, nonce, "op-ref-2", now.plusSeconds(2)), "Replay consumption must fail")

        val postConsume = store.findChallenge(tenantId, nonce)
        assertNotNull(postConsume)
        assertTrue(postConsume!!.consumed)
        assertEquals("op-ref-1", postConsume.consumedByOperationRef)

        // Active count drops to 0 after consumption
        assertEquals(0, store.countActiveChallenges(tenantId, userId, sessionId, now))

        // 4. Audit record and idempotency
        val audit = OperationAttestationAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = ProtectedOperation.WAGER,
            nonceValue = nonce,
            decision = AttestationDecision.ALLOW,
            reason = AttestationFailureReason.CHALLENGE_VALID,
            appPackageName = "com.slotting.game.connected",
            appVersionCode = 1L,
            clientReportedFingerprint = "sha256:test",
            occurredAt = now,
            idempotencyKey = "idem-audit-persist-1",
            correlationId = "corr-1",
            causationId = "cause-1",
            evidenceReference = "evid-1",
            detailsRedacted = "Audit verified",
        )

        assertTrue(store.recordAudit(audit), "Initial audit save must succeed")
        assertFalse(store.recordAudit(audit), "Duplicate audit with same idempotency key must fail")

        val fetchedAudit = store.findAuditByIdempotency(tenantId, "idem-audit-persist-1")
        assertNotNull(fetchedAudit)
        assertEquals(audit.auditId, fetchedAudit?.auditId)
    }
}
