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

class SourceOfFundsEvidenceTest {
    private val now = Instant.parse("2026-09-17T19:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `AML-003-01-T001 Collect source-of-funds evidence produces the required authoritative outcome`() {
        val store = MemorySourceOfFundsStore()
        val service = service(store)

        // 1. Initial state: before SOF review, payout must be held / blocked (prevent payout before required review)
        val preReviewPayout = service.verifyPayoutEligibility(
            VerifySofPayoutEligibilityCommand("tenant-1", "player-sof-001", 500_000L)
        )
        assertFalse(preReviewPayout.canPayout)
        assertEquals(SofPayoutEligibility.HELD_FOR_SOF_REVIEW, preReviewPayout.eligibility)
        assertNotNull(preReviewPayout.denialReason)

        // 2. Collect initial SOF evidence: payslip
        val initialCmd = command(
            subjectReference = "player-sof-001",
            evidence = SofEvidenceDocument(
                documentReference = "DOC-PAYSLIP-2026-09",
                evidenceType = SofEvidenceType.PAYSLIP,
                checksumSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                issuingInstitution = "Acme Corp Payroll Ltd",
                verifiedAmountMinorUnits = 600_000L,
                currencyCode = "EUR",
            ),
            idempotencyKey = "key-sof-001",
            correlationId = "corr-sof-1",
            causationId = "cause-sof-1",
        )
        val initialResult = service.collectEvidence(initialCmd)

        // Assert: Decision immutable; superseding record only; minimal retention per approved policy
        assertEquals("player-sof-001", initialResult.subjectReference)
        assertEquals(SofReviewStatus.PENDING_REVIEW, initialResult.status)
        assertNull(initialResult.supersedesRecordId)
        assertNotNull(initialResult.amlCaseReference)
        assertEquals(AmlReviewState.QUEUED, initialResult.queuedAmlItem.state)
        assertFalse(initialResult.financialAuthorityCreated) // Outcome cannot create financial authority
        assertFalse(initialResult.moneyMutated)             // Cannot mutate money
        assertEquals("EVID-SOF-player-sof-001", initialResult.evidenceReference)
        assertTrue(initialResult.retentionExpiresAt.isAfter(now))

        // Payout is STILL held while SOF is PENDING_REVIEW
        val pendingPayout = service.verifyPayoutEligibility(
            VerifySofPayoutEligibilityCommand("tenant-1", "player-sof-001", 500_000L)
        )
        assertFalse(pendingPayout.canPayout)
        assertEquals(SofPayoutEligibility.HELD_FOR_SOF_REVIEW, pendingPayout.eligibility)

        // 3. Superseding record: Player provides additional bank statement evidence superseding previous payslip
        val supersedingCmd = command(
            subjectReference = "player-sof-001",
            evidence = SofEvidenceDocument(
                documentReference = "DOC-BANK-STATEMENT-2026",
                evidenceType = SofEvidenceType.BANK_STATEMENT,
                checksumSha256 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                issuingInstitution = "BNP Paribas",
                verifiedAmountMinorUnits = 2_500_000L,
                currencyCode = "EUR",
            ),
            supersedesRecordId = initialResult.recordId,
            idempotencyKey = "key-sof-supersede-001",
        )
        val supersededResult = service.collectEvidence(supersedingCmd)

        assertEquals(initialResult.recordId, supersededResult.supersedesRecordId)
        assertNotEquals(initialResult.recordId, supersededResult.recordId)

        // Immutable decision verification: old record still exists with its original metadata, now marked SUPERSEDED
        val oldRecord = store.findRecordById("tenant-1", initialResult.recordId)
        assertNotNull(oldRecord)
        assertEquals(SofReviewStatus.SUPERSEDED, oldRecord.status)
        assertEquals("DOC-PAYSLIP-2026-09", oldRecord.evidence.documentReference)

        // New superseding record is active
        val newRecord = store.findRecordById("tenant-1", supersededResult.recordId)
        assertNotNull(newRecord)
        assertEquals(SofReviewStatus.PENDING_REVIEW, newRecord.status)
        assertEquals(2L, newRecord.serverVersion)

        // 4. Replay with identical idempotency key returns identical result
        val replay = service.collectEvidence(initialCmd)
        assertEquals(initialResult.resultId, replay.resultId)
        assertEquals(initialResult.recordId, replay.recordId)
        assertEquals(initialResult.evidenceReference, replay.evidenceReference)

        // Observability check
        assertEquals(2, store.audit.size)
        assertEquals("AML_SOF_EVIDENCE_COLLECTED", store.audit[0].type)
        assertEquals("corr-sof-1", store.audit[0].correlationId)
        assertEquals("cause-sof-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    @Test
    fun `AML-003-01-T002 Collect source-of-funds evidence rejects invalid, boundary, unauthorized, and stale input`() {
        val store = MemorySourceOfFundsStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized role lacking MANAGE_SECURITY
        val supportAdmin = AuthenticatedPrincipal("admin-support", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(principal = supportAdmin, idempotencyKey = "key-support-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = SourceOfFundsEvidenceService(AdminRbacPolicy(true), TestSofExpiredSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.collectEvidence(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(subjectReference = "   ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank document reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(
                evidence = SofEvidenceDocument(
                    documentReference = "   ",
                    evidenceType = SofEvidenceType.PAYSLIP,
                    checksumSha256 = "hash",
                    issuingInstitution = "Bank",
                    verifiedAmountMinorUnits = 1000L,
                    currencyCode = "EUR",
                ),
                idempotencyKey = "key-blank-doc"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid supersedes record ID (non-existent)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(
                supersedesRecordId = UUID.randomUUID(),
                idempotencyKey = "key-bad-supersede"
            ))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(expectedVersion = 6L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.collectEvidence(command(idempotencyKey = "key-conflict-sof"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.collectEvidence(command(
                evidence = SofEvidenceDocument(
                    documentReference = "DOC-DIFFERENT",
                    evidenceType = SofEvidenceType.TAX_RETURN,
                    checksumSha256 = "different-hash",
                    issuingInstitution = "Tax Office",
                    verifiedAmountMinorUnits = 9999L,
                    currencyCode = "EUR",
                ),
                idempotencyKey = "key-conflict-sof"
            ))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `AML-003-01-T003 Collect source-of-funds evidence survives concurrency, duplicate delivery, and dependency failure`() {
        val store = MemorySourceOfFundsStore()
        val service = service(store)

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-sof-001")
        val calls = (1..4).map {
            pool.submit<SofEvidenceCollectionResult> {
                gate.await()
                service.collectEvidence(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingService = SourceOfFundsEvidenceService(AdminRbacPolicy(true), TestSofFailingSessionDirectory(), store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.collectEvidence(command(idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `AML-003-01-T004 Collect source-of-funds evidence remains compatible, recoverable, observable, and lifecycle-safe`() {
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

        // Assert: restart/recreation preserves consistency and immutability
        val store = MemorySourceOfFundsStore()
        val service = service(store)

        val cmd = command(
            subjectReference = "player-reboot-sof-001",
            idempotencyKey = "key-reboot-sof",
            correlationId = "corr-reboot-sof-1",
            causationId = "cause-reboot-sof-1",
        )
        val first = service.collectEvidence(cmd)

        // Recreate service (restart)
        val restartedService = service(store)

        // Payout eligibility remains held after reboot
        val eligibility = restartedService.verifyPayoutEligibility(
            VerifySofPayoutEligibilityCommand("tenant-1", "player-reboot-sof-001", 100_000L)
        )
        assertFalse(eligibility.canPayout)
        assertEquals(SofPayoutEligibility.HELD_FOR_SOF_REVIEW, eligibility.eligibility)

        // Replay produces identical result
        val second = restartedService.collectEvidence(cmd)
        assertEquals(first.resultId, second.resultId)
        assertEquals(first.recordId, second.recordId)
        assertEquals(first.amlCaseReference, second.amlCaseReference)
        assertFalse(second.financialAuthorityCreated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_SOF_EVIDENCE_COLLECTED", store.audit[0].type)
        assertEquals("corr-reboot-sof-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-sof-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: SourceOfFundsStore) =
        SourceOfFundsEvidenceService(AdminRbacPolicy(true), TestSofActiveSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-sof-001",
        evidence: SofEvidenceDocument = SofEvidenceDocument(
            documentReference = "DOC-PAYSLIP-DEFAULT",
            evidenceType = SofEvidenceType.PAYSLIP,
            checksumSha256 = "checksum-sha256-default",
            issuingInstitution = "Default Employer",
            verifiedAmountMinorUnits = 500_000L,
            currencyCode = "EUR",
        ),
        supersedesRecordId: UUID? = null,
        idempotencyKey: String = "key-sof-cmd-001",
        correlationId: String = "corr-sof-default",
        causationId: String = "cause-sof-default",
        expectedVersion: Long = 1L,
    ) = CollectSofEvidenceCommand(
        principal = principal,
        sessionId = "session-sof-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        evidence = evidence,
        supersedesRecordId = supersedesRecordId,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-sof-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-sof-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestSofActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-sof-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T20:30:00Z"))
        else null
}

private class TestSofExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T18:30:00Z"))
}

private class TestSofFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory failure")
}

private class MemorySourceOfFundsStore : SourceOfFundsStore {
    val results = mutableMapOf<String, Pair<String, SofEvidenceCollectionResult>>()
    val records = mutableMapOf<UUID, SofDecisionRecord>()
    val latestBySubject = mutableMapOf<String, SofDecisionRecord>()
    val queueItems = mutableMapOf<String, AmlQueueItem>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findLatestRecord(tenantId: String, subjectReference: String) =
        synchronized(this) { latestBySubject["$tenantId:$subjectReference"] }

    override fun findRecordById(tenantId: String, recordId: UUID) =
        synchronized(this) { records[recordId] }

    override fun save(
        record: SofDecisionRecord,
        result: SofEvidenceCollectionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queueItem: AmlQueueItem,
        supersededRecord: SofDecisionRecord?,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        records[record.recordId] = record
        latestBySubject["$tenantId:${record.subjectReference}"] = record
        if (supersededRecord != null) {
            records[supersededRecord.recordId] = supersededRecord
        }
        queueItems[queueItem.caseReference] = queueItem
        this.audit += audit
        this.outbox += outbox
    }
}
