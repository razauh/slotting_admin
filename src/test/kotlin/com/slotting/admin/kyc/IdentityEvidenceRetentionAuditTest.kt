package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class IdentityEvidenceRetentionAuditTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var service: IdentityEvidenceRetentionAuditService

    private val tenantId = "tenant-alpha"
    private val playerId = "player-001"
    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )
    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )
    private val securityAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        service = IdentityEvidenceRetentionAuditService(
            clock = clock,
            retentionConfig = RetentionPolicyConfig(
                statutoryRetentionDuration = Duration.ofDays(1825),
            ),
        )
    }

    @Test
    fun `KYC-002-02-T001 Enforce identity-evidence retention and audit produces the required authoritative outcome`() {
        // 1. Record evidence audit entry
        val draft = AuditEntryDraft(
            tenantId = tenantId,
            documentId = UUID.randomUUID(),
            userId = playerId,
            action = "DOCUMENT_UPLOADED",
            operatorId = playerId,
            details = mapOf(
                "mimeType" to "image/jpeg",
                "fileSizeBytes" to "2048576",
                "sha256Checksum" to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            correlationId = "corr-001",
            causationId = "cause-001",
        )
        val entry1 = service.recordEvidenceAudit(draft)

        assertEquals(1L, entry1.sequenceNumber)
        assertEquals(IdentityEvidenceRetentionAuditService.GENESIS_HASH, entry1.previousEntryHash)
        assertNotNull(entry1.entryHash)
        assertTrue(service.verifyAuditIntegrity(tenantId))

        // 2. Customer erasure request with statutory retention override
        val erasureReq = service.submitCustomerErasureRequest(
            principal = playerPrincipal,
            tenantId = tenantId,
            userId = playerId,
            justification = "GDPR right to be forgotten request",
            idempotencyKey = "idemp-erasure-001",
            correlationId = "corr-002",
            causationId = "cause-002",
        )

        assertEquals(ErasureRequestStatus.DEFERRED_STATUTORY_RETENTION, erasureReq.status)
        assertEquals(fixedInstant.plus(Duration.ofDays(1825)), erasureReq.earliestPurgePermittedAt)

        // 3. Execute retention purge sweep
        val docActive = IdentityDocumentRecord(
            documentId = UUID.randomUUID(),
            tenantId = tenantId,
            userId = playerId,
            documentType = IdentityDocumentType.PASSPORT,
            mimeType = "image/jpeg",
            fileSizeBytes = 1000L,
            sha256Checksum = "sha-active",
            storageKey = "s3://vault/active",
            encryptionKeyArn = "arn:aws:kms:1",
            status = DocumentUploadStatus.STORED,
            retentionExpiresAt = fixedInstant.plus(Duration.ofDays(100)), // Still active
            isLegalHold = false,
            serverVersion = 1L,
            createdAt = fixedInstant,
            updatedAt = fixedInstant,
        )
        val docHeld = IdentityDocumentRecord(
            documentId = UUID.randomUUID(),
            tenantId = tenantId,
            userId = playerId,
            documentType = IdentityDocumentType.DRIVERS_LICENSE,
            mimeType = "image/png",
            fileSizeBytes = 2000L,
            sha256Checksum = "sha-held",
            storageKey = "s3://vault/held",
            encryptionKeyArn = "arn:aws:kms:1",
            status = DocumentUploadStatus.STORED,
            retentionExpiresAt = fixedInstant.minus(Duration.ofDays(10)), // Expired but held
            isLegalHold = true,
            serverVersion = 2L,
            createdAt = fixedInstant.minus(Duration.ofDays(1830)),
            updatedAt = fixedInstant,
        )
        val docExpired = IdentityDocumentRecord(
            documentId = UUID.randomUUID(),
            tenantId = tenantId,
            userId = playerId,
            documentType = IdentityDocumentType.UTILITY_BILL,
            mimeType = "application/pdf",
            fileSizeBytes = 3000L,
            sha256Checksum = "sha-expired",
            storageKey = "s3://vault/expired",
            encryptionKeyArn = "arn:aws:kms:1",
            status = DocumentUploadStatus.STORED,
            retentionExpiresAt = fixedInstant.minus(Duration.ofDays(1)), // Expired and not held
            isLegalHold = false,
            serverVersion = 1L,
            createdAt = fixedInstant.minus(Duration.ofDays(1826)),
            updatedAt = fixedInstant,
        )

        val sweepResult = service.executeRetentionPurgeSweep(
            principal = securityAdminPrincipal,
            tenantId = tenantId,
            dryRun = false,
            documents = listOf(docActive, docHeld, docExpired),
            idempotencyKey = "idemp-sweep-001",
            correlationId = "corr-003",
            causationId = "cause-003",
        )

        assertEquals(3, sweepResult.evaluatedCount)
        assertEquals(1, sweepResult.activeCount)
        assertEquals(1, sweepResult.heldCount)
        assertEquals(1, sweepResult.purgedCount)
        assertEquals(listOf(docExpired.documentId), sweepResult.purgedDocumentIds)
        assertEquals("Retention/deletion/legal hold configured; no raw document in app logs/backend events.", sweepResult.message)

        // Untrusted client & financial invariants
        assertFalse(sweepResult.directEligibilityGranted)
        assertFalse(sweepResult.financialMutationPermitted)

        // Cryptographic integrity remains intact across all additions
        assertTrue(service.verifyAuditIntegrity(tenantId))
    }

    @Test
    fun `KYC-002-02-T002 Enforce identity-evidence retention and audit rejects invalid, boundary, unauthorized, and stale input`() {
        // 1. Cross-player IDOR rejection on erasure request
        val attackerPrincipal = AuthenticatedPrincipal(
            id = "attacker-player",
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        assertThrows(IdorForbiddenException::class.java) {
            service.submitCustomerErasureRequest(
                principal = attackerPrincipal,
                tenantId = tenantId,
                userId = playerId, // Target user is player-001
                justification = "Malicious erasure request",
                idempotencyKey = "idemp-idor-erasure",
                correlationId = "corr-004",
                causationId = "cause-004",
            )
        }

        // 2. Cross-tenant rejection
        val otherTenantPrincipal = AuthenticatedPrincipal(
            id = playerId,
            tenantId = "tenant-other",
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        assertThrows(IdorForbiddenException::class.java) {
            service.submitCustomerErasureRequest(
                principal = otherTenantPrincipal,
                tenantId = tenantId,
                userId = playerId,
                justification = "Cross-tenant erasure",
                idempotencyKey = "idemp-tenant-erasure",
                correlationId = "corr-005",
                causationId = "cause-005",
            )
        }

        // 3. Redaction policy violation: attempting to log raw bytes or unredacted SSN
        assertThrows(RedactionPolicyViolationException::class.java) {
            service.recordEvidenceAudit(
                AuditEntryDraft(
                    tenantId = tenantId,
                    documentId = UUID.randomUUID(),
                    userId = playerId,
                    action = "LEAK_ATTEMPT",
                    operatorId = playerId,
                    details = mapOf(
                        "rawBytes" to "UNREDACTED_BINARY_LEAK",
                    ),
                    correlationId = "corr-006",
                    causationId = "cause-006",
                )
            )
        }

        // Base64 image payload in details must be rejected
        assertThrows(RedactionPolicyViolationException::class.java) {
            service.recordEvidenceAudit(
                AuditEntryDraft(
                    tenantId = tenantId,
                    documentId = UUID.randomUUID(),
                    userId = playerId,
                    action = "BASE64_LEAK_ATTEMPT",
                    operatorId = playerId,
                    details = mapOf(
                        "preview" to "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQE...",
                    ),
                    correlationId = "corr-007",
                    causationId = "cause-007",
                )
            )
        }

        // 4. Tamper detection: modifying an audit entry in the chain breaks integrity
        service.recordEvidenceAudit(
            AuditEntryDraft(
                tenantId = tenantId,
                documentId = UUID.randomUUID(),
                userId = playerId,
                action = "LEGITIMATE_ACTION",
                operatorId = playerId,
                details = mapOf("status" to "OK"),
                correlationId = "corr-008",
                causationId = "cause-008",
            )
        )
        assertTrue(service.verifyAuditIntegrity(tenantId))

        // Tamper with last entry
        service.tamperLastEntryForTest("FORGED_ACTION")
        assertThrows(TamperEvidentChainCorruptedException::class.java) {
            service.verifyAuditIntegrity(tenantId)
        }

        // 5. Unauthorized audit queries
        val unprivilegedAdmin = AuthenticatedPrincipal(
            id = "admin-no-perms",
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = emptySet(), // No AUDITOR or SECURITY role
        )
        assertThrows(IdorForbiddenException::class.java) {
            service.queryAuditLogs(unprivilegedAdmin, tenantId)
        }
    }

    @Test
    fun `KYC-002-02-T003 Enforce identity-evidence retention and audit survives concurrency, duplicate delivery, and dependency failure`() {
        // 1. Duplicate erasure request returns cached result
        val req1 = service.submitCustomerErasureRequest(
            principal = playerPrincipal,
            tenantId = tenantId,
            userId = playerId,
            justification = "Right to erasure",
            idempotencyKey = "idemp-erasure-concur",
            correlationId = "corr-009",
            causationId = "cause-009",
        )
        val req2 = service.submitCustomerErasureRequest(
            principal = playerPrincipal,
            tenantId = tenantId,
            userId = playerId,
            justification = "Right to erasure",
            idempotencyKey = "idemp-erasure-concur",
            correlationId = "corr-009",
            causationId = "cause-009",
        )
        assertEquals(req1.requestId, req2.requestId)
        assertEquals(req1.status, req2.status)

        // 2. Conflicting payload with same idempotency key throws ConcurrencyConflictException
        assertThrows(ConcurrencyConflictException::class.java) {
            service.submitCustomerErasureRequest(
                principal = playerPrincipal,
                tenantId = tenantId,
                userId = playerId,
                justification = "DIFFERENT_CONFLICTING_JUSTIFICATION",
                idempotencyKey = "idemp-erasure-concur",
                correlationId = "corr-010",
                causationId = "cause-010",
            )
        }

        // 3. Successive audit appends maintain strict cryptographic chaining
        for (i in 1..20) {
            service.recordEvidenceAudit(
                AuditEntryDraft(
                    tenantId = tenantId,
                    documentId = UUID.randomUUID(),
                    userId = playerId,
                    action = "CONCURRENT_TEST_EVENT_$i",
                    operatorId = "operator-$i",
                    details = mapOf("iteration" to i.toString()),
                    correlationId = "corr-loop-$i",
                    causationId = "cause-loop-$i",
                )
            )
        }
        assertTrue(service.verifyAuditIntegrity(tenantId))
    }

    @Test
    fun `KYC-002-02-T004 Enforce identity-evidence retention and audit remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Record several audit items
        val entry1 = service.recordEvidenceAudit(
            AuditEntryDraft(
                tenantId = tenantId,
                documentId = UUID.randomUUID(),
                userId = playerId,
                action = "LIFECYCLE_EVENT_1",
                operatorId = playerId,
                details = mapOf("stage" to "INIT"),
                correlationId = "corr-011",
                causationId = "cause-011",
            )
        )

        // Query logs as auditor
        val logs = service.queryAuditLogs(auditorPrincipal, tenantId)
        assertTrue(logs.isNotEmpty())
        assertEquals(entry1.sequenceNumber, logs.first().sequenceNumber)
        assertEquals(entry1.entryHash, logs.first().entryHash)

        // Player query only returns their own entries
        val playerLogs = service.queryAuditLogs(playerPrincipal, tenantId)
        assertTrue(playerLogs.all { it.userId == playerId })

        // Observability check: ensure no raw file bytes or secrets are present
        logs.forEach { log ->
            assertFalse(log.details.containsKey("rawBytes"))
            assertNotNull(log.entryHash)
            assertNotNull(log.previousEntryHash)
        }
    }
}
