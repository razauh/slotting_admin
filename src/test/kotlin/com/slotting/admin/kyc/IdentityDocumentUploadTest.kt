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

class IdentityDocumentUploadTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var testScanner: TestMalwareScanner
    private lateinit var testStorage: TestEncryptedStorage
    private lateinit var service: IdentityDocumentUploadService

    private val tenantId = "tenant-alpha"
    private val playerId = "player-123"
    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )
    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    class TestMalwareScanner : MalwareScannerPort {
        var outcome: MalwareScanOutcome = MalwareScanOutcome(status = MalwareScanStatus.CLEAN)
        var shouldThrow: Boolean = false

        override fun scan(fileBytes: ByteArray, filename: String): MalwareScanOutcome {
            if (shouldThrow) {
                throw RuntimeException("Scanner daemon unreachable")
            }
            return outcome
        }
    }

    class TestEncryptedStorage : EncryptedStoragePort {
        val stored = mutableMapOf<String, ByteArray>()
        var shouldThrow: Boolean = false

        override fun storeEncrypted(
            tenantId: String,
            userId: String,
            documentId: UUID,
            fileBytes: ByteArray,
            mimeType: String,
        ): EncryptedStorageReference {
            if (shouldThrow) {
                throw RuntimeException("Storage unreachable")
            }
            val key = "s3://secure-kyc-vault/enc/$tenantId/$userId/$documentId"
            stored[key] = fileBytes
            return EncryptedStorageReference(
                storageKey = key,
                encryptionKeyArn = "arn:aws:kms:us-east-1:123456789012:key/kyc-doc-storage",
            )
        }

        override fun delete(storageKey: String): Boolean {
            return stored.remove(storageKey) != null
        }
    }

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        testScanner = TestMalwareScanner()
        testStorage = TestEncryptedStorage()
        service = IdentityDocumentUploadService(
            clock = clock,
            malwareScanner = testScanner,
            encryptedStorage = testStorage,
            retentionDays = 1825L,
            maxFileSizeBytes = 10L * 1024L * 1024L,
        )
    }

    @Test
    fun `KYC-002-01-T001 Implement secure identity-document upload produces the required authoritative outcome`() {
        val sampleBytes = "PASS_PORT_VALID_BINARY_DATA".toByteArray(Charsets.UTF_8)
        val command = IdentityDocumentUploadCommand(
            principal = playerPrincipal,
            tenantId = tenantId,
            userId = playerId,
            documentType = IdentityDocumentType.PASSPORT,
            filename = "passport.jpg",
            mimeType = "image/jpeg",
            fileBytes = sampleBytes,
            idempotencyKey = "idemp-upload-001",
            correlationId = "corr-001",
            causationId = "cause-001",
        )

        val result = service.uploadDocument(command)

        assertNotNull(result.documentId)
        assertEquals(DocumentUploadStatus.STORED, result.status)
        assertFalse(result.isLegalHold)
        assertEquals(fixedInstant.plus(Duration.ofDays(1825)), result.retentionExpiresAt)
        assertEquals(fixedInstant, result.serverTime)
        assertEquals(1L, result.serverVersion)
        assertEquals("Retention/deletion/legal hold configured; no raw document in app logs/backend events.", result.message)

        // Untrusted client & financial rule invariants
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)

        // Verify document persisted in store
        val record = service.getDocument(tenantId, result.documentId)
        assertNotNull(record)
        assertEquals(playerId, record!!.userId)
        assertEquals(IdentityDocumentType.PASSPORT, record.documentType)
        assertEquals("image/jpeg", record.mimeType)
        assertEquals(sampleBytes.size.toLong(), record.fileSizeBytes)
        assertFalse(record.isLegalHold)

        // Verify encrypted storage reference
        assertTrue(testStorage.stored.containsKey(result.storageKey))

        // Verify audit log
        val audits = service.getAuditLogs()
        assertEquals(1, audits.size)
        val audit = audits.first()
        assertEquals("DOCUMENT_UPLOADED", audit.action)
        assertEquals(playerId, audit.performedBy)
        assertEquals(result.sha256Checksum, audit.sha256Checksum)
        assertEquals(result.documentId, audit.documentId)
    }

    @Test
    fun `KYC-002-01-T002 Implement secure identity-document upload rejects invalid, boundary, unauthorized, and stale input`() {
        val sampleBytes = "VALID_CONTENT".toByteArray(Charsets.UTF_8)

        // 1. Invalid MIME type (e.g. .exe / dosexec)
        assertThrows(InvalidDocumentTypeException::class.java) {
            service.uploadDocument(
                IdentityDocumentUploadCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    userId = playerId,
                    documentType = IdentityDocumentType.PASSPORT,
                    filename = "malicious.exe",
                    mimeType = "application/x-dosexec",
                    fileBytes = sampleBytes,
                    idempotencyKey = "idemp-bad-mime",
                    correlationId = "corr-002",
                    causationId = "cause-002",
                )
            )
        }

        // 2. Empty file (0 bytes)
        assertThrows(InvalidFileSizeException::class.java) {
            service.uploadDocument(
                IdentityDocumentUploadCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    userId = playerId,
                    documentType = IdentityDocumentType.PASSPORT,
                    filename = "empty.pdf",
                    mimeType = "application/pdf",
                    fileBytes = ByteArray(0),
                    idempotencyKey = "idemp-empty-file",
                    correlationId = "corr-003",
                    causationId = "cause-003",
                )
            )
        }

        // 3. File too large (> 10MB)
        assertThrows(InvalidFileSizeException::class.java) {
            val largeBytes = ByteArray(10 * 1024 * 1024 + 1)
            service.uploadDocument(
                IdentityDocumentUploadCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    userId = playerId,
                    documentType = IdentityDocumentType.PASSPORT,
                    filename = "oversized.pdf",
                    mimeType = "application/pdf",
                    fileBytes = largeBytes,
                    idempotencyKey = "idemp-large-file",
                    correlationId = "corr-004",
                    causationId = "cause-004",
                )
            )
        }

        // 4. Malware infected file
        testScanner.outcome = MalwareScanOutcome(
            status = MalwareScanStatus.INFECTED,
            threatName = "Trojan.IdentityTheft.Sig",
        )
        assertThrows(MalwareDetectedException::class.java) {
            service.uploadDocument(
                IdentityDocumentUploadCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    userId = playerId,
                    documentType = IdentityDocumentType.PASSPORT,
                    filename = "infected.png",
                    mimeType = "image/png",
                    fileBytes = sampleBytes,
                    idempotencyKey = "idemp-infected",
                    correlationId = "corr-005",
                    causationId = "cause-005",
                )
            )
        }
        testScanner.outcome = MalwareScanOutcome(status = MalwareScanStatus.CLEAN)

        // 5. Cross-player IDOR upload (Player A attempts to upload for Player B)
        val otherPlayerPrincipal = AuthenticatedPrincipal(
            id = "attacker-player-456",
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        assertThrows(IdorForbiddenException::class.java) {
            service.uploadDocument(
                IdentityDocumentUploadCommand(
                    principal = otherPlayerPrincipal,
                    tenantId = tenantId,
                    userId = playerId, // Target user is player-123
                    documentType = IdentityDocumentType.PASSPORT,
                    filename = "idor.jpg",
                    mimeType = "image/jpeg",
                    fileBytes = sampleBytes,
                    idempotencyKey = "idemp-idor",
                    correlationId = "corr-006",
                    causationId = "cause-006",
                )
            )
        }

        // 6. Cross-tenant upload
        val otherTenantPrincipal = AuthenticatedPrincipal(
            id = playerId,
            tenantId = "tenant-other",
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )
        assertThrows(IdorForbiddenException::class.java) {
            service.uploadDocument(
                IdentityDocumentUploadCommand(
                    principal = otherTenantPrincipal,
                    tenantId = tenantId,
                    userId = playerId,
                    documentType = IdentityDocumentType.PASSPORT,
                    filename = "tenant.jpg",
                    mimeType = "image/jpeg",
                    fileBytes = sampleBytes,
                    idempotencyKey = "idemp-tenant",
                    correlationId = "corr-007",
                    causationId = "cause-007",
                )
            )
        }

        // 7. Legal hold rejection on purge:
        // First upload valid document
        val validUpload = service.uploadDocument(
            IdentityDocumentUploadCommand(
                principal = playerPrincipal,
                tenantId = tenantId,
                userId = playerId,
                documentType = IdentityDocumentType.DRIVERS_LICENSE,
                filename = "license.png",
                mimeType = "image/png",
                fileBytes = sampleBytes,
                idempotencyKey = "idemp-valid-purge-target",
                correlationId = "corr-008",
                causationId = "cause-008",
            )
        )
        // Place legal hold
        service.setLegalHold(
            LegalHoldCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                documentId = validUpload.documentId,
                active = true,
                reason = "Regulatory subpoena inquiry #8492",
                idempotencyKey = "idemp-legal-hold-place",
                correlationId = "corr-009",
                causationId = "cause-009",
                expectedVersion = 1L,
            )
        )
        // Purge attempt during legal hold must fail
        assertThrows(LegalHoldActiveException::class.java) {
            service.purgeDocument(
                PurgeDocumentCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    documentId = validUpload.documentId,
                    reason = "Routine purge",
                    idempotencyKey = "idemp-purge-held",
                    correlationId = "corr-010",
                    causationId = "cause-010",
                    expectedVersion = 2L,
                )
            )
        }

        // Release legal hold but retention period is still active -> must fail with RetentionPeriodActiveException
        service.setLegalHold(
            LegalHoldCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                documentId = validUpload.documentId,
                active = false,
                reason = "Subpoena cleared",
                idempotencyKey = "idemp-legal-hold-rel",
                correlationId = "corr-011",
                causationId = "cause-011",
                expectedVersion = 2L,
            )
        )
        assertThrows(RetentionPeriodActiveException::class.java) {
            service.purgeDocument(
                PurgeDocumentCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    documentId = validUpload.documentId,
                    reason = "Purge before expiration",
                    idempotencyKey = "idemp-purge-before-exp",
                    correlationId = "corr-012",
                    causationId = "cause-012",
                    expectedVersion = 3L,
                )
            )
        }
    }

    @Test
    fun `KYC-002-01-T003 Implement secure identity-document upload survives concurrency, duplicate delivery, and dependency failure`() {
        val sampleBytes = "ROBUST_BINARY_DOC".toByteArray(Charsets.UTF_8)
        val command = IdentityDocumentUploadCommand(
            principal = playerPrincipal,
            tenantId = tenantId,
            userId = playerId,
            documentType = IdentityDocumentType.NATIONAL_ID,
            filename = "nat_id.pdf",
            mimeType = "application/pdf",
            fileBytes = sampleBytes,
            idempotencyKey = "idemp-concur-001",
            correlationId = "corr-013",
            causationId = "cause-013",
        )

        // 1. Initial upload
        val firstResult = service.uploadDocument(command)

        // 2. Duplicate delivery (exact replay) -> returns identical result
        val secondResult = service.uploadDocument(command)
        assertEquals(firstResult.documentId, secondResult.documentId)
        assertEquals(firstResult.sha256Checksum, secondResult.sha256Checksum)
        assertEquals(firstResult.storageKey, secondResult.storageKey)

        // 3. Same idempotency key with conflicting payload -> throws ConcurrencyConflictException
        val conflictingCommand = command.copy(
            fileBytes = "DIFFERENT_PAYLOAD_TAMPERED".toByteArray(Charsets.UTF_8),
        )
        assertThrows(ConcurrencyConflictException::class.java) {
            service.uploadDocument(conflictingCommand)
        }

        // 4. Scanner dependency failure -> fails closed, no document persisted
        testScanner.shouldThrow = true
        val failedCommand = command.copy(
            idempotencyKey = "idemp-scanner-down",
            filename = "scanner_down.pdf",
        )
        assertThrows(DependencyFailureException::class.java) {
            service.uploadDocument(failedCommand)
        }
        testScanner.shouldThrow = false

        // 5. Storage dependency failure -> fails closed
        testStorage.shouldThrow = true
        val failedStorageCommand = command.copy(
            idempotencyKey = "idemp-storage-down",
            filename = "storage_down.pdf",
        )
        assertThrows(DependencyFailureException::class.java) {
            service.uploadDocument(failedStorageCommand)
        }
    }

    @Test
    fun `KYC-002-01-T004 Implement secure identity-document upload remains compatible, recoverable, observable, and lifecycle-safe`() {
        val sampleBytes = "DOCUMENT_FOR_LIFECYCLE".toByteArray(Charsets.UTF_8)
        val uploadResult = service.uploadDocument(
            IdentityDocumentUploadCommand(
                principal = playerPrincipal,
                tenantId = tenantId,
                userId = playerId,
                documentType = IdentityDocumentType.UTILITY_BILL,
                filename = "utility.pdf",
                mimeType = "application/pdf",
                fileBytes = sampleBytes,
                idempotencyKey = "idemp-lifecycle-001",
                correlationId = "corr-014",
                causationId = "cause-014",
            )
        )

        // Advance clock past retention period (5 years + 1 day)
        val advancedInstant = fixedInstant.plus(Duration.ofDays(1826))
        val advancedClock = Clock.fixed(advancedInstant, ZoneOffset.UTC)
        val lifecycleService = IdentityDocumentUploadService(
            clock = advancedClock,
            malwareScanner = testScanner,
            encryptedStorage = testStorage,
            retentionDays = 1825L,
        )

        // Seed with state from previous run (recoverability)
        val initialRecord = service.getDocument(tenantId, uploadResult.documentId)!!
        val docField = IdentityDocumentUploadService::class.java.getDeclaredField("documentsStore")
        docField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val store = docField.get(lifecycleService) as java.util.concurrent.ConcurrentHashMap<UUID, IdentityDocumentRecord>
        store[uploadResult.documentId] = initialRecord

        // Purge should now succeed because retention has expired and no legal hold is active
        val purgedRecord = lifecycleService.purgeDocument(
            PurgeDocumentCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                documentId = uploadResult.documentId,
                reason = "GDPR / statutory retention period expired",
                idempotencyKey = "idemp-purge-ok",
                correlationId = "corr-015",
                causationId = "cause-015",
                expectedVersion = 1L,
            )
        )

        assertEquals(DocumentUploadStatus.PURGED, purgedRecord.status)
        assertEquals(2L, purgedRecord.serverVersion)
        assertFalse(testStorage.stored.containsKey(purgedRecord.storageKey))

        // Check audit log contains no raw file payload
        val auditLogs = lifecycleService.getAuditLogs()
        assertTrue(auditLogs.any { it.action == "DOCUMENT_PURGED" })
        auditLogs.forEach { audit ->
            assertNotNull(audit.sha256Checksum)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.reason?.contains("DOCUMENT_FOR_LIFECYCLE") == true)
        }
    }
}
