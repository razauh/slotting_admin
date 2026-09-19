package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for KYC-002-01:
 * "type/size/malware/IDOR/log leak"
 */
object IdentityDocumentUploadBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("type/size/malware/IDOR/log leak")
        }
    }
}

enum class IdentityDocumentType {
    PASSPORT,
    DRIVERS_LICENSE,
    NATIONAL_ID,
    PROOF_OF_ADDRESS,
    UTILITY_BILL,
}

enum class DocumentUploadStatus {
    STORED,
    QUARANTINED,
    PURGED,
}

enum class MalwareScanStatus {
    CLEAN,
    INFECTED,
    SCAN_FAILED,
}

data class MalwareScanOutcome(
    val status: MalwareScanStatus,
    val threatName: String? = null,
    val scannerVersion: String = "v1.0.0",
)

interface MalwareScannerPort {
    fun scan(fileBytes: ByteArray, filename: String): MalwareScanOutcome
}

data class EncryptedStorageReference(
    val storageKey: String,
    val encryptionKeyArn: String,
    val algorithm: String = "AES-256-GCM",
)

interface EncryptedStoragePort {
    fun storeEncrypted(
        tenantId: String,
        userId: String,
        documentId: UUID,
        fileBytes: ByteArray,
        mimeType: String,
    ): EncryptedStorageReference

    fun delete(storageKey: String): Boolean
}

data class IdentityDocumentRecord(
    val documentId: UUID,
    val tenantId: String,
    val userId: String,
    val documentType: IdentityDocumentType,
    val mimeType: String,
    val fileSizeBytes: Long,
    val sha256Checksum: String,
    val storageKey: String,
    val encryptionKeyArn: String,
    val status: DocumentUploadStatus,
    val retentionExpiresAt: Instant,
    val isLegalHold: Boolean = false,
    val legalHoldReason: String? = null,
    val legalHoldPlacedBy: String? = null,
    val legalHoldPlacedAt: Instant? = null,
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class IdentityDocumentUploadCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val userId: String,
    val documentType: IdentityDocumentType,
    val filename: String,
    val mimeType: String,
    val fileBytes: ByteArray,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 0L,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IdentityDocumentUploadCommand) return false
        return principal == other.principal &&
                tenantId == other.tenantId &&
                userId == other.userId &&
                documentType == other.documentType &&
                filename == other.filename &&
                mimeType == other.mimeType &&
                fileBytes.contentEquals(other.fileBytes) &&
                idempotencyKey == other.idempotencyKey &&
                correlationId == other.correlationId &&
                causationId == other.causationId &&
                expectedVersion == other.expectedVersion
    }

    override fun hashCode(): Int {
        var result = principal?.hashCode() ?: 0
        result = 31 * result + tenantId.hashCode()
        result = 31 * result + userId.hashCode()
        result = 31 * result + documentType.hashCode()
        result = 31 * result + filename.hashCode()
        result = 31 * result + mimeType.hashCode()
        result = 31 * result + fileBytes.contentHashCode()
        result = 31 * result + idempotencyKey.hashCode()
        result = 31 * result + correlationId.hashCode()
        result = 31 * result + causationId.hashCode()
        result = 31 * result + expectedVersion.hashCode()
        return result
    }

    // Explicit redaction of raw file payload from toString()
    override fun toString(): String {
        return "IdentityDocumentUploadCommand(principal=${principal?.id}, tenantId=$tenantId, userId=$userId, documentType=$documentType, filename=$filename, mimeType=$mimeType, fileSizeBytes=${fileBytes.size}, idempotencyKey=$idempotencyKey, correlationId=$correlationId, causationId=$causationId, expectedVersion=$expectedVersion)"
    }
}

data class IdentityDocumentUploadResult(
    val resultId: UUID,
    val documentId: UUID,
    val status: DocumentUploadStatus,
    val sha256Checksum: String,
    val storageKey: String,
    val retentionExpiresAt: Instant,
    val isLegalHold: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val directEligibilityGranted: Boolean = false, // Untrusted client invariant
    val financialMutationPermitted: Boolean = false, // Financial rule invariant
    val evidenceReference: String,
    val message: String = "Retention/deletion/legal hold configured; no raw document in app logs/backend events.",
)

data class LegalHoldCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val documentId: UUID,
    val active: Boolean,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class PurgeDocumentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val documentId: UUID,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class DocumentAuditEvent(
    val eventId: UUID,
    val tenantId: String,
    val documentId: UUID?,
    val action: String,
    val performedBy: String,
    val reason: String?,
    val sha256Checksum: String?,
    val mimeType: String?,
    val fileSizeBytes: Long?,
    val correlationId: String,
    val causationId: String,
    val timestamp: Instant,
)

open class DocumentUploadException(val errorCode: String, message: String) : RuntimeException(message)
class InvalidDocumentTypeException(message: String) : DocumentUploadException("INVALID_DOCUMENT_TYPE", message)
class InvalidFileSizeException(message: String) : DocumentUploadException("INVALID_FILE_SIZE", message)
class MalwareDetectedException(val threatName: String?, message: String) : DocumentUploadException("MALWARE_DETECTED", message)
class IdorForbiddenException(message: String) : DocumentUploadException("FORBIDDEN_IDOR", message)
class LegalHoldActiveException(message: String) : DocumentUploadException("LEGAL_HOLD_ACTIVE", message)
class RetentionPeriodActiveException(message: String) : DocumentUploadException("RETENTION_PERIOD_ACTIVE", message)
class DocumentNotFoundException(message: String) : DocumentUploadException("DOCUMENT_NOT_FOUND", message)
class DependencyFailureException(message: String) : DocumentUploadException("DEPENDENCY_FAILURE", message)
class ConcurrencyConflictException(message: String) : DocumentUploadException("CONFLICT", message)
class UnauthorizedException(message: String) : DocumentUploadException("UNAUTHORIZED", message)

/**
 * Authoritative service managing secure identity-document upload, malware scanning,
 * IDOR prevention, encrypted storage abstraction, legal hold, and retention lifecycle.
 *
 * Semantic contract: "Retention/deletion/legal hold configured; no raw document in app logs/backend events."
 * Protected risk assertion: "type/size/malware/IDOR/log leak"
 */
class IdentityDocumentUploadService(
    private val clock: Clock = Clock.systemUTC(),
    private val malwareScanner: MalwareScannerPort = object : MalwareScannerPort {
        override fun scan(fileBytes: ByteArray, filename: String): MalwareScanOutcome {
            return MalwareScanOutcome(status = MalwareScanStatus.CLEAN)
        }
    },
    private val encryptedStorage: EncryptedStoragePort = object : EncryptedStoragePort {
        private val storageMap = ConcurrentHashMap<String, ByteArray>()
        override fun storeEncrypted(
            tenantId: String,
            userId: String,
            documentId: UUID,
            fileBytes: ByteArray,
            mimeType: String,
        ): EncryptedStorageReference {
            val key = "s3://secure-kyc-vault/enc/$tenantId/$userId/$documentId"
            storageMap[key] = fileBytes
            return EncryptedStorageReference(
                storageKey = key,
                encryptionKeyArn = "arn:aws:kms:us-east-1:123456789012:key/kyc-doc-storage",
            )
        }

        override fun delete(storageKey: String): Boolean {
            return storageMap.remove(storageKey) != null
        }
    },
    private val retentionDays: Long = 1825L, // 5 years
    private val maxFileSizeBytes: Long = 10L * 1024L * 1024L, // 10 MB
) {
    companion object {
        val ALLOWED_MIME_TYPES = setOf("image/jpeg", "image/png", "application/pdf")
    }

    private val documentsStore = ConcurrentHashMap<UUID, IdentityDocumentRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, IdentityDocumentUploadResult>>()
    private val auditLogs = mutableListOf<DocumentAuditEvent>()

    /**
     * Authoritative secure upload operation.
     */
    @Synchronized
    fun uploadDocument(command: IdentityDocumentUploadCommand): IdentityDocumentUploadResult {
        IdentityDocumentUploadBinding.checkBound()

        // 1. Authentication check
        val principal = command.principal ?: throw UnauthorizedException("Unauthenticated document upload")

        // 2. Tenant isolation check
        if (principal.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant access forbidden: principal tenant ${principal.tenantId} != ${command.tenantId}")
        }

        // 3. IDOR check: if principal is a player, cannot upload for another user
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.userId) {
            throw IdorForbiddenException("Player ${principal.id} cannot upload documents for user ${command.userId}")
        }

        // 4. If principal is admin, ensure admin has security or support role
        if (principal.kind == PrincipalKind.ADMIN && principal.roles.none { it in setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN, AdminRole.SUPPORT) }) {
            throw IdorForbiddenException("Admin lacks permission to upload identity documents")
        }

        // 5. Check idempotency
        val payloadSignature = computePayloadSignature(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedSignature, cachedResult) ->
            if (cachedSignature == payloadSignature) {
                return cachedResult
            } else {
                throw ConcurrencyConflictException("Idempotency key ${command.idempotencyKey} reused with conflicting payload")
            }
        }

        // 6. MIME type validation
        if (command.mimeType !in ALLOWED_MIME_TYPES) {
            throw InvalidDocumentTypeException("MIME type ${command.mimeType} is not permitted. Allowed: $ALLOWED_MIME_TYPES")
        }

        // 7. File size validation
        val size = command.fileBytes.size.toLong()
        if (size <= 0L) {
            throw InvalidFileSizeException("Document file cannot be empty")
        }
        if (size > maxFileSizeBytes) {
            throw InvalidFileSizeException("Document size $size exceeds maximum allowable size of $maxFileSizeBytes bytes")
        }

        // 8. Malware scanning
        val scanOutcome = try {
            malwareScanner.scan(command.fileBytes, command.filename)
        } catch (e: Exception) {
            throw DependencyFailureException("Malware scanner dependency error: ${e.message}")
        }

        when (scanOutcome.status) {
            MalwareScanStatus.INFECTED -> {
                // Record quarantine audit event (redacted, no file bytes)
                val sha = computeSha256(command.fileBytes)
                recordAudit(
                    tenantId = command.tenantId,
                    documentId = null,
                    action = "DOCUMENT_QUARANTINED_MALWARE",
                    performedBy = principal.id,
                    reason = "Malware detected: ${scanOutcome.threatName ?: "Unknown threat"}",
                    sha256 = sha,
                    mimeType = command.mimeType,
                    fileSize = size,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                )
                throw MalwareDetectedException(scanOutcome.threatName, "Document rejected: malware threat detected")
            }
            MalwareScanStatus.SCAN_FAILED -> {
                throw DependencyFailureException("Malware scanner returned failure status")
            }
            MalwareScanStatus.CLEAN -> {
                // Proceed
            }
        }

        // 9. Compute checksum & store in encrypted storage
        val sha256 = computeSha256(command.fileBytes)
        val documentId = UUID.randomUUID()
        val storageRef = try {
            encryptedStorage.storeEncrypted(
                tenantId = command.tenantId,
                userId = command.userId,
                documentId = documentId,
                fileBytes = command.fileBytes,
                mimeType = command.mimeType,
            )
        } catch (e: Exception) {
            throw DependencyFailureException("Encrypted storage failure: ${e.message}")
        }

        val now = clock.instant()
        val retentionExpiresAt = now.plus(Duration.ofDays(retentionDays))

        // 10. Persist document metadata
        val record = IdentityDocumentRecord(
            documentId = documentId,
            tenantId = command.tenantId,
            userId = command.userId,
            documentType = command.documentType,
            mimeType = command.mimeType,
            fileSizeBytes = size,
            sha256Checksum = sha256,
            storageKey = storageRef.storageKey,
            encryptionKeyArn = storageRef.encryptionKeyArn,
            status = DocumentUploadStatus.STORED,
            retentionExpiresAt = retentionExpiresAt,
            isLegalHold = false,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )
        documentsStore[documentId] = record

        // 11. Record redacted audit event
        recordAudit(
            tenantId = command.tenantId,
            documentId = documentId,
            action = "DOCUMENT_UPLOADED",
            performedBy = principal.id,
            reason = "KYC document uploaded (${command.documentType})",
            sha256 = sha256,
            mimeType = command.mimeType,
            fileSize = size,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val result = IdentityDocumentUploadResult(
            resultId = UUID.randomUUID(),
            documentId = documentId,
            status = DocumentUploadStatus.STORED,
            sha256Checksum = sha256,
            storageKey = storageRef.storageKey,
            retentionExpiresAt = retentionExpiresAt,
            isLegalHold = false,
            serverTime = now,
            serverVersion = 1L,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            evidenceReference = "evidence://kyc/docs/$documentId?ver=1",
        )

        idempotencyStore[command.idempotencyKey] = payloadSignature to result
        return result
    }

    /**
     * Configure or remove legal hold on a document.
     */
    @Synchronized
    fun setLegalHold(command: LegalHoldCommand): IdentityDocumentRecord {
        IdentityDocumentUploadBinding.checkBound()

        val principal = command.principal ?: throw UnauthorizedException("Unauthenticated legal hold operation")
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN, AdminRole.AUDITOR) }) {
            throw IdorForbiddenException("Only authorized compliance/security admin may alter legal hold")
        }
        if (principal.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant access forbidden")
        }

        val record = documentsStore[command.documentId]
            ?: throw DocumentNotFoundException("Document ${command.documentId} not found")

        if (record.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant document access forbidden")
        }

        if (record.serverVersion != command.expectedVersion) {
            throw ConcurrencyConflictException("Version conflict: expected ${command.expectedVersion} but found ${record.serverVersion}")
        }

        val now = clock.instant()
        val updated = record.copy(
            isLegalHold = command.active,
            legalHoldReason = if (command.active) command.reason else null,
            legalHoldPlacedBy = if (command.active) principal.id else null,
            legalHoldPlacedAt = if (command.active) now else null,
            serverVersion = record.serverVersion + 1,
            updatedAt = now,
        )
        documentsStore[command.documentId] = updated

        recordAudit(
            tenantId = command.tenantId,
            documentId = command.documentId,
            action = if (command.active) "LEGAL_HOLD_PLACED" else "LEGAL_HOLD_RELEASED",
            performedBy = principal.id,
            reason = command.reason,
            sha256 = record.sha256Checksum,
            mimeType = record.mimeType,
            fileSize = record.fileSizeBytes,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        return updated
    }

    /**
     * Purge / delete document after retention expires and if no legal hold exists.
     */
    @Synchronized
    fun purgeDocument(command: PurgeDocumentCommand): IdentityDocumentRecord {
        IdentityDocumentUploadBinding.checkBound()

        val principal = command.principal ?: throw UnauthorizedException("Unauthenticated purge operation")
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN) }) {
            throw IdorForbiddenException("Only authorized security admin may purge documents")
        }
        if (principal.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant access forbidden")
        }

        val record = documentsStore[command.documentId]
            ?: throw DocumentNotFoundException("Document ${command.documentId} not found")

        if (record.tenantId != command.tenantId) {
            throw IdorForbiddenException("Cross-tenant document access forbidden")
        }

        if (record.isLegalHold) {
            throw LegalHoldActiveException("Document ${command.documentId} is under legal hold and cannot be purged")
        }

        val now = clock.instant()
        if (now.isBefore(record.retentionExpiresAt)) {
            throw RetentionPeriodActiveException("Document ${command.documentId} retention period expires at ${record.retentionExpiresAt}, cannot purge before expiration")
        }

        if (record.serverVersion != command.expectedVersion) {
            throw ConcurrencyConflictException("Version conflict: expected ${command.expectedVersion} but found ${record.serverVersion}")
        }

        // Delete from storage
        encryptedStorage.delete(record.storageKey)

        val updated = record.copy(
            status = DocumentUploadStatus.PURGED,
            serverVersion = record.serverVersion + 1,
            updatedAt = now,
        )
        documentsStore[command.documentId] = updated

        recordAudit(
            tenantId = command.tenantId,
            documentId = command.documentId,
            action = "DOCUMENT_PURGED",
            performedBy = principal.id,
            reason = command.reason,
            sha256 = record.sha256Checksum,
            mimeType = record.mimeType,
            fileSize = record.fileSizeBytes,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        return updated
    }

    fun getDocument(tenantId: String, documentId: UUID): IdentityDocumentRecord? {
        val record = documentsStore[documentId] ?: return null
        if (record.tenantId != tenantId) return null
        return record
    }

    fun getAuditLogs(): List<DocumentAuditEvent> = auditLogs.toList()

    private fun recordAudit(
        tenantId: String,
        documentId: UUID?,
        action: String,
        performedBy: String,
        reason: String?,
        sha256: String?,
        mimeType: String?,
        fileSize: Long?,
        correlationId: String,
        causationId: String,
    ) {
        auditLogs.add(
            DocumentAuditEvent(
                eventId = UUID.randomUUID(),
                tenantId = tenantId,
                documentId = documentId,
                action = action,
                performedBy = performedBy,
                reason = reason,
                sha256Checksum = sha256,
                mimeType = mimeType,
                fileSizeBytes = fileSize,
                correlationId = correlationId,
                causationId = causationId,
                timestamp = clock.instant(),
            )
        )
    }

    private fun computeSha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(bytes)
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun computePayloadSignature(command: IdentityDocumentUploadCommand): String {
        val content = "${command.tenantId}:${command.userId}:${command.documentType}:${command.mimeType}:${command.filename}:${computeSha256(command.fileBytes)}"
        return computeSha256(content.toByteArray(Charsets.UTF_8))
    }
}
