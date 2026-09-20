package com.slotting.admin.support

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Traceability binding for SUPPORT-001-03: Secure support notes and attachments.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "unverified disclosure/attachment abuse/SLA invisible".
 */
object SecureSupportNotesAttachmentsBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified disclosure/attachment abuse/SLA invisible")
        }
    }
}

/**
 * Outcome-specific semantic contract for SUPPORT-001-03.
 */
const val SECURE_SUPPORT_NOTES_ATTACHMENTS_CONTRACT =
    "Notes do not mutate finance; attachments scanned; identity checks and access audited."

/**
 * Classification level for support notes.
 */
enum class NoteClassification {
    PUBLIC_CUSTOMER,
    TEAM_COLLABORATION,
    INTERNAL_RESTRICTED,
    AUDIT_COMPLIANCE
}

/**
 * Malware scan status for attachments.
 */
enum class SecureAttachmentScanStatus {
    CLEAN,
    INFECTED,
    QUARANTINED,
    FAILED
}

/**
 * Requester identity status for support session.
 */
enum class RequesterIdentityState {
    IDENTITY_VERIFIED,
    IDENTITY_UNVERIFIED,
    IDENTITY_SUSPICIOUS
}

/**
 * SLA compliance state for document review.
 */
enum class SecureAttachmentSlaStatus {
    WITHIN_SLA,
    AT_RISK,
    BREACHED
}

/**
 * Document type classification for support attachments.
 */
enum class SupportDocumentType {
    IDENTITY_ID_PROOF,
    PAYMENT_RECEIPT,
    BANK_STATEMENT,
    GAMEPLAY_LOG,
    CORRESPONDENCE,
    GENERAL_SUPPORT
}

/**
 * Case communication note.
 * Invariant: Notes NEVER mutate finance or create ledger balance adjustments.
 */
data class SecureNote(
    val noteId: String,
    val caseId: String,
    val tenantId: String,
    val authorId: String,
    val authorRole: String,
    val classification: NoteClassification,
    val content: String,
    val isInternal: Boolean,
    val containsPii: Boolean = false,
    val createdAt: Instant,
    val serverVersion: Long = 1L
)

/**
 * Secure attachment descriptor after malware scan verification.
 */
data class SecureAttachment(
    val attachmentId: String,
    val caseId: String,
    val tenantId: String,
    val fileName: String,
    val mimeType: String,
    val fileSize: Long,
    val sha256Hex: String,
    val scanStatus: SecureAttachmentScanStatus,
    val isQuarantined: Boolean,
    val documentType: SupportDocumentType,
    val encryptedPayloadRef: String,
    val uploadedBy: String,
    val uploadedAt: Instant,
    val scanDetails: String,
    val reviewSlaDueAt: Instant,
    val reviewedAt: Instant? = null,
    val slaStatus: SecureAttachmentSlaStatus = SecureAttachmentSlaStatus.WITHIN_SLA,
    val serverVersion: Long = 1L
)

/**
 * Container representing case context for secure notes and attachments.
 */
data class SecureCaseContainer(
    val caseId: String,
    val tenantId: String,
    val playerReference: String,
    val identityState: RequesterIdentityState = RequesterIdentityState.IDENTITY_UNVERIFIED,
    val verifiedAt: Instant? = null,
    val verificationMethod: String? = null,
    val notes: List<SecureNote> = emptyList(),
    val attachments: List<SecureAttachment> = emptyList(),
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant
)

/**
 * Audit actions for secure support notes and attachments.
 */
enum class SecureSupportAuditAction {
    CASE_CONTAINER_INITIALIZED,
    NOTE_ADDED,
    NOTE_VIEWED,
    ATTACHMENT_SCANNED,
    ATTACHMENT_QUARANTINED,
    ATTACHMENT_ACCESSED,
    IDENTITY_VERIFIED,
    IDENTITY_CHECK_FAILED,
    NOTES_ATTACHMENTS_VIEWED,
    UNVERIFIED_DISCLOSURE_PREVENTED,
    FINANCIAL_MUTATION_REJECTED,
    SLA_EVALUATED,
    SLA_BREACH_ALERTED
}

/**
 * Structured audit record for secure support notes and attachments.
 * Guarantees identity checks and access are audited.
 */
data class SecureSupportAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val caseId: String,
    val principalId: String,
    val action: SecureSupportAuditAction,
    val identityCheckPerformed: Boolean,
    val success: Boolean,
    val timestamp: Instant,
    val correlationId: String,
    val causationId: String,
    val detailsRedacted: String,
    val alertTriggered: Boolean = false
)

/**
 * Alert record for security, attachment quarantine, or SLA breaches.
 */
data class SecureSupportAlertRecord(
    val alertId: String,
    val tenantId: String,
    val caseId: String,
    val severity: String, // "INFO", "WARN", "CRITICAL"
    val alertType: String,
    val message: String,
    val correlationId: String,
    val timestamp: Instant
)

// =============================================================================
// Malware Scanner Port & Adapters
// =============================================================================

data class SecureAttachmentScanResult(
    val isClean: Boolean,
    val threatName: String? = null,
    val scanEngineVersion: String = "v2026.09-antivirus-support"
)

interface SecureAttachmentScanner {
    fun scan(fileName: String, content: ByteArray): SecureAttachmentScanResult
}

class FakeSecureAttachmentScanner : SecureAttachmentScanner {
    @Volatile var shouldFail: Boolean = false
    @Volatile var simulateTimeout: Boolean = false
    @Volatile var simulateInfection: Boolean = false

    override fun scan(fileName: String, content: ByteArray): SecureAttachmentScanResult {
        if (simulateTimeout) {
            throw IllegalStateException("Secure attachment scanner timeout")
        }
        if (shouldFail) {
            throw IllegalStateException("Secure attachment scanner service unavailable")
        }
        if (simulateInfection || fileName.contains("eicar", ignoreCase = true) ||
            fileName.endsWith(".exe", ignoreCase = true) || fileName.endsWith(".bat", ignoreCase = true) ||
            fileName.endsWith(".sh", ignoreCase = true) || fileName.endsWith(".cmd", ignoreCase = true) ||
            fileName.endsWith(".ps1", ignoreCase = true) || fileName.endsWith(".vbs", ignoreCase = true) ||
            fileName.endsWith(".jar", ignoreCase = true)) {
            return SecureAttachmentScanResult(isClean = false, threatName = "Threat.Malware.Generic")
        }
        return SecureAttachmentScanResult(isClean = true)
    }
}

class SandboxSecureAttachmentScanner : SecureAttachmentScanner {
    override fun scan(fileName: String, content: ByteArray): SecureAttachmentScanResult {
        return SecureAttachmentScanResult(isClean = true, threatName = null)
    }
}

// =============================================================================
// Store Port & In-Memory Store
// =============================================================================

interface SecureSupportNotesAttachmentsStore {
    fun saveCase(case: SecureCaseContainer)
    fun findCase(tenantId: String, caseId: String): SecureCaseContainer?
    fun listCases(tenantId: String): List<SecureCaseContainer>
    fun recordAudit(audit: SecureSupportAuditRecord)
    fun getAudits(tenantId: String): List<SecureSupportAuditRecord>
    fun recordAlert(alert: SecureSupportAlertRecord)
    fun getAlerts(tenantId: String): List<SecureSupportAlertRecord>
    fun recordOutbox(outbox: OutboxEvent)
    fun getOutbox(): List<OutboxEvent>
    fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

class InMemorySecureSupportNotesAttachmentsStore : SecureSupportNotesAttachmentsStore {
    private val cases = ConcurrentHashMap<String, SecureCaseContainer>()
    private val audits = mutableListOf<SecureSupportAuditRecord>()
    private val alerts = mutableListOf<SecureSupportAlertRecord>()
    private val outbox = mutableListOf<OutboxEvent>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, Any>>()

    private fun caseKey(tenantId: String, caseId: String): String = "$tenantId::$caseId"
    private fun idempKey(tenantId: String, idempotencyKey: String): String = "$tenantId::$idempotencyKey"

    override fun saveCase(case: SecureCaseContainer) {
        cases[caseKey(case.tenantId, case.caseId)] = case
    }

    override fun findCase(tenantId: String, caseId: String): SecureCaseContainer? {
        return cases[caseKey(tenantId, caseId)]
    }

    override fun listCases(tenantId: String): List<SecureCaseContainer> {
        return cases.values.filter { it.tenantId == tenantId }
    }

    @Synchronized
    override fun recordAudit(audit: SecureSupportAuditRecord) {
        audits.add(audit)
    }

    @Synchronized
    override fun getAudits(tenantId: String): List<SecureSupportAuditRecord> {
        return audits.filter { it.tenantId == tenantId }.toList()
    }

    @Synchronized
    override fun recordAlert(alert: SecureSupportAlertRecord) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(tenantId: String): List<SecureSupportAlertRecord> {
        return alerts.filter { it.tenantId == tenantId }.toList()
    }

    @Synchronized
    override fun recordOutbox(outboxEvent: OutboxEvent) {
        outbox.add(outboxEvent)
    }

    @Synchronized
    override fun getOutbox(): List<OutboxEvent> {
        return outbox.toList()
    }

    override fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>? {
        return idempotency[idempKey(tenantId, idempotencyKey)]
    }

    override fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any) {
        idempotency[idempKey(tenantId, idempotencyKey)] = Pair(fingerprint, result)
    }
}

// =============================================================================
// Commands & Results
// =============================================================================

data class InitializeCaseContainerCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val playerReference: String,
    val initialIdentityState: RequesterIdentityState = RequesterIdentityState.IDENTITY_UNVERIFIED,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class AddSecureNoteCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val classification: NoteClassification = NoteClassification.TEAM_COLLABORATION,
    val content: String,
    val isInternal: Boolean = true,
    val containsPii: Boolean = false,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesFinance: Boolean = false,
    val balanceAdjustmentMinorUnits: Long? = null,
    val mutatesMoney: Boolean = false
)

data class UploadSecureAttachmentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val fileName: String,
    val mimeType: String,
    val documentType: SupportDocumentType = SupportDocumentType.GENERAL_SUPPORT,
    val contentBytes: ByteArray,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class AccessSecureAttachmentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val attachmentId: String,
    val correlationId: String,
    val causationId: String
)

data class VerifyRequesterIdentityCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val verificationMethod: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class GetSecureCaseNotesAndAttachmentsCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val correlationId: String,
    val causationId: String
)

data class EvaluateAttachmentReviewSlaCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val attachmentId: String,
    val asOfTime: Instant,
    val correlationId: String,
    val causationId: String
)

data class InitializeCaseContainerResult(
    val resultId: UUID,
    val caseId: String,
    val tenantId: String,
    val playerReference: String,
    val identityState: RequesterIdentityState,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class AddSecureNoteResult(
    val resultId: UUID,
    val caseId: String,
    val noteId: String,
    val authorRole: String,
    val classification: NoteClassification,
    val notesCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class UploadSecureAttachmentResult(
    val resultId: UUID,
    val caseId: String,
    val attachmentId: String,
    val fileName: String,
    val sha256Hex: String,
    val scanStatus: SecureAttachmentScanStatus,
    val attachmentsCount: Int,
    val reviewSlaDueAt: Instant,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class AccessSecureAttachmentResult(
    val resultId: UUID,
    val caseId: String,
    val attachmentId: String,
    val fileName: String,
    val mimeType: String,
    val fileSize: Long,
    val sha256Hex: String,
    val encryptedPayloadRef: String,
    val scanStatus: SecureAttachmentScanStatus,
    val accessedAt: Instant,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class VerifyRequesterIdentityResult(
    val resultId: UUID,
    val caseId: String,
    val identityState: RequesterIdentityState,
    val verifiedAt: Instant,
    val verificationMethod: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class SecureCaseNotesAndAttachmentsViewResult(
    val caseId: String,
    val tenantId: String,
    val playerReferenceRedacted: String,
    val identityState: RequesterIdentityState,
    val notes: List<SecureNote>,
    val attachments: List<SecureAttachment>,
    val sensitiveDataDisclosed: Boolean,
    val evidenceReference: String
)

data class AttachmentSlaEvaluationResult(
    val caseId: String,
    val attachmentId: String,
    val slaStatus: SecureAttachmentSlaStatus,
    val remainingTimeMs: Long,
    val isBreached: Boolean,
    val isAtRisk: Boolean,
    val alertEmitted: Boolean,
    val evidenceReference: String
)

// =============================================================================
// Authoritative Service
// =============================================================================

class SecureSupportNotesAttachmentsService(
    private val store: SecureSupportNotesAttachmentsStore,
    private val scanner: SecureAttachmentScanner,
    private val clock: Clock
) {
    private val lock = Any()

    companion object {
        const val MAX_FILE_SIZE_BYTES = 10L * 1024L * 1024L // 10MB
        val PROHIBITED_EXTENSIONS = listOf(".exe", ".bat", ".cmd", ".sh", ".vbs", ".js", ".jar", ".ps1", ".scr")
        val ALLOWED_MIME_TYPES = setOf(
            "application/pdf",
            "image/png",
            "image/jpeg",
            "image/webp",
            "text/plain",
            "text/csv",
            "application/json",
            "application/octet-stream"
        )
    }

    /**
     * Initializes a case container for holding secure notes and attachments.
     */
    fun initializeCaseContainer(command: InitializeCaseContainerCommand): InitializeCaseContainerResult = synchronized(lock) {
        SecureSupportNotesAttachmentsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.caseId.isBlank() || command.playerReference.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "INIT:${command.tenantId}:${command.caseId}:${command.playerReference}:${command.expectedVersion}"
        val cached = checkIdempotency<InitializeCaseContainerResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val now = clock.instant()
        val container = SecureCaseContainer(
            caseId = command.caseId,
            tenantId = command.tenantId,
            playerReference = command.playerReference,
            identityState = command.initialIdentityState,
            createdAt = now,
            updatedAt = now,
            serverVersion = 1L
        )
        store.saveCase(container)

        val resultId = UUID.randomUUID()
        val evidenceRef = "secure-case-init:${command.tenantId}:${command.caseId}:v1:$resultId"
        val result = InitializeCaseContainerResult(
            resultId = resultId,
            caseId = command.caseId,
            tenantId = command.tenantId,
            playerReference = command.playerReference,
            identityState = command.initialIdentityState,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            SecureSupportAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = command.principal!!.id,
                action = SecureSupportAuditAction.CASE_CONTAINER_INITIALIZED,
                identityCheckPerformed = command.initialIdentityState == RequesterIdentityState.IDENTITY_VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Initialized case container ${command.caseId}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Adds an internal, customer, or audit note to the case.
     * Enforces semantic contract: Notes NEVER mutate finance or create balance adjustments!
     */
    fun addSecureNote(command: AddSecureNoteCommand): AddSecureNoteResult = synchronized(lock) {
        SecureSupportNotesAttachmentsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        // Strict semantic invariant: Notes do not mutate finance!
        if (command.mutatesFinance || command.balanceAdjustmentMinorUnits != null || command.mutatesMoney) {
            store.recordAudit(
                SecureSupportAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    caseId = command.caseId,
                    principalId = command.principal!!.id,
                    action = SecureSupportAuditAction.FINANCIAL_MUTATION_REJECTED,
                    identityCheckPerformed = false,
                    success = false,
                    timestamp = clock.instant(),
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Rejected financial mutation attempt via note",
                    alertTriggered = true
                )
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.content.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "NOTE:${command.tenantId}:${command.caseId}:${command.content}:${command.isInternal}:${command.classification}:${command.expectedVersion}"
        val cached = checkIdempotency<AddSecureNoteResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val principal = command.principal!!
        // Player cannot post internal notes
        if (principal.kind == PrincipalKind.PLAYER && command.isInternal) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val noteId = "note-${UUID.randomUUID()}"
        val authorRole = principal.roles.joinToString(",") { it.name }.ifEmpty { principal.kind.name }

        val note = SecureNote(
            noteId = noteId,
            caseId = command.caseId,
            tenantId = command.tenantId,
            authorId = principal.id,
            authorRole = authorRole,
            classification = command.classification,
            content = command.content,
            isInternal = command.isInternal,
            containsPii = command.containsPii,
            createdAt = now,
            serverVersion = existing.serverVersion + 1
        )

        val updatedCase = existing.copy(
            notes = existing.notes + note,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveCase(updatedCase)

        val resultId = UUID.randomUUID()
        val evidenceRef = "secure-note:${command.tenantId}:${command.caseId}:$noteId:$resultId"
        val result = AddSecureNoteResult(
            resultId = resultId,
            caseId = command.caseId,
            noteId = noteId,
            authorRole = authorRole,
            classification = command.classification,
            notesCount = updatedCase.notes.size,
            serverTime = now,
            serverVersion = updatedCase.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            SecureSupportAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = principal.id,
                action = SecureSupportAuditAction.NOTE_ADDED,
                identityCheckPerformed = existing.identityState == RequesterIdentityState.IDENTITY_VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Added note $noteId classification=${command.classification} internal=${command.isInternal}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Uploads an attachment after mandatory malware and format scanning.
     * Rejects unscanned, dangerous, or infected files; infected attachments are quarantined.
     */
    fun uploadSecureAttachment(command: UploadSecureAttachmentCommand): UploadSecureAttachmentResult = synchronized(lock) {
        SecureSupportNotesAttachmentsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.fileName.isBlank() || command.contentBytes.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.contentBytes.size > MAX_FILE_SIZE_BYTES) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate prohibited dangerous extensions
        if (PROHIBITED_EXTENSIONS.any { command.fileName.endsWith(it, ignoreCase = true) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "ATTACHMENT:${command.tenantId}:${command.caseId}:${command.fileName}:${command.contentBytes.size}:${command.expectedVersion}"
        val cached = checkIdempotency<UploadSecureAttachmentResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Perform mandatory malware scan (fail-closed if scanner fails)
        val scanResult = try {
            scanner.scan(command.fileName, command.contentBytes)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant()
        val sha256Hex = sha256Hex(command.contentBytes)

        if (!scanResult.isClean) {
            // Quarantine infected file, emit critical security alert, reject attachment upload
            val alert = SecureSupportAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                caseId = command.caseId,
                severity = "CRITICAL",
                alertType = "ATTACHMENT_MALWARE_DETECTED",
                message = "Malware threat detected in attachment ${command.fileName}: ${scanResult.threatName}. Quarantined.",
                correlationId = command.correlationId,
                timestamp = now
            )
            store.recordAlert(alert)

            store.recordAudit(
                SecureSupportAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    caseId = command.caseId,
                    principalId = command.principal!!.id,
                    action = SecureSupportAuditAction.ATTACHMENT_QUARANTINED,
                    identityCheckPerformed = existing.identityState == RequesterIdentityState.IDENTITY_VERIFIED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Quarantined malicious file ${command.fileName} threat=${scanResult.threatName}",
                    alertTriggered = true
                )
            )

            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val attachmentId = "att-${UUID.randomUUID()}"
        val encryptedPayloadRef = "enc://payloads/${command.tenantId}/${command.caseId}/$attachmentId.dat"
        val reviewSlaHours = calculateDocumentReviewSlaHours(command.documentType)
        val reviewSlaDueAt = now.plus(Duration.ofHours(reviewSlaHours))

        val attachment = SecureAttachment(
            attachmentId = attachmentId,
            caseId = command.caseId,
            tenantId = command.tenantId,
            fileName = command.fileName,
            mimeType = command.mimeType,
            fileSize = command.contentBytes.size.toLong(),
            sha256Hex = sha256Hex,
            scanStatus = SecureAttachmentScanStatus.CLEAN,
            isQuarantined = false,
            documentType = command.documentType,
            encryptedPayloadRef = encryptedPayloadRef,
            uploadedBy = command.principal!!.id,
            uploadedAt = now,
            scanDetails = "Clean scan engine: ${scanResult.scanEngineVersion}",
            reviewSlaDueAt = reviewSlaDueAt,
            slaStatus = SecureAttachmentSlaStatus.WITHIN_SLA,
            serverVersion = existing.serverVersion + 1
        )

        val updatedCase = existing.copy(
            attachments = existing.attachments + attachment,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveCase(updatedCase)

        val resultId = UUID.randomUUID()
        val evidenceRef = "secure-att:${command.tenantId}:${command.caseId}:$attachmentId:$resultId"
        val result = UploadSecureAttachmentResult(
            resultId = resultId,
            caseId = command.caseId,
            attachmentId = attachmentId,
            fileName = command.fileName,
            sha256Hex = sha256Hex,
            scanStatus = SecureAttachmentScanStatus.CLEAN,
            attachmentsCount = updatedCase.attachments.size,
            reviewSlaDueAt = reviewSlaDueAt,
            serverTime = now,
            serverVersion = updatedCase.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            SecureSupportAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = command.principal.id,
                action = SecureSupportAuditAction.ATTACHMENT_SCANNED,
                identityCheckPerformed = existing.identityState == RequesterIdentityState.IDENTITY_VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Attached clean file ${command.fileName} sha256=$sha256Hex reviewDue=$reviewSlaDueAt",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Accesses or downloads a secure attachment with audited access and quarantine protection.
     */
    fun accessSecureAttachment(command: AccessSecureAttachmentCommand): AccessSecureAttachmentResult = synchronized(lock) {
        SecureSupportNotesAttachmentsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val principal = command.principal!!
        // Player check: only case owner and verified identity allowed to access sensitive attachments
        if (principal.kind == PrincipalKind.PLAYER) {
            if (principal.id != existing.playerReference) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            if (existing.identityState != RequesterIdentityState.IDENTITY_VERIFIED) {
                store.recordAudit(
                    SecureSupportAuditRecord(
                        auditId = UUID.randomUUID(),
                        tenantId = command.tenantId,
                        caseId = command.caseId,
                        principalId = principal.id,
                        action = SecureSupportAuditAction.UNVERIFIED_DISCLOSURE_PREVENTED,
                        identityCheckPerformed = true,
                        success = false,
                        timestamp = clock.instant(),
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        detailsRedacted = "Prevented unverified attachment download for player ${principal.id}",
                        alertTriggered = false
                    )
                )
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }

        val attachment = existing.attachments.find { it.attachmentId == command.attachmentId }
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (attachment.isQuarantined || attachment.scanStatus == SecureAttachmentScanStatus.INFECTED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "secure-att-access:${command.tenantId}:${command.caseId}:${attachment.attachmentId}:$resultId"

        store.recordAudit(
            SecureSupportAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = principal.id,
                action = SecureSupportAuditAction.ATTACHMENT_ACCESSED,
                identityCheckPerformed = existing.identityState == RequesterIdentityState.IDENTITY_VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Accessed attachment ${attachment.attachmentId} file=${attachment.fileName}",
                alertTriggered = false
            )
        )

        return AccessSecureAttachmentResult(
            resultId = resultId,
            caseId = command.caseId,
            attachmentId = attachment.attachmentId,
            fileName = attachment.fileName,
            mimeType = attachment.mimeType,
            fileSize = attachment.fileSize,
            sha256Hex = attachment.sha256Hex,
            encryptedPayloadRef = attachment.encryptedPayloadRef,
            scanStatus = attachment.scanStatus,
            accessedAt = now,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )
    }

    /**
     * Verifies the requester identity for the support case.
     */
    fun verifyRequesterIdentity(command: VerifyRequesterIdentityCommand): VerifyRequesterIdentityResult = synchronized(lock) {
        SecureSupportNotesAttachmentsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.verificationMethod.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "VERIFY_ID:${command.tenantId}:${command.caseId}:${command.verificationMethod}:${command.expectedVersion}"
        val cached = checkIdempotency<VerifyRequesterIdentityResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val updatedCase = existing.copy(
            identityState = RequesterIdentityState.IDENTITY_VERIFIED,
            verifiedAt = now,
            verificationMethod = command.verificationMethod,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveCase(updatedCase)

        val resultId = UUID.randomUUID()
        val evidenceRef = "secure-id-verify:${command.tenantId}:${command.caseId}:$resultId"
        val result = VerifyRequesterIdentityResult(
            resultId = resultId,
            caseId = command.caseId,
            identityState = RequesterIdentityState.IDENTITY_VERIFIED,
            verifiedAt = now,
            verificationMethod = command.verificationMethod,
            serverTime = now,
            serverVersion = updatedCase.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            SecureSupportAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = command.principal!!.id,
                action = SecureSupportAuditAction.IDENTITY_VERIFIED,
                identityCheckPerformed = true,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Verified requester identity for case ${command.caseId} method=${command.verificationMethod}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Retrieves case notes and attachments with audited access and unverified disclosure protection.
     */
    fun getSecureCaseNotesAndAttachments(command: GetSecureCaseNotesAndAttachmentsCommand): SecureCaseNotesAndAttachmentsViewResult = synchronized(lock) {
        SecureSupportNotesAttachmentsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val principal = command.principal!!
        if (principal.kind == PrincipalKind.PLAYER && principal.id != existing.playerReference) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val isVerified = existing.identityState == RequesterIdentityState.IDENTITY_VERIFIED

        // Audit view access
        store.recordAudit(
            SecureSupportAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = principal.id,
                action = SecureSupportAuditAction.NOTES_ATTACHMENTS_VIEWED,
                identityCheckPerformed = isVerified,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Viewed notes and attachments for case ${command.caseId} verified=$isVerified",
                alertTriggered = false
            )
        )

        // Protect against unverified disclosure:
        // If player is unverified: playerReference is redacted, PII notes are redacted to REDACTED-UNVERIFIED
        val redactedPlayerRef = if (isVerified || principal.kind == PrincipalKind.ADMIN) existing.playerReference else "REDACTED-UNVERIFIED"

        val filteredNotes = existing.notes
            .filter { !it.isInternal || principal.kind == PrincipalKind.ADMIN }
            .map { note ->
                if (!isVerified && principal.kind == PrincipalKind.PLAYER && note.containsPii) {
                    note.copy(content = "REDACTED-UNVERIFIED")
                } else {
                    note
                }
            }

        val filteredAttachments = existing.attachments.filter { !it.isQuarantined }
        val evidenceRef = "secure-view:${command.tenantId}:${command.caseId}:v${existing.serverVersion}"

        return SecureCaseNotesAndAttachmentsViewResult(
            caseId = existing.caseId,
            tenantId = existing.tenantId,
            playerReferenceRedacted = redactedPlayerRef,
            identityState = existing.identityState,
            notes = filteredNotes,
            attachments = filteredAttachments,
            sensitiveDataDisclosed = isVerified,
            evidenceReference = evidenceRef
        )
    }

    /**
     * Evaluates attachment review SLA and emits alerts on at-risk or breached status.
     * Prevents invisible SLA failures.
     */
    fun evaluateAttachmentReviewSla(command: EvaluateAttachmentReviewSlaCommand): AttachmentSlaEvaluationResult = synchronized(lock) {
        SecureSupportNotesAttachmentsBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val attachment = existing.attachments.find { it.attachmentId == command.attachmentId }
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val asOf = command.asOfTime
        val dueAt = attachment.reviewSlaDueAt
        val remainingMs = Duration.between(asOf, dueAt).toMillis()

        val isBreached = attachment.reviewedAt == null && asOf.isAfter(dueAt)
        val isAtRisk = !isBreached && attachment.reviewedAt == null && remainingMs < Duration.ofHours(1).toMillis()

        val slaStatus = when {
            isBreached -> SecureAttachmentSlaStatus.BREACHED
            isAtRisk -> SecureAttachmentSlaStatus.AT_RISK
            else -> SecureAttachmentSlaStatus.WITHIN_SLA
        }

        var alertEmitted = false
        if (isBreached) {
            val alert = SecureSupportAlertRecord(
                alertId = "sla-alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                caseId = command.caseId,
                severity = "CRITICAL",
                alertType = "ATTACHMENT_REVIEW_SLA_BREACHED",
                message = "Attachment review SLA breached for ${attachment.fileName} on case ${command.caseId}",
                correlationId = command.correlationId,
                timestamp = asOf
            )
            store.recordAlert(alert)
            alertEmitted = true

            store.recordAudit(
                SecureSupportAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    caseId = command.caseId,
                    principalId = command.principal!!.id,
                    action = SecureSupportAuditAction.SLA_BREACH_ALERTED,
                    identityCheckPerformed = true,
                    success = true,
                    timestamp = asOf,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "SLA breached for attachment ${attachment.attachmentId}",
                    alertTriggered = true
                )
            )
        } else if (isAtRisk) {
            val alert = SecureSupportAlertRecord(
                alertId = "sla-alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                caseId = command.caseId,
                severity = "WARN",
                alertType = "ATTACHMENT_REVIEW_SLA_AT_RISK",
                message = "Attachment review SLA at risk (<1h remaining) for ${attachment.fileName}",
                correlationId = command.correlationId,
                timestamp = asOf
            )
            store.recordAlert(alert)
            alertEmitted = true
        }

        val updatedAttachment = attachment.copy(slaStatus = slaStatus)
        val updatedAttachments = existing.attachments.map {
            if (it.attachmentId == attachment.attachmentId) updatedAttachment else it
        }
        store.saveCase(existing.copy(attachments = updatedAttachments))

        val evidenceRef = "sla-eval:${command.tenantId}:${command.caseId}:${attachment.attachmentId}:$slaStatus"
        return AttachmentSlaEvaluationResult(
            caseId = command.caseId,
            attachmentId = attachment.attachmentId,
            slaStatus = slaStatus,
            remainingTimeMs = remainingMs,
            isBreached = isBreached,
            isAtRisk = isAtRisk,
            alertEmitted = alertEmitted,
            evidenceReference = evidenceRef
        )
    }

    // =========================================================================
    // Helper Validations
    // =========================================================================

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String, requireAdmin: Boolean) {
        if (principal == null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }
        if (principal.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (requireAdmin && principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    private fun validateCommonInvariants(idempotencyKey: String, expectedVersion: Long, mutatesMoney: Boolean) {
        if (idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (mutatesMoney) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> checkIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String): T? {
        val cached = store.findIdempotentResult(tenantId, idempotencyKey) ?: return null
        if (cached.first != fingerprint) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        return cached.second as T
    }

    private fun calculateDocumentReviewSlaHours(docType: SupportDocumentType): Long {
        return when (docType) {
            SupportDocumentType.IDENTITY_ID_PROOF -> 2L
            SupportDocumentType.PAYMENT_RECEIPT -> 4L
            SupportDocumentType.BANK_STATEMENT -> 8L
            SupportDocumentType.GAMEPLAY_LOG -> 12L
            SupportDocumentType.CORRESPONDENCE -> 24L
            SupportDocumentType.GENERAL_SUPPORT -> 24L
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
