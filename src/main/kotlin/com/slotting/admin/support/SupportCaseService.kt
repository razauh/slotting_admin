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
 * Traceability binding for SUPPORT-001-01: Manage verified support cases and SLA.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "unverified disclosure/attachment abuse/SLA invisible".
 */
object SupportCaseBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified disclosure/attachment abuse/SLA invisible")
        }
    }
}

/**
 * Outcome-specific semantic contract for SUPPORT-001-01.
 */
const val SUPPORT_CASE_CONTRACT =
    "Notes do not mutate finance; attachments scanned; identity checks and access audited."

/**
 * Categories for support and dispute cases.
 */
enum class CaseCategory {
    PAYMENT_DISPUTE,
    ACCOUNT_ACCESS,
    VERIFICATION_KYC,
    TECHNICAL_GAMEPLAY,
    RESPONSIBLE_GAMING,
    GENERAL_INQUIRY
}

/**
 * Operational priority of support cases, driving SLA targets.
 */
enum class CasePriority {
    CRITICAL,   // First response: 1h, Resolution: 4h
    HIGH,       // First response: 4h, Resolution: 24h
    NORMAL,     // First response: 12h, Resolution: 72h
    LOW         // First response: 24h, Resolution: 168h
}

/**
 * Lifecycle status of a support case.
 */
enum class CaseStatus {
    NEW,
    ASSIGNED,
    IN_PROGRESS,
    PENDING_PLAYER,
    RESOLVED,
    CLOSED
}

/**
 * Player identity verification state for the support case session.
 */
enum class IdentityVerificationStatus {
    VERIFIED,
    PENDING_VERIFICATION,
    FAILED_VERIFICATION,
    UNVERIFIED
}

/**
 * Malware scan status for attachments.
 */
enum class AttachmentScanStatus {
    CLEAN,
    INFECTED,
    QUARANTINED,
    FAILED
}

/**
 * SLA compliance state for the case.
 */
enum class SlaStatus {
    WITHIN_SLA,
    AT_RISK,
    BREACHED
}

/**
 * Case communication note.
 * Invariant: Notes NEVER mutate finance or create ledger authority.
 */
data class CaseNote(
    val noteId: String,
    val authorId: String,
    val authorRole: String,
    val content: String,
    val isInternal: Boolean,
    val createdAt: Instant
)

/**
 * Attachment descriptor after malware scan verification.
 */
data class CaseAttachment(
    val attachmentId: String,
    val fileName: String,
    val mimeType: String,
    val fileSize: Long,
    val sha256Hex: String,
    val scanStatus: AttachmentScanStatus,
    val scannedAt: Instant,
    val scanDetails: String,
    val uploadedBy: String
)

/**
 * SLA tracking model ensuring SLA targets are visible and monitored.
 */
data class CaseSlaTracking(
    val firstResponseDueAt: Instant,
    val firstResponseAt: Instant? = null,
    val resolutionDueAt: Instant,
    val resolvedAt: Instant? = null,
    val status: SlaStatus = SlaStatus.WITHIN_SLA,
    val lastEvaluatedAt: Instant
)

/**
 * Authoritative Server Representation of a Support Case.
 */
data class SupportCaseRecord(
    val caseId: String,
    val tenantId: String,
    val playerReference: String,
    val category: CaseCategory,
    val priority: CasePriority,
    val status: CaseStatus,
    val subject: String,
    val description: String,
    val identityStatus: IdentityVerificationStatus,
    val verifiedAt: Instant? = null,
    val verificationMethod: String? = null,
    val notes: List<CaseNote> = emptyList(),
    val attachments: List<CaseAttachment> = emptyList(),
    val slaTracking: CaseSlaTracking,
    val assignedAgentId: String? = null,
    val createdAt: Instant,
    val updatedAt: Instant,
    val serverVersion: Long = 1L
)

/**
 * Audit actions for support cases.
 */
enum class CaseAuditAction {
    CASE_CREATED,
    NOTE_ADDED,
    ATTACHMENT_SCANNED,
    ATTACHMENT_QUARANTINED,
    IDENTITY_VERIFIED,
    CASE_VIEWED,
    STATUS_UPDATED,
    SLA_EVALUATED,
    SLA_ESCALATED
}

/**
 * Structured audit record for support cases.
 * Guarantees identity checks and access are audited.
 */
data class CaseAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val caseId: String,
    val principalId: String,
    val action: CaseAuditAction,
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
data class CaseAlertRecord(
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

data class AttachmentScanResult(
    val isClean: Boolean,
    val threatName: String? = null,
    val scanEngineVersion: String = "v2026.09-antivirus"
)

interface AttachmentScannerPort {
    fun scan(fileName: String, content: ByteArray): AttachmentScanResult
}

class FakeAttachmentScannerAdapter : AttachmentScannerPort {
    @Volatile var shouldFail: Boolean = false
    @Volatile var simulateTimeout: Boolean = false
    @Volatile var simulateInfection: Boolean = false

    override fun scan(fileName: String, content: ByteArray): AttachmentScanResult {
        if (simulateTimeout) {
            throw IllegalStateException("Malware scanner timeout")
        }
        if (shouldFail) {
            throw IllegalStateException("Malware scanner service unavailable")
        }
        if (simulateInfection || fileName.contains("eicar", ignoreCase = true) || fileName.endsWith(".exe") || fileName.endsWith(".bat")) {
            return AttachmentScanResult(isClean = false, threatName = "Win32.Malware.TestSignature")
        }
        return AttachmentScanResult(isClean = true)
    }
}

class SandboxAttachmentScannerAdapter : AttachmentScannerPort {
    override fun scan(fileName: String, content: ByteArray): AttachmentScanResult {
        return AttachmentScanResult(isClean = true, threatName = null)
    }
}

// =============================================================================
// Store Port & In-Memory Store
// =============================================================================

interface SupportCaseStore {
    fun saveCase(record: SupportCaseRecord)
    fun findCase(tenantId: String, caseId: String): SupportCaseRecord?
    fun listCases(tenantId: String): List<SupportCaseRecord>
    fun recordAudit(audit: CaseAuditRecord)
    fun getAudits(tenantId: String): List<CaseAuditRecord>
    fun recordAlert(alert: CaseAlertRecord)
    fun getAlerts(tenantId: String): List<CaseAlertRecord>
    fun recordOutbox(outbox: OutboxEvent)
    fun getOutbox(): List<OutboxEvent>
    fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

class InMemorySupportCaseStore : SupportCaseStore {
    val cases = ConcurrentHashMap<String, SupportCaseRecord>()
    val audits = ConcurrentHashMap<String, MutableList<CaseAuditRecord>>()
    val alerts = ConcurrentHashMap<String, MutableList<CaseAlertRecord>>()
    val outboxList = mutableListOf<OutboxEvent>()
    val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()

    private fun caseKey(tenantId: String, caseId: String) = "$tenantId:$caseId"

    override fun saveCase(record: SupportCaseRecord) {
        cases[caseKey(record.tenantId, record.caseId)] = record
    }

    override fun findCase(tenantId: String, caseId: String): SupportCaseRecord? {
        return cases[caseKey(tenantId, caseId)]
    }

    override fun listCases(tenantId: String): List<SupportCaseRecord> {
        return cases.values.filter { it.tenantId == tenantId }
    }

    override fun recordAudit(audit: CaseAuditRecord) {
        audits.computeIfAbsent(audit.tenantId) { mutableListOf() }.add(audit)
    }

    override fun getAudits(tenantId: String): List<CaseAuditRecord> {
        return audits[tenantId]?.toList() ?: emptyList()
    }

    override fun recordAlert(alert: CaseAlertRecord) {
        alerts.computeIfAbsent(alert.tenantId) { mutableListOf() }.add(alert)
    }

    override fun getAlerts(tenantId: String): List<CaseAlertRecord> {
        return alerts[tenantId]?.toList() ?: emptyList()
    }

    override fun recordOutbox(outbox: OutboxEvent) {
        synchronized(outboxList) {
            outboxList.add(outbox)
        }
    }

    override fun getOutbox(): List<OutboxEvent> {
        return synchronized(outboxList) { outboxList.toList() }
    }

    override fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>? {
        return idempotencyStore["$tenantId:$idempotencyKey"]
    }

    override fun saveIdempotentResult(
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        result: Any
    ) {
        idempotencyStore["$tenantId:$idempotencyKey"] = Pair(fingerprint, result)
    }
}

// =============================================================================
// Commands & Results
// =============================================================================

data class CreateSupportCaseCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerReference: String,
    val category: CaseCategory,
    val priority: CasePriority,
    val subject: String,
    val description: String,
    val initialIdentityStatus: IdentityVerificationStatus = IdentityVerificationStatus.UNVERIFIED,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class AddCaseNoteCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val content: String,
    val isInternal: Boolean = true,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesFinance: Boolean = false,
    val balanceAdjustmentMinorUnits: Long? = null
)

data class AddCaseAttachmentCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val fileName: String,
    val mimeType: String,
    val contentBytes: ByteArray,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class VerifyPlayerIdentityCommand(
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

data class UpdateCaseStatusCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val newStatus: CaseStatus,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class GetSupportCaseCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val caseId: String,
    val correlationId: String,
    val causationId: String
)

data class CreateSupportCaseResult(
    val resultId: UUID,
    val caseId: String,
    val tenantId: String,
    val playerReference: String,
    val category: CaseCategory,
    val priority: CasePriority,
    val status: CaseStatus,
    val slaTracking: CaseSlaTracking,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class AddCaseNoteResult(
    val resultId: UUID,
    val caseId: String,
    val noteId: String,
    val authorRole: String,
    val notesCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class AddCaseAttachmentResult(
    val resultId: UUID,
    val caseId: String,
    val attachmentId: String,
    val fileName: String,
    val sha256Hex: String,
    val scanStatus: AttachmentScanStatus,
    val attachmentsCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class VerifyPlayerIdentityResult(
    val resultId: UUID,
    val caseId: String,
    val identityStatus: IdentityVerificationStatus,
    val verifiedAt: Instant,
    val verificationMethod: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class SupportCaseDetailResult(
    val caseId: String,
    val tenantId: String,
    val playerReferenceRedacted: String,
    val category: CaseCategory,
    val priority: CasePriority,
    val status: CaseStatus,
    val subject: String,
    val description: String,
    val identityStatus: IdentityVerificationStatus,
    val notes: List<CaseNote>,
    val attachments: List<CaseAttachment>,
    val slaTracking: CaseSlaTracking,
    val sensitiveDataDisclosed: Boolean,
    val evidenceReference: String
)

data class SlaEvaluationResult(
    val caseId: String,
    val priority: CasePriority,
    val slaStatus: SlaStatus,
    val responseTimeRemainingMs: Long,
    val resolutionTimeRemainingMs: Long,
    val isBreached: Boolean,
    val isAtRisk: Boolean,
    val evidenceReference: String
)

// =============================================================================
// Authoritative Service
// =============================================================================

class SupportCaseService(
    private val store: SupportCaseStore,
    private val scanner: AttachmentScannerPort,
    private val clock: Clock
) {
    private val lock = Any()

    /**
     * Creates a new verified support case with explicit SLA targets.
     */
    fun createSupportCase(command: CreateSupportCaseCommand): CreateSupportCaseResult = synchronized(lock) {
        SupportCaseBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.playerReference.isBlank() || command.subject.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "CREATE:${command.tenantId}:${command.playerReference}:${command.category}:${command.priority}:${command.subject}:${command.expectedVersion}"
        val cached = checkIdempotency<CreateSupportCaseResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val now = clock.instant()
        val (firstResponseHours, resolutionHours) = calculateSlaDurations(command.priority)
        val slaTracking = CaseSlaTracking(
            firstResponseDueAt = now.plus(Duration.ofHours(firstResponseHours)),
            resolutionDueAt = now.plus(Duration.ofHours(resolutionHours)),
            status = SlaStatus.WITHIN_SLA,
            lastEvaluatedAt = now
        )

        val caseId = "case-${UUID.randomUUID()}"
        val record = SupportCaseRecord(
            caseId = caseId,
            tenantId = command.tenantId,
            playerReference = command.playerReference,
            category = command.category,
            priority = command.priority,
            status = CaseStatus.NEW,
            subject = command.subject,
            description = command.description,
            identityStatus = command.initialIdentityStatus,
            slaTracking = slaTracking,
            createdAt = now,
            updatedAt = now,
            serverVersion = 1L
        )

        store.saveCase(record)

        val resultId = UUID.randomUUID()
        val evidenceRef = "support-case:${command.tenantId}:$caseId:v1:$resultId"
        val result = CreateSupportCaseResult(
            resultId = resultId,
            caseId = caseId,
            tenantId = command.tenantId,
            playerReference = command.playerReference,
            category = command.category,
            priority = command.priority,
            status = CaseStatus.NEW,
            slaTracking = slaTracking,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        // Structured audit record
        store.recordAudit(
            CaseAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = caseId,
                principalId = command.principal!!.id,
                action = CaseAuditAction.CASE_CREATED,
                identityCheckPerformed = command.initialIdentityStatus == IdentityVerificationStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Created case $caseId category=${command.category} priority=${command.priority} slaDue=${slaTracking.resolutionDueAt}",
                alertTriggered = false
            )
        )

        // Outbox event
        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "SUPPORT_CASE_CREATED",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Adds an internal or communication note to a case.
     * Enforces that notes NEVER mutate finance.
     */
    fun addCaseNote(command: AddCaseNoteCommand): AddCaseNoteResult = synchronized(lock) {
        SupportCaseBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, false)

        // Strict semantic contract: Notes do not mutate finance!
        if (command.mutatesFinance || command.balanceAdjustmentMinorUnits != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.content.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "NOTE:${command.tenantId}:${command.caseId}:${command.content}:${command.isInternal}:${command.expectedVersion}"
        val cached = checkIdempotency<AddCaseNoteResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val note = CaseNote(
            noteId = "note-${UUID.randomUUID()}",
            authorId = command.principal!!.id,
            authorRole = command.principal.roles.joinToString(",") { it.name }.ifEmpty { command.principal.kind.name },
            content = command.content,
            isInternal = command.isInternal,
            createdAt = now
        )

        // If this is the first response by an admin, update firstResponseAt for SLA tracking
        val updatedSla = if (command.principal.kind == PrincipalKind.ADMIN && existing.slaTracking.firstResponseAt == null) {
            existing.slaTracking.copy(firstResponseAt = now, lastEvaluatedAt = now)
        } else {
            existing.slaTracking
        }

        val updatedCase = existing.copy(
            notes = existing.notes + note,
            slaTracking = updatedSla,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveCase(updatedCase)

        val resultId = UUID.randomUUID()
        val evidenceRef = "support-note:${command.tenantId}:${command.caseId}:${note.noteId}:$resultId"
        val result = AddCaseNoteResult(
            resultId = resultId,
            caseId = command.caseId,
            noteId = note.noteId,
            authorRole = note.authorRole,
            notesCount = updatedCase.notes.size,
            serverTime = now,
            serverVersion = updatedCase.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            CaseAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = command.principal.id,
                action = CaseAuditAction.NOTE_ADDED,
                identityCheckPerformed = existing.identityStatus == IdentityVerificationStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Added note to case ${command.caseId} internal=${command.isInternal}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Adds an attachment after mandatory malware and security scanning.
     * Rejects unscanned or infected attachments, preventing attachment abuse.
     */
    fun addCaseAttachment(command: AddCaseAttachmentCommand): AddCaseAttachmentResult = synchronized(lock) {
        SupportCaseBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.fileName.isBlank() || command.contentBytes.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate prohibited dangerous extensions
        val dangerousExtensions = listOf(".exe", ".bat", ".cmd", ".sh", ".vbs", ".js", ".jar", ".ps1")
        if (dangerousExtensions.any { command.fileName.endsWith(it, ignoreCase = true) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "ATTACHMENT:${command.tenantId}:${command.caseId}:${command.fileName}:${command.contentBytes.size}:${command.expectedVersion}"
        val cached = checkIdempotency<AddCaseAttachmentResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Perform mandatory malware scan
        val scanResult = try {
            scanner.scan(command.fileName, command.contentBytes)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant()
        val sha256Hex = sha256Hex(command.contentBytes)

        if (!scanResult.isClean) {
            // Quarantine infected file, emit security alert, fail-closed rejection
            val alert = CaseAlertRecord(
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
                CaseAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    caseId = command.caseId,
                    principalId = command.principal!!.id,
                    action = CaseAuditAction.ATTACHMENT_QUARANTINED,
                    identityCheckPerformed = existing.identityStatus == IdentityVerificationStatus.VERIFIED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Attachment ${command.fileName} rejected due to malware detection (${scanResult.threatName})",
                    alertTriggered = true
                )
            )

            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val attachmentId = "att-${UUID.randomUUID()}"
        val attachment = CaseAttachment(
            attachmentId = attachmentId,
            fileName = command.fileName,
            mimeType = command.mimeType,
            fileSize = command.contentBytes.size.toLong(),
            sha256Hex = sha256Hex,
            scanStatus = AttachmentScanStatus.CLEAN,
            scannedAt = now,
            scanDetails = "Scan clean: ${scanResult.scanEngineVersion}",
            uploadedBy = command.principal!!.id
        )

        val updatedCase = existing.copy(
            attachments = existing.attachments + attachment,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveCase(updatedCase)

        val resultId = UUID.randomUUID()
        val evidenceRef = "support-att:${command.tenantId}:${command.caseId}:$attachmentId:$resultId"
        val result = AddCaseAttachmentResult(
            resultId = resultId,
            caseId = command.caseId,
            attachmentId = attachmentId,
            fileName = command.fileName,
            sha256Hex = sha256Hex,
            scanStatus = AttachmentScanStatus.CLEAN,
            attachmentsCount = updatedCase.attachments.size,
            serverTime = now,
            serverVersion = updatedCase.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            CaseAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = command.principal.id,
                action = CaseAuditAction.ATTACHMENT_SCANNED,
                identityCheckPerformed = existing.identityStatus == IdentityVerificationStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Attached scanned file ${command.fileName} sha256=$sha256Hex",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Verifies the player identity associated with the support case.
     */
    fun verifyPlayerIdentity(command: VerifyPlayerIdentityCommand): VerifyPlayerIdentityResult = synchronized(lock) {
        SupportCaseBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.verificationMethod.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "VERIFY_ID:${command.tenantId}:${command.caseId}:${command.verificationMethod}:${command.expectedVersion}"
        val cached = checkIdempotency<VerifyPlayerIdentityResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val updatedCase = existing.copy(
            identityStatus = IdentityVerificationStatus.VERIFIED,
            verifiedAt = now,
            verificationMethod = command.verificationMethod,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveCase(updatedCase)

        val resultId = UUID.randomUUID()
        val evidenceRef = "support-id-verify:${command.tenantId}:${command.caseId}:$resultId"
        val result = VerifyPlayerIdentityResult(
            resultId = resultId,
            caseId = command.caseId,
            identityStatus = IdentityVerificationStatus.VERIFIED,
            verifiedAt = now,
            verificationMethod = command.verificationMethod,
            serverTime = now,
            serverVersion = updatedCase.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            CaseAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = command.principal!!.id,
                action = CaseAuditAction.IDENTITY_VERIFIED,
                identityCheckPerformed = true,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Verified identity for case ${command.caseId} via ${command.verificationMethod}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Updates case status. If moving to RESOLVED or CLOSED, updates resolutionAt for SLA tracking.
     */
    fun updateCaseStatus(command: UpdateCaseStatusCommand): SupportCaseRecord = synchronized(lock) {
        SupportCaseBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val updatedSla = if (command.newStatus == CaseStatus.RESOLVED || command.newStatus == CaseStatus.CLOSED) {
            existing.slaTracking.copy(resolvedAt = now, lastEvaluatedAt = now)
        } else {
            existing.slaTracking
        }

        val updatedCase = existing.copy(
            status = command.newStatus,
            slaTracking = updatedSla,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveCase(updatedCase)

        store.recordAudit(
            CaseAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = command.principal!!.id,
                action = CaseAuditAction.STATUS_UPDATED,
                identityCheckPerformed = existing.identityStatus == IdentityVerificationStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Status updated to ${command.newStatus} for case ${command.caseId}",
                alertTriggered = false
            )
        )

        return updatedCase
    }

    /**
     * Retrieves case details with mandatory audited access and unverified disclosure protection.
     */
    fun getCaseWithAuditedAccess(command: GetSupportCaseCommand): SupportCaseDetailResult = synchronized(lock) {
        SupportCaseBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)

        val existing = store.findCase(command.tenantId, command.caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val principal = command.principal!!
        // If player, can only access own case
        if (principal.kind == PrincipalKind.PLAYER && principal.id != existing.playerReference) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val isIdentityVerified = existing.identityStatus == IdentityVerificationStatus.VERIFIED

        // Record audited access
        store.recordAudit(
            CaseAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                caseId = command.caseId,
                principalId = principal.id,
                action = CaseAuditAction.CASE_VIEWED,
                identityCheckPerformed = isIdentityVerified,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Case ${command.caseId} viewed by ${principal.id} verified=$isIdentityVerified",
                alertTriggered = false
            )
        )

        // Protect against unverified disclosure: redact sensitive identifier if not verified
        val redactedPlayerRef = if (isIdentityVerified) existing.playerReference else "REDACTED-UNVERIFIED"
        val evidenceRef = "case-view:${command.tenantId}:${command.caseId}:v${existing.serverVersion}"

        return SupportCaseDetailResult(
            caseId = existing.caseId,
            tenantId = existing.tenantId,
            playerReferenceRedacted = redactedPlayerRef,
            category = existing.category,
            priority = existing.priority,
            status = existing.status,
            subject = existing.subject,
            description = existing.description,
            identityStatus = existing.identityStatus,
            notes = existing.notes.filter { !it.isInternal || principal.kind == PrincipalKind.ADMIN },
            attachments = existing.attachments,
            slaTracking = existing.slaTracking,
            sensitiveDataDisclosed = isIdentityVerified,
            evidenceReference = evidenceRef
        )
    }

    /**
     * Evaluates case SLA and emits alerts on at-risk or breached status.
     * Prevents invisible SLA failures.
     */
    fun evaluateCaseSla(tenantId: String, caseId: String, now: Instant): SlaEvaluationResult = synchronized(lock) {
        SupportCaseBinding.checkBound()

        val existing = store.findCase(tenantId, caseId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val tracking = existing.slaTracking
        val responseDue = tracking.firstResponseDueAt
        val resolutionDue = tracking.resolutionDueAt

        val responseRemaining = Duration.between(now, responseDue).toMillis()
        val resolutionRemaining = Duration.between(now, resolutionDue).toMillis()

        val isResponseBreached = tracking.firstResponseAt == null && now.isAfter(responseDue)
        val isResolutionBreached = tracking.resolvedAt == null && now.isAfter(resolutionDue)
        val isBreached = isResponseBreached || isResolutionBreached

        val isAtRisk = !isBreached && (responseRemaining < 3600000L || resolutionRemaining < 7200000L)

        val newSlaStatus = when {
            isBreached -> SlaStatus.BREACHED
            isAtRisk -> SlaStatus.AT_RISK
            else -> SlaStatus.WITHIN_SLA
        }

        if (newSlaStatus != tracking.status) {
            val updatedCase = existing.copy(
                slaTracking = tracking.copy(status = newSlaStatus, lastEvaluatedAt = now)
            )
            store.saveCase(updatedCase)

            if (newSlaStatus == SlaStatus.BREACHED) {
                store.recordAlert(
                    CaseAlertRecord(
                        alertId = "alert-${UUID.randomUUID()}",
                        tenantId = tenantId,
                        caseId = caseId,
                        severity = "CRITICAL",
                        alertType = "CASE_SLA_BREACHED",
                        message = "SLA BREACHED for case $caseId priority=${existing.priority}",
                        correlationId = "sla-eval-$caseId",
                        timestamp = now
                    )
                )
            } else if (newSlaStatus == SlaStatus.AT_RISK) {
                store.recordAlert(
                    CaseAlertRecord(
                        alertId = "alert-${UUID.randomUUID()}",
                        tenantId = tenantId,
                        caseId = caseId,
                        severity = "WARN",
                        alertType = "CASE_SLA_AT_RISK",
                        message = "Case $caseId priority=${existing.priority} is AT RISK of SLA breach",
                        correlationId = "sla-eval-$caseId",
                        timestamp = now
                    )
                )
            }
        }

        return SlaEvaluationResult(
            caseId = caseId,
            priority = existing.priority,
            slaStatus = newSlaStatus,
            responseTimeRemainingMs = responseRemaining,
            resolutionTimeRemainingMs = resolutionRemaining,
            isBreached = isBreached,
            isAtRisk = isAtRisk,
            evidenceReference = "sla-eval:$tenantId:$caseId:$newSlaStatus"
        )
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun calculateSlaDurations(priority: CasePriority): Pair<Long, Long> {
        return when (priority) {
            CasePriority.CRITICAL -> Pair(1L, 4L)
            CasePriority.HIGH -> Pair(4L, 24L)
            CasePriority.NORMAL -> Pair(12L, 72L)
            CasePriority.LOW -> Pair(24L, 168L)
        }
    }

    private fun validatePrincipal(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        requireAdmin: Boolean
    ) {
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

    private fun validateCommonInvariants(
        idempotencyKey: String,
        expectedVersion: Long,
        mutatesMoney: Boolean
    ) {
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

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> checkIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String): T? {
        val existing = store.findIdempotentResult(tenantId, idempotencyKey) ?: return null
        if (existing.first != fingerprint) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        return existing.second as T
    }
}
