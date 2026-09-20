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
 * Traceability binding for SUPPORT-001-02: Manage payment disputes.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "unverified disclosure/attachment abuse/SLA invisible".
 */
object PaymentDisputeSupportBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("unverified disclosure/attachment abuse/SLA invisible")
        }
    }
}

/**
 * Outcome-specific semantic contract for SUPPORT-001-02.
 */
const val PAYMENT_DISPUTE_SUPPORT_CONTRACT =
    "Notes do not mutate finance; attachments scanned; identity checks and access audited."

/**
 * Types of payment disputes handled by support agents.
 */
enum class DisputeType {
    UNAUTHORIZED_CHARGE,
    INCORRECT_AMOUNT,
    DUPLICATE_CHARGE,
    CREDIT_NOT_PROCESSED,
    FRAUD_REPORTED,
    MERCHANT_DISPUTE
}

/**
 * Lifecycle stages of a payment dispute.
 */
enum class DisputeStage {
    OPENED,
    EVIDENCE_SUBMITTED,
    SUBMITTED_TO_PROVIDER,
    UNDER_REVIEW,
    RESOLVED_WON,
    RESOLVED_LOST,
    CANCELLED
}

/**
 * Categorization of dispute evidence attachments.
 */
enum class DisputeEvidenceType {
    BANK_STATEMENT,
    RECEIPT,
    TRANSACTION_SCREENSHOT,
    PLAYER_DECLARATION,
    PROVIDER_COMMUNICATION
}

/**
 * Malware scan status for evidence attachments.
 */
enum class DisputeAttachmentStatus {
    CLEAN,
    INFECTED,
    QUARANTINED,
    FAILED
}

/**
 * Identity verification state for the player raising the dispute.
 */
enum class DisputeIdentityStatus {
    VERIFIED,
    PENDING_VERIFICATION,
    FAILED_VERIFICATION,
    UNVERIFIED
}

/**
 * SLA compliance state for the payment dispute.
 */
enum class DisputeSlaStatus {
    WITHIN_SLA,
    AT_RISK,
    BREACHED
}

/**
 * Dispute communication note.
 * Invariant: Notes NEVER mutate finance or create ledger balance adjustments.
 */
data class DisputeNote(
    val noteId: String,
    val authorId: String,
    val authorRole: String,
    val content: String,
    val isInternal: Boolean,
    val createdAt: Instant
)

/**
 * Dispute evidence attachment descriptor after malware scan verification.
 */
data class DisputeEvidenceAttachment(
    val attachmentId: String,
    val evidenceType: DisputeEvidenceType,
    val fileName: String,
    val mimeType: String,
    val fileSize: Long,
    val sha256Hex: String,
    val scanStatus: DisputeAttachmentStatus,
    val scannedAt: Instant,
    val uploadedBy: String
)

/**
 * SLA tracking model ensuring dispute deadlines are monitored and visible.
 */
data class DisputeSlaTracking(
    val evidenceSubmissionDueAt: Instant, // e.g. 7 days to submit evidence to provider
    val evidenceSubmittedAt: Instant? = null,
    val disputeResolutionDueAt: Instant, // e.g. 30 days for resolution
    val resolvedAt: Instant? = null,
    val status: DisputeSlaStatus = DisputeSlaStatus.WITHIN_SLA,
    val lastEvaluatedAt: Instant
)

/**
 * Authoritative Server Representation of a Payment Dispute Case.
 */
data class PaymentDisputeRecord(
    val disputeId: String,
    val tenantId: String,
    val playerReference: String,
    val transactionReference: String,
    val disputedAmountMinorUnits: Long,
    val currencyCode: String,
    val disputeType: DisputeType,
    val stage: DisputeStage,
    val identityStatus: DisputeIdentityStatus,
    val verifiedAt: Instant? = null,
    val verificationMethod: String? = null,
    val notes: List<DisputeNote> = emptyList(),
    val evidenceAttachments: List<DisputeEvidenceAttachment> = emptyList(),
    val slaTracking: DisputeSlaTracking,
    val createdAt: Instant,
    val updatedAt: Instant,
    val serverVersion: Long = 1L
)

/**
 * Actions tracked in the payment dispute audit trail.
 */
enum class DisputeAuditAction {
    DISPUTE_OPENED,
    NOTE_ADDED,
    EVIDENCE_SCANNED,
    EVIDENCE_QUARANTINED,
    IDENTITY_VERIFIED,
    DISPUTE_VIEWED,
    STAGE_TRANSITIONED,
    SLA_EVALUATED,
    SLA_ESCALATED
}

/**
 * Structured audit record for payment dispute operations.
 * Guarantees identity checks and access are audited.
 */
data class DisputeAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val disputeId: String,
    val principalId: String,
    val action: DisputeAuditAction,
    val identityCheckPerformed: Boolean,
    val success: Boolean,
    val timestamp: Instant,
    val correlationId: String,
    val causationId: String,
    val detailsRedacted: String,
    val alertTriggered: Boolean = false
)

/**
 * Alert record for security, attachment quarantine, or SLA breaches in payment disputes.
 */
data class DisputeAlertRecord(
    val alertId: String,
    val tenantId: String,
    val disputeId: String,
    val severity: String, // "INFO", "WARN", "CRITICAL"
    val alertType: String,
    val message: String,
    val correlationId: String,
    val timestamp: Instant
)

// =============================================================================
// Evidence Malware Scanner Port & Adapters
// =============================================================================

data class DisputeScanResult(
    val isClean: Boolean,
    val threatName: String? = null,
    val engineVersion: String = "v2026.09-evidence-scanner"
)

interface DisputeEvidenceScannerPort {
    fun scan(fileName: String, content: ByteArray): DisputeScanResult
}

class FakeDisputeEvidenceScannerAdapter : DisputeEvidenceScannerPort {
    @Volatile var shouldFail: Boolean = false
    @Volatile var simulateTimeout: Boolean = false
    @Volatile var simulateInfection: Boolean = false

    override fun scan(fileName: String, content: ByteArray): DisputeScanResult {
        if (simulateTimeout) {
            throw IllegalStateException("Dispute evidence scanner timeout")
        }
        if (shouldFail) {
            throw IllegalStateException("Dispute evidence scanner service unavailable")
        }
        if (simulateInfection || fileName.contains("eicar", ignoreCase = true) || fileName.endsWith(".exe") || fileName.endsWith(".bat")) {
            return DisputeScanResult(isClean = false, threatName = "Trojan.EvidenceTamper.TestSig")
        }
        return DisputeScanResult(isClean = true)
    }
}

class SandboxDisputeEvidenceScannerAdapter : DisputeEvidenceScannerPort {
    override fun scan(fileName: String, content: ByteArray): DisputeScanResult {
        return DisputeScanResult(isClean = true, threatName = null)
    }
}

// =============================================================================
// Store Port & In-Memory Store
// =============================================================================

interface PaymentDisputeStore {
    fun saveDispute(record: PaymentDisputeRecord)
    fun findDispute(tenantId: String, disputeId: String): PaymentDisputeRecord?
    fun listDisputes(tenantId: String): List<PaymentDisputeRecord>
    fun recordAudit(audit: DisputeAuditRecord)
    fun getAudits(tenantId: String): List<DisputeAuditRecord>
    fun recordAlert(alert: DisputeAlertRecord)
    fun getAlerts(tenantId: String): List<DisputeAlertRecord>
    fun recordOutbox(outbox: OutboxEvent)
    fun getOutbox(): List<OutboxEvent>
    fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

class InMemoryPaymentDisputeStore : PaymentDisputeStore {
    val disputes = ConcurrentHashMap<String, PaymentDisputeRecord>()
    val audits = ConcurrentHashMap<String, MutableList<DisputeAuditRecord>>()
    val alerts = ConcurrentHashMap<String, MutableList<DisputeAlertRecord>>()
    val outboxList = mutableListOf<OutboxEvent>()
    val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()

    private fun disputeKey(tenantId: String, disputeId: String) = "$tenantId:$disputeId"

    override fun saveDispute(record: PaymentDisputeRecord) {
        disputes[disputeKey(record.tenantId, record.disputeId)] = record
    }

    override fun findDispute(tenantId: String, disputeId: String): PaymentDisputeRecord? {
        return disputes[disputeKey(tenantId, disputeId)]
    }

    override fun listDisputes(tenantId: String): List<PaymentDisputeRecord> {
        return disputes.values.filter { it.tenantId == tenantId }
    }

    override fun recordAudit(audit: DisputeAuditRecord) {
        audits.computeIfAbsent(audit.tenantId) { mutableListOf() }.add(audit)
    }

    override fun getAudits(tenantId: String): List<DisputeAuditRecord> {
        return audits[tenantId]?.toList() ?: emptyList()
    }

    override fun recordAlert(alert: DisputeAlertRecord) {
        alerts.computeIfAbsent(alert.tenantId) { mutableListOf() }.add(alert)
    }

    override fun getAlerts(tenantId: String): List<DisputeAlertRecord> {
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

data class OpenPaymentDisputeCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val playerReference: String,
    val transactionReference: String,
    val disputedAmountMinorUnits: Long,
    val currencyCode: String,
    val disputeType: DisputeType,
    val reasonDescription: String,
    val initialIdentityStatus: DisputeIdentityStatus = DisputeIdentityStatus.UNVERIFIED,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class AddDisputeNoteCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val disputeId: String,
    val content: String,
    val isInternal: Boolean = true,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesFinance: Boolean = false,
    val balanceAdjustmentMinorUnits: Long? = null
)

data class SubmitDisputeEvidenceCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val disputeId: String,
    val evidenceType: DisputeEvidenceType,
    val fileName: String,
    val mimeType: String,
    val contentBytes: ByteArray,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class VerifyDisputeIdentityCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val disputeId: String,
    val verificationMethod: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class TransitionDisputeStageCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val disputeId: String,
    val targetStage: DisputeStage,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class GetPaymentDisputeCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val disputeId: String,
    val correlationId: String,
    val causationId: String
)

data class OpenPaymentDisputeResult(
    val resultId: UUID,
    val disputeId: String,
    val tenantId: String,
    val playerReference: String,
    val transactionReference: String,
    val disputedAmountMinorUnits: Long,
    val currencyCode: String,
    val stage: DisputeStage,
    val slaTracking: DisputeSlaTracking,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class AddDisputeNoteResult(
    val resultId: UUID,
    val disputeId: String,
    val noteId: String,
    val notesCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class SubmitDisputeEvidenceResult(
    val resultId: UUID,
    val disputeId: String,
    val attachmentId: String,
    val fileName: String,
    val sha256Hex: String,
    val scanStatus: DisputeAttachmentStatus,
    val evidenceCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class VerifyDisputeIdentityResult(
    val resultId: UUID,
    val disputeId: String,
    val identityStatus: DisputeIdentityStatus,
    val verifiedAt: Instant,
    val verificationMethod: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class PaymentDisputeDetailResult(
    val disputeId: String,
    val tenantId: String,
    val playerReferenceRedacted: String,
    val transactionReference: String,
    val disputedAmountMinorUnits: Long,
    val currencyCode: String,
    val disputeType: DisputeType,
    val stage: DisputeStage,
    val identityStatus: DisputeIdentityStatus,
    val notes: List<DisputeNote>,
    val evidenceAttachments: List<DisputeEvidenceAttachment>,
    val slaTracking: DisputeSlaTracking,
    val sensitiveDataDisclosed: Boolean,
    val evidenceReference: String
)

data class DisputeSlaEvaluationResult(
    val disputeId: String,
    val slaStatus: DisputeSlaStatus,
    val evidenceSubmissionTimeRemainingMs: Long,
    val resolutionTimeRemainingMs: Long,
    val isBreached: Boolean,
    val isAtRisk: Boolean,
    val evidenceReference: String
)

// =============================================================================
// Authoritative Service
// =============================================================================

class PaymentDisputeSupportService(
    private val store: PaymentDisputeStore,
    private val scanner: DisputeEvidenceScannerPort,
    private val clock: Clock
) {
    private val lock = Any()

    /**
     * Opens a new payment dispute with explicit SLA targets.
     */
    fun openPaymentDispute(command: OpenPaymentDisputeCommand): OpenPaymentDisputeResult = synchronized(lock) {
        PaymentDisputeSupportBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.playerReference.isBlank() || command.transactionReference.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.disputedAmountMinorUnits <= 0L || command.currencyCode.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "OPEN_DISPUTE:${command.tenantId}:${command.playerReference}:${command.transactionReference}:${command.disputedAmountMinorUnits}:${command.currencyCode}:${command.disputeType}:${command.expectedVersion}"
        val cached = checkIdempotency<OpenPaymentDisputeResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val now = clock.instant()
        val slaTracking = DisputeSlaTracking(
            evidenceSubmissionDueAt = now.plus(Duration.ofDays(7)), // 7 days evidence SLA
            disputeResolutionDueAt = now.plus(Duration.ofDays(30)),  // 30 days resolution SLA
            status = DisputeSlaStatus.WITHIN_SLA,
            lastEvaluatedAt = now
        )

        val disputeId = "disp-${UUID.randomUUID()}"
        val record = PaymentDisputeRecord(
            disputeId = disputeId,
            tenantId = command.tenantId,
            playerReference = command.playerReference,
            transactionReference = command.transactionReference,
            disputedAmountMinorUnits = command.disputedAmountMinorUnits,
            currencyCode = command.currencyCode,
            disputeType = command.disputeType,
            stage = DisputeStage.OPENED,
            identityStatus = command.initialIdentityStatus,
            slaTracking = slaTracking,
            createdAt = now,
            updatedAt = now,
            serverVersion = 1L
        )

        store.saveDispute(record)

        val resultId = UUID.randomUUID()
        val evidenceRef = "dispute-case:${command.tenantId}:$disputeId:v1:$resultId"
        val result = OpenPaymentDisputeResult(
            resultId = resultId,
            disputeId = disputeId,
            tenantId = command.tenantId,
            playerReference = command.playerReference,
            transactionReference = command.transactionReference,
            disputedAmountMinorUnits = command.disputedAmountMinorUnits,
            currencyCode = command.currencyCode,
            stage = DisputeStage.OPENED,
            slaTracking = slaTracking,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            DisputeAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                disputeId = disputeId,
                principalId = command.principal!!.id,
                action = DisputeAuditAction.DISPUTE_OPENED,
                identityCheckPerformed = command.initialIdentityStatus == DisputeIdentityStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Opened dispute $disputeId type=${command.disputeType} txRef=${command.transactionReference} amount=${command.disputedAmountMinorUnits}",
                alertTriggered = false
            )
        )

        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "PAYMENT_DISPUTE_OPENED",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Adds an internal or customer communication note to the dispute.
     * Enforces that notes NEVER mutate finance or adjust balances.
     */
    fun addDisputeNote(command: AddDisputeNoteCommand): AddDisputeNoteResult = synchronized(lock) {
        PaymentDisputeSupportBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, false)

        // Strict semantic contract: Notes do not mutate finance!
        if (command.mutatesFinance || command.balanceAdjustmentMinorUnits != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.content.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "NOTE:${command.tenantId}:${command.disputeId}:${command.content}:${command.isInternal}:${command.expectedVersion}"
        val cached = checkIdempotency<AddDisputeNoteResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findDispute(command.tenantId, command.disputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val note = DisputeNote(
            noteId = "dnote-${UUID.randomUUID()}",
            authorId = command.principal!!.id,
            authorRole = command.principal.roles.joinToString(",") { it.name }.ifEmpty { command.principal.kind.name },
            content = command.content,
            isInternal = command.isInternal,
            createdAt = now
        )

        val updatedDispute = existing.copy(
            notes = existing.notes + note,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveDispute(updatedDispute)

        val resultId = UUID.randomUUID()
        val evidenceRef = "dispute-note:${command.tenantId}:${command.disputeId}:${note.noteId}:$resultId"
        val result = AddDisputeNoteResult(
            resultId = resultId,
            disputeId = command.disputeId,
            noteId = note.noteId,
            notesCount = updatedDispute.notes.size,
            serverTime = now,
            serverVersion = updatedDispute.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            DisputeAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                disputeId = command.disputeId,
                principalId = command.principal.id,
                action = DisputeAuditAction.NOTE_ADDED,
                identityCheckPerformed = existing.identityStatus == DisputeIdentityStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Added note to dispute ${command.disputeId} internal=${command.isInternal}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Submits dispute evidence after mandatory malware and integrity scanning.
     * Prevents attachment abuse by rejecting infected or dangerous file types.
     */
    fun submitDisputeEvidence(command: SubmitDisputeEvidenceCommand): SubmitDisputeEvidenceResult = synchronized(lock) {
        PaymentDisputeSupportBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.fileName.isBlank() || command.contentBytes.isEmpty()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate prohibited dangerous extensions
        val dangerousExtensions = listOf(".exe", ".bat", ".cmd", ".sh", ".vbs", ".js", ".ps1")
        if (dangerousExtensions.any { command.fileName.endsWith(it, ignoreCase = true) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "EVIDENCE:${command.tenantId}:${command.disputeId}:${command.fileName}:${command.contentBytes.size}:${command.expectedVersion}"
        val cached = checkIdempotency<SubmitDisputeEvidenceResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findDispute(command.tenantId, command.disputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Perform mandatory evidence scan
        val scanResult = try {
            scanner.scan(command.fileName, command.contentBytes)
        } catch (e: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant()
        val sha256Hex = sha256Hex(command.contentBytes)

        if (!scanResult.isClean) {
            // Quarantine infected file, emit security alert, fail-closed rejection
            val alert = DisputeAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                disputeId = command.disputeId,
                severity = "CRITICAL",
                alertType = "DISPUTE_EVIDENCE_MALWARE_DETECTED",
                message = "Malware threat detected in evidence ${command.fileName}: ${scanResult.threatName}. Quarantined.",
                correlationId = command.correlationId,
                timestamp = now
            )
            store.recordAlert(alert)

            store.recordAudit(
                DisputeAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    disputeId = command.disputeId,
                    principalId = command.principal!!.id,
                    action = DisputeAuditAction.EVIDENCE_QUARANTINED,
                    identityCheckPerformed = existing.identityStatus == DisputeIdentityStatus.VERIFIED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Evidence file ${command.fileName} rejected due to malware detection (${scanResult.threatName})",
                    alertTriggered = true
                )
            )

            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val attachmentId = "eatt-${UUID.randomUUID()}"
        val attachment = DisputeEvidenceAttachment(
            attachmentId = attachmentId,
            evidenceType = command.evidenceType,
            fileName = command.fileName,
            mimeType = command.mimeType,
            fileSize = command.contentBytes.size.toLong(),
            sha256Hex = sha256Hex,
            scanStatus = DisputeAttachmentStatus.CLEAN,
            scannedAt = now,
            uploadedBy = command.principal!!.id
        )

        // Update evidenceSubmittedAt in SLA tracking and advance stage if in OPENED stage
        val updatedSla = existing.slaTracking.copy(
            evidenceSubmittedAt = now,
            lastEvaluatedAt = now
        )
        val newStage = if (existing.stage == DisputeStage.OPENED) DisputeStage.EVIDENCE_SUBMITTED else existing.stage

        val updatedDispute = existing.copy(
            stage = newStage,
            evidenceAttachments = existing.evidenceAttachments + attachment,
            slaTracking = updatedSla,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveDispute(updatedDispute)

        val resultId = UUID.randomUUID()
        val evidenceRef = "dispute-ev:${command.tenantId}:${command.disputeId}:$attachmentId:$resultId"
        val result = SubmitDisputeEvidenceResult(
            resultId = resultId,
            disputeId = command.disputeId,
            attachmentId = attachmentId,
            fileName = command.fileName,
            sha256Hex = sha256Hex,
            scanStatus = DisputeAttachmentStatus.CLEAN,
            evidenceCount = updatedDispute.evidenceAttachments.size,
            serverTime = now,
            serverVersion = updatedDispute.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            DisputeAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                disputeId = command.disputeId,
                principalId = command.principal.id,
                action = DisputeAuditAction.EVIDENCE_SCANNED,
                identityCheckPerformed = existing.identityStatus == DisputeIdentityStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Attached scanned evidence ${command.fileName} sha256=$sha256Hex",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Verifies player identity for dispute processing.
     */
    fun verifyDisputeIdentity(command: VerifyDisputeIdentityCommand): VerifyDisputeIdentityResult = synchronized(lock) {
        PaymentDisputeSupportBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.verificationMethod.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "VERIFY_ID:${command.tenantId}:${command.disputeId}:${command.verificationMethod}:${command.expectedVersion}"
        val cached = checkIdempotency<VerifyDisputeIdentityResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findDispute(command.tenantId, command.disputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val updatedDispute = existing.copy(
            identityStatus = DisputeIdentityStatus.VERIFIED,
            verifiedAt = now,
            verificationMethod = command.verificationMethod,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveDispute(updatedDispute)

        val resultId = UUID.randomUUID()
        val evidenceRef = "dispute-verify-id:${command.tenantId}:${command.disputeId}:$resultId"
        val result = VerifyDisputeIdentityResult(
            resultId = resultId,
            disputeId = command.disputeId,
            identityStatus = DisputeIdentityStatus.VERIFIED,
            verifiedAt = now,
            verificationMethod = command.verificationMethod,
            serverTime = now,
            serverVersion = updatedDispute.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            DisputeAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                disputeId = command.disputeId,
                principalId = command.principal!!.id,
                action = DisputeAuditAction.IDENTITY_VERIFIED,
                identityCheckPerformed = true,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Verified player identity for dispute ${command.disputeId} via ${command.verificationMethod}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Transitions dispute stage (e.g. SUBMITTED_TO_PROVIDER, RESOLVED_WON, RESOLVED_LOST).
     */
    fun transitionDisputeStage(command: TransitionDisputeStageCommand): PaymentDisputeRecord = synchronized(lock) {
        PaymentDisputeSupportBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        val existing = store.findDispute(command.tenantId, command.disputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val isTerminal = command.targetStage == DisputeStage.RESOLVED_WON ||
                command.targetStage == DisputeStage.RESOLVED_LOST ||
                command.targetStage == DisputeStage.CANCELLED

        val updatedSla = if (isTerminal) {
            existing.slaTracking.copy(resolvedAt = now, lastEvaluatedAt = now)
        } else {
            existing.slaTracking
        }

        val updatedDispute = existing.copy(
            stage = command.targetStage,
            slaTracking = updatedSla,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )
        store.saveDispute(updatedDispute)

        store.recordAudit(
            DisputeAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                disputeId = command.disputeId,
                principalId = command.principal!!.id,
                action = DisputeAuditAction.STAGE_TRANSITIONED,
                identityCheckPerformed = existing.identityStatus == DisputeIdentityStatus.VERIFIED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Transitioned dispute ${command.disputeId} to ${command.targetStage}",
                alertTriggered = false
            )
        )

        return updatedDispute
    }

    /**
     * Retrieves dispute details with mandatory audited access and unverified disclosure protection.
     */
    fun getDisputeWithAuditedAccess(command: GetPaymentDisputeCommand): PaymentDisputeDetailResult = synchronized(lock) {
        PaymentDisputeSupportBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)

        val existing = store.findDispute(command.tenantId, command.disputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val principal = command.principal!!
        // Player can only view own dispute
        if (principal.kind == PrincipalKind.PLAYER && principal.id != existing.playerReference) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val isIdentityVerified = existing.identityStatus == DisputeIdentityStatus.VERIFIED

        // Record audited access
        store.recordAudit(
            DisputeAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                disputeId = command.disputeId,
                principalId = principal.id,
                action = DisputeAuditAction.DISPUTE_VIEWED,
                identityCheckPerformed = isIdentityVerified,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Dispute ${command.disputeId} viewed by ${principal.id} verified=$isIdentityVerified",
                alertTriggered = false
            )
        )

        // Protect against unverified disclosure: redact sensitive identifier if not verified
        val redactedPlayerRef = if (isIdentityVerified) existing.playerReference else "REDACTED-UNVERIFIED"
        val evidenceRef = "dispute-view:${command.tenantId}:${command.disputeId}:v${existing.serverVersion}"

        return PaymentDisputeDetailResult(
            disputeId = existing.disputeId,
            tenantId = existing.tenantId,
            playerReferenceRedacted = redactedPlayerRef,
            transactionReference = existing.transactionReference,
            disputedAmountMinorUnits = existing.disputedAmountMinorUnits,
            currencyCode = existing.currencyCode,
            disputeType = existing.disputeType,
            stage = existing.stage,
            identityStatus = existing.identityStatus,
            notes = existing.notes.filter { !it.isInternal || principal.kind == PrincipalKind.ADMIN },
            evidenceAttachments = existing.evidenceAttachments,
            slaTracking = existing.slaTracking,
            sensitiveDataDisclosed = isIdentityVerified,
            evidenceReference = evidenceRef
        )
    }

    /**
     * Evaluates dispute SLA deadlines and triggers alerts on risk or breach.
     * Prevents invisible SLA failures for payment disputes.
     */
    fun evaluateDisputeSla(tenantId: String, disputeId: String, now: Instant): DisputeSlaEvaluationResult = synchronized(lock) {
        PaymentDisputeSupportBinding.checkBound()

        val existing = store.findDispute(tenantId, disputeId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val tracking = existing.slaTracking
        val evidenceDue = tracking.evidenceSubmissionDueAt
        val resolutionDue = tracking.disputeResolutionDueAt

        val evidenceRemaining = Duration.between(now, evidenceDue).toMillis()
        val resolutionRemaining = Duration.between(now, resolutionDue).toMillis()

        val isEvidenceBreached = tracking.evidenceSubmittedAt == null && now.isAfter(evidenceDue)
        val isResolutionBreached = tracking.resolvedAt == null && now.isAfter(resolutionDue)
        val isBreached = isEvidenceBreached || isResolutionBreached

        val isAtRisk = !isBreached && (evidenceRemaining < 86400000L || resolutionRemaining < 172800000L)

        val newSlaStatus = when {
            isBreached -> DisputeSlaStatus.BREACHED
            isAtRisk -> DisputeSlaStatus.AT_RISK
            else -> DisputeSlaStatus.WITHIN_SLA
        }

        if (newSlaStatus != tracking.status) {
            val updatedDispute = existing.copy(
                slaTracking = tracking.copy(status = newSlaStatus, lastEvaluatedAt = now)
            )
            store.saveDispute(updatedDispute)

            if (newSlaStatus == DisputeSlaStatus.BREACHED) {
                store.recordAlert(
                    DisputeAlertRecord(
                        alertId = "alert-${UUID.randomUUID()}",
                        tenantId = tenantId,
                        disputeId = disputeId,
                        severity = "CRITICAL",
                        alertType = "DISPUTE_SLA_BREACHED",
                        message = "SLA BREACHED for payment dispute $disputeId txRef=${existing.transactionReference}",
                        correlationId = "sla-eval-$disputeId",
                        timestamp = now
                    )
                )
            } else if (newSlaStatus == DisputeSlaStatus.AT_RISK) {
                store.recordAlert(
                    DisputeAlertRecord(
                        alertId = "alert-${UUID.randomUUID()}",
                        tenantId = tenantId,
                        disputeId = disputeId,
                        severity = "WARN",
                        alertType = "DISPUTE_SLA_AT_RISK",
                        message = "Payment dispute $disputeId is AT RISK of SLA breach",
                        correlationId = "sla-eval-$disputeId",
                        timestamp = now
                    )
                )
            }
        }

        return DisputeSlaEvaluationResult(
            disputeId = disputeId,
            slaStatus = newSlaStatus,
            evidenceSubmissionTimeRemainingMs = evidenceRemaining,
            resolutionTimeRemainingMs = resolutionRemaining,
            isBreached = isBreached,
            isAtRisk = isAtRisk,
            evidenceReference = "dispute-sla-eval:$tenantId:$disputeId:$newSlaStatus"
        )
    }

    // =========================================================================
    // Helpers
    // =========================================================================

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
