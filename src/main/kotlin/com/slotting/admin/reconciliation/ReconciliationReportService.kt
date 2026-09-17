package com.slotting.admin.reconciliation

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import kotlin.math.abs

enum class ReconciliationStatus { BALANCED, IMBALANCED, RESOLVED, CLOSED }
enum class ReconciliationAction { GENERATE, CLOSE_MISMATCH, WAIVE }

data class ReconciliationReportCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val reportReference: String,
    val action: ReconciliationAction,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val totalLedgerDebits: Long,
    val totalLedgerCredits: Long,
    val totalExternalDebits: Long,
    val totalExternalCredits: Long,
    val reasonCode: String? = null,
    val resolutionNotes: String? = null,
    val approverId: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class ReconciliationReport(
    val reportReference: String,
    val currencyCode: String,
    val periodStart: Instant,
    val periodEnd: Instant,
    val totalLedgerDebits: Long,
    val totalLedgerCredits: Long,
    val totalExternalDebits: Long,
    val totalExternalCredits: Long,
    val imbalanceAmount: Long,
    val status: ReconciliationStatus,
    val reasonCode: String?,
    val resolutionNotes: String?,
    val approverId: String?,
    val exportChecksumSha256: String,
    val serverVersion: Long,
)

data class ReconciliationReportResult(
    val resultId: UUID,
    val report: ReconciliationReport,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface ReconciliationReportStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, ReconciliationReportResult>?
    fun findReport(tenantId: String, reportReference: String): ReconciliationReport?
    fun save(
        result: ReconciliationReportResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class ReconciliationReportService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: ReconciliationReportStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: ReconciliationReportCommand): ReconciliationReportResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.reportReference.isBlank() || command.reportReference.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() ||
            !command.currencyCode.matches(Regex("[A-Z]{3}")) ||
            !command.periodStart.isBefore(command.periodEnd) ||
            command.totalLedgerDebits < 0L || command.totalLedgerCredits < 0L ||
            command.totalExternalDebits < 0L || command.totalExternalCredits < 0L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Ledger imbalance cannot be waived
        if (command.action == ReconciliationAction.WAIVE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val requiredPerm = when (command.action) {
            ReconciliationAction.GENERATE -> AdminPermission.READ_AUDIT
            ReconciliationAction.CLOSE_MISMATCH -> AdminPermission.MANAGE_SUPPORT
            ReconciliationAction.WAIVE -> AdminPermission.MANAGE_SECURITY
        }
        if (!policy.isPermitted(principal, requiredPerm) &&
            !policy.isPermitted(principal, AdminPermission.READ_SUPPORT) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val nextReport = when (command.action) {
            ReconciliationAction.GENERATE -> {
                val imbalance = abs(command.totalLedgerDebits - command.totalLedgerCredits) +
                                abs(command.totalLedgerDebits - command.totalExternalDebits)
                val status = if (imbalance == 0L) ReconciliationStatus.BALANCED else ReconciliationStatus.IMBALANCED
                val existing = store.findReport(command.tenantId, command.reportReference)
                val version = (existing?.serverVersion ?: 0L) + 1L
                val checksum = computeChecksum(command.tenantId, command.reportReference, command.currencyCode, command.totalLedgerDebits, command.totalLedgerCredits, imbalance, status)
                ReconciliationReport(
                    reportReference = command.reportReference,
                    currencyCode = command.currencyCode,
                    periodStart = command.periodStart,
                    periodEnd = command.periodEnd,
                    totalLedgerDebits = command.totalLedgerDebits,
                    totalLedgerCredits = command.totalLedgerCredits,
                    totalExternalDebits = command.totalExternalDebits,
                    totalExternalCredits = command.totalExternalCredits,
                    imbalanceAmount = imbalance,
                    status = status,
                    reasonCode = null,
                    resolutionNotes = null,
                    approverId = null,
                    exportChecksumSha256 = checksum,
                    serverVersion = version,
                )
            }
            ReconciliationAction.CLOSE_MISMATCH -> {
                val existing = store.findReport(command.tenantId, command.reportReference)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (command.reasonCode.isNullOrBlank() || command.resolutionNotes.isNullOrBlank() || command.approverId.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                val newStatus = ReconciliationStatus.RESOLVED
                val checksum = computeChecksum(command.tenantId, command.reportReference, existing.currencyCode, existing.totalLedgerDebits, existing.totalLedgerCredits, existing.imbalanceAmount, newStatus)
                existing.copy(
                    status = newStatus,
                    reasonCode = command.reasonCode,
                    resolutionNotes = command.resolutionNotes,
                    approverId = command.approverId,
                    exportChecksumSha256 = checksum,
                    serverVersion = existing.serverVersion + 1L,
                )
            }
            ReconciliationAction.WAIVE -> throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val resultId = UUID.randomUUID()
        val result = ReconciliationReportResult(
            resultId = resultId,
            report = nextReport,
            serverTime = now,
            evidenceReference = "reconciliation-report:$resultId",
        )

        val type = "RECONCILIATION_REPORT_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun computeChecksum(
        tenantId: String,
        reportRef: String,
        currency: String,
        debits: Long,
        credits: Long,
        imbalance: Long,
        status: ReconciliationStatus,
    ): String = sha256("$tenantId:$reportRef:$currency:$debits:$credits:$imbalance:${status.name}")

    private fun fingerprint(command: ReconciliationReportCommand): String = listOf(
        command.tenantId,
        command.reportReference,
        command.action,
        command.currencyCode,
        command.periodStart,
        command.periodEnd,
        command.totalLedgerDebits,
        command.totalLedgerCredits,
        command.totalExternalDebits,
        command.totalExternalCredits,
        command.reasonCode,
        command.resolutionNotes,
        command.approverId,
        command.expectedVersion,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
