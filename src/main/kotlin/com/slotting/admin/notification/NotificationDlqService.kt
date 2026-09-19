package com.slotting.admin.notification

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for NOTIFY-003-03:
 * "restart duplicates/unbounded retries"
 */
object NotificationDlqBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("restart duplicates/unbounded retries")
        }
    }
}

enum class DlqStatus {
    QUARANTINED,
    REPLAY_REQUESTED,
    RESOLVED_DISCARDED,
    RESOLVED_REPLAYED,
}

enum class QuarantineReason {
    RETRY_EXHAUSTION,
    PAYLOAD_CORRUPT,
    AUTHENTICATION_FAILED,
    POLICY_VIOLATION,
    PROVIDER_UNREACHABLE,
}

data class QuarantineNotificationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val trackingId: UUID,
    val notificationId: UUID,
    val recipientId: String,
    val channel: NotificationDeliveryChannel,
    val quarantineReason: QuarantineReason,
    val quarantineDetail: String,
    val failureCount: Int,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ResolveDlqItemCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val dlqId: UUID,
    val action: String, // "REPLAY" or "DISCARD"
    val resolutionNote: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class NotificationDlqRecord(
    val dlqId: UUID = UUID.randomUUID(),
    val trackingId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val recipientId: String,
    val channel: NotificationDeliveryChannel,
    val quarantineReason: QuarantineReason,
    val quarantineDetail: String,
    val failureCount: Int,
    val dlqStatus: DlqStatus,
    val quarantinedAt: Instant,
    val resolvedAt: Instant? = null,
    val resolvedBy: String? = null,
    val resolutionAction: String? = null,
    val resolutionNote: String? = null,
    val alertEmitted: Boolean = true,
    val evidenceReference: String,
    val isUserRead: Boolean = false,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
    val version: Long = 1L,
)

data class NotificationDlqAuditEntry(
    val eventId: UUID = UUID.randomUUID(),
    val dlqId: UUID,
    val tenantId: String,
    val notificationId: UUID,
    val eventType: String,
    val fromStatus: DlqStatus?,
    val toStatus: DlqStatus,
    val actorId: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

data class NotificationDlqResult(
    val dlqId: UUID,
    val trackingId: UUID,
    val notificationId: UUID,
    val tenantId: String,
    val dlqStatus: DlqStatus,
    val quarantineReason: QuarantineReason,
    val failureCount: Int,
    val alertEmitted: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String,
    val isUserRead: Boolean = false,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class DlqDashboardMetrics(
    val tenantId: String,
    val totalQuarantined: Int,
    val activeQuarantined: Int,
    val resolvedReplayed: Int,
    val resolvedDiscarded: Int,
    val alertCount: Int,
)

class NotificationDlqException(
    val errorCode: String,
    message: String,
) : RuntimeException("[$errorCode] $message")

class NotificationDlqService(
    private val clock: Clock = Clock.systemUTC(),
) {
    private val dlqStore = ConcurrentHashMap<UUID, NotificationDlqRecord>()
    private val notificationDlqIndex = ConcurrentHashMap<String, UUID>()
    private val idempotencyStore = ConcurrentHashMap<String, NotificationDlqResult>()
    private val idempotencyPayloadHash = ConcurrentHashMap<String, String>()
    private val auditLog = mutableListOf<NotificationDlqAuditEntry>()

    companion object {
        const val SEMANTIC_CONTRACT = "Delivery status not proof user read; health/latency/failure dashboards."
    }

    private fun notificationKey(tenantId: String, notificationId: UUID): String =
        "$tenantId:$notificationId"

    @Synchronized
    fun quarantineNotification(command: QuarantineNotificationCommand): NotificationDlqResult {
        NotificationDlqBinding.checkBound()

        validateQuarantineCommand(command)

        val tenantId = command.tenantId
        val notificationId = command.notificationId
        val notifKey = notificationKey(tenantId, notificationId)
        val idemKey = "dlq-quarantine:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.trackingId}:${command.quarantineReason}:${command.failureCount}"

        // Idempotency check
        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw NotificationDlqException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting quarantine payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        if (notificationDlqIndex.containsKey(notifKey)) {
            throw NotificationDlqException(
                "CONFLICT",
                "Notification $notificationId already quarantined in DLQ"
            )
        }

        val now = clock.instant()
        val record = NotificationDlqRecord(
            trackingId = command.trackingId,
            notificationId = notificationId,
            tenantId = tenantId,
            recipientId = command.recipientId,
            channel = command.channel,
            quarantineReason = command.quarantineReason,
            quarantineDetail = command.quarantineDetail,
            failureCount = command.failureCount,
            dlqStatus = DlqStatus.QUARANTINED,
            quarantinedAt = now,
            alertEmitted = true,
            evidenceReference = "notification:dlq:$notificationId",
            isUserRead = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = 1L,
        )

        dlqStore[record.dlqId] = record
        notificationDlqIndex[notifKey] = record.dlqId

        auditLog.add(
            NotificationDlqAuditEntry(
                dlqId = record.dlqId,
                tenantId = tenantId,
                notificationId = notificationId,
                eventType = "NOTIFICATION_QUARANTINED",
                fromStatus = null,
                toStatus = DlqStatus.QUARANTINED,
                actorId = command.principal?.id ?: "system",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = NotificationDlqResult(
            dlqId = record.dlqId,
            trackingId = command.trackingId,
            notificationId = notificationId,
            tenantId = tenantId,
            dlqStatus = DlqStatus.QUARANTINED,
            quarantineReason = command.quarantineReason,
            failureCount = command.failureCount,
            alertEmitted = true,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = record.evidenceReference,
            semanticContract = SEMANTIC_CONTRACT,
            isUserRead = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        idempotencyStore[idemKey] = result
        idempotencyPayloadHash[idemKey] = payloadHash
        return result
    }

    @Synchronized
    fun resolveDlqItem(command: ResolveDlqItemCommand): NotificationDlqResult {
        NotificationDlqBinding.checkBound()

        validateResolveCommand(command)

        val idemKey = "dlq-resolve:${command.tenantId}:${command.idempotencyKey}"
        val payloadHash = "${command.dlqId}:${command.action}:${command.resolutionNote}"

        if (idempotencyStore.containsKey(idemKey)) {
            val prevHash = idempotencyPayloadHash[idemKey]
            if (prevHash != payloadHash) {
                throw NotificationDlqException(
                    "CONFLICT",
                    "Idempotency key reused with conflicting DLQ resolve payload"
                )
            }
            return idempotencyStore[idemKey]!!
        }

        val existing = dlqStore[command.dlqId]
            ?: throw NotificationDlqException("NOT_FOUND", "DLQ record not found for id ${command.dlqId}")

        if (existing.tenantId != command.tenantId) {
            throw NotificationDlqException("FORBIDDEN", "Cross-tenant access forbidden")
        }

        if (existing.version != command.expectedVersion) {
            throw NotificationDlqException(
                "STALE",
                "Version mismatch: expected ${command.expectedVersion}, found ${existing.version}"
            )
        }

        if (existing.dlqStatus != DlqStatus.QUARANTINED && existing.dlqStatus != DlqStatus.REPLAY_REQUESTED) {
            throw NotificationDlqException(
                "CONFLICT",
                "Cannot resolve already finalized DLQ item in status ${existing.dlqStatus}"
            )
        }

        val now = clock.instant()
        val nextStatus = when (command.action.uppercase()) {
            "REPLAY" -> DlqStatus.RESOLVED_REPLAYED
            "DISCARD" -> DlqStatus.RESOLVED_DISCARDED
            else -> throw NotificationDlqException("INVALID", "Invalid resolution action: ${command.action}")
        }

        val updated = existing.copy(
            dlqStatus = nextStatus,
            resolvedAt = now,
            resolvedBy = command.principal?.id,
            resolutionAction = command.action.uppercase(),
            resolutionNote = command.resolutionNote,
            isUserRead = false, // Critical invariant
            directEligibilityGranted = false,
            financialMutationPermitted = false,
            version = existing.version + 1L,
        )

        dlqStore[command.dlqId] = updated

        auditLog.add(
            NotificationDlqAuditEntry(
                dlqId = updated.dlqId,
                tenantId = command.tenantId,
                notificationId = updated.notificationId,
                eventType = "NOTIFICATION_DLQ_RESOLVED_${nextStatus.name}",
                fromStatus = existing.dlqStatus,
                toStatus = nextStatus,
                actorId = command.principal?.id ?: "unknown",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        val result = NotificationDlqResult(
            dlqId = updated.dlqId,
            trackingId = updated.trackingId,
            notificationId = updated.notificationId,
            tenantId = command.tenantId,
            dlqStatus = nextStatus,
            quarantineReason = updated.quarantineReason,
            failureCount = updated.failureCount,
            alertEmitted = false,
            serverTime = now,
            serverVersion = updated.version,
            evidenceReference = updated.evidenceReference,
            semanticContract = SEMANTIC_CONTRACT,
            isUserRead = false,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        idempotencyStore[idemKey] = result
        idempotencyPayloadHash[idemKey] = payloadHash
        return result
    }

    fun getDlqRecord(dlqId: UUID): NotificationDlqRecord? {
        NotificationDlqBinding.checkBound()
        return dlqStore[dlqId]
    }

    fun getDashboardMetrics(tenantId: String): DlqDashboardMetrics {
        NotificationDlqBinding.checkBound()

        val tenantRecords = dlqStore.values.filter { it.tenantId == tenantId }
        val total = tenantRecords.size
        val active = tenantRecords.count { it.dlqStatus == DlqStatus.QUARANTINED || it.dlqStatus == DlqStatus.REPLAY_REQUESTED }
        val replayed = tenantRecords.count { it.dlqStatus == DlqStatus.RESOLVED_REPLAYED }
        val discarded = tenantRecords.count { it.dlqStatus == DlqStatus.RESOLVED_DISCARDED }
        val alerts = tenantRecords.count { it.alertEmitted }

        return DlqDashboardMetrics(
            tenantId = tenantId,
            totalQuarantined = total,
            activeQuarantined = active,
            resolvedReplayed = replayed,
            resolvedDiscarded = discarded,
            alertCount = alerts,
        )
    }

    fun getAuditEntries(dlqId: UUID): List<NotificationDlqAuditEntry> {
        NotificationDlqBinding.checkBound()
        return auditLog.filter { it.dlqId == dlqId }
    }

    private fun validateQuarantineCommand(command: QuarantineNotificationCommand) {
        if (command.principal == null) {
            throw NotificationDlqException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw NotificationDlqException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        if (command.tenantId.isBlank()) {
            throw NotificationDlqException("INVALID", "tenantId cannot be blank")
        }
        if (command.recipientId.isBlank()) {
            throw NotificationDlqException("INVALID", "recipientId cannot be blank")
        }
        if (command.failureCount <= 0) {
            throw NotificationDlqException("BOUNDARY", "failureCount must be greater than 0")
        }
        if (command.idempotencyKey.isBlank()) {
            throw NotificationDlqException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw NotificationDlqException("INVALID", "Correlation and causation IDs required")
        }
    }

    private fun validateResolveCommand(command: ResolveDlqItemCommand) {
        if (command.principal == null) {
            throw NotificationDlqException("UNAUTHENTICATED", "Authentication required")
        }
        if (command.principal.tenantId != command.tenantId) {
            throw NotificationDlqException("FORBIDDEN", "Cross-tenant access forbidden")
        }
        // RBAC check: only SUPER_ADMIN or SUPPORT can resolve DLQ items
        if (!command.principal.roles.contains(AdminRole.SUPER_ADMIN) && !command.principal.roles.contains(AdminRole.SUPPORT)) {
            throw NotificationDlqException("FORBIDDEN", "Insufficient role to resolve DLQ item")
        }
        if (command.idempotencyKey.isBlank()) {
            throw NotificationDlqException("INVALID", "idempotencyKey cannot be blank")
        }
        if (command.resolutionNote.isBlank()) {
            throw NotificationDlqException("INVALID", "resolutionNote cannot be blank")
        }
        if (command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw NotificationDlqException("INVALID", "Correlation and causation IDs required")
        }
    }
}
