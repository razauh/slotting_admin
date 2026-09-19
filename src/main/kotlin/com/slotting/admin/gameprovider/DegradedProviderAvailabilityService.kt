package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate enforcing GAME-009-02: Control degraded provider availability.
 * Protected risk: "timeout double-posts/stuck round invisible"
 * Semantic contract: "Disabled/degraded provider blocks new launch while settling safe known outcomes."
 */
object DegradedProviderAvailabilityBinding {
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("timeout double-posts/stuck round invisible")
        }
    }
}

enum class ProviderAvailabilityStatus {
    AVAILABLE,
    DEGRADED,
    DISABLED,
    MAINTENANCE,
}

data class ProviderAvailabilityRecord(
    val tenantId: String,
    val providerId: String,
    var status: ProviderAvailabilityStatus,
    var consecutiveFailures: Int = 0,
    var reason: String,
    var updatedBy: String,
    var updatedAt: Instant,
    val inFlightSettlementPermitted: Boolean = true,
    val newLaunchPermitted: Boolean,
    var version: Long = 1L,
    var evidenceReference: String,
)

data class UpdateProviderAvailabilityCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val providerId: String,
    val targetStatus: ProviderAvailabilityStatus,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class RecordProviderHealthSignalCommand(
    val tenantId: String,
    val providerId: String,
    val success: Boolean,
    val latencyMs: Long,
    val errorReason: String? = null,
    val failureThreshold: Int = 3,
)

data class ProviderAvailabilityResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val status: ProviderAvailabilityStatus,
    val newLaunchPermitted: Boolean,
    val inFlightSettlementPermitted: Boolean,
    val reason: String,
    val version: Long,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface ProviderAvailabilityAlertSink {
    fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String)
}

class InMemoryProviderAvailabilityAlertSink : ProviderAvailabilityAlertSink {
    val alerts = mutableListOf<String>()

    @Synchronized
    override fun sendAlert(tenantId: String, severity: String, alertType: String, detail: String) {
        alerts.add("$tenantId:$severity:$alertType:$detail")
    }
}

interface ProviderAvailabilityStore {
    fun findAvailability(tenantId: String, providerId: String): ProviderAvailabilityRecord?
    fun saveAvailability(
        record: ProviderAvailabilityRecord,
        result: ProviderAvailabilityResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun updateRecord(record: ProviderAvailabilityRecord)
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ProviderAvailabilityResult>?
    fun listAll(tenantId: String): List<ProviderAvailabilityRecord>
}

class InMemoryProviderAvailabilityStore : ProviderAvailabilityStore {
    private val records = ConcurrentHashMap<String, ProviderAvailabilityRecord>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, ProviderAvailabilityResult>>()
    val auditEvents = mutableListOf<AuditEvent>()
    val outboxEvents = mutableListOf<OutboxEvent>()

    private fun key(tenantId: String, providerId: String) = "$tenantId:$providerId"

    @Synchronized
    override fun findAvailability(tenantId: String, providerId: String): ProviderAvailabilityRecord? {
        return records[key(tenantId, providerId)]?.copy()
    }

    @Synchronized
    override fun saveAvailability(
        record: ProviderAvailabilityRecord,
        result: ProviderAvailabilityResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        records[key(record.tenantId, record.providerId)] = record.copy()
        idempotency["${record.tenantId}:$idempotencyKey"] = fingerprint to result
        auditEvents.add(audit)
        outboxEvents.add(outbox)
    }

    @Synchronized
    override fun updateRecord(record: ProviderAvailabilityRecord) {
        records[key(record.tenantId, record.providerId)] = record.copy()
    }

    @Synchronized
    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ProviderAvailabilityResult>? {
        return idempotency["$tenantId:$idempotencyKey"]
    }

    @Synchronized
    override fun listAll(tenantId: String): List<ProviderAvailabilityRecord> {
        return records.values.filter { it.tenantId == tenantId }.map { it.copy() }
    }
}

class DegradedProviderAvailabilityService(
    private val store: ProviderAvailabilityStore,
    private val rbacPolicy: AdminRbacPolicy = AdminRbacPolicy(true),
    private val alertSink: ProviderAvailabilityAlertSink = InMemoryProviderAvailabilityAlertSink(),
    private val clock: Clock = Clock.systemUTC(),
) {
    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun fingerprint(cmd: UpdateProviderAvailabilityCommand): String {
        return sha256("${cmd.tenantId}:${cmd.providerId}:${cmd.targetStatus}:${cmd.reason}:${cmd.expectedVersion}")
    }

    /**
     * Asserts whether new game launches are permitted.
     * Semantic contract: "Disabled/degraded provider blocks new launch while settling safe known outcomes."
     */
    fun assertLaunchPermitted(tenantId: String, providerId: String) {
        DegradedProviderAvailabilityBinding.checkBound()

        val record = store.findAvailability(tenantId, providerId)
        val status = record?.status ?: ProviderAvailabilityStatus.AVAILABLE

        if (status != ProviderAvailabilityStatus.AVAILABLE) {
            alertSink.sendAlert(
                tenantId = tenantId,
                severity = "HIGH",
                alertType = "PROVIDER_LAUNCH_BLOCKED_UNAVAILABLE",
                detail = "Launch blocked for provider $providerId because status is $status (reason: ${record?.reason})",
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    /**
     * Asserts whether settling safe known outcomes (win settlement, refund, rollback) is permitted.
     * Semantic contract: "Disabled/degraded provider blocks new launch while settling safe known outcomes."
     * In-flight safe settlements are ALWAYS permitted even if DEGRADED or DISABLED.
     */
    fun assertSettlementPermitted(tenantId: String, providerId: String): Boolean {
        DegradedProviderAvailabilityBinding.checkBound()
        // Always permitted for safe in-flight resolution
        return true
    }

    @Synchronized
    fun updateProviderAvailability(command: UpdateProviderAvailabilityCommand): ProviderAvailabilityResult {
        DegradedProviderAvailabilityBinding.checkBound()

        // 1. Validation
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.reason.isBlank() ||
            command.idempotencyKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Authorization Check (Least privilege RBAC)
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!rbacPolicy.isPermitted(principal, AdminPermission.FINANCIAL_MUTATION) &&
            !rbacPolicy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Idempotency Check
        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()

        // 4. Retrieve or Create Availability Record
        val existing = store.findAvailability(command.tenantId, command.providerId)
        val currentVersion = existing?.version ?: 1L

        if (command.expectedVersion != currentVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val resultId = UUID.randomUUID()
        val evidenceRef = sha256("${command.tenantId}:${command.providerId}:${command.targetStatus}:$resultId:${now.toEpochMilli()}")

        val launchPermitted = (command.targetStatus == ProviderAvailabilityStatus.AVAILABLE)

        val updatedRecord = ProviderAvailabilityRecord(
            tenantId = command.tenantId,
            providerId = command.providerId,
            status = command.targetStatus,
            consecutiveFailures = if (command.targetStatus == ProviderAvailabilityStatus.AVAILABLE) 0 else (existing?.consecutiveFailures ?: 0),
            reason = command.reason,
            updatedBy = principal.id,
            updatedAt = now,
            inFlightSettlementPermitted = true, // Always true to settle safe known outcomes!
            newLaunchPermitted = launchPermitted,
            version = currentVersion + 1L,
            evidenceReference = evidenceRef,
        )

        val result = ProviderAvailabilityResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            status = command.targetStatus,
            newLaunchPermitted = launchPermitted,
            inFlightSettlementPermitted = true,
            reason = command.reason,
            version = updatedRecord.version,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PROVIDER_AVAILABILITY_CHANGED_${command.targetStatus}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PROVIDER_AVAILABILITY_CHANGED",
            createdAt = now,
        )

        store.saveAvailability(updatedRecord, result, command.idempotencyKey, fp, audit, outbox)

        // Alert on degradation or disablement (Prevent stuck round invisible)
        if (command.targetStatus != ProviderAvailabilityStatus.AVAILABLE) {
            alertSink.sendAlert(
                tenantId = command.tenantId,
                severity = "HIGH",
                alertType = "PROVIDER_AVAILABILITY_ALERT",
                detail = "Provider ${command.providerId} transitioned to ${command.targetStatus}: ${command.reason}",
            )
        }

        return result
    }

    @Synchronized
    fun recordHealthSignal(command: RecordProviderHealthSignalCommand): ProviderAvailabilityRecord {
        DegradedProviderAvailabilityBinding.checkBound()

        val now = clock.instant()
        val record = store.findAvailability(command.tenantId, command.providerId)
            ?: ProviderAvailabilityRecord(
                tenantId = command.tenantId,
                providerId = command.providerId,
                status = ProviderAvailabilityStatus.AVAILABLE,
                consecutiveFailures = 0,
                reason = "Initial health registration",
                updatedBy = "SYSTEM",
                updatedAt = now,
                inFlightSettlementPermitted = true,
                newLaunchPermitted = true,
                version = 1L,
                evidenceReference = "init",
            )

        if (command.success) {
            record.consecutiveFailures = 0
            if (record.status == ProviderAvailabilityStatus.DEGRADED) {
                record.status = ProviderAvailabilityStatus.AVAILABLE
                record.reason = "Recovered from degraded state via healthy probe"
                record.updatedAt = now
                record.version += 1L
                val evidence = sha256("${command.tenantId}:${command.providerId}:HEALTHY:${now.toEpochMilli()}")
                record.evidenceReference = evidence

                val resultId = UUID.randomUUID()
                val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, "PROVIDER_RECOVERED_HEALTHY", now, "c-probe", "cause-probe")
                val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, "PROVIDER_RECOVERED_HEALTHY", now)
                val res = ProviderAvailabilityResult(resultId, command.tenantId, command.providerId, record.status, true, true, record.reason, record.version, now, evidence)
                store.saveAvailability(record, res, "k-probe-heal-${now.toEpochMilli()}-${UUID.randomUUID()}", "fp-heal", audit, outbox)
            } else {
                store.updateRecord(record)
            }
        } else {
            record.consecutiveFailures += 1
            if (record.consecutiveFailures >= command.failureThreshold && record.status == ProviderAvailabilityStatus.AVAILABLE) {
                record.status = ProviderAvailabilityStatus.DEGRADED
                record.reason = "Tripped to DEGRADED after ${record.consecutiveFailures} consecutive failures: ${command.errorReason}"
                record.updatedAt = now
                record.version += 1L
                val evidence = sha256("${command.tenantId}:${command.providerId}:TRIPPED_DEGRADED:${now.toEpochMilli()}")
                record.evidenceReference = evidence

                val resultId = UUID.randomUUID()
                val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, "PROVIDER_TRIPPED_DEGRADED", now, "c-trip", "cause-trip")
                val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, "PROVIDER_TRIPPED_DEGRADED", now)
                val res = ProviderAvailabilityResult(resultId, command.tenantId, command.providerId, record.status, false, true, record.reason, record.version, now, evidence)
                store.saveAvailability(record, res, "k-probe-trip-${now.toEpochMilli()}-${UUID.randomUUID()}", "fp-trip", audit, outbox)

                alertSink.sendAlert(
                    tenantId = command.tenantId,
                    severity = "HIGH",
                    alertType = "PROVIDER_AUTOMATIC_TRIP_DEGRADED",
                    detail = record.reason,
                )
            } else {
                store.updateRecord(record)
            }
        }

        return record
    }
}
