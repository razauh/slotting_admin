package com.slotting.admin.aml

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class FraudRestrictionLevel {
    NONE,
    FLAGGED,
    RESTRICTED,
    FROZEN,
}

enum class FraudAlertSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

data class FraudSignalPayload(
    val subjectReference: String,
    val deviceFingerprint: String,
    val ipAddress: String,
    val isVpnOrProxy: Boolean = false,
    val isDeviceCompromised: Boolean = false,
    val velocityCountInWindow: Int = 0,
    val distinctIpCountInWindow: Int = 1,
    val signalMetadata: Map<String, String> = emptyMap(),
)

data class CollectFraudSignalsCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val subjectReference: String,
    val signals: FraudSignalPayload,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class FraudDecisionProvenance(
    val detectedAnomalies: List<String>,
    val observedVelocity: Int,
    val observedDistinctIps: Int,
    val deviceCompromised: Boolean,
    val vpnOrProxyDetected: Boolean,
    val evaluatedAt: Instant,
)

data class FraudSignalCollectionResult(
    val resultId: UUID,
    val tenantId: String,
    val subjectReference: String,
    val restrictionLevel: FraudRestrictionLevel,
    val alertSeverity: FraudAlertSeverity?,
    val amlCaseReference: String?,
    val amlQueueReason: AmlReviewReason?,
    val detectedAnomalies: List<String>,
    val provenance: FraudDecisionProvenance,
    val financialAuthorityCreated: Boolean, // Invariant: must be false
    val moneyMutated: Boolean,             // Invariant: must be false
    val evidenceReference: String,
    val serverTime: Instant,
)

data class DurableFraudRecord(
    val tenantId: String,
    val subjectReference: String,
    val restrictionLevel: FraudRestrictionLevel,
    val activeAlertSeverity: FraudAlertSeverity?,
    val amlCaseReference: String?,
    val signalHistoryCount: Int,
    val lastSignalAt: Instant,
    val serverVersion: Long,
)

interface EphemeralFraudSignalCache {
    fun getRestriction(tenantId: String, subjectReference: String): FraudRestrictionLevel?
    fun putRestriction(tenantId: String, subjectReference: String, level: FraudRestrictionLevel)
    fun evict(tenantId: String, subjectReference: String)
    fun flushAll()
}

interface FraudSignalStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, FraudSignalCollectionResult>?
    fun findRecord(tenantId: String, subjectReference: String): DurableFraudRecord?
    fun save(
        record: DurableFraudRecord,
        result: FraudSignalCollectionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queuedAmlItem: AmlQueueItem? = null,
    )
}

class AuthoritativeFraudSignalService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: FraudSignalStore,
    private val cache: EphemeralFraudSignalCache,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun collectSignals(command: CollectFraudSignalsCommand): FraudSignalCollectionResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.subjectReference.isBlank() ||
            command.signals.subjectReference.isBlank() ||
            command.signals.deviceFingerprint.isBlank() ||
            command.signals.ipAddress.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val anomalies = mutableListOf<String>()
        if (command.signals.isDeviceCompromised) {
            anomalies += "COMPROMISED_DEVICE"
        }
        if (command.signals.velocityCountInWindow > 10 || command.signals.distinctIpCountInWindow > 3) {
            anomalies += "VELOCITY_SPIKE"
        }
        if (command.signals.isVpnOrProxy) {
            anomalies += "VPN_OR_PROXY_DETECTED"
        }

        val (alertSeverity, restrictionLevel, amlReason) = when {
            command.signals.isDeviceCompromised -> Triple(
                FraudAlertSeverity.CRITICAL,
                FraudRestrictionLevel.FROZEN,
                AmlReviewReason.HIGH_RISK_ACTION,
            )
            anomalies.contains("VELOCITY_SPIKE") -> Triple(
                FraudAlertSeverity.HIGH,
                FraudRestrictionLevel.RESTRICTED,
                AmlReviewReason.SUSPICIOUS_ACTIVITY,
            )
            anomalies.contains("VPN_OR_PROXY_DETECTED") -> Triple(
                FraudAlertSeverity.MEDIUM,
                FraudRestrictionLevel.FLAGGED,
                AmlReviewReason.SUSPICIOUS_ACTIVITY,
            )
            else -> Triple(
                FraudAlertSeverity.LOW,
                FraudRestrictionLevel.NONE,
                null,
            )
        }

        // Alert no case prevented: Every alert causing restriction/freeze must have an authoritative review case
        val (caseRef, queueItem) = if (restrictionLevel in setOf(FraudRestrictionLevel.RESTRICTED, FraudRestrictionLevel.FROZEN)) {
            val ref = "AML-CASE-${command.subjectReference}"
            val item = AmlQueueItem(
                caseReference = ref,
                state = AmlReviewState.QUEUED,
                claimedBy = null,
                claimExpiresAt = null,
                serverVersion = 0L,
            )
            ref to item
        } else {
            null to null
        }

        val now = clock.instant()
        val existingRecord = store.findRecord(command.tenantId, command.subjectReference)
        val newVersion = (existingRecord?.serverVersion ?: 0L) + 1L

        val record = DurableFraudRecord(
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            restrictionLevel = restrictionLevel,
            activeAlertSeverity = alertSeverity,
            amlCaseReference = caseRef,
            signalHistoryCount = (existingRecord?.signalHistoryCount ?: 0) + 1,
            lastSignalAt = now,
            serverVersion = newVersion,
        )

        // Ephemeral cache write: Populated in cache, but durable store is source of truth
        cache.putRestriction(command.tenantId, command.subjectReference, restrictionLevel)

        val resultId = UUID.randomUUID()
        val provenance = FraudDecisionProvenance(
            detectedAnomalies = anomalies,
            observedVelocity = command.signals.velocityCountInWindow,
            observedDistinctIps = command.signals.distinctIpCountInWindow,
            deviceCompromised = command.signals.isDeviceCompromised,
            vpnOrProxyDetected = command.signals.isVpnOrProxy,
            evaluatedAt = now,
        )

        val result = FraudSignalCollectionResult(
            resultId = resultId,
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            restrictionLevel = restrictionLevel,
            alertSeverity = alertSeverity,
            amlCaseReference = caseRef,
            amlQueueReason = amlReason,
            detectedAnomalies = anomalies,
            provenance = provenance,
            financialAuthorityCreated = false, // Invariant: No financial authority created
            moneyMutated = false,             // Invariant: Cannot mutate money
            evidenceReference = "EVID-FRAUD-${command.subjectReference}",
            serverTime = now,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_FRAUD_SIGNAL_COLLECTION",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "AML_FRAUD_SIGNAL_COLLECTION",
            createdAt = now,
        )

        store.save(record, result, command.tenantId, fp, command.idempotencyKey, audit, outbox, queueItem)
        return result
    }

    private fun fingerprint(command: CollectFraudSignalsCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.subjectReference}:${command.signals.deviceFingerprint}:${command.signals.ipAddress}:${command.signals.isDeviceCompromised}:${command.signals.isVpnOrProxy}:${command.signals.velocityCountInWindow}:${command.signals.distinctIpCountInWindow}:${command.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    @Synchronized
    fun checkRestriction(tenantId: String, subjectReference: String): FraudRestrictionLevel {
        // Check ephemeral cache first
        val cached = cache.getRestriction(tenantId, subjectReference)
        if (cached != null) {
            return cached
        }
        // Ephemeral cache loss never erases restriction: fall back to durable store
        val durable = store.findRecord(tenantId, subjectReference)
        val level = durable?.restrictionLevel ?: FraudRestrictionLevel.NONE
        // Repopulate ephemeral cache
        cache.putRestriction(tenantId, subjectReference, level)
        return level
    }
}
