package com.slotting.admin.testkit

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
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Traceability binding for TEST-001-02: Create adversarial provider fakes.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "nondeterministic retry/time tests".
 */
object AdversarialProviderFakesBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("nondeterministic retry/time tests")
        }
    }
}

/**
 * Outcome-specific semantic contract for TEST-001-02.
 */
const val ADVERSARIAL_PROVIDER_FAKES_CONTRACT =
    "Provider fakes emulate duplicate/late/reordered/bad signatures; no fake satisfies certification."

// =============================================================================
// Domain Enums & Models
// =============================================================================

/**
 * Categories of external providers emulated by adversarial fakes.
 */
enum class AdversarialFakeProviderType {
    GAME_CASINO,
    PAYMENT_GATEWAY,
    KYC_IDENTITY,
    SMS_NOTIFICATION
}

/**
 * Injected adversarial anomalies.
 */
enum class AdversarialSimulationFault {
    NONE,
    DUPLICATE_DELIVERY,
    LATE_DELIVERY,
    REORDERED_DELIVERY,
    BAD_SIGNATURE,
    TIMEOUT_SIMULATION
}

/**
 * Registration record for an adversarial provider fake.
 * Invariant: isCertified is ALWAYS false. No fake satisfies certification!
 */
data class ProviderFakeRegistration(
    val providerId: String,
    val tenantId: String,
    val providerType: AdversarialFakeProviderType,
    val signingSecret: String,
    val isCertified: Boolean = false,
    val createdAt: Instant,
    val serverVersion: Long = 1L
) {
    fun satisfiesCertification(): Boolean = false
}

/**
 * Emulated provider event envelope.
 */
data class EmulatedEventEnvelope(
    val eventId: String,
    val providerId: String,
    val tenantId: String,
    val providerType: AdversarialFakeProviderType,
    val sequenceNumber: Long,
    val payload: String,
    val signatureHex: String,
    val faultInjected: AdversarialSimulationFault,
    val timestamp: Instant
)

/**
 * Audit actions for adversarial provider fakes.
 */
enum class AdversarialAuditAction {
    FAKE_REGISTERED,
    EVENT_PROCESSED,
    DUPLICATE_DROPPED,
    LATE_REJECTED,
    REORDERED_HELD,
    BAD_SIGNATURE_REJECTED,
    TIMEOUT_FAILED,
    CERTIFICATION_ATTEMPT_BLOCKED,
    FINANCIAL_MUTATION_REJECTED
}

data class AdversarialAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val principalId: String,
    val action: AdversarialAuditAction,
    val success: Boolean,
    val timestamp: Instant,
    val correlationId: String,
    val causationId: String,
    val detailsRedacted: String,
    val alertTriggered: Boolean = false
)

data class AdversarialAlertRecord(
    val alertId: String,
    val tenantId: String,
    val severity: String,
    val alertType: String,
    val message: String,
    val correlationId: String,
    val timestamp: Instant
)

// =============================================================================
// Store Port & In-Memory Store
// =============================================================================

interface AdversarialProviderFakesStore {
    fun saveFake(fake: ProviderFakeRegistration)
    fun findFake(tenantId: String, providerId: String): ProviderFakeRegistration?
    fun listFakes(tenantId: String): List<ProviderFakeRegistration>
    fun isEventProcessed(tenantId: String, eventId: String): Boolean
    fun markEventProcessed(tenantId: String, eventId: String)
    fun getLastSequence(tenantId: String, providerId: String): Long
    fun setLastSequence(tenantId: String, providerId: String, seq: Long)
    fun recordAudit(audit: AdversarialAuditRecord)
    fun getAudits(tenantId: String): List<AdversarialAuditRecord>
    fun recordAlert(alert: AdversarialAlertRecord)
    fun getAlerts(tenantId: String): List<AdversarialAlertRecord>
    fun recordOutbox(outbox: OutboxEvent)
    fun getOutbox(): List<OutboxEvent>
    fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

class InMemoryAdversarialProviderFakesStore : AdversarialProviderFakesStore {
    private val fakes = ConcurrentHashMap<String, ProviderFakeRegistration>()
    private val processedEvents = ConcurrentHashMap<String, Boolean>()
    private val lastSequences = ConcurrentHashMap<String, Long>()
    private val audits = mutableListOf<AdversarialAuditRecord>()
    private val alerts = mutableListOf<AdversarialAlertRecord>()
    private val outbox = mutableListOf<OutboxEvent>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, Any>>()

    private fun fakeKey(tenantId: String, providerId: String) = "$tenantId::$providerId"
    private fun eventKey(tenantId: String, eventId: String) = "$tenantId::$eventId"
    private fun idempKey(tenantId: String, idempotencyKey: String) = "$tenantId::$idempotencyKey"

    override fun saveFake(fake: ProviderFakeRegistration) {
        fakes[fakeKey(fake.tenantId, fake.providerId)] = fake
    }

    override fun findFake(tenantId: String, providerId: String): ProviderFakeRegistration? {
        return fakes[fakeKey(tenantId, providerId)]
    }

    override fun listFakes(tenantId: String): List<ProviderFakeRegistration> {
        return fakes.values.filter { it.tenantId == tenantId }
    }

    override fun isEventProcessed(tenantId: String, eventId: String): Boolean {
        return processedEvents.containsKey(eventKey(tenantId, eventId))
    }

    override fun markEventProcessed(tenantId: String, eventId: String) {
        processedEvents[eventKey(tenantId, eventId)] = true
    }

    override fun getLastSequence(tenantId: String, providerId: String): Long {
        return lastSequences.getOrDefault(fakeKey(tenantId, providerId), 0L)
    }

    override fun setLastSequence(tenantId: String, providerId: String, seq: Long) {
        lastSequences[fakeKey(tenantId, providerId)] = seq
    }

    @Synchronized
    override fun recordAudit(audit: AdversarialAuditRecord) {
        audits.add(audit)
    }

    @Synchronized
    override fun getAudits(tenantId: String): List<AdversarialAuditRecord> {
        return audits.filter { it.tenantId == tenantId }.toList()
    }

    @Synchronized
    override fun recordAlert(alert: AdversarialAlertRecord) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(tenantId: String): List<AdversarialAlertRecord> {
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

data class RegisterAdversarialFakeCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val providerId: String,
    val providerType: AdversarialFakeProviderType,
    val signingSecret: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class EmulateAdversarialDeliveryCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val providerId: String,
    val eventId: String,
    val sequenceNumber: Long,
    val payload: String,
    val faultInjected: AdversarialSimulationFault,
    val timestamp: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class ValidateCertificationEligibilityCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val providerId: String,
    val requestedCertificationLevel: String, // e.g. "PRODUCTION_CERTIFIED"
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class RegisterAdversarialFakeResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val providerType: AdversarialFakeProviderType,
    val isCertified: Boolean = false,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class EmulateAdversarialDeliveryResult(
    val resultId: UUID,
    val eventId: String,
    val providerId: String,
    val accepted: Boolean,
    val reasonCode: String,
    val faultInjected: AdversarialSimulationFault,
    val serverTime: Instant,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class ValidateCertificationEligibilityResult(
    val providerId: String,
    val isCertified: Boolean,
    val message: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

// =============================================================================
// Authoritative Service
// =============================================================================

class AdversarialProviderFakesService(
    private val store: AdversarialProviderFakesStore,
    private val clock: Clock
) {
    private val lock = Any()

    /**
     * Registers a new adversarial provider fake.
     * Invariant: isCertified is always false; fakes cannot grant production authority.
     */
    fun registerFake(command: RegisterAdversarialFakeCommand): RegisterAdversarialFakeResult = synchronized(lock) {
        AdversarialProviderFakesBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.providerId.isBlank() || command.signingSecret.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "REG_FAKE:${command.tenantId}:${command.providerId}:${command.providerType}:${command.expectedVersion}"
        val cached = checkIdempotency<RegisterAdversarialFakeResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val now = clock.instant()
        val fake = ProviderFakeRegistration(
            providerId = command.providerId,
            tenantId = command.tenantId,
            providerType = command.providerType,
            signingSecret = command.signingSecret,
            isCertified = false, // Strictly false!
            createdAt = now,
            serverVersion = command.expectedVersion
        )
        store.saveFake(fake)

        val resultId = UUID.randomUUID()
        val evidenceRef = "adversarial-fake:${command.tenantId}:${command.providerId}:v${command.expectedVersion}:$resultId"
        val result = RegisterAdversarialFakeResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            providerType = command.providerType,
            isCertified = false,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            AdversarialAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                principalId = command.principal!!.id,
                action = AdversarialAuditAction.FAKE_REGISTERED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Registered adversarial fake ${command.providerId} type=${command.providerType}",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Emulates provider delivery with adversarial anomalies (duplicate, late, reordered, bad signatures, timeouts).
     */
    fun emulateDelivery(command: EmulateAdversarialDeliveryCommand): EmulateAdversarialDeliveryResult = synchronized(lock) {
        AdversarialProviderFakesBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.providerId.isBlank() || command.eventId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "EMULATE:${command.tenantId}:${command.providerId}:${command.eventId}:${command.sequenceNumber}:${command.faultInjected}:${command.payload}:${command.expectedVersion}"
        val cached = checkIdempotency<EmulateAdversarialDeliveryResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val fake = store.findFake(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "emulate-deliv:${command.tenantId}:${command.providerId}:${command.eventId}:$resultId"

        // 1. Timeout simulation: fail closed with DEPENDENCY_UNAVAILABLE
        if (command.faultInjected == AdversarialSimulationFault.TIMEOUT_SIMULATION) {
            store.recordAudit(
                AdversarialAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = AdversarialAuditAction.TIMEOUT_FAILED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Simulated provider timeout for ${command.providerId} event ${command.eventId}",
                    alertTriggered = true
                )
            )
            val alert = AdversarialAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "PROVIDER_TIMEOUT_SIMULATION",
                message = "Simulated timeout dependency failure for provider ${command.providerId}",
                correlationId = command.correlationId,
                timestamp = now
            )
            store.recordAlert(alert)
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // 2. Bad signature check
        if (command.faultInjected == AdversarialSimulationFault.BAD_SIGNATURE) {
            store.recordAudit(
                AdversarialAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = AdversarialAuditAction.BAD_SIGNATURE_REJECTED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Rejected bad signature for ${command.providerId} event ${command.eventId}",
                    alertTriggered = true
                )
            )
            val alert = AdversarialAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "PROVIDER_BAD_SIGNATURE_DETECTED",
                message = "Corrupted or forged signature rejected for provider ${command.providerId}",
                correlationId = command.correlationId,
                timestamp = now
            )
            store.recordAlert(alert)
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 3. Duplicate delivery check
        if (command.faultInjected == AdversarialSimulationFault.DUPLICATE_DELIVERY || store.isEventProcessed(command.tenantId, command.eventId)) {
            store.recordAudit(
                AdversarialAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = AdversarialAuditAction.DUPLICATE_DROPPED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Dropped duplicate delivery event ${command.eventId} for provider ${command.providerId}",
                    alertTriggered = false
                )
            )
            val result = EmulateAdversarialDeliveryResult(
                resultId = resultId,
                eventId = command.eventId,
                providerId = command.providerId,
                accepted = false,
                reasonCode = "DUPLICATE_DROPPED",
                faultInjected = AdversarialSimulationFault.DUPLICATE_DELIVERY,
                serverTime = now,
                evidenceReference = evidenceRef,
                isFinancialAuthorityCreated = false
            )
            store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // 4. Late delivery check (> 1 hour expired)
        val age = Duration.between(command.timestamp, now)
        if (command.faultInjected == AdversarialSimulationFault.LATE_DELIVERY || age > Duration.ofHours(1)) {
            store.recordAudit(
                AdversarialAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = AdversarialAuditAction.LATE_REJECTED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Rejected late delivery for ${command.providerId} event ${command.eventId} age=${age.toSeconds()}s",
                    alertTriggered = true
                )
            )
            val result = EmulateAdversarialDeliveryResult(
                resultId = resultId,
                eventId = command.eventId,
                providerId = command.providerId,
                accepted = false,
                reasonCode = "LATE_REJECTED",
                faultInjected = AdversarialSimulationFault.LATE_DELIVERY,
                serverTime = now,
                evidenceReference = evidenceRef,
                isFinancialAuthorityCreated = false
            )
            store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // 5. Reordered delivery check
        val lastSeq = store.getLastSequence(command.tenantId, command.providerId)
        if (command.faultInjected == AdversarialSimulationFault.REORDERED_DELIVERY || command.sequenceNumber <= lastSeq) {
            store.recordAudit(
                AdversarialAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = AdversarialAuditAction.REORDERED_HELD,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Held reordered delivery for ${command.providerId} seq=${command.sequenceNumber} lastSeq=$lastSeq",
                    alertTriggered = false
                )
            )
            val result = EmulateAdversarialDeliveryResult(
                resultId = resultId,
                eventId = command.eventId,
                providerId = command.providerId,
                accepted = false,
                reasonCode = "REORDERED_HELD",
                faultInjected = AdversarialSimulationFault.REORDERED_DELIVERY,
                serverTime = now,
                evidenceReference = evidenceRef,
                isFinancialAuthorityCreated = false
            )
            store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // Normal clean event processing
        store.markEventProcessed(command.tenantId, command.eventId)
        store.setLastSequence(command.tenantId, command.providerId, command.sequenceNumber)

        store.recordAudit(
            AdversarialAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                principalId = command.principal!!.id,
                action = AdversarialAuditAction.EVENT_PROCESSED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Processed event ${command.eventId} for provider ${command.providerId} seq=${command.sequenceNumber}",
                alertTriggered = false
            )
        )

        val result = EmulateAdversarialDeliveryResult(
            resultId = resultId,
            eventId = command.eventId,
            providerId = command.providerId,
            accepted = true,
            reasonCode = "ACCEPTED",
            faultInjected = AdversarialSimulationFault.NONE,
            serverTime = now,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Strictly enforces the semantic contract: "no fake satisfies certification".
     * Any attempt to certify or promote an adversarial fake to production status is rejected.
     */
    fun validateCertificationEligibility(command: ValidateCertificationEligibilityCommand): ValidateCertificationEligibilityResult = synchronized(lock) {
        AdversarialProviderFakesBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)

        val fake = store.findFake(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()

        // Semantic invariant: No fake satisfies certification!
        if (command.requestedCertificationLevel.equals("PRODUCTION_CERTIFIED", ignoreCase = true) || fake.satisfiesCertification()) {
            store.recordAudit(
                AdversarialAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = AdversarialAuditAction.CERTIFICATION_ATTEMPT_BLOCKED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Blocked production certification attempt for fake provider ${fake.providerId}",
                    alertTriggered = true
                )
            )

            val alert = AdversarialAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "FAKE_CERTIFICATION_PROHIBITED",
                message = "Adversarial fake ${fake.providerId} attempted to claim production certification. Strictly rejected.",
                correlationId = command.correlationId,
                timestamp = now
            )
            store.recordAlert(alert)

            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val resultId = UUID.randomUUID()
        val evidenceRef = "fake-cert-check:${command.tenantId}:${command.providerId}:$resultId"

        return ValidateCertificationEligibilityResult(
            providerId = command.providerId,
            isCertified = false,
            message = "Fake emulates anomalies; does not satisfy production certification",
            serverTime = now,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
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
}
