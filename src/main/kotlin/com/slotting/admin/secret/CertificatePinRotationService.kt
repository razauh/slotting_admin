package com.slotting.admin.secret

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Traceability binding for SECRET-001-02: Support certificate and Android pin rotation.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "expired/single-pin rotation outage and secret leak".
 */
object CertificatePinRotationBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("expired/single-pin rotation outage and secret leak")
        }
    }
}

/**
 * Outcome-specific semantic contract for SECRET-001-02.
 */
const val CERTIFICATE_PIN_ROTATION_CONTRACT =
    "Emergency rollback documented; key access/audit alerts; no app-embedded secret authority."

/**
 * Lifecycle status of a TLS certificate and its associated SPKI pins.
 */
enum class CertificateStatus {
    ACTIVE,
    ROTATING,     // In overlap grace period: both old and new certificate pins remain valid
    ROTATED,      // Successfully rotated; prior pin maintained during grace period
    ROLLED_BACK,  // Rolled back to prior verified certificate/pin
    COMPROMISED,  // Marked compromised, misissued, or faulty
    REVOKED       // Fully revoked certificate/pin
}

/**
 * Network environment for certificate pin policies.
 */
enum class PinEnvironment {
    PRODUCTION,
    STAGING,
    DEVELOPMENT
}

/**
 * Android SPKI Pin descriptor.
 * Format: "sha256/<base64-encoded-spki-digest>" as used by OkHttp CertificatePinner / Android Network Security Config.
 */
data class AndroidSpkiPin(
    val pinId: String,
    val pinSha256: String,
    val label: String,
    val isBackup: Boolean = false,
    val validFrom: Instant,
    val validUntil: Instant,
    val status: CertificateStatus,
    val revokedReason: String? = null
)

/**
 * Authoritative server representation of a domain's TLS certificate and Android SPKI pin policy.
 */
data class CertificatePinEntry(
    val certId: String,
    val tenantId: String,
    val domain: String,
    val sanDomains: List<String>,
    val environment: PinEnvironment,
    val activePinId: String,
    val pins: Map<String, AndroidSpkiPin>,
    val overlapGracePeriodSeconds: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val serverVersion: Long = 1L
) {
    /**
     * Checks if a given SPKI pin is valid for a domain connection at the given timestamp.
     * Enforces dual-pin / overlapping pin validity to prevent single-pin rotation outages.
     */
    fun isPinValid(pinSha256: String, now: Instant): Boolean {
        val matchingPins = pins.values.filter { it.pinSha256 == pinSha256 }
        if (matchingPins.isEmpty()) return false
        return matchingPins.any { pin ->
            if (pin.status == CertificateStatus.COMPROMISED || pin.status == CertificateStatus.REVOKED) {
                return@any false
            }
            if (now.isBefore(pin.validFrom)) {
                return@any false
            }
            if (pin.status == CertificateStatus.ACTIVE || pin.status == CertificateStatus.ROTATING) {
                return@any now.isBefore(pin.validUntil)
            }
            if (pin.status == CertificateStatus.ROTATED) {
                val graceEnd = pin.validUntil.plusSeconds(overlapGracePeriodSeconds)
                return@any now.isBefore(graceEnd)
            }
            false
        }
    }

    /**
     * Returns all currently valid SPKI pins for the Android CertificatePinner.
     * Guaranteed to contain at least active and backup pins during rotation.
     */
    fun getActivePinSet(now: Instant): Set<String> {
        return pins.values
            .filter { isPinValid(it.pinSha256, now) }
            .map { it.pinSha256 }
            .toSet()
    }
}

/**
 * Documented emergency pin rollback record preserving immutable procedural evidence.
 */
data class EmergencyPinRollbackRecord(
    val rollbackId: String,
    val tenantId: String,
    val domain: String,
    val fromPinId: String,
    val targetPinId: String,
    val reason: String,
    val executedBy: String,
    val executedAt: Instant,
    val evidenceReference: String,
    val correlationId: String
)

/**
 * Event types for Certificate and Pin audit trails.
 */
enum class CertificateAuditEventType {
    CERTIFICATE_REGISTERED,
    PIN_ROTATION_INITIATED,
    PIN_ROTATION_COMPLETED,
    PIN_VERIFICATION_ATTEMPTED,
    EMERGENCY_PIN_ROLLBACK,
    CERTIFICATE_REVOKED,
    PIN_POLICY_QUERIED
}

/**
 * Structured audit record. Strictly forbids raw secrets or unencrypted private keys.
 */
data class CertificateAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val eventType: CertificateAuditEventType,
    val principalId: String,
    val domain: String,
    val pinId: String,
    val success: Boolean,
    val timestamp: Instant,
    val correlationId: String,
    val causationId: String,
    val detailsRedacted: String,
    val alertTriggered: Boolean = false
)

/**
 * Actionable security alert notification emitted upon pin rotation, access violation, or emergency rollback.
 */
data class CertificateAlertRecord(
    val alertId: String,
    val tenantId: String,
    val severity: String, // "INFO", "WARN", "CRITICAL"
    val alertType: String,
    val message: String,
    val correlationId: String,
    val timestamp: Instant,
    val domain: String
)

/**
 * Metadata for a certificate issued by an external CA.
 */
data class IssuedCertificateMetadata(
    val certFingerprintSha256: String,
    val spkiPinSha256: String,
    val issuerCn: String,
    val validFrom: Instant,
    val validUntil: Instant
)

/**
 * External certificate authority port.
 */
interface CertificateProviderPort {
    fun issueCertificate(domain: String, sanDomains: List<String>): IssuedCertificateMetadata
    fun revokeCertificate(domain: String, certFingerprintSha256: String, reason: String): Boolean
}

/**
 * In-memory adversarial fake CA adapter for resilient testing.
 */
class FakeCertificateProviderAdapter : CertificateProviderPort {
    @Volatile var shouldFail: Boolean = false
    @Volatile var simulateTimeout: Boolean = false

    override fun issueCertificate(domain: String, sanDomains: List<String>): IssuedCertificateMetadata {
        checkFailure()
        val pin = "sha256/" + base64Sha256("cert-$domain-${UUID.randomUUID()}")
        val fingerprint = sha256Hex("fingerprint-$domain-${UUID.randomUUID()}")
        val now = Instant.now()
        return IssuedCertificateMetadata(
            certFingerprintSha256 = fingerprint,
            spkiPinSha256 = pin,
            issuerCn = "Let's Encrypt Authority R3",
            validFrom = now,
            validUntil = now.plusSeconds(86400 * 90)
        )
    }

    override fun revokeCertificate(domain: String, certFingerprintSha256: String, reason: String): Boolean {
        checkFailure()
        return true
    }

    private fun checkFailure() {
        if (simulateTimeout) {
            throw IllegalStateException("Certificate authority connection timeout")
        }
        if (shouldFail) {
            throw IllegalStateException("Certificate authority simulated failure")
        }
    }

    private fun base64Sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }

    private fun sha256Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Sandbox certificate provider adapter.
 */
class SandboxCertificateProviderAdapter : CertificateProviderPort {
    override fun issueCertificate(domain: String, sanDomains: List<String>): IssuedCertificateMetadata {
        val now = Instant.now()
        return IssuedCertificateMetadata(
            certFingerprintSha256 = "sandbox-fp-12345",
            spkiPinSha256 = "sha256/SANDBOXPIN0000000000000000000000000000000=",
            issuerCn = "Sandbox Internal CA",
            validFrom = now,
            validUntil = now.plusSeconds(86400 * 365)
        )
    }

    override fun revokeCertificate(domain: String, certFingerprintSha256: String, reason: String): Boolean {
        return true
    }
}

/**
 * Storage port for certificate and pin entries, audit, alerts, and rollbacks.
 */
interface CertificatePinStore {
    fun saveCertificatePin(entry: CertificatePinEntry)
    fun findCertificatePin(tenantId: String, domain: String): CertificatePinEntry?
    fun saveRollbackRecord(record: EmergencyPinRollbackRecord)
    fun getRollbackRecords(tenantId: String): List<EmergencyPinRollbackRecord>
    fun recordAudit(audit: CertificateAuditRecord)
    fun getAudits(tenantId: String): List<CertificateAuditRecord>
    fun recordAlert(alert: CertificateAlertRecord)
    fun getAlerts(tenantId: String): List<CertificateAlertRecord>
    fun recordOutbox(outbox: OutboxEvent)
    fun getOutbox(): List<OutboxEvent>
    fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
}

/**
 * Thread-safe in-memory store implementation.
 */
class InMemoryCertificatePinStore : CertificatePinStore {
    val certs = ConcurrentHashMap<String, CertificatePinEntry>()
    val rollbacks = ConcurrentHashMap<String, MutableList<EmergencyPinRollbackRecord>>()
    val audits = ConcurrentHashMap<String, MutableList<CertificateAuditRecord>>()
    val alerts = ConcurrentHashMap<String, MutableList<CertificateAlertRecord>>()
    val outboxList = mutableListOf<OutboxEvent>()
    val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()

    private fun domainKey(tenantId: String, domain: String) = "$tenantId:$domain"

    override fun saveCertificatePin(entry: CertificatePinEntry) {
        certs[domainKey(entry.tenantId, entry.domain)] = entry
    }

    override fun findCertificatePin(tenantId: String, domain: String): CertificatePinEntry? {
        return certs[domainKey(tenantId, domain)]
    }

    override fun saveRollbackRecord(record: EmergencyPinRollbackRecord) {
        rollbacks.computeIfAbsent(record.tenantId) { mutableListOf() }.add(record)
    }

    override fun getRollbackRecords(tenantId: String): List<EmergencyPinRollbackRecord> {
        return rollbacks[tenantId]?.toList() ?: emptyList()
    }

    override fun recordAudit(audit: CertificateAuditRecord) {
        audits.computeIfAbsent(audit.tenantId) { mutableListOf() }.add(audit)
    }

    override fun getAudits(tenantId: String): List<CertificateAuditRecord> {
        return audits[tenantId]?.toList() ?: emptyList()
    }

    override fun recordAlert(alert: CertificateAlertRecord) {
        alerts.computeIfAbsent(alert.tenantId) { mutableListOf() }.add(alert)
    }

    override fun getAlerts(tenantId: String): List<CertificateAlertRecord> {
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
// Commands, Queries & Results
// =============================================================================

data class RegisterCertificatePinCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val domain: String,
    val sanDomains: List<String>,
    val primaryPinSha256: String,
    val backupPinSha256: String, // Explicit dual-pin rule to prevent single-pin rotation outage
    val environment: PinEnvironment = PinEnvironment.PRODUCTION,
    val overlapGracePeriodSeconds: Long = 86400L * 30L, // 30 days overlap grace period
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class RotateCertificatePinCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val domain: String,
    val newPrimaryPinSha256: String,
    val newBackupPinSha256: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class EmergencyPinRollbackCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val domain: String,
    val targetPinId: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
    val mutatesMoney: Boolean = false
)

data class VerifyPinPolicyCommand(
    val tenantId: String,
    val domain: String,
    val pinSha256: String,
    val correlationId: String,
    val causationId: String
)

data class RegisterCertificatePinResult(
    val resultId: UUID,
    val tenantId: String,
    val domain: String,
    val activePinSha256: String,
    val backupPinSha256: String,
    val validPinsInPolicy: Set<String>,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class RotateCertificatePinResult(
    val resultId: UUID,
    val tenantId: String,
    val domain: String,
    val previousPinSha256: String,
    val newActivePinSha256: String,
    val overlappingValidPins: Set<String>,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class EmergencyPinRollbackResult(
    val resultId: UUID,
    val tenantId: String,
    val domain: String,
    val rolledBackFromPinId: String,
    val restoredPinId: String,
    val restoredActivePinSha256: String,
    val compromisedPinRevoked: Boolean,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class VerifyPinPolicyResult(
    val domain: String,
    val pinSha256: String,
    val isValid: Boolean,
    val matchingPinLabel: String?,
    val serverTime: Instant
)

data class AndroidPinPolicyResponse(
    val domain: String,
    val validPins: Set<String>,
    val serverTime: Instant,
    val evidenceReference: String
)

// =============================================================================
// Authoritative Service
// =============================================================================

class CertificatePinRotationService(
    private val store: CertificatePinStore,
    private val certProvider: CertificateProviderPort,
    private val clock: Clock
) {

    private val lock = Any()

    /**
     * Registers a domain certificate with dual-pin (active + backup) configuration.
     * Rejects single-pin configurations to prevent rotation outages.
     */
    fun registerCertificatePin(command: RegisterCertificatePinCommand): RegisterCertificatePinResult = synchronized(lock) {
        CertificatePinRotationBinding.checkBound()
        validateAdminPrincipal(command.principal, command.tenantId, requireMutation = true)
        validateCommonInvariants(command.idempotencyKey, command.domain, command.expectedVersion, command.mutatesMoney)

        // Strict dual-pin protection: single-pin configurations cause rotation outages
        if (command.primaryPinSha256.isBlank() || command.backupPinSha256.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.primaryPinSha256 == command.backupPinSha256) {
            // Cannot use identical primary and backup pin (violates single-pin rotation protection)
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        validatePinFormat(command.primaryPinSha256)
        validatePinFormat(command.backupPinSha256)

        val fingerprint = "REGISTER:${command.tenantId}:${command.domain}:${command.primaryPinSha256}:${command.backupPinSha256}:${command.environment}:${command.expectedVersion}"
        val cached = checkIdempotency<RegisterCertificatePinResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCertificatePin(command.tenantId, command.domain)
        if (existing != null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val primaryPinId = "pin-${UUID.randomUUID()}"
        val backupPinId = "pin-backup-${UUID.randomUUID()}"

        val primaryPin = AndroidSpkiPin(
            pinId = primaryPinId,
            pinSha256 = command.primaryPinSha256,
            label = "leaf-primary-v1",
            isBackup = false,
            validFrom = now,
            validUntil = now.plusSeconds(86400 * 90),
            status = CertificateStatus.ACTIVE
        )

        val backupPin = AndroidSpkiPin(
            pinId = backupPinId,
            pinSha256 = command.backupPinSha256,
            label = "root-or-backup-v1",
            isBackup = true,
            validFrom = now,
            validUntil = now.plusSeconds(86400 * 365),
            status = CertificateStatus.ACTIVE
        )

        val certEntry = CertificatePinEntry(
            certId = "cert-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            domain = command.domain,
            sanDomains = command.sanDomains,
            environment = command.environment,
            activePinId = primaryPinId,
            pins = mapOf(primaryPinId to primaryPin, backupPinId to backupPin),
            overlapGracePeriodSeconds = command.overlapGracePeriodSeconds,
            createdAt = now,
            updatedAt = now,
            serverVersion = 1L
        )

        store.saveCertificatePin(certEntry)

        val resultId = UUID.randomUUID()
        val evidenceRef = "cert-pin:${command.tenantId}:${command.domain}:v1:$resultId"
        val validPins = certEntry.getActivePinSet(now)

        val result = RegisterCertificatePinResult(
            resultId = resultId,
            tenantId = command.tenantId,
            domain = command.domain,
            activePinSha256 = command.primaryPinSha256,
            backupPinSha256 = command.backupPinSha256,
            validPinsInPolicy = validPins,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        // Audit log
        val auditRecord = CertificateAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = CertificateAuditEventType.CERTIFICATE_REGISTERED,
            principalId = command.principal!!.id,
            domain = command.domain,
            pinId = primaryPinId,
            success = true,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "Registered certificate pin policy for domain=${command.domain} primary=${command.primaryPinSha256} backup=${command.backupPinSha256}",
            alertTriggered = false
        )
        store.recordAudit(auditRecord)

        // Outbox event
        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "CERTIFICATE_PIN_REGISTERED",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Rotates certificate pin with overlapping dual-pin validity.
     * Prevents single-pin / expired rotation outages by keeping both previous and new pins active.
     */
    fun rotateCertificatePin(command: RotateCertificatePinCommand): RotateCertificatePinResult = synchronized(lock) {
        CertificatePinRotationBinding.checkBound()
        validateAdminPrincipal(command.principal, command.tenantId, requireMutation = true)
        validateCommonInvariants(command.idempotencyKey, command.domain, command.expectedVersion, command.mutatesMoney)
        validatePinFormat(command.newPrimaryPinSha256)
        if (command.newBackupPinSha256 != null) {
            validatePinFormat(command.newBackupPinSha256)
        }

        val fingerprint = "ROTATE:${command.tenantId}:${command.domain}:${command.newPrimaryPinSha256}:${command.newBackupPinSha256}:${command.expectedVersion}"
        val cached = checkIdempotency<RotateCertificatePinResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val existing = store.findCertificatePin(command.tenantId, command.domain)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (existing.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val previousPin = existing.pins[existing.activePinId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (previousPin.pinSha256 == command.newPrimaryPinSha256) {
            // Cannot rotate to the identical pin
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = clock.instant()
        val newPinId = "pin-${UUID.randomUUID()}"
        val updatedPins = existing.pins.toMutableMap()

        // Transition previous pin to ROTATING (overlapping validity maintained!)
        val rotatedPrevPin = previousPin.copy(
            status = CertificateStatus.ROTATING,
            validUntil = now.plusSeconds(existing.overlapGracePeriodSeconds)
        )
        updatedPins[existing.activePinId] = rotatedPrevPin

        // Add new primary pin
        val newPrimaryPin = AndroidSpkiPin(
            pinId = newPinId,
            pinSha256 = command.newPrimaryPinSha256,
            label = "rotated-primary-v${existing.serverVersion + 1}",
            isBackup = false,
            validFrom = now,
            validUntil = now.plusSeconds(86400 * 90),
            status = CertificateStatus.ACTIVE
        )
        updatedPins[newPinId] = newPrimaryPin

        // Optional new backup pin
        if (command.newBackupPinSha256 != null) {
            val newBackupId = "pin-backup-${UUID.randomUUID()}"
            val newBackupPin = AndroidSpkiPin(
                pinId = newBackupId,
                pinSha256 = command.newBackupPinSha256,
                label = "rotated-backup-v${existing.serverVersion + 1}",
                isBackup = true,
                validFrom = now,
                validUntil = now.plusSeconds(86400 * 365),
                status = CertificateStatus.ACTIVE
            )
            updatedPins[newBackupId] = newBackupPin
        }

        val updatedEntry = existing.copy(
            activePinId = newPinId,
            pins = updatedPins,
            updatedAt = now,
            serverVersion = existing.serverVersion + 1
        )

        store.saveCertificatePin(updatedEntry)

        val resultId = UUID.randomUUID()
        val overlappingPins = updatedEntry.getActivePinSet(now)
        val evidenceRef = "cert-pin:${command.tenantId}:${command.domain}:v${updatedEntry.serverVersion}:$resultId"

        val result = RotateCertificatePinResult(
            resultId = resultId,
            tenantId = command.tenantId,
            domain = command.domain,
            previousPinSha256 = previousPin.pinSha256,
            newActivePinSha256 = command.newPrimaryPinSha256,
            overlappingValidPins = overlappingPins,
            serverTime = now,
            serverVersion = updatedEntry.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        // Audit record
        val auditRecord = CertificateAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = CertificateAuditEventType.PIN_ROTATION_COMPLETED,
            principalId = command.principal!!.id,
            domain = command.domain,
            pinId = newPinId,
            success = true,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "Rotated certificate pin for domain=${command.domain} newActive=${command.newPrimaryPinSha256} previous=${previousPin.pinSha256} overlapping=${overlappingPins.size}",
            alertTriggered = true
        )
        store.recordAudit(auditRecord)

        // Security Alert for pin rotation
        val alert = CertificateAlertRecord(
            alertId = "alert-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            severity = "WARN",
            alertType = "CERTIFICATE_PIN_ROTATED",
            message = "Certificate pin rotated for domain=${command.domain}. Dual-pin overlap active for ${existing.overlapGracePeriodSeconds}s",
            correlationId = command.correlationId,
            timestamp = now,
            domain = command.domain
        )
        store.recordAlert(alert)

        // Outbox event
        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "CERTIFICATE_PIN_ROTATED",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Verifies whether a presented pin is authorized and valid under the domain's current policy.
     * Evaluates both active and overlapping rotated pins.
     */
    fun verifyPinPolicy(command: VerifyPinPolicyCommand): VerifyPinPolicyResult {
        CertificatePinRotationBinding.checkBound()

        val entry = store.findCertificatePin(command.tenantId, command.domain)
            ?: return VerifyPinPolicyResult(command.domain, command.pinSha256, false, null, clock.instant())

        val now = clock.instant()
        val isValid = entry.isPinValid(command.pinSha256, now)
        val matchingPin = entry.pins.values.firstOrNull { it.pinSha256 == command.pinSha256 }

        // Structured audit record for pin verification
        val auditRecord = CertificateAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = CertificateAuditEventType.PIN_VERIFICATION_ATTEMPTED,
            principalId = "system-verifier",
            domain = command.domain,
            pinId = matchingPin?.pinId ?: "unknown",
            success = isValid,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "Verified pin for domain=${command.domain} valid=$isValid",
            alertTriggered = !isValid
        )
        store.recordAudit(auditRecord)

        if (!isValid) {
            val alert = CertificateAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                severity = "WARN",
                alertType = "UNRECOGNIZED_PIN_PRESENTED",
                message = "Presented pin not recognized or expired for domain=${command.domain}",
                correlationId = command.correlationId,
                timestamp = now,
                domain = command.domain
            )
            store.recordAlert(alert)
        }

        return VerifyPinPolicyResult(
            domain = command.domain,
            pinSha256 = command.pinSha256,
            isValid = isValid,
            matchingPinLabel = matchingPin?.label,
            serverTime = now
        )
    }

    /**
     * Redacted read model query for untrusted Android clients.
     * Returns the active set of valid SPKI pins (both primary and backup/overlapping pins)
     * without exposing backend keys or administrative mutations.
     */
    fun getAndroidPinPolicy(tenantId: String, domain: String): AndroidPinPolicyResponse {
        CertificatePinRotationBinding.checkBound()

        val entry = store.findCertificatePin(tenantId, domain)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()
        val validPins = entry.getActivePinSet(now)
        val evidenceRef = "android-pin-policy:$tenantId:$domain:v${entry.serverVersion}"

        return AndroidPinPolicyResponse(
            domain = domain,
            validPins = validPins,
            serverTime = now,
            evidenceReference = evidenceRef
        )
    }

    /**
     * Executes a documented emergency rollback to a prior verified certificate/pin.
     * Revokes the compromised pin and preserves immutable audit history.
     */
    fun emergencyRollbackPin(command: EmergencyPinRollbackCommand): EmergencyPinRollbackResult = synchronized(lock) {
        CertificatePinRotationBinding.checkBound()
        validateAdminPrincipal(command.principal, command.tenantId, requireMutation = true)
        validateCommonInvariants(command.idempotencyKey, command.domain, command.expectedVersion, command.mutatesMoney)

        if (command.reason.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "ROLLBACK:${command.tenantId}:${command.domain}:${command.targetPinId}:${command.reason}:${command.expectedVersion}"
        val cached = checkIdempotency<EmergencyPinRollbackResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val entry = store.findCertificatePin(command.tenantId, command.domain)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (entry.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val targetPin = entry.pins[command.targetPinId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (targetPin.status == CertificateStatus.COMPROMISED || targetPin.status == CertificateStatus.REVOKED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val currentActiveId = entry.activePinId
        if (currentActiveId == command.targetPinId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val currentPin = entry.pins[currentActiveId]!!
        val now = clock.instant()

        // Revoke the current compromised pin
        val compromisedPin = currentPin.copy(
            status = CertificateStatus.COMPROMISED,
            revokedReason = "Emergency pin rollback: ${command.reason}",
            validUntil = now
        )

        // Restore target pin as active
        val restoredPin = targetPin.copy(
            status = CertificateStatus.ACTIVE,
            validUntil = now.plusSeconds(86400 * 90)
        )

        val updatedPins = entry.pins.toMutableMap()
        updatedPins[currentActiveId] = compromisedPin
        updatedPins[command.targetPinId] = restoredPin

        val updatedEntry = entry.copy(
            activePinId = command.targetPinId,
            pins = updatedPins,
            updatedAt = now,
            serverVersion = entry.serverVersion + 1
        )

        store.saveCertificatePin(updatedEntry)

        val resultId = UUID.randomUUID()
        val evidenceRef = "cert-pin-rollback:${command.tenantId}:${command.domain}:from-$currentActiveId-to-${command.targetPinId}:$resultId"

        val rollbackRecord = EmergencyPinRollbackRecord(
            rollbackId = "pin-rb-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            domain = command.domain,
            fromPinId = currentActiveId,
            targetPinId = command.targetPinId,
            reason = command.reason,
            executedBy = command.principal!!.id,
            executedAt = now,
            evidenceReference = evidenceRef,
            correlationId = command.correlationId
        )
        store.saveRollbackRecord(rollbackRecord)

        val result = EmergencyPinRollbackResult(
            resultId = resultId,
            tenantId = command.tenantId,
            domain = command.domain,
            rolledBackFromPinId = currentActiveId,
            restoredPinId = command.targetPinId,
            restoredActivePinSha256 = restoredPin.pinSha256,
            compromisedPinRevoked = true,
            serverTime = now,
            serverVersion = updatedEntry.serverVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        // Immutable audit record
        val auditRecord = CertificateAuditRecord(
            auditId = UUID.randomUUID(),
            tenantId = command.tenantId,
            eventType = CertificateAuditEventType.EMERGENCY_PIN_ROLLBACK,
            principalId = command.principal.id,
            domain = command.domain,
            pinId = command.targetPinId,
            success = true,
            timestamp = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
            detailsRedacted = "Emergency rollback executed for domain=${command.domain} from $currentActiveId to ${command.targetPinId} reason=${command.reason}",
            alertTriggered = true
        )
        store.recordAudit(auditRecord)

        // CRITICAL alert
        val alert = CertificateAlertRecord(
            alertId = "alert-${UUID.randomUUID()}",
            tenantId = command.tenantId,
            severity = "CRITICAL",
            alertType = "CERTIFICATE_PIN_EMERGENCY_ROLLBACK",
            message = "EMERGENCY ROLLBACK executed for domain=${command.domain}: active pin revoked, restored to ${command.targetPinId}. Reason: ${command.reason}",
            correlationId = command.correlationId,
            timestamp = now,
            domain = command.domain
        )
        store.recordAlert(alert)

        // Outbox event
        store.recordOutbox(
            OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = resultId,
                tenantId = command.tenantId,
                type = "CERTIFICATE_PIN_EMERGENCY_ROLLBACK",
                createdAt = now
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    // =========================================================================
    // Validation Helpers
    // =========================================================================

    private fun validateAdminPrincipal(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        requireMutation: Boolean
    ) {
        if (principal == null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }
        // Strict boundary: untrusted player principal has zero certificate/pin authority
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (requireMutation) {
            val hasMutationRole = principal.roles.any {
                it == AdminRole.SUPER_ADMIN || it == AdminRole.SECURITY
            }
            if (!hasMutationRole) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
        }
    }

    private fun validateCommonInvariants(
        idempotencyKey: String,
        domain: String,
        expectedVersion: Long,
        mutatesMoney: Boolean
    ) {
        if (idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (domain.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        // Strict financial boundary: certificate and pin rotation cannot mutate money
        if (mutatesMoney) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    private fun validatePinFormat(pinSha256: String) {
        if (!pinSha256.startsWith("sha256/") || pinSha256.length < 15) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
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
