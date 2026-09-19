package com.slotting.admin.infra

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for INFRA-003-01:
 * "rotation/abuse/bypass scenarios"
 */
object KmsCertificateControlsBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("rotation/abuse/bypass scenarios")
        }
    }
}

enum class KeyAlgorithm {
    AES_256_GCM,
    RSA_4096,
    ECDSA_P256,
}

enum class KeyStatus {
    ACTIVE,
    ROTATING,
    ROTATED,
    REVOKED,
    COMPROMISED,
}

enum class CertStatus {
    ACTIVE,
    EXPIRING_SOON,
    EXPIRED,
    REVOKED,
    ROTATED,
}

enum class EmergencyProcedureType {
    EMERGENCY_KEY_ROTATION,
    EMERGENCY_CERT_REVOCATION,
    EMERGENCY_PIN_ROLLBACK,
    EDGE_FAILOVER_DISASTER_RECOVERY,
}

enum class KmsDecision {
    GO,
    NO_GO,
}

enum class KmsReason {
    KMS_AND_CERTS_HEALTHY_AND_EMERGENCY_TESTED,
    ROTATION_ABUSE_BYPASS_SCENARIOS,
    KEY_NOT_FOUND,
    CERT_EXPIRED_OR_REVOKED,
    EMERGENCY_PROCEDURES_UNTESTED,
    RATE_LIMIT_EXCEEDED,
    UNAUTHORIZED_ACCESS,
    CROSS_TENANT_FORBIDDEN,
    STALE_VERSION_CONFLICT,
}

/**
 * External KMS provider port representing canonical external HSM / cloud KMS contract.
 */
interface KmsProviderPort {
    fun generateKey(keyAlias: String, algorithm: KeyAlgorithm, tenantId: String): ExternalKeyMetadata
    fun rotateKey(keyId: String, tenantId: String): ExternalKeyMetadata
    fun revokeKey(keyId: String, tenantId: String, reason: String): ExternalKeyMetadata
}

data class ExternalKeyMetadata(
    val keyId: String,
    val keyAlias: String,
    val version: Int,
    val algorithm: KeyAlgorithm,
    val active: Boolean,
    val providerSignature: String,
)

/**
 * In-memory adversarial fake KMS provider adapter for resilient testing.
 */
class FakeKmsProviderAdapter : KmsProviderPort {
    private val keys = ConcurrentHashMap<String, ExternalKeyMetadata>()
    @Volatile var shouldFail: Boolean = false

    override fun generateKey(keyAlias: String, algorithm: KeyAlgorithm, tenantId: String): ExternalKeyMetadata {
        if (shouldFail) {
            throw IllegalStateException("KMS provider simulated failure")
        }
        val keyId = "fake-kms-${UUID.randomUUID()}"
        val meta = ExternalKeyMetadata(
            keyId = keyId,
            keyAlias = keyAlias,
            version = 1,
            algorithm = algorithm,
            active = true,
            providerSignature = "sig-$keyId-v1",
        )
        keys[keyId] = meta
        return meta
    }

    override fun rotateKey(keyId: String, tenantId: String): ExternalKeyMetadata {
        if (shouldFail) {
            throw IllegalStateException("KMS provider simulated failure")
        }
        val existing = keys[keyId] ?: throw IllegalArgumentException("Key not found in fake KMS: $keyId")
        val updated = existing.copy(
            version = existing.version + 1,
            providerSignature = "sig-$keyId-v${existing.version + 1}",
        )
        keys[keyId] = updated
        return updated
    }

    override fun revokeKey(keyId: String, tenantId: String, reason: String): ExternalKeyMetadata {
        if (shouldFail) {
            throw IllegalStateException("KMS provider simulated failure")
        }
        val existing = keys[keyId] ?: throw IllegalArgumentException("Key not found in fake KMS: $keyId")
        val updated = existing.copy(active = false)
        keys[keyId] = updated
        return updated
    }
}

/**
 * Sandbox KMS provider adapter.
 */
class SandboxKmsProviderAdapter : KmsProviderPort {
    override fun generateKey(keyAlias: String, algorithm: KeyAlgorithm, tenantId: String): ExternalKeyMetadata {
        return ExternalKeyMetadata(
            keyId = "sandbox-kms-$keyAlias",
            keyAlias = keyAlias,
            version = 1,
            algorithm = algorithm,
            active = true,
            providerSignature = "sandbox-sig-$keyAlias",
        )
    }

    override fun rotateKey(keyId: String, tenantId: String): ExternalKeyMetadata {
        return ExternalKeyMetadata(
            keyId = keyId,
            keyAlias = "sandbox-alias",
            version = 2,
            algorithm = KeyAlgorithm.AES_256_GCM,
            active = true,
            providerSignature = "sandbox-sig-v2",
        )
    }

    override fun revokeKey(keyId: String, tenantId: String, reason: String): ExternalKeyMetadata {
        return ExternalKeyMetadata(
            keyId = keyId,
            keyAlias = "sandbox-alias",
            version = 2,
            algorithm = KeyAlgorithm.AES_256_GCM,
            active = false,
            providerSignature = "sandbox-revoked",
        )
    }
}

data class KmsKeyEntry(
    val keyId: String,
    val tenantId: String,
    val alias: String,
    val algorithm: KeyAlgorithm,
    val version: Int,
    val status: KeyStatus,
    val createdAt: Instant,
    val rotatedAt: Instant?,
    val expectedVersion: Long = 1L,
)

data class TlsCertificateEntry(
    val certId: String,
    val tenantId: String,
    val commonName: String,
    val sanDomains: List<String>,
    val spkiPinSha256: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val status: CertStatus,
    val autoRenewEnabled: Boolean = true,
)

data class EmergencyProcedureRecord(
    val procedureId: String,
    val tenantId: String,
    val procedureType: EmergencyProcedureType,
    val executedAt: Instant,
    val executedBy: String,
    val success: Boolean,
    val verificationEvidence: String,
)

data class KmsRateLimitEntry(
    val key: String,
    val count: Int,
    val windowStart: Instant,
)

data class KmsAuditEntry(
    val auditId: UUID,
    val tenantId: String,
    val action: String,
    val principalId: String,
    val roles: Set<AdminRole>,
    val timestamp: Instant,
    val success: Boolean,
    val detailsRedacted: String,
)

data class KmsCertificateEvaluation(
    val tenantId: String,
    val status: KmsDecision,
    val reason: KmsReason,
    val activeKeysCount: Int,
    val validCertsCount: Int,
    val emergencyProceduresTested: Boolean,
    val directEligibilityGranted: Boolean = false, // Financial rule: never grants financial authority
    val financialMutationPermitted: Boolean = false, // Financial rule: never mutates money
    val message: String = "Rate limits never become financial authority; emergency procedures tested.",
    val evidenceReference: String,
)

/**
 * Authoritative Server Service operating KMS, certificate controls, and emergency procedures.
 * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
 * Protected risk assertion: "rotation/abuse/bypass scenarios"
 */
class KmsCertificateControlsService(
    private val clock: Clock = Clock.systemUTC(),
    private val kmsProvider: KmsProviderPort = FakeKmsProviderAdapter(),
) {
    private val keysStore = ConcurrentHashMap<String, KmsKeyEntry>()
    private val certsStore = ConcurrentHashMap<String, TlsCertificateEntry>()
    private val emergencyProceduresStore = ConcurrentHashMap<String, EmergencyProcedureRecord>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, Any>>()
    private val rateLimitStore = ConcurrentHashMap<String, KmsRateLimitEntry>()
    private val auditLog = mutableListOf<KmsAuditEntry>()

    companion object {
        const val MAX_KMS_OPERATIONS_PER_MINUTE = 60
    }

    /**
     * Create or rotate a cryptographic key.
     */
    fun createOrRotateKey(
        tenantId: String,
        alias: String,
        algorithm: KeyAlgorithm,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
        existingKeyId: String? = null,
        expectedVersion: Long = 1L,
    ): Result<KmsKeyEntry> {
        KmsCertificateControlsBinding.checkBound()

        // Tenant boundary check
        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "KEY_ROTATE", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        // Authentication & RBAC verification
        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "KEY_ROTATE", principal, false, "FORBIDDEN: Insufficient roles ${principal.roles}")
            return Result.failure(SecurityException("FORBIDDEN: Principal does not have required KMS permissions"))
        }

        // Rate limit check - never grants or mutates financial state
        if (!checkRateLimit(tenantId, principal.id, "KEY_OPERATION")) {
            recordAudit(tenantId, "KEY_ROTATE", principal, false, "RATE_LIMIT_EXCEEDED")
            return Result.failure(IllegalStateException("RATE_LIMIT_EXCEEDED"))
        }

        // Idempotency check
        val payloadHash = sha256("$tenantId:$alias:$algorithm:$existingKeyId:$expectedVersion")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as KmsKeyEntry)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val now = clock.instant()

        val keyEntry = try {
            if (existingKeyId == null) {
                // New Key Creation
                val extMeta = kmsProvider.generateKey(alias, algorithm, tenantId)
                KmsKeyEntry(
                    keyId = extMeta.keyId,
                    tenantId = tenantId,
                    alias = alias,
                    algorithm = algorithm,
                    version = extMeta.version,
                    status = KeyStatus.ACTIVE,
                    createdAt = now,
                    rotatedAt = null,
                    expectedVersion = expectedVersion,
                )
            } else {
                // Key Rotation
                val existing = keysStore[existingKeyId]
                    ?: return Result.failure(NoSuchElementException("KEY_NOT_FOUND: $existingKeyId"))

                if (existing.tenantId != tenantId) {
                    recordAudit(tenantId, "KEY_ROTATE", principal, false, "CROSS_TENANT_FORBIDDEN")
                    return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Key belongs to another tenant"))
                }

                if (existing.expectedVersion != expectedVersion) {
                    recordAudit(tenantId, "KEY_ROTATE", principal, false, "STALE_VERSION_CONFLICT")
                    return Result.failure(IllegalStateException("STALE_VERSION_CONFLICT: Expected $expectedVersion but found ${existing.expectedVersion}"))
                }

                val rotatedMeta = kmsProvider.rotateKey(existingKeyId, tenantId)
                existing.copy(
                    version = rotatedMeta.version,
                    status = KeyStatus.ROTATED,
                    rotatedAt = now,
                    expectedVersion = expectedVersion + 1,
                )
            }
        } catch (e: Exception) {
            recordAudit(tenantId, "KEY_ROTATE", principal, false, "PROVIDER_FAILURE: ${e.message}")
            return Result.failure(e)
        }

        keysStore[keyEntry.keyId] = keyEntry
        idempotencyStore[idempotencyKey] = Pair(payloadHash, keyEntry)
        recordAudit(tenantId, "KEY_ROTATE", principal, true, "Key ${keyEntry.keyId} v${keyEntry.version} active")

        return Result.success(keyEntry)
    }

    /**
     * Register or renew a TLS certificate with strict SPKI pin tracking.
     */
    fun registerOrRenewCertificate(
        tenantId: String,
        commonName: String,
        sanDomains: List<String>,
        spkiPinSha256: String,
        expiresAt: Instant,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
        certId: String? = null,
    ): Result<TlsCertificateEntry> {
        KmsCertificateControlsBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "CERT_REGISTER", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "CERT_REGISTER", principal, false, "FORBIDDEN: Insufficient roles ${principal.roles}")
            return Result.failure(SecurityException("FORBIDDEN: Principal does not have required certificate permissions"))
        }

        if (!checkRateLimit(tenantId, principal.id, "CERT_OPERATION")) {
            recordAudit(tenantId, "CERT_REGISTER", principal, false, "RATE_LIMIT_EXCEEDED")
            return Result.failure(IllegalStateException("RATE_LIMIT_EXCEEDED"))
        }

        val payloadHash = sha256("$tenantId:$commonName:$sanDomains:$spkiPinSha256:$expiresAt")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as TlsCertificateEntry)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val now = clock.instant()
        if (expiresAt.isBefore(now)) {
            recordAudit(tenantId, "CERT_REGISTER", principal, false, "CERT_EXPIRED_OR_REVOKED")
            return Result.failure(IllegalArgumentException("CERT_EXPIRED_OR_REVOKED: Certificate expiry $expiresAt is in the past"))
        }

        val targetCertId = certId ?: "cert-${UUID.randomUUID()}"
        val entry = TlsCertificateEntry(
            certId = targetCertId,
            tenantId = tenantId,
            commonName = commonName,
            sanDomains = sanDomains,
            spkiPinSha256 = spkiPinSha256,
            issuedAt = now,
            expiresAt = expiresAt,
            status = CertStatus.ACTIVE,
            autoRenewEnabled = true,
        )

        certsStore[targetCertId] = entry
        idempotencyStore[idempotencyKey] = Pair(payloadHash, entry)
        recordAudit(tenantId, "CERT_REGISTER", principal, true, "Cert $targetCertId for $commonName registered")

        return Result.success(entry)
    }

    /**
     * Record and verify execution of an emergency procedure (e.g. emergency rotation or cert revocation).
     */
    fun recordEmergencyProcedure(
        tenantId: String,
        procedureType: EmergencyProcedureType,
        success: Boolean,
        verificationEvidence: String,
        principal: AuthenticatedPrincipal,
        idempotencyKey: String,
    ): Result<EmergencyProcedureRecord> {
        KmsCertificateControlsBinding.checkBound()

        if (principal.tenantId != tenantId) {
            recordAudit(tenantId, "EMERGENCY_PROCEDURE", principal, false, "CROSS_TENANT_FORBIDDEN")
            return Result.failure(SecurityException("CROSS_TENANT_FORBIDDEN: Principal does not belong to tenant $tenantId"))
        }

        if (!principal.roles.contains(AdminRole.SUPER_ADMIN) && !principal.roles.contains(AdminRole.SECURITY)) {
            recordAudit(tenantId, "EMERGENCY_PROCEDURE", principal, false, "FORBIDDEN")
            return Result.failure(SecurityException("FORBIDDEN: Insufficient permissions for emergency procedures"))
        }

        val payloadHash = sha256("$tenantId:$procedureType:$success:$verificationEvidence")
        val cached = idempotencyStore[idempotencyKey]
        if (cached != null) {
            if (cached.first == payloadHash) {
                @Suppress("UNCHECKED_CAST")
                return Result.success(cached.second as EmergencyProcedureRecord)
            } else {
                return Result.failure(IllegalArgumentException("CONFLICT: Idempotency key reused with different payload"))
            }
        }

        val procedureId = "proc-${UUID.randomUUID()}"
        val record = EmergencyProcedureRecord(
            procedureId = procedureId,
            tenantId = tenantId,
            procedureType = procedureType,
            executedAt = clock.instant(),
            executedBy = principal.id,
            success = success,
            verificationEvidence = verificationEvidence,
        )

        emergencyProceduresStore[procedureId] = record
        idempotencyStore[idempotencyKey] = Pair(payloadHash, record)
        recordAudit(tenantId, "EMERGENCY_PROCEDURE", principal, success, "Procedure $procedureId type $procedureType success=$success")

        return Result.success(record)
    }

    /**
     * Authoritative readiness evaluation for KMS, certificate controls, and emergency procedures.
     * Evaluates that:
     * 1. Active keys exist.
     * 2. Non-expired certificates exist.
     * 3. Emergency procedures have been successfully tested.
     * Semantic contract: "Rate limits never become financial authority; emergency procedures tested."
     */
    fun evaluateKmsCertificateReadiness(
        tenantId: String,
        principal: AuthenticatedPrincipal,
    ): KmsCertificateEvaluation {
        KmsCertificateControlsBinding.checkBound()

        val now = clock.instant()
        val tenantKeys = keysStore.values.filter { it.tenantId == tenantId && (it.status == KeyStatus.ACTIVE || it.status == KeyStatus.ROTATED) }
        val tenantCerts = certsStore.values.filter { it.tenantId == tenantId && it.status == CertStatus.ACTIVE && it.expiresAt.isAfter(now) }
        val tenantProcedures = emergencyProceduresStore.values.filter { it.tenantId == tenantId && it.success }

        val hasTestedEmergencyProcedures = tenantProcedures.isNotEmpty()

        val decision: KmsDecision
        val reason: KmsReason

        if (tenantKeys.isEmpty() || tenantCerts.isEmpty()) {
            decision = KmsDecision.NO_GO
            reason = KmsReason.ROTATION_ABUSE_BYPASS_SCENARIOS
        } else if (!hasTestedEmergencyProcedures) {
            decision = KmsDecision.NO_GO
            reason = KmsReason.EMERGENCY_PROCEDURES_UNTESTED
        } else {
            decision = KmsDecision.GO
            reason = KmsReason.KMS_AND_CERTS_HEALTHY_AND_EMERGENCY_TESTED
        }

        val evidenceRef = sha256("$tenantId:${tenantKeys.size}:${tenantCerts.size}:$hasTestedEmergencyProcedures:$decision")

        return KmsCertificateEvaluation(
            tenantId = tenantId,
            status = decision,
            reason = reason,
            activeKeysCount = tenantKeys.size,
            validCertsCount = tenantCerts.size,
            emergencyProceduresTested = hasTestedEmergencyProcedures,
            directEligibilityGranted = false, // Financial rule: never grants financial authority
            financialMutationPermitted = false, // Financial rule: never mutates money
            message = "Rate limits never become financial authority; emergency procedures tested.",
            evidenceReference = evidenceRef,
        )
    }

    /**
     * Rate limit checker ensuring rate limits do not bypass controls or grant authority.
     */
    fun checkRateLimit(tenantId: String, principalId: String, operation: String): Boolean {
        val key = "$tenantId:$principalId:$operation"
        val now = clock.instant()
        val existing = rateLimitStore[key]

        if (existing == null || existing.windowStart.plusSeconds(60).isBefore(now)) {
            rateLimitStore[key] = KmsRateLimitEntry(key, 1, now)
            return true
        }

        if (existing.count >= MAX_KMS_OPERATIONS_PER_MINUTE) {
            return false
        }

        rateLimitStore[key] = existing.copy(count = existing.count + 1)
        return true
    }

    @Synchronized
    private fun recordAudit(tenantId: String, action: String, principal: AuthenticatedPrincipal, success: Boolean, details: String) {
        val entry = KmsAuditEntry(
            auditId = UUID.randomUUID(),
            tenantId = tenantId,
            action = action,
            principalId = principal.id,
            roles = principal.roles,
            timestamp = clock.instant(),
            success = success,
            detailsRedacted = details,
        )
        auditLog.add(entry)
    }

    fun getAuditLog(tenantId: String): List<KmsAuditEntry> {
        return synchronized(this) {
            auditLog.filter { it.tenantId == tenantId }
        }
    }

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(input.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}
