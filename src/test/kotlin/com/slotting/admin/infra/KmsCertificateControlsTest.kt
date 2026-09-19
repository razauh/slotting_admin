package com.slotting.admin.infra

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class KmsCertificateControlsTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var fakeKms: FakeKmsProviderAdapter
    private lateinit var service: KmsCertificateControlsService

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-1",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val superAdmin = AuthenticatedPrincipal(
        id = "admin-super-1",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val readOnlyAdmin = AuthenticatedPrincipal(
        id = "admin-audit-1",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        fakeKms = FakeKmsProviderAdapter()
        service = KmsCertificateControlsService(clock = clock, kmsProvider = fakeKms)
    }

    // =========================================================================
    // INFRA-003-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `INFRA-003-01-T001 Operate KMS and certificate controls produces the required authoritative outcome`() {
        // Must fail with AssertionError("rotation/abuse/bypass scenarios") in RED phase
        KmsCertificateControlsBinding.checkBound()

        val tenantId = "tenant-prod-1"

        // 1. Create and rotate cryptographic key
        val keyResult = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "data-encryption-master",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "key-create-1",
        )
        assertTrue(keyResult.isSuccess)
        val createdKey = keyResult.getOrThrow()
        assertEquals(KeyStatus.ACTIVE, createdKey.status)
        assertEquals(1, createdKey.version)

        val rotatedResult = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "data-encryption-master",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "key-rotate-1",
            existingKeyId = createdKey.keyId,
            expectedVersion = 1L,
        )
        assertTrue(rotatedResult.isSuccess)
        val rotatedKey = rotatedResult.getOrThrow()
        assertEquals(KeyStatus.ROTATED, rotatedKey.status)
        assertEquals(2, rotatedKey.version)

        // 2. Register valid TLS certificate
        val certResult = service.registerOrRenewCertificate(
            tenantId = tenantId,
            commonName = "api.slotting.example.com",
            sanDomains = listOf("api.slotting.example.com", "gateway.slotting.example.com"),
            spkiPinSha256 = "sha256/HXXQgxueCIU5TTLHob/bPbwcKOKw6DHgUECCoAhCXXM=",
            expiresAt = fixedInstant.plusSeconds(86400 * 90),
            principal = securityAdmin,
            idempotencyKey = "cert-reg-1",
        )
        assertTrue(certResult.isSuccess)
        val cert = certResult.getOrThrow()
        assertEquals(CertStatus.ACTIVE, cert.status)

        // 3. Record emergency procedure
        val procResult = service.recordEmergencyProcedure(
            tenantId = tenantId,
            procedureType = EmergencyProcedureType.EMERGENCY_KEY_ROTATION,
            success = true,
            verificationEvidence = "Simulated HSM breach; emergency rotated to v2 without service interruption",
            principal = superAdmin,
            idempotencyKey = "proc-test-1",
        )
        assertTrue(procResult.isSuccess)

        // 4. Authoritative readiness evaluation
        val evaluation = service.evaluateKmsCertificateReadiness(tenantId, securityAdmin)
        assertEquals(KmsDecision.GO, evaluation.status)
        assertEquals(KmsReason.KMS_AND_CERTS_HEALTHY_AND_EMERGENCY_TESTED, evaluation.reason)
        assertEquals(1, evaluation.activeKeysCount)
        assertEquals(1, evaluation.validCertsCount)
        assertTrue(evaluation.emergencyProceduresTested)

        // Financial & Semantic contracts
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertTrue(evaluation.evidenceReference.isNotBlank())
    }

    // =========================================================================
    // INFRA-003-01-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `INFRA-003-01-T002 Operate KMS and certificate controls rejects invalid, boundary, unauthorized, and stale input`() {
        KmsCertificateControlsBinding.checkBound()

        val tenantId = "tenant-prod-1"

        // Unauthorized principal cannot create key
        val unauthKeyResult = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "test-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = readOnlyAdmin,
            idempotencyKey = "unauth-key-1",
        )
        assertTrue(unauthKeyResult.isFailure)
        assertTrue(unauthKeyResult.exceptionOrNull() is SecurityException)

        // Unauthorized principal cannot register certificate
        val unauthCertResult = service.registerOrRenewCertificate(
            tenantId = tenantId,
            commonName = "api.slotting.example.com",
            sanDomains = listOf("api.slotting.example.com"),
            spkiPinSha256 = "pin-1",
            expiresAt = fixedInstant.plusSeconds(86400),
            principal = readOnlyAdmin,
            idempotencyKey = "unauth-cert-1",
        )
        assertTrue(unauthCertResult.isFailure)
        assertTrue(unauthCertResult.exceptionOrNull() is SecurityException)

        // Expired certificate rejected
        val expiredCertResult = service.registerOrRenewCertificate(
            tenantId = tenantId,
            commonName = "expired.slotting.example.com",
            sanDomains = listOf("expired.slotting.example.com"),
            spkiPinSha256 = "pin-1",
            expiresAt = fixedInstant.minusSeconds(3600), // In the past
            principal = securityAdmin,
            idempotencyKey = "expired-cert-1",
        )
        assertTrue(expiredCertResult.isFailure)
        assertTrue(expiredCertResult.exceptionOrNull() is IllegalArgumentException)

        // Stale expected version conflict
        val key = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "versioned-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "key-v1",
        ).getOrThrow()

        val staleResult = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "versioned-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "key-v-stale",
            existingKeyId = key.keyId,
            expectedVersion = 999L, // Stale version
        )
        assertTrue(staleResult.isFailure)
        assertTrue(staleResult.exceptionOrNull() is IllegalStateException)

        // Cross-tenant key access forbidden
        val crossTenantPrincipal = AuthenticatedPrincipal(
            id = "admin-other-tenant",
            tenantId = "other-tenant",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        val crossTenantResult = service.createOrRotateKey(
            tenantId = "other-tenant",
            alias = "versioned-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = crossTenantPrincipal,
            idempotencyKey = "key-cross-tenant",
            existingKeyId = key.keyId,
            expectedVersion = 1L,
        )
        assertTrue(crossTenantResult.isFailure)
        assertTrue(crossTenantResult.exceptionOrNull() is SecurityException)

        // Readiness evaluation with untested emergency procedures returns NO_GO
        service.registerOrRenewCertificate(
            tenantId = tenantId,
            commonName = "valid.slotting.example.com",
            sanDomains = listOf("valid.slotting.example.com"),
            spkiPinSha256 = "pin-valid",
            expiresAt = fixedInstant.plusSeconds(86400 * 30),
            principal = securityAdmin,
            idempotencyKey = "cert-valid-1",
        )
        val evalUntested = service.evaluateKmsCertificateReadiness(tenantId, securityAdmin)
        assertEquals(KmsDecision.NO_GO, evalUntested.status)
        assertEquals(KmsReason.EMERGENCY_PROCEDURES_UNTESTED, evalUntested.reason)

        // Audit log records rejections
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.any { !it.success })
    }

    // =========================================================================
    // INFRA-003-01-T003: Concurrency, Duplicate Delivery, and Failure Recovery
    // =========================================================================

    @Test
    fun `INFRA-003-01-T003 Operate KMS and certificate controls survives concurrency, duplicate delivery, and dependency failure`() {
        KmsCertificateControlsBinding.checkBound()

        val tenantId = "tenant-prod-1"

        // Duplicate delivery with same payload returns idempotent cached result
        val key1 = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "idempotent-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "idem-key-1",
        ).getOrThrow()

        val key2 = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "idempotent-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "idem-key-1",
        ).getOrThrow()

        assertEquals(key1.keyId, key2.keyId)
        assertEquals(key1.version, key2.version)

        // Changed payload with reused key yields CONFLICT
        val conflictResult = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "different-alias",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "idem-key-1",
        )
        assertTrue(conflictResult.isFailure)
        assertTrue(conflictResult.exceptionOrNull() is IllegalArgumentException)

        // Simulated external KMS dependency failure
        fakeKms.shouldFail = true
        val failedResult = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "failing-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "fail-key-1",
        )
        assertTrue(failedResult.isFailure)

        // Restore provider health and recover
        fakeKms.shouldFail = false
        val recoveredResult = service.createOrRotateKey(
            tenantId = tenantId,
            alias = "failing-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "recover-key-1",
        )
        assertTrue(recoveredResult.isSuccess)

        // Concurrent certificate registrations
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..8).map { i ->
            pool.submit(Callable {
                service.registerOrRenewCertificate(
                    tenantId = tenantId,
                    commonName = "app-$i.slotting.example.com",
                    sanDomains = listOf("app-$i.slotting.example.com"),
                    spkiPinSha256 = "pin-$i",
                    expiresAt = fixedInstant.plusSeconds(86400 * 30),
                    principal = securityAdmin,
                    idempotencyKey = "concurrent-cert-$i",
                )
            })
        }
        val results = futures.map { it.get() }
        pool.shutdown()

        assertTrue(results.all { it.isSuccess })
    }

    // =========================================================================
    // INFRA-003-01-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `INFRA-003-01-T004 Operate KMS and certificate controls remains compatible, recoverable, observable, and lifecycle-safe`() {
        KmsCertificateControlsBinding.checkBound()

        val tenantId = "tenant-prod-1"

        // Sandbox adapter compatibility
        val sandboxAdapter = SandboxKmsProviderAdapter()
        val sandboxService = KmsCertificateControlsService(clock = clock, kmsProvider = sandboxAdapter)

        val sandboxKey = sandboxService.createOrRotateKey(
            tenantId = tenantId,
            alias = "sandbox-master",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "sandbox-key-1",
        ).getOrThrow()
        assertEquals(1, sandboxKey.version)

        // Rate limiting test: rate limit never grants financial mutation or authority
        val rateLimitDecision = service.checkRateLimit(tenantId, securityAdmin.id, "TEST_OP")
        assertTrue(rateLimitDecision)

        // Test emergency procedure recording and readiness
        service.createOrRotateKey(
            tenantId = tenantId,
            alias = "prod-key",
            algorithm = KeyAlgorithm.AES_256_GCM,
            principal = securityAdmin,
            idempotencyKey = "prod-key-1",
        )
        service.registerOrRenewCertificate(
            tenantId = tenantId,
            commonName = "api.prod.example.com",
            sanDomains = listOf("api.prod.example.com"),
            spkiPinSha256 = "pin-prod",
            expiresAt = fixedInstant.plusSeconds(86400 * 60),
            principal = securityAdmin,
            idempotencyKey = "cert-prod-1",
        )
        service.recordEmergencyProcedure(
            tenantId = tenantId,
            procedureType = EmergencyProcedureType.EMERGENCY_PIN_ROLLBACK,
            success = true,
            verificationEvidence = "Rollback rehearsal succeeded under 5 minutes",
            principal = superAdmin,
            idempotencyKey = "proc-rehearsal-1",
        )

        val evaluation = service.evaluateKmsCertificateReadiness(tenantId, securityAdmin)
        assertEquals(KmsDecision.GO, evaluation.status)
        assertEquals("Rate limits never become financial authority; emergency procedures tested.", evaluation.message)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)

        // Audit observability
        val audits = service.getAuditLog(tenantId)
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.all { it.detailsRedacted.isNotBlank() })
    }
}
