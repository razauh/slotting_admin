package com.slotting.admin.secret

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Contract test suite for SECRET-001-01: Store backend secrets and keys in KMS.
 *
 * Source implementation-plan family: SECRET-001
 * Semantic Contract: "Emergency rollback documented; key access/audit alerts; no app-embedded secret authority."
 * Expected RED failure: "expired/single-pin rotation outage and secret leak"
 */
class KmsBackendSecretsTest {

    private val now = Instant.parse("2026-09-20T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-01",
        tenantId = "tenant-kms-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN)
    )

    private val auditorAdmin = AuthenticatedPrincipal(
        id = "admin-audit-01",
        tenantId = "tenant-kms-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-untrusted-01",
        tenantId = "tenant-kms-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    @BeforeEach
    fun setUp() {
        KmsBackendSecretsBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        KmsBackendSecretsBinding.isBound = true
    }

    // =========================================================================
    // SECRET-001-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `SECRET-001-01-T001 Store backend secrets and keys in KMS produces the required authoritative outcome`() {
        // Expected RED failure: assertion check bound
        KmsBackendSecretsBinding.checkBound()

        val store = InMemoryKmsBackendSecretsStore()
        val fakeKms = FakeKmsBackendProviderAdapter()
        val service = KmsBackendSecretsService(store, fakeKms, clock)

        // 1. Store backend secret key in KMS
        val storeCommand = StoreSecretKeyCommand(
            principal = securityAdmin,
            tenantId = "tenant-kms-1",
            secretKeyAlias = "payment-gateway-jwt-key",
            secretType = BackendSecretType.JWT_SIGNING_KEY,
            algorithm = BackendKeyAlgorithm.AES_256_GCM,
            overlapGracePeriodSeconds = 86400L,
            idempotencyKey = "idemp-store-sec-01",
            correlationId = "corr-sec-101",
            causationId = "caus-sec-101",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        val storeResult = service.storeSecretKey(storeCommand)
        assertEquals("tenant-kms-1", storeResult.tenantId)
        assertEquals("payment-gateway-jwt-key", storeResult.secretKeyAlias)
        assertEquals(1, storeResult.activeVersion)
        assertEquals(1L, storeResult.serverVersion)
        assertEquals(now, storeResult.serverTime)
        assertFalse(storeResult.isFinancialAuthorityCreated)
        assertTrue(storeResult.kmsKeyUri.startsWith("kms://tenant-kms-1/keys/payment-gateway-jwt-key/v1"))
        assertTrue(storeResult.evidenceReference.startsWith("kms-secret:tenant-kms-1:payment-gateway-jwt-key:v1:"))

        // Verify that data can be encrypted with v1
        val testPlaintext = "SensitivePayload-PaymentAuthorizationToken".toByteArray(Charsets.UTF_8)
        val (encVer1, ciphertext1) = service.encryptWithActiveKey("tenant-kms-1", "payment-gateway-jwt-key", testPlaintext, securityAdmin)
        assertEquals(1, encVer1)
        val decrypted1 = service.decryptWithKeyVersion("tenant-kms-1", "payment-gateway-jwt-key", 1, ciphertext1, securityAdmin)
        assertTrue(testPlaintext.contentEquals(decrypted1))

        // 2. Rotate key with overlapping dual-pin / dual-key validity
        val rotateCommand = RotateSecretKeyCommand(
            principal = securityAdmin,
            tenantId = "tenant-kms-1",
            secretKeyAlias = "payment-gateway-jwt-key",
            idempotencyKey = "idemp-rotate-sec-01",
            correlationId = "corr-sec-102",
            causationId = "caus-sec-102",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        val rotateResult = service.rotateSecretKey(rotateCommand)
        assertEquals(1, rotateResult.previousVersion)
        assertEquals(2, rotateResult.newActiveVersion)
        assertEquals(2L, rotateResult.serverVersion)
        assertEquals(listOf(2, 1), rotateResult.overlappingValidVersions)
        assertFalse(rotateResult.isFinancialAuthorityCreated)

        // 3. Prove dual-pin / overlapping key validity:
        // New encryption uses active version 2
        val (encVer2, ciphertext2) = service.encryptWithActiveKey("tenant-kms-1", "payment-gateway-jwt-key", testPlaintext, securityAdmin)
        assertEquals(2, encVer2)
        val decrypted2 = service.decryptWithKeyVersion("tenant-kms-1", "payment-gateway-jwt-key", 2, ciphertext2, securityAdmin)
        assertTrue(testPlaintext.contentEquals(decrypted2))

        // And crucially: ciphertext1 encrypted under version 1 CAN STILL BE DECRYPTED under version 1 during overlap!
        // This explicitly prevents "expired/single-pin rotation outage"!
        val decrypted1DuringOverlap = service.decryptWithKeyVersion("tenant-kms-1", "payment-gateway-jwt-key", 1, ciphertext1, securityAdmin)
        assertTrue(testPlaintext.contentEquals(decrypted1DuringOverlap))

        // 4. Verify exact semantic contract
        assertEquals(
            "Emergency rollback documented; key access/audit alerts; no app-embedded secret authority.",
            KMS_BACKEND_SECRETS_CONTRACT
        )

        // 5. Verify audit and alert generation with ZERO secret leak
        val audits = store.getAudits("tenant-kms-1")
        assertTrue(audits.isNotEmpty())
        val alerts = store.getAlerts("tenant-kms-1")
        assertTrue(alerts.any { it.alertType == "KMS_KEY_ROTATED" })

        // Assert no plaintext secrets or raw keys exist in audit, alerts, or stored metadata
        val allAuditText = audits.joinToString(" ") { "${it.detailsRedacted} ${it.eventType}" }
        val allAlertText = alerts.joinToString(" ") { "${it.message} ${it.alertType}" }
        assertFalse(allAuditText.contains("SensitivePayload", ignoreCase = true))
        assertFalse(allAlertText.contains("SensitivePayload", ignoreCase = true))
        assertFalse(allAuditText.contains("PRIVATE_KEY", ignoreCase = true))

        // 6. Assert zero financial mutation methods
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // SECRET-001-01-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `SECRET-001-01-T002 Store backend secrets and keys in KMS rejects invalid boundary unauthorized and stale input`() {
        KmsBackendSecretsBinding.isBound = true

        val store = InMemoryKmsBackendSecretsStore()
        val fakeKms = FakeKmsBackendProviderAdapter()
        val service = KmsBackendSecretsService(store, fakeKms, clock)

        val validCommand = StoreSecretKeyCommand(
            principal = securityAdmin,
            tenantId = "tenant-kms-1",
            secretKeyAlias = "auth-signing-key",
            secretType = BackendSecretType.JWT_SIGNING_KEY,
            algorithm = BackendKeyAlgorithm.ECDSA_P256,
            idempotencyKey = "idemp-t002-valid",
            correlationId = "corr-t002",
            causationId = "caus-t002",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Untrusted Player principal rejected (No app-embedded secret authority!)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(principal = playerPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Player principal cannot access KMS secrets
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.accessSecretKey(
                AccessSecretKeyCommand(
                    principal = playerPrincipal,
                    tenantId = "tenant-kms-1",
                    secretKeyAlias = "auth-signing-key",
                    idempotencyKey = "idemp-player-access",
                    correlationId = "corr-player",
                    causationId = "caus-player"
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Auditor cannot mutate (rotate/store) keys
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(principal = auditorAdmin))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Cross-tenant request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(tenantId = "other-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Stale expected version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 6. Blank idempotency key or blank alias rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(idempotencyKey = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(secretKeyAlias = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Money mutation attempt rejected (strict financial boundary)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand.copy(mutatesMoney = true))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Dependency failure / KMS unavailable fails closed
        fakeKms.shouldFail = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(validCommand)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
        fakeKms.shouldFail = false

        // 9. Successfully store key, then test rotation rejections
        service.storeSecretKey(validCommand)

        // Rotate with stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.rotateSecretKey(
                RotateSecretKeyCommand(
                    principal = securityAdmin,
                    tenantId = "tenant-kms-1",
                    secretKeyAlias = "auth-signing-key",
                    idempotencyKey = "idemp-rotate-stale",
                    correlationId = "corr-stale",
                    causationId = "caus-stale",
                    expectedVersion = 99L
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Access on non-existent key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.accessSecretKey(
                AccessSecretKeyCommand(
                    principal = securityAdmin,
                    tenantId = "tenant-kms-1",
                    secretKeyAlias = "non-existent-alias",
                    idempotencyKey = "idemp-nonexist",
                    correlationId = "corr-nonexist",
                    causationId = "caus-nonexist"
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // SECRET-001-01-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `SECRET-001-01-T003 Store backend secrets and keys in KMS survives concurrency duplicate delivery and dependency failure`() {
        KmsBackendSecretsBinding.isBound = true

        val store = InMemoryKmsBackendSecretsStore()
        val fakeKms = FakeKmsBackendProviderAdapter()
        val service = KmsBackendSecretsService(store, fakeKms, clock)

        val command = StoreSecretKeyCommand(
            principal = securityAdmin,
            tenantId = "tenant-kms-1",
            secretKeyAlias = "concurrent-key-test",
            secretType = BackendSecretType.DATA_ENCRYPTION_KEY,
            algorithm = BackendKeyAlgorithm.AES_256_GCM,
            idempotencyKey = "idemp-concurrent-01",
            correlationId = "corr-conc-01",
            causationId = "caus-conc-01",
            expectedVersion = 1L
        )

        // 1. Concurrent equivalent submissions
        val threads = 10
        val pool = Executors.newFixedThreadPool(threads)
        val futures = (1..threads).map {
            pool.submit(Callable {
                service.storeSecretKey(command)
            })
        }
        val results = futures.map { it.get() }
        pool.shutdown()

        // Exactly one lawful effect: all returned identical resultId and version
        val firstResultId = results.first().resultId
        results.forEach {
            assertEquals(firstResultId, it.resultId)
            assertEquals(1, it.activeVersion)
            assertEquals("concurrent-key-test", it.secretKeyAlias)
        }

        // Single secret stored, single audit record for the initial store
        assertEquals(1, store.secrets.size)
        assertEquals(1, store.getAudits("tenant-kms-1").size)

        // 2. Conflicting payload under same idempotency key produces CONFLICT
        val conflictingCommand = command.copy(secretType = BackendSecretType.API_INTEGRATION_TOKEN)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.storeSecretKey(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Dependency timeout / failure handling during rotation fails closed
        fakeKms.simulateTimeout = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.rotateSecretKey(
                RotateSecretKeyCommand(
                    principal = securityAdmin,
                    tenantId = "tenant-kms-1",
                    secretKeyAlias = "concurrent-key-test",
                    idempotencyKey = "idemp-timeout-rotate",
                    correlationId = "corr-timeout",
                    causationId = "caus-timeout",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // Authoritative state was NOT corrupted by timeout: active version is still 1
        val currentEntry = store.findSecret("tenant-kms-1", "concurrent-key-test")
        assertNotNull(currentEntry)
        assertEquals(1, currentEntry.activeVersion)
        assertEquals(1L, currentEntry.serverVersion)
    }

    // =========================================================================
    // SECRET-001-01-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `SECRET-001-01-T004 Store backend secrets and keys in KMS remains compatible recoverable observable and lifecycle safe`() {
        val store = InMemoryKmsBackendSecretsStore()
        val fakeKms = FakeKmsBackendProviderAdapter()
        val service = KmsBackendSecretsService(store, fakeKms, clock)

        // 1. Fail-closed gate verification: throws "expired/single-pin rotation outage and secret leak"
        KmsBackendSecretsBinding.isBound = false
        val redFailure = assertFailsWith<AssertionError> {
            KmsBackendSecretsBinding.checkBound()
        }
        assertEquals("expired/single-pin rotation outage and secret leak", redFailure.message)

        // Re-bind to test full lifecycle and emergency rollback
        KmsBackendSecretsBinding.isBound = true

        // 2. Store initial key (v1)
        val storeResult = service.storeSecretKey(
            StoreSecretKeyCommand(
                principal = securityAdmin,
                tenantId = "tenant-kms-1",
                secretKeyAlias = "lifecycle-master-key",
                secretType = BackendSecretType.DATA_ENCRYPTION_KEY,
                algorithm = BackendKeyAlgorithm.AES_256_GCM,
                idempotencyKey = "idemp-lifecycle-store",
                correlationId = "corr-life-01",
                causationId = "caus-life-01"
            )
        )
        assertEquals(1, storeResult.activeVersion)

        // 3. Rotate key to v2
        val rotateResult = service.rotateSecretKey(
            RotateSecretKeyCommand(
                principal = securityAdmin,
                tenantId = "tenant-kms-1",
                secretKeyAlias = "lifecycle-master-key",
                idempotencyKey = "idemp-lifecycle-rotate",
                correlationId = "corr-life-02",
                causationId = "caus-life-02",
                expectedVersion = 1L
            )
        )
        assertEquals(2, rotateResult.newActiveVersion)

        // 4. Execute Documented Emergency Rollback (anomaly or compromise in v2 -> rollback to v1)
        val rollbackCommand = EmergencyRollbackKeyCommand(
            principal = securityAdmin,
            tenantId = "tenant-kms-1",
            secretKeyAlias = "lifecycle-master-key",
            targetVersion = 1,
            reason = "Security anomaly detected in rotated v2 key material; urgent rollback requested by SOC",
            idempotencyKey = "idemp-emergency-rollback-01",
            correlationId = "corr-life-rb",
            causationId = "caus-life-rb",
            expectedVersion = 2L
        )

        val rollbackResult = service.emergencyRollback(rollbackCommand)
        assertEquals(2, rollbackResult.rolledBackFromVersion)
        assertEquals(1, rollbackResult.restoredVersion)
        assertTrue(rollbackResult.compromisedVersionRevoked)
        assertFalse(rollbackResult.isFinancialAuthorityCreated)
        assertEquals(3L, rollbackResult.serverVersion)
        assertTrue(rollbackResult.evidenceReference.contains("from-v2-to-v1"))

        // Documented emergency procedure record verified
        val rollbackRecords = store.getRollbackRecords("tenant-kms-1")
        assertEquals(1, rollbackRecords.size)
        val record = rollbackRecords.first()
        assertEquals("lifecycle-master-key", record.secretKeyAlias)
        assertEquals(2, record.fromVersion)
        assertEquals(1, record.targetVersion)
        assertEquals(rollbackCommand.reason, record.reason)
        assertEquals(securityAdmin.id, record.executedBy)
        assertEquals(now, record.executedAt)

        // Assert compromised version v2 cannot be accessed for encryption/decryption
        val compromisedEntry = store.findSecret("tenant-kms-1", "lifecycle-master-key")!!
        assertEquals(BackendSecretStatus.COMPROMISED, compromisedEntry.versions[2]?.status)
        assertFalse(compromisedEntry.isVersionValid(2, now))

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.accessSecretKey(
                AccessSecretKeyCommand(
                    principal = securityAdmin,
                    tenantId = "tenant-kms-1",
                    secretKeyAlias = "lifecycle-master-key",
                    targetVersion = 2,
                    idempotencyKey = "idemp-access-compromised",
                    correlationId = "corr-access-comp",
                    causationId = "caus-access-comp"
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Verify security alerts: CRITICAL alert emitted on emergency rollback
        val alerts = store.getAlerts("tenant-kms-1")
        val criticalAlert = alerts.firstOrNull { it.alertType == "KMS_EMERGENCY_ROLLBACK" }
        assertNotNull(criticalAlert)
        assertEquals("CRITICAL", criticalAlert.severity)
        assertTrue(criticalAlert.message.contains("EMERGENCY ROLLBACK"))

        // 6. Test Sandbox KMS provider adapter compatibility
        val sandboxProvider = SandboxKmsBackendProviderAdapter()
        val sandboxService = KmsBackendSecretsService(store, sandboxProvider, clock)
        val sandboxAdmin = securityAdmin.copy(tenantId = "tenant-sandbox-1")
        val sandboxResult = sandboxService.storeSecretKey(
            StoreSecretKeyCommand(
                principal = sandboxAdmin,
                tenantId = "tenant-sandbox-1",
                secretKeyAlias = "sandbox-key",
                secretType = BackendSecretType.PIN_DERIVATION_SALT,
                algorithm = BackendKeyAlgorithm.HMAC_SHA256,
                idempotencyKey = "idemp-sandbox-01",
                correlationId = "corr-sb-01",
                causationId = "caus-sb-01"
            )
        )
        assertTrue(sandboxResult.kmsKeyUri.startsWith("arn:aws:kms:us-east-1:tenant-sandbox-1:key/sandbox-key-v1"))

        // 7. Audit immutability: past audit entries were never modified or deleted
        val allAudits = store.getAudits("tenant-kms-1")
        assertEquals(4, allAudits.size) // STORE, ROTATE, ROLLBACK, and failed access attempt
    }
}
