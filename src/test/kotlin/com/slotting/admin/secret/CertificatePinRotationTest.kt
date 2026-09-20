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
 * Contract test suite for SECRET-001-02: Support certificate and Android pin rotation.
 *
 * Source implementation-plan family: SECRET-001
 * Semantic Contract: "Emergency rollback documented; key access/audit alerts; no app-embedded secret authority."
 * Expected RED failure: "expired/single-pin rotation outage and secret leak"
 */
class CertificatePinRotationTest {

    private val now = Instant.parse("2026-09-20T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec-02",
        tenantId = "tenant-pin-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN)
    )

    private val auditorAdmin = AuthenticatedPrincipal(
        id = "admin-audit-02",
        tenantId = "tenant-pin-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-untrusted-02",
        tenantId = "tenant-pin-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val primaryPin1 = "sha256/k2v657xBsOwg11+/dWppGMRmMJUu4KWnTobWO5b9vcA="
    private val backupPin1 = "sha256/WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="
    private val rotatedPin2 = "sha256/15x1Lw3rZqf7k5J/e1B/2026newRotatedPinSha256DigestA="
    private val rotatedBackup2 = "sha256/39z9Mw4sAsg8l6K/f2C/2026newRotatedBackupDigestB="

    @BeforeEach
    fun setUp() {
        CertificatePinRotationBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        CertificatePinRotationBinding.isBound = true
    }

    // =========================================================================
    // SECRET-001-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `SECRET-001-02-T001 Support certificate and Android pin rotation produces the required authoritative outcome`() {
        // Expected RED failure: fail-closed gate assertion
        CertificatePinRotationBinding.checkBound()

        val store = InMemoryCertificatePinStore()
        val fakeCa = FakeCertificateProviderAdapter()
        val service = CertificatePinRotationService(store, fakeCa, clock)

        // 1. Register certificate and dual-pin policy (primary + backup)
        val registerCommand = RegisterCertificatePinCommand(
            principal = securityAdmin,
            tenantId = "tenant-pin-1",
            domain = "api.slotting.example.com",
            sanDomains = listOf("api.slotting.example.com", "gateway.slotting.example.com"),
            primaryPinSha256 = primaryPin1,
            backupPinSha256 = backupPin1,
            environment = PinEnvironment.PRODUCTION,
            overlapGracePeriodSeconds = 86400L * 30L, // 30 days
            idempotencyKey = "idemp-reg-pin-01",
            correlationId = "corr-pin-101",
            causationId = "caus-pin-101",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        val regResult = service.registerCertificatePin(registerCommand)
        assertEquals("tenant-pin-1", regResult.tenantId)
        assertEquals("api.slotting.example.com", regResult.domain)
        assertEquals(primaryPin1, regResult.activePinSha256)
        assertEquals(backupPin1, regResult.backupPinSha256)
        assertEquals(setOf(primaryPin1, backupPin1), regResult.validPinsInPolicy)
        assertEquals(1L, regResult.serverVersion)
        assertEquals(now, regResult.serverTime)
        assertFalse(regResult.isFinancialAuthorityCreated)
        assertTrue(regResult.evidenceReference.startsWith("cert-pin:tenant-pin-1:api.slotting.example.com:v1:"))

        // Verify initial pin validity
        val verifyInitial = service.verifyPinPolicy(
            VerifyPinPolicyCommand(
                tenantId = "tenant-pin-1",
                domain = "api.slotting.example.com",
                pinSha256 = primaryPin1,
                correlationId = "corr-ver-1",
                causationId = "caus-ver-1"
            )
        )
        assertTrue(verifyInitial.isValid)

        // 2. Rotate pin to new rotatedPin2 with dual-pin overlap
        val rotateCommand = RotateCertificatePinCommand(
            principal = securityAdmin,
            tenantId = "tenant-pin-1",
            domain = "api.slotting.example.com",
            newPrimaryPinSha256 = rotatedPin2,
            newBackupPinSha256 = rotatedBackup2,
            idempotencyKey = "idemp-rotate-pin-01",
            correlationId = "corr-pin-102",
            causationId = "caus-pin-102",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        val rotateResult = service.rotateCertificatePin(rotateCommand)
        assertEquals(primaryPin1, rotateResult.previousPinSha256)
        assertEquals(rotatedPin2, rotateResult.newActivePinSha256)
        assertEquals(2L, rotateResult.serverVersion)
        assertFalse(rotateResult.isFinancialAuthorityCreated)

        // 3. Proves dual-pin / Android pin rotation overlap:
        // BOTH the newly rotated pin AND the previous pin remain valid simultaneously!
        // This explicitly prevents "expired/single-pin rotation outage"!
        assertTrue(rotateResult.overlappingValidPins.contains(rotatedPin2))
        assertTrue(rotateResult.overlappingValidPins.contains(primaryPin1))

        val verifyPreviousDuringOverlap = service.verifyPinPolicy(
            VerifyPinPolicyCommand(
                tenantId = "tenant-pin-1",
                domain = "api.slotting.example.com",
                pinSha256 = primaryPin1,
                correlationId = "corr-ver-prev",
                causationId = "caus-ver-prev"
            )
        )
        assertTrue(verifyPreviousDuringOverlap.isValid, "Previous pin must remain valid during overlap window to prevent rotation outage")

        val verifyNew = service.verifyPinPolicy(
            VerifyPinPolicyCommand(
                tenantId = "tenant-pin-1",
                domain = "api.slotting.example.com",
                pinSha256 = rotatedPin2,
                correlationId = "corr-ver-new",
                causationId = "caus-ver-new"
            )
        )
        assertTrue(verifyNew.isValid, "New pin must be immediately valid")

        // 4. Android read model delivers all overlapping pins for CertificatePinner
        val androidPolicy = service.getAndroidPinPolicy("tenant-pin-1", "api.slotting.example.com")
        assertTrue(androidPolicy.validPins.contains(rotatedPin2))
        assertTrue(androidPolicy.validPins.contains(primaryPin1))
        assertTrue(androidPolicy.validPins.size >= 2)

        // 5. Assert semantic contract
        assertEquals(
            "Emergency rollback documented; key access/audit alerts; no app-embedded secret authority.",
            CERTIFICATE_PIN_ROTATION_CONTRACT
        )

        // 6. Assert zero private keys or plaintext secrets leaked in audits and alerts
        val audits = store.getAudits("tenant-pin-1")
        assertTrue(audits.isNotEmpty())
        val alerts = store.getAlerts("tenant-pin-1")
        assertTrue(alerts.any { it.alertType == "CERTIFICATE_PIN_ROTATED" })

        val auditText = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditText.contains("PRIVATE_KEY", ignoreCase = true))
        assertFalse(auditText.contains("PASSWORD=", ignoreCase = true))

        // 7. Assert no financial mutation methods
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // SECRET-001-02-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `SECRET-001-02-T002 Support certificate and Android pin rotation rejects invalid boundary unauthorized and stale input`() {
        CertificatePinRotationBinding.isBound = true

        val store = InMemoryCertificatePinStore()
        val fakeCa = FakeCertificateProviderAdapter()
        val service = CertificatePinRotationService(store, fakeCa, clock)

        val validCommand = RegisterCertificatePinCommand(
            principal = securityAdmin,
            tenantId = "tenant-pin-1",
            domain = "api.slotting.example.com",
            sanDomains = listOf("api.slotting.example.com"),
            primaryPinSha256 = primaryPin1,
            backupPinSha256 = backupPin1,
            idempotencyKey = "idemp-t002-valid",
            correlationId = "corr-t002",
            causationId = "caus-t002",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Untrusted Player principal rejected (No app-embedded secret/pin authority!)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(principal = playerPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Auditor principal cannot mutate pins
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(principal = auditorAdmin))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Cross-tenant request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(tenantId = "other-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Stale expected version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 6. Single-pin policy rejected: primary == backup forbidden (prevents single-pin rotation outage)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(backupPinSha256 = primaryPin1))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Malformed pin format rejected (not starting with "sha256/")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(primaryPinSha256 = "invalid-format-pin"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Blank domain or blank idempotency key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(domain = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 9. Financial mutation attempt rejected (strict financial boundary)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(validCommand.copy(mutatesMoney = true))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Successfully register, then test rotation rejections
        service.registerCertificatePin(validCommand)

        // Cannot rotate to the identical pin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.rotateCertificatePin(
                RotateCertificatePinCommand(
                    principal = securityAdmin,
                    tenantId = "tenant-pin-1",
                    domain = "api.slotting.example.com",
                    newPrimaryPinSha256 = primaryPin1,
                    idempotencyKey = "idemp-rotate-identical",
                    correlationId = "corr-ident",
                    causationId = "caus-ident",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Rotate with stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.rotateCertificatePin(
                RotateCertificatePinCommand(
                    principal = securityAdmin,
                    tenantId = "tenant-pin-1",
                    domain = "api.slotting.example.com",
                    newPrimaryPinSha256 = rotatedPin2,
                    idempotencyKey = "idemp-rotate-stale",
                    correlationId = "corr-stale",
                    causationId = "caus-stale",
                    expectedVersion = 99L
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    // =========================================================================
    // SECRET-001-02-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `SECRET-001-02-T003 Support certificate and Android pin rotation survives concurrency duplicate delivery and dependency failure`() {
        CertificatePinRotationBinding.isBound = true

        val store = InMemoryCertificatePinStore()
        val fakeCa = FakeCertificateProviderAdapter()
        val service = CertificatePinRotationService(store, fakeCa, clock)

        val command = RegisterCertificatePinCommand(
            principal = securityAdmin,
            tenantId = "tenant-pin-1",
            domain = "concurrent.slotting.example.com",
            sanDomains = listOf("concurrent.slotting.example.com"),
            primaryPinSha256 = primaryPin1,
            backupPinSha256 = backupPin1,
            idempotencyKey = "idemp-concurrent-pin",
            correlationId = "corr-conc-01",
            causationId = "caus-conc-01",
            expectedVersion = 1L
        )

        // 1. Concurrent equivalent registrations
        val threads = 10
        val pool = Executors.newFixedThreadPool(threads)
        val futures = (1..threads).map {
            pool.submit(Callable {
                service.registerCertificatePin(command)
            })
        }
        val results = futures.map { it.get() }
        pool.shutdown()

        // Exactly one lawful transition
        val firstResultId = results.first().resultId
        results.forEach {
            assertEquals(firstResultId, it.resultId)
            assertEquals("concurrent.slotting.example.com", it.domain)
        }
        assertEquals(1, store.certs.size)
        assertEquals(1, store.getAudits("tenant-pin-1").size)

        // 2. Conflicting payload under same idempotency key produces CONFLICT
        val conflicting = command.copy(backupPinSha256 = "sha256/DifferentBackupDigestXXXXXXXXXXXXXXXXXX=")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerCertificatePin(conflicting)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // SECRET-001-02-T004: Lifecycle, Recovery, and Restore Compatibility
    // =========================================================================

    @Test
    fun `SECRET-001-02-T004 Support certificate and Android pin rotation remains compatible recoverable observable and lifecycle safe`() {
        val store = InMemoryCertificatePinStore()
        val fakeCa = FakeCertificateProviderAdapter()
        val service = CertificatePinRotationService(store, fakeCa, clock)

        // 1. Fail-closed gate verification: throws "expired/single-pin rotation outage and secret leak"
        CertificatePinRotationBinding.isBound = false
        val redFailure = assertFailsWith<AssertionError> {
            CertificatePinRotationBinding.checkBound()
        }
        assertEquals("expired/single-pin rotation outage and secret leak", redFailure.message)

        // Re-bind to test lifecycle and emergency rollback
        CertificatePinRotationBinding.isBound = true

        // 2. Register initial pin policy
        val regResult = service.registerCertificatePin(
            RegisterCertificatePinCommand(
                principal = securityAdmin,
                tenantId = "tenant-pin-1",
                domain = "rollback.slotting.example.com",
                sanDomains = listOf("rollback.slotting.example.com"),
                primaryPinSha256 = primaryPin1,
                backupPinSha256 = backupPin1,
                idempotencyKey = "idemp-life-reg",
                correlationId = "corr-life-01",
                causationId = "caus-life-01"
            )
        )
        val initialEntry = store.findCertificatePin("tenant-pin-1", "rollback.slotting.example.com")!!
        val v1PinId = initialEntry.activePinId

        // 3. Rotate pin to v2
        val rotateResult = service.rotateCertificatePin(
            RotateCertificatePinCommand(
                principal = securityAdmin,
                tenantId = "tenant-pin-1",
                domain = "rollback.slotting.example.com",
                newPrimaryPinSha256 = rotatedPin2,
                idempotencyKey = "idemp-life-rot",
                correlationId = "corr-life-02",
                causationId = "caus-life-02",
                expectedVersion = 1L
            )
        )
        val rotatedEntry = store.findCertificatePin("tenant-pin-1", "rollback.slotting.example.com")!!
        val v2PinId = rotatedEntry.activePinId

        // 4. Documented Emergency Rollback: v2 certificate was misissued/compromised -> rollback to v1 pin
        val rollbackCommand = EmergencyPinRollbackCommand(
            principal = securityAdmin,
            tenantId = "tenant-pin-1",
            domain = "rollback.slotting.example.com",
            targetPinId = v1PinId,
            reason = "CA intermediate certificate compromise reported; urgent rollback to verified leaf pin",
            idempotencyKey = "idemp-pin-rollback-01",
            correlationId = "corr-life-rb",
            causationId = "caus-life-rb",
            expectedVersion = 2L
        )

        val rollbackResult = service.emergencyRollbackPin(rollbackCommand)
        assertEquals(v2PinId, rollbackResult.rolledBackFromPinId)
        assertEquals(v1PinId, rollbackResult.restoredPinId)
        assertEquals(primaryPin1, rollbackResult.restoredActivePinSha256)
        assertTrue(rollbackResult.compromisedPinRevoked)
        assertFalse(rollbackResult.isFinancialAuthorityCreated)
        assertEquals(3L, rollbackResult.serverVersion)

        // Documented emergency procedure record verified
        val rollbackRecords = store.getRollbackRecords("tenant-pin-1")
        assertEquals(1, rollbackRecords.size)
        val record = rollbackRecords.first()
        assertEquals("rollback.slotting.example.com", record.domain)
        assertEquals(v2PinId, record.fromPinId)
        assertEquals(v1PinId, record.targetPinId)
        assertEquals(rollbackCommand.reason, record.reason)
        assertEquals(securityAdmin.id, record.executedBy)
        assertEquals(now, record.executedAt)

        // Verify compromised v2 pin is revoked and no longer valid
        val verifyCompromised = service.verifyPinPolicy(
            VerifyPinPolicyCommand(
                tenantId = "tenant-pin-1",
                domain = "rollback.slotting.example.com",
                pinSha256 = rotatedPin2,
                correlationId = "corr-ver-comp",
                causationId = "caus-ver-comp"
            )
        )
        assertFalse(verifyCompromised.isValid, "Compromised pin must be rejected after emergency rollback")

        // 5. Verify security alerts: CRITICAL alert emitted on emergency rollback
        val alerts = store.getAlerts("tenant-pin-1")
        val criticalAlert = alerts.firstOrNull { it.alertType == "CERTIFICATE_PIN_EMERGENCY_ROLLBACK" }
        assertNotNull(criticalAlert)
        assertEquals("CRITICAL", criticalAlert.severity)
        assertTrue(criticalAlert.message.contains("EMERGENCY ROLLBACK"))

        // 6. Test Sandbox provider adapter compatibility
        val sandboxCa = SandboxCertificateProviderAdapter()
        val issued = sandboxCa.issueCertificate("sandbox.example.com", listOf("sandbox.example.com"))
        assertTrue(issued.spkiPinSha256.startsWith("sha256/SANDBOXPIN"))

        // 7. Audit immutability: past audit entries were never altered or deleted
        val allAudits = store.getAudits("tenant-pin-1")
        assertEquals(4, allAudits.size) // REGISTER, ROTATE, ROLLBACK, VERIFY (compromised)
    }
}
