package com.slotting.admin.validation.device

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class PhysicalDeviceMatrixTest {

    private lateinit var service: PhysicalDeviceMatrixService
    private lateinit var evidenceStore: InMemoryDeviceMatrixEvidenceStore
    private lateinit var alertSink: InMemoryDeviceMatrixAlertSink
    private lateinit var observability: InMemoryDeviceMatrixObservability

    private val tenantId = "tenant-matrix-validation"
    private val adminPrincipal = AuthenticatedPrincipal(
        id = "superadmin-device-matrix-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
        tenantId = tenantId
    )
    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-device-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
        tenantId = tenantId
    )

    private val now = Instant.now()
    private val validManifest = DeviceArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:physical-device-matrix-v1",
        configurationVersion = "1.0.0",
        environment = "device-lab-matrix-mirror",
        owner = "mobile-qa-engineering-lead",
        reviewer = "staff-client-platform-engineer",
        signedAt = now.minus(2, ChronoUnit.HOURS),
        expiry = now.plus(48, ChronoUnit.HOURS)
    )

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryDeviceMatrixEvidenceStore()
        alertSink = InMemoryDeviceMatrixAlertSink()
        observability = InMemoryDeviceMatrixObservability()
        service = PhysicalDeviceMatrixService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability
        )
    }

    private fun createValidCommand(
        idempotencyKey: String = UUID.randomUUID().toString(),
        dimensions: Set<MatrixDimension> = MatrixDimension.values().toSet(),
        targetTiers: Set<DeviceTier> = DeviceTier.values().toSet(),
        injectedFailures: Set<MatrixDimension> = emptySet()
    ): RunDeviceMatrixValidationCommand {
        return RunDeviceMatrixValidationCommand(
            principal = adminPrincipal,
            tenantId = tenantId,
            dimensions = dimensions,
            targetTiers = targetTiers,
            manifest = validManifest,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}",
            injectedFailures = injectedFailures
        )
    }

    @Test
    @DisplayName("SYS-006-T001 — Physical device/a11y/performance matrix produces the required authoritative outcome")
    fun testSYS006T001PrimaryAuthoritativeOutcome() {
        val cmd = createValidCommand()
        val report = service.runDeviceMatrixValidation(cmd)

        // Outcome contract assertion
        assertEquals(
            "TalkBack/switch/font/foldable/rotation/battery/startup/network/socket and process death.",
            report.semanticContract
        )
        assertEquals(DeviceMatrixStatus.CERTIFIED_PASSED, report.status)
        assertTrue(report.isMatrixCertified)
        assertEquals(0, report.totalFailedTests)
        assertTrue(report.totalPassedTests > 0)
        assertEquals(report.totalPassedTests, report.totalTestsExecuted)

        // All 10 dimensions must be present and PASSED_CERTIFIED
        assertEquals(10, report.dimensionResults.size)
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.TALKBACK))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.SWITCH_ACCESS))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.FONT_SCALING))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.FOLDABLE_POSTURE))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.CONFIGURATION_ROTATION))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.BATTERY_OPTIMIZATION))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.COLD_HOT_STARTUP))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.NETWORK_ADAPTABILITY))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.SOCKET_RESILIENCE))
        assertTrue(report.dimensionResults.containsKey(MatrixDimension.PROCESS_DEATH))

        for ((_, result) in report.dimensionResults) {
            assertEquals(MatrixDimensionStatus.PASSED_CERTIFIED, result.status)
            assertEquals(0, result.failedTests)
            assertEquals(cmd.targetTiers, result.testedTiers)
        }

        // Specific dimension metric checks
        val startupResult = report.dimensionResults[MatrixDimension.COLD_HOT_STARTUP]!!
        assertEquals("1120", startupResult.metrics["coldStartupMs"])
        val fontResult = report.dimensionResults[MatrixDimension.FONT_SCALING]!!
        assertEquals("200%", fontResult.metrics["maxScaleFactor"])
        assertEquals("false", fontResult.metrics["layoutTruncationDetected"])

        // Strict Android boundary: presentation layer untrusted
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Correlated evidence reference
        assertNotNull(report.evidenceReference)
        assertEquals(cmd.correlationId, report.correlationId)
        assertEquals(cmd.causationId, report.causationId)

        // Saved in evidence store
        val stored = evidenceStore.getReport(report.reportId)
        assertNotNull(stored)
        assertEquals(report.reportId, stored!!.reportId)
    }

    @Test
    @DisplayName("SYS-006-T002 — Physical device/a11y/performance matrix rejects invalid, boundary, unauthorized, and stale input")
    fun testSYS006T002RejectsInvalidBoundaryUnauthorizedInput() {
        val validCmd = createValidCommand()

        // 1. Unauthenticated principal
        val unauthCmd = validCmd.copy(principal = null)
        assertThrows<UnauthorizedDeviceMatrixException> {
            service.runDeviceMatrixValidation(unauthCmd)
        }

        // 2. Insufficient permissions (AUDITOR cannot run device matrix certification)
        val auditorCmd = validCmd.copy(principal = auditorPrincipal)
        assertThrows<UnauthorizedDeviceMatrixException> {
            service.runDeviceMatrixValidation(auditorCmd)
        }

        // 3. Cross-tenant execution
        val crossTenantCmd = validCmd.copy(tenantId = "cross-tenant-device-target")
        assertThrows<UnauthorizedDeviceMatrixException> {
            service.runDeviceMatrixValidation(crossTenantCmd)
        }

        // 4. Blank input fields
        assertThrows<InvalidDeviceMatrixInputException> {
            service.runDeviceMatrixValidation(validCmd.copy(idempotencyKey = "   "))
        }
        assertThrows<InvalidDeviceMatrixInputException> {
            service.runDeviceMatrixValidation(validCmd.copy(correlationId = "   "))
        }
        assertThrows<InvalidDeviceMatrixInputException> {
            service.runDeviceMatrixValidation(validCmd.copy(causationId = "   "))
        }
        assertThrows<InvalidDeviceMatrixInputException> {
            service.runDeviceMatrixValidation(validCmd.copy(dimensions = emptySet()))
        }
        assertThrows<InvalidDeviceMatrixInputException> {
            service.runDeviceMatrixValidation(validCmd.copy(targetTiers = emptySet()))
        }

        // 5. Expired manifest
        val expiredManifest = validManifest.copy(expiry = now.minus(1, ChronoUnit.HOURS))
        assertThrows<InvalidDeviceManifestException> {
            service.runDeviceMatrixValidation(validCmd.copy(manifest = expiredManifest))
        }

        // 6. Injected matrix failures must be rejected with MatrixValidationBreachedException
        val fontFailureCmd = createValidCommand(injectedFailures = setOf(MatrixDimension.FONT_SCALING))
        val exFont = assertThrows<MatrixValidationBreachedException> {
            service.runDeviceMatrixValidation(fontFailureCmd)
        }
        assertTrue(exFont.message!!.contains("record matrix failures"))

        val processDeathFailureCmd = createValidCommand(injectedFailures = setOf(MatrixDimension.PROCESS_DEATH))
        val exProcess = assertThrows<MatrixValidationBreachedException> {
            service.runDeviceMatrixValidation(processDeathFailureCmd)
        }
        assertTrue(exProcess.message!!.contains("record matrix failures"))

        // Verify alert emitted
        assertTrue(alertSink.getAlerts().any { it.message.contains("record matrix failures") })
    }

    @Test
    @DisplayName("SYS-006-T003 — Physical device/a11y/performance matrix survives concurrency, duplicate delivery, and dependency failure")
    fun testSYS006T003ConcurrencyIdempotencyDependencyFailure() {
        val idempotencyKey = "matrix-idem-${UUID.randomUUID()}"
        val cmd1 = createValidCommand(idempotencyKey = idempotencyKey)

        // 1. First execution succeeds
        val report1 = service.runDeviceMatrixValidation(cmd1)
        assertEquals(DeviceMatrixStatus.CERTIFIED_PASSED, report1.status)

        // 2. Duplicate delivery with identical payload returns exact same report
        val report2 = service.runDeviceMatrixValidation(cmd1)
        assertEquals(report1.reportId, report2.reportId)
        assertEquals(report1.evaluatedAt, report2.evaluatedAt)

        // 3. Changed-payload key reuse throws IdempotencyConflictException
        val conflictingCmd = cmd1.copy(
            dimensions = setOf(MatrixDimension.TALKBACK, MatrixDimension.SWITCH_ACCESS)
        )
        assertThrows<IdempotencyConflictException> {
            service.runDeviceMatrixValidation(conflictingCmd)
        }

        // 4. Dependency failure handling
        service.scenarioFaults["DEPENDENCY_FAILURE"] = "Simulated device lab telemetry synchronization failure"
        val depFailCmd = createValidCommand()
        val depEx = assertThrows<DeviceMatrixValidationException> {
            service.runDeviceMatrixValidation(depFailCmd)
        }
        assertTrue(depEx.message!!.contains("Dependency failure"))
        assertTrue(alertSink.getAlerts().any { it.message.contains("Dependency failure") })
        service.scenarioFaults.remove("DEPENDENCY_FAILURE")

        // 5. Concurrency: multiple parallel requests handle cleanly
        val executor = Executors.newFixedThreadPool(4)
        val callables = (1..8).map { i ->
            Callable {
                val threadCmd = createValidCommand(idempotencyKey = "thread-idem-matrix-$i")
                service.runDeviceMatrixValidation(threadCmd)
            }
        }
        val futures = executor.invokeAll(callables)
        for (f in futures) {
            val r = f.get()
            assertEquals(DeviceMatrixStatus.CERTIFIED_PASSED, r.status)
            assertTrue(r.isMatrixCertified)
        }
        executor.shutdown()
    }

    @Test
    @DisplayName("SYS-006-T004 — Physical device/a11y/performance matrix remains compatible, recoverable, observable, and lifecycle-safe")
    fun testSYS006T004LifecycleRecoveryObservability() {
        val cmd = createValidCommand()
        val report = service.runDeviceMatrixValidation(cmd)

        // Zero Android lifecycle surface
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Observability metrics recorded
        assertTrue(observability.getEvaluationsCount() > 0)
        assertTrue(observability.getDimensionsEvaluatedCount() >= 10)

        // Immutable evidence binding
        assertEquals(validManifest.commitHash, report.manifest.commitHash)
        assertEquals(validManifest.artifactDigest, report.manifest.artifactDigest)
        assertEquals(validManifest.environment, report.manifest.environment)
        assertEquals(validManifest.owner, report.manifest.owner)
        assertEquals(validManifest.reviewer, report.manifest.reviewer)
        assertTrue(report.evidenceReference.startsWith("ev-devicematrix-"))
    }
}
