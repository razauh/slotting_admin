package com.slotting.admin.validation.release

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

class ConnectedReleaseCiArtifactTest {

    private lateinit var service: ConnectedReleaseCiArtifactService
    private lateinit var evidenceStore: InMemoryReleasePipelineEvidenceStore
    private lateinit var alertSink: InMemoryReleasePipelineAlertSink
    private lateinit var observability: InMemoryReleasePipelineObservability

    private val tenantId = "tenant-release-pipeline"
    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-officer-release-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
        tenantId = tenantId
    )
    private val superAdminPrincipal = AuthenticatedPrincipal(
        id = "superadmin-release-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
        tenantId = tenantId
    )
    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-release-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
        tenantId = tenantId
    )

    private val now = Instant.now()
    private val validManifest = ReleaseArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:release-candidate-v1-bundle",
        configurationVersion = "1.0.0",
        environment = "production-release-gate",
        owner = "devops-release-engineering-lead",
        reviewer = "chief-security-architect",
        signedAt = now.minus(2, ChronoUnit.HOURS),
        expiry = now.plus(48, ChronoUnit.HOURS)
    )

    private val validKmsRecord = KmsSignerAuditRecord(
        kmsKeyArn = "arn:aws:kms:us-east-1:123456789012:key/release-signing-key-production",
        signingAlgorithm = "SHA256withECDSA",
        custodianSignatures = listOf("sig-custodian-security-lead", "sig-custodian-principal-architect"),
        cloudTrailAuditId = "ct-audit-event-994827110",
        isHsmBacked = true,
        signedAt = now.minus(1, ChronoUnit.HOURS)
    )

    private val validReproducibleRecord = ReproducibleArtifactRecord(
        artifactName = "slotting-release.aab",
        candidateDigest = "sha256:4a8e3d09a12b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
        referenceDigest = "sha256:4a8e3d09a12b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
        isReproducible = true,
        sbomFormat = "SPDX-2.3-JSON",
        sbomDigest = "sha256:sbom-digest-release-v1",
        criticalVulnerabilitiesCount = 0,
        slsaLevel = 3
    )

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryReleasePipelineEvidenceStore()
        alertSink = InMemoryReleasePipelineAlertSink()
        observability = InMemoryReleasePipelineObservability()
        service = ConnectedReleaseCiArtifactService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability
        )
    }

    private fun createValidSuiteRecords(): Map<ReleaseTestSuite, SuiteExecutionRecord> {
        return ReleaseTestSuite.values().associateWith { suite ->
            SuiteExecutionRecord(
                suite = suite,
                priority = if (suite.name.startsWith("GATE_") || suite == ReleaseTestSuite.SYS_CRITICAL_JOURNEY || suite == ReleaseTestSuite.SYS_PROVIDER_CERTIFICATION || suite == ReleaseTestSuite.SYS_RESTORE_REHEARSAL) "P0" else "P1",
                status = SuiteExecutionStatus.PASSED,
                testCount = 12,
                executedAt = now.minus(30, ChronoUnit.MINUTES),
                evidenceDigest = "sha256:suite-pass-${suite.name}"
            )
        }
    }

    private fun createValidCommand(
        idempotencyKey: String = UUID.randomUUID().toString(),
        suiteRecords: Map<ReleaseTestSuite, SuiteExecutionRecord> = createValidSuiteRecords(),
        kmsSignerRecord: KmsSignerAuditRecord = validKmsRecord,
        reproducibleRecord: ReproducibleArtifactRecord = validReproducibleRecord
    ): RunReleasePipelineCommand {
        return RunReleasePipelineCommand(
            principal = securityPrincipal,
            tenantId = tenantId,
            manifest = validManifest,
            suiteRecords = suiteRecords,
            kmsSignerRecord = kmsSignerRecord,
            reproducibleRecord = reproducibleRecord,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}"
        )
    }

    @Test
    @DisplayName("SYS-007-T001 — Connected release CI/artifact produces the required authoritative outcome")
    fun testSYS007T001PrimaryAuthoritativeOutcome() {
        val cmd = createValidCommand()
        val report = service.runReleasePipelineValidation(cmd)

        // Outcome contract assertion
        assertEquals(
            "P0/P1 suites unskippable; signer/KMS audit; reproducible artifact comparison.",
            report.semanticContract
        )
        assertEquals(ReleasePipelineStatus.CERTIFIED_APPROVED, report.status)
        assertTrue(report.isAllMandatorySuitesPassed)
        assertTrue(report.isKmsAuditValid)
        assertTrue(report.isArtifactReproducible)

        // All 13 mandatory suites verified
        assertEquals(13, report.suiteExecutions.size)
        for ((_, record) in report.suiteExecutions) {
            assertEquals(SuiteExecutionStatus.PASSED, record.status)
            assertTrue(record.testCount > 0)
        }

        // KMS Dual-custody audit
        assertEquals(2, report.kmsAudit.custodianSignatures.size)
        assertTrue(report.kmsAudit.isHsmBacked)

        // Reproducible build comparison
        assertEquals(report.reproducibility.candidateDigest, report.reproducibility.referenceDigest)
        assertTrue(report.reproducibility.isReproducible)
        assertEquals(0, report.reproducibility.criticalVulnerabilitiesCount)
        assertTrue(report.reproducibility.slsaLevel >= 3)

        // Strict Android boundary: presentation layer untrusted
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Correlated evidence reference
        assertNotNull(report.evidenceReference)
        assertEquals(cmd.correlationId, report.correlationId)
        assertEquals(cmd.causationId, report.causationId)

        // Saved in evidence store
        val stored = evidenceStore.getReport(report.releaseId)
        assertNotNull(stored)
        assertEquals(report.releaseId, stored!!.releaseId)
    }

    @Test
    @DisplayName("SYS-007-T002 — Connected release CI/artifact rejects invalid, boundary, unauthorized, and stale input")
    fun testSYS007T002RejectsInvalidBoundaryUnauthorizedInput() {
        val validCmd = createValidCommand()

        // 1. Unauthenticated principal
        val unauthCmd = validCmd.copy(principal = null)
        assertThrows<UnauthorizedReleasePipelineException> {
            service.runReleasePipelineValidation(unauthCmd)
        }

        // 2. Insufficient permissions (SUPPORT cannot approve release pipeline)
        val supportCmd = validCmd.copy(principal = supportPrincipal)
        assertThrows<UnauthorizedReleasePipelineException> {
            service.runReleasePipelineValidation(supportCmd)
        }

        // 3. Cross-tenant execution
        val crossTenantCmd = validCmd.copy(tenantId = "cross-tenant-release")
        assertThrows<UnauthorizedReleasePipelineException> {
            service.runReleasePipelineValidation(crossTenantCmd)
        }

        // 4. Blank input fields
        assertThrows<InvalidReleasePipelineInputException> {
            service.runReleasePipelineValidation(validCmd.copy(idempotencyKey = "   "))
        }
        assertThrows<InvalidReleasePipelineInputException> {
            service.runReleasePipelineValidation(validCmd.copy(correlationId = "   "))
        }
        assertThrows<InvalidReleasePipelineInputException> {
            service.runReleasePipelineValidation(validCmd.copy(causationId = "   "))
        }
        assertThrows<InvalidReleasePipelineInputException> {
            service.runReleasePipelineValidation(validCmd.copy(suiteRecords = emptyMap()))
        }

        // 5. Expired manifest
        val expiredManifest = validManifest.copy(expiry = now.minus(1, ChronoUnit.HOURS))
        assertThrows<InvalidReleaseManifestException> {
            service.runReleasePipelineValidation(validCmd.copy(manifest = expiredManifest))
        }

        // 6. Skipped mandatory suite must be rejected with ReleasePipelineMissingEvidenceException
        val skippedSuites = createValidSuiteRecords().toMutableMap()
        val financialSuite = skippedSuites[ReleaseTestSuite.GATE_FINANCIAL]!!
        skippedSuites[ReleaseTestSuite.GATE_FINANCIAL] = financialSuite.copy(status = SuiteExecutionStatus.SKIPPED)
        val skippedCmd = createValidCommand(suiteRecords = skippedSuites)
        val exSkipped = assertThrows<ReleasePipelineMissingEvidenceException> {
            service.runReleasePipelineValidation(skippedCmd)
        }
        assertTrue(exSkipped.message!!.contains("pipeline accepts missing evidence"))

        // 7. Missing KMS dual-custody audit must be rejected
        val invalidKms = validKmsRecord.copy(custodianSignatures = listOf("only-single-signature"))
        val invalidKmsCmd = createValidCommand(kmsSignerRecord = invalidKms)
        val exKms = assertThrows<ReleasePipelineMissingEvidenceException> {
            service.runReleasePipelineValidation(invalidKmsCmd)
        }
        assertTrue(exKms.message!!.contains("pipeline accepts missing evidence"))

        // 8. Non-reproducible artifact comparison must be rejected
        val nonReproducible = validReproducibleRecord.copy(
            referenceDigest = "sha256:different-digest-build-drift",
            isReproducible = false
        )
        val reproCmd = createValidCommand(reproducibleRecord = nonReproducible)
        val exRepro = assertThrows<ReleasePipelineMissingEvidenceException> {
            service.runReleasePipelineValidation(reproCmd)
        }
        assertTrue(exRepro.message!!.contains("pipeline accepts missing evidence"))

        // Verify alert emitted
        assertTrue(alertSink.getAlerts().any { it.message.contains("pipeline accepts missing evidence") })
    }

    @Test
    @DisplayName("SYS-007-T003 — Connected release CI/artifact survives concurrency, duplicate delivery, and dependency failure")
    fun testSYS007T003ConcurrencyIdempotencyDependencyFailure() {
        val idempotencyKey = "release-idem-${UUID.randomUUID()}"
        val cmd1 = createValidCommand(idempotencyKey = idempotencyKey)

        // 1. First execution succeeds
        val report1 = service.runReleasePipelineValidation(cmd1)
        assertEquals(ReleasePipelineStatus.CERTIFIED_APPROVED, report1.status)

        // 2. Duplicate delivery with identical payload returns exact same report
        val report2 = service.runReleasePipelineValidation(cmd1)
        assertEquals(report1.releaseId, report2.releaseId)
        assertEquals(report1.evaluatedAt, report2.evaluatedAt)

        // 3. Changed-payload key reuse throws IdempotencyConflictException
        val conflictingCmd = cmd1.copy(
            kmsSignerRecord = validKmsRecord.copy(cloudTrailAuditId = "different-audit-id")
        )
        assertThrows<IdempotencyConflictException> {
            service.runReleasePipelineValidation(conflictingCmd)
        }

        // 4. Dependency failure handling
        service.scenarioFaults["DEPENDENCY_FAILURE"] = "Simulated KMS CloudTrail audit retrieval failure"
        val depFailCmd = createValidCommand()
        val depEx = assertThrows<ReleasePipelineValidationException> {
            service.runReleasePipelineValidation(depFailCmd)
        }
        assertTrue(depEx.message!!.contains("Dependency failure"))
        assertTrue(alertSink.getAlerts().any { it.message.contains("Dependency failure") })
        service.scenarioFaults.remove("DEPENDENCY_FAILURE")

        // 5. Concurrency: multiple parallel requests handle cleanly
        val executor = Executors.newFixedThreadPool(4)
        val callables = (1..8).map { i ->
            Callable {
                val threadCmd = createValidCommand(idempotencyKey = "thread-idem-release-$i")
                service.runReleasePipelineValidation(threadCmd)
            }
        }
        val futures = executor.invokeAll(callables)
        for (f in futures) {
            val r = f.get()
            assertEquals(ReleasePipelineStatus.CERTIFIED_APPROVED, r.status)
            assertTrue(r.isAllMandatorySuitesPassed)
        }
        executor.shutdown()
    }

    @Test
    @DisplayName("SYS-007-T004 — Connected release CI/artifact remains compatible, recoverable, observable, and lifecycle-safe")
    fun testSYS007T004LifecycleRecoveryObservability() {
        val cmd = createValidCommand()
        val report = service.runReleasePipelineValidation(cmd)

        // Zero Android lifecycle surface
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Observability metrics recorded
        assertTrue(observability.getEvaluationsCount() > 0)
        assertTrue(observability.getSuitesVerifiedCount() >= 13)

        // Immutable evidence binding
        assertEquals(validManifest.commitHash, report.manifest.commitHash)
        assertEquals(validManifest.artifactDigest, report.manifest.artifactDigest)
        assertEquals(validManifest.environment, report.manifest.environment)
        assertEquals(validManifest.owner, report.manifest.owner)
        assertEquals(validManifest.reviewer, report.manifest.reviewer)
        assertTrue(report.evidenceReference.startsWith("ev-release-"))
    }
}
