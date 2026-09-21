package com.slotting.admin.validation.pack

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

class TechnicalLaunchEvidencePackTest {

    private lateinit var service: TechnicalLaunchEvidencePackService
    private lateinit var evidenceStore: InMemoryTechnicalEvidencePackStore
    private lateinit var alertSink: InMemoryEvidencePackAlertSink
    private lateinit var observability: InMemoryEvidencePackObservability

    private val tenantId = "tenant-launch-ops"
    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-director-launch-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
        tenantId = tenantId
    )
    private val superAdminPrincipal = AuthenticatedPrincipal(
        id = "superadmin-launch-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
        tenantId = tenantId
    )
    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-launch-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
        tenantId = tenantId
    )

    private val now = Instant.now()
    private val validManifest = EvidencePackArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:production-launch-evidence-v1",
        configurationVersion = "1.0.0",
        environment = "production-launch-pack",
        owner = "launch-readiness-commander",
        reviewer = "chief-compliance-security-officer",
        signedAt = now.minus(2, ChronoUnit.HOURS),
        expiry = now.plus(48, ChronoUnit.HOURS)
    )

    private fun createValidTechnicalEvidenceItems(): List<EvidenceItemRecord> {
        return EvidenceItemType.values().map { type ->
            EvidenceItemRecord(
                type = type,
                evidenceId = "ev-$type-${UUID.randomUUID()}",
                status = EvidenceItemStatus.PASSED,
                artifactDigest = "sha256:production-launch-evidence-v1",
                evaluatedAt = now.minus(1, ChronoUnit.HOURS),
                expiry = now.plus(24, ChronoUnit.HOURS),
                summary = "Authoritative gate/validation passed for $type"
            )
        }
    }

    private fun createValidExternalApprovals(): List<ExternalApprovalRecord> {
        return ExternalApprovalType.values().map { type ->
            ExternalApprovalRecord(
                approvalType = type,
                approvalId = "ext-appr-$type-${UUID.randomUUID()}",
                authorityName = when (type) {
                    ExternalApprovalType.LEGAL_COMPLIANCE -> "Gaming Control Regulatory Commission"
                    ExternalApprovalType.APP_STORE -> "Google Play Developer Review Authority"
                    ExternalApprovalType.PROVIDER_REGULATORY -> "Certified Casino Provider Compliance Board"
                },
                status = ExternalApprovalStatus.APPROVED,
                approvedAt = now.minus(6, ChronoUnit.HOURS),
                expiry = now.plus(72, ChronoUnit.HOURS),
                referenceDoc = "REG-APPROVAL-DOC-$type-2026"
            )
        }
    }

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryTechnicalEvidencePackStore()
        alertSink = InMemoryEvidencePackAlertSink()
        observability = InMemoryEvidencePackObservability()
        service = TechnicalLaunchEvidencePackService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability
        )
    }

    private fun createValidCommand(
        idempotencyKey: String = UUID.randomUUID().toString(),
        technicalEvidenceItems: List<EvidenceItemRecord> = createValidTechnicalEvidenceItems(),
        externalApprovals: List<ExternalApprovalRecord> = createValidExternalApprovals(),
        attemptExternalApprovalSubstitution: Boolean = false
    ): RunEvidencePackCommand {
        return RunEvidencePackCommand(
            principal = superAdminPrincipal,
            tenantId = tenantId,
            manifest = validManifest,
            technicalEvidenceItems = technicalEvidenceItems,
            externalApprovals = externalApprovals,
            attemptExternalApprovalSubstitution = attemptExternalApprovalSubstitution,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}"
        )
    }

    @Test
    @DisplayName("SYS-009-T001 — Technical launch evidence pack produces the required authoritative outcome")
    fun testSYS009T001PrimaryAuthoritativeOutcome() {
        val cmd = createValidCommand()
        val report = service.compileEvidencePack(cmd)

        assertEquals(
            "Technical pack cannot substitute legal/store/provider approvals; CI-004 computes decision.",
            report.semanticContract
        )
        assertEquals(Ci004GateDecision.READY_FOR_FINAL_SIGN_OFF, report.decision)
        assertTrue(report.isContractSatisfied)
        assertEquals(15, report.evaluatedItems.size)
        assertEquals(3, report.externalApprovals.size)

        // Financial conservation: debits equal credits, zero imbalance, no double effect
        assertEquals(50_000_000L, report.financialEvidence.totalDebitsMinor)
        assertEquals(50_000_000L, report.financialEvidence.totalCreditsMinor)
        assertEquals(0L, report.financialEvidence.netImbalanceMinor)
        assertFalse(report.financialEvidence.postedHistoryModified)
        assertEquals("RECONCILED_MATCH", report.financialEvidence.reconciliationStatus)

        // Android boundary: presentation layer untrusted, no lifecycle or DB claims
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Correlated evidence lineage
        assertNotNull(report.evidenceReference)
        assertEquals(cmd.correlationId, report.correlationId)
        assertEquals(cmd.causationId, report.causationId)

        // Saved in evidence store
        val stored = evidenceStore.getReport(report.packId)
        assertNotNull(stored)
        assertEquals(report.packId, stored!!.packId)
    }

    @Test
    @DisplayName("SYS-009-T002 — Technical launch evidence pack rejects invalid, boundary, unauthorized, and stale input")
    fun testSYS009T002RejectsInvalidBoundaryUnauthorizedInput() {
        // 1. Unauthenticated principal
        assertThrows<UnauthorizedEvidencePackException> {
            service.compileEvidencePack(createValidCommand().copy(principal = null))
        }

        // 2. Insufficient permissions (SUPPORT cannot compile launch pack)
        assertThrows<UnauthorizedEvidencePackException> {
            service.compileEvidencePack(createValidCommand().copy(principal = supportPrincipal))
        }

        // 3. Cross-tenant invocation
        assertThrows<UnauthorizedEvidencePackException> {
            service.compileEvidencePack(createValidCommand().copy(tenantId = "cross-tenant-launch"))
        }

        // 4. Blank input fields
        assertThrows<InvalidEvidencePackInputException> {
            service.compileEvidencePack(createValidCommand().copy(tenantId = "   "))
        }
        assertThrows<InvalidEvidencePackInputException> {
            service.compileEvidencePack(createValidCommand().copy(idempotencyKey = "   "))
        }
        assertThrows<InvalidEvidencePackInputException> {
            service.compileEvidencePack(createValidCommand().copy(correlationId = "   "))
        }
        assertThrows<InvalidEvidencePackInputException> {
            service.compileEvidencePack(createValidCommand().copy(causationId = "   "))
        }

        // 5. Expired / invalid manifest
        val expiredManifest = validManifest.copy(expiry = now.minus(1, ChronoUnit.HOURS))
        val expiredManifestEx = assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(createValidCommand().copy(manifest = expiredManifest))
        }
        assertTrue(expiredManifestEx.message!!.contains("missing/stale item rejected"))

        // 6. Missing technical evidence item (e.g. dropping GATE_FINANCIAL_001)
        val missingItem = createValidTechnicalEvidenceItems().filter { it.type != EvidenceItemType.GATE_FINANCIAL_001 }
        val missingEx = assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(createValidCommand(technicalEvidenceItems = missingItem))
        }
        assertTrue(missingEx.message!!.contains("missing/stale item rejected"))
        assertTrue(missingEx.message!!.contains("Missing required technical evidence item"))

        // 7. Stale technical evidence item (expired > 24 hours)
        val staleItems = createValidTechnicalEvidenceItems().map {
            if (it.type == EvidenceItemType.SYS_008_ROLLOUT) it.copy(expiry = now.minus(2, ChronoUnit.HOURS))
            else it
        }
        val staleEx = assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(createValidCommand(technicalEvidenceItems = staleItems))
        }
        assertTrue(staleEx.message!!.contains("missing/stale item rejected"))
        assertTrue(staleEx.message!!.contains("stale/expired"))

        // 8. Failed technical evidence item
        val failedItems = createValidTechnicalEvidenceItems().map {
            if (it.type == EvidenceItemType.SYS_004_CHAOS) it.copy(status = EvidenceItemStatus.FAILED)
            else it
        }
        val failedEx = assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(createValidCommand(technicalEvidenceItems = failedItems))
        }
        assertTrue(failedEx.message!!.contains("missing/stale item rejected"))
        assertTrue(failedEx.message!!.contains("status is not PASSED"))

        // 9. Artifact digest mismatch
        val mismatchItems = createValidTechnicalEvidenceItems().map {
            if (it.type == EvidenceItemType.SYS_007_RELEASE_CI) it.copy(artifactDigest = "sha256:tampered-digest")
            else it
        }
        val mismatchEx = assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(createValidCommand(technicalEvidenceItems = mismatchItems))
        }
        assertTrue(mismatchEx.message!!.contains("missing/stale item rejected"))
        assertTrue(mismatchEx.message!!.contains("artifact digest mismatch"))

        // 10. Attempting external approval substitution
        val substitutionEx = assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(createValidCommand(attemptExternalApprovalSubstitution = true))
        }
        assertTrue(substitutionEx.message!!.contains("missing/stale item rejected"))
        assertTrue(substitutionEx.message!!.contains("Technical pack cannot substitute legal/store/provider approvals"))

        // 11. Missing external approval
        val missingApproval = createValidExternalApprovals().filter { it.approvalType != ExternalApprovalType.APP_STORE }
        val missingApprEx = assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(createValidCommand(externalApprovals = missingApproval))
        }
        assertTrue(missingApprEx.message!!.contains("missing/stale item rejected"))
        assertTrue(missingApprEx.message!!.contains("Missing external approval"))
    }

    @Test
    @DisplayName("SYS-009-T003 — Technical launch evidence pack survives concurrency, duplicate delivery, and dependency failure")
    fun testSYS009T003SurvivesConcurrencyDuplicateDeliveryDependencyFailure() {
        val validCmd = createValidCommand()

        // 1. Exact duplicate delivery (idempotent replay returns same result)
        val report1 = service.compileEvidencePack(validCmd)
        val report2 = service.compileEvidencePack(validCmd)
        assertEquals(report1.packId, report2.packId)
        assertEquals(report1.semanticContract, report2.semanticContract)

        // 2. Changed payload with same idempotency key conflicts
        val changedCmd = validCmd.copy(tenantId = tenantId, attemptExternalApprovalSubstitution = true)
        assertThrows<IdempotencyConflictException> {
            service.compileEvidencePack(changedCmd)
        }

        // 3. Concurrency safety: multi-threaded compilation
        val threadCount = 6
        val executor = Executors.newFixedThreadPool(threadCount)
        val futures = (1..threadCount).map { idx ->
            executor.submit(Callable {
                val threadCmd = createValidCommand(idempotencyKey = "concurrent-pack-$idx")
                service.compileEvidencePack(threadCmd)
            })
        }
        val reports = futures.map { it.get() }
        executor.shutdown()

        assertEquals(threadCount, reports.size)
        reports.forEach { report ->
            assertEquals(Ci004GateDecision.READY_FOR_FINAL_SIGN_OFF, report.decision)
            assertEquals(0L, report.financialEvidence.netImbalanceMinor)
            assertFalse(report.financialEvidence.postedHistoryModified)
        }

        // 4. Injected dependency failure fails closed and emits alert
        service.scenarioFaults["DEPENDENCY_FAILURE"] = "Vault KMS certificate service unavailable"
        val depFaultCmd = createValidCommand(idempotencyKey = "dep-fault-${UUID.randomUUID()}")
        val depEx = assertThrows<TechnicalEvidencePackException> {
            service.compileEvidencePack(depFaultCmd)
        }
        assertTrue(depEx.message!!.contains("Dependency failure"))
        assertTrue(alertSink.getAlerts().any { it.message.contains("Dependency failure") })
    }

    @Test
    @DisplayName("SYS-009-T004 — Technical launch evidence pack remains compatible, recoverable, observable, and lifecycle-safe")
    fun testSYS009T004ObservabilityRecoveryAndLifecycleSafety() {
        val cmd = createValidCommand()
        val report = service.compileEvidencePack(cmd)

        // Outcome contract verified
        assertEquals(
            "Technical pack cannot substitute legal/store/provider approvals; CI-004 computes decision.",
            report.semanticContract
        )

        // Observability metrics updated
        assertTrue(observability.getEvaluationsCount() >= 1L)

        // Complete immutable evidence recorded with full lineage
        val stored = evidenceStore.getReport(report.packId)
        assertNotNull(stored)
        assertEquals(validManifest.commitHash, stored!!.manifest.commitHash)
        assertEquals(validManifest.artifactDigest, stored.manifest.artifactDigest)
        assertEquals(validManifest.configurationVersion, stored.manifest.configurationVersion)
        assertEquals(validManifest.environment, stored.manifest.environment)
        assertEquals(validManifest.owner, stored.manifest.owner)
        assertEquals(validManifest.reviewer, stored.manifest.reviewer)

        // Strict Android boundary: no lifecycle or DB mutation
        assertFalse(stored.hasAndroidLifecycleClaim)
        assertFalse(stored.hasAndroidDbImpact)

        // Failure alert sink emits alert on rejection
        val staleItems = cmd.technicalEvidenceItems.map {
            if (it.type == EvidenceItemType.SYS_001_JOURNEY) it.copy(expiry = now.minus(5, ChronoUnit.HOURS))
            else it
        }
        val failingCmd = cmd.copy(
            idempotencyKey = "failing-obs-${UUID.randomUUID()}",
            technicalEvidenceItems = staleItems
        )
        assertThrows<MissingStaleEvidencePackException> {
            service.compileEvidencePack(failingCmd)
        }

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.isNotEmpty())
        assertTrue(alerts.any { it.message.contains("missing/stale item rejected") })
    }
}
