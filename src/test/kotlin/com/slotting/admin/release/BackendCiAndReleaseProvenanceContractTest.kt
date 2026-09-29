package com.slotting.admin.release

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*

/**
 * TC-041: Backend CI, artifact provenance, staged migration/deployment,
 * and rollback gates contract test.
 */
class BackendCiAndReleaseProvenanceContractTest {

    private val fixedNow = Instant.parse("2026-09-27T08:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    // =========================================================================
    // 1. CI WORKFLOW & DYNAMIC MIGRATION RANGE DISCOVERY
    // =========================================================================

    @Test
    fun `TC041-01 CI workflow dynamically discovers current migration ceiling without hardcoding V37`() {
        val discoverer = DynamicFlywayMigrationRangeDiscoverer()
        val range = discoverer.discoverRange(File("src/main/resources/db/migration"))

        assertTrue(range.minVersion >= 1, "Min migration version should be at least V1")
        assertTrue(range.maxVersion >= 37, "Max migration version should dynamically detect at least V37")
        assertEquals(range.sqlFilesCount, range.expectedVersions.size, "Every migration file must form a contiguous version sequence")
        assertFalse(range.hasGaps, "Migration chain must have no missing versions")
    }

    @Test
    fun `TC041-02 CI workflow definition file exists with required pipeline gates`() {
        val workflowFile = File(".github/workflows/backend-ci.yml")
        assertTrue(workflowFile.exists(), "GitHub CI workflow file must exist at .github/workflows/backend-ci.yml")
        val content = workflowFile.readText()
        assertTrue(content.contains("gradlew test"), "Workflow must run tests")
        assertTrue(content.contains("flyway", ignoreCase = true), "Workflow must run Flyway migration checks")
        assertTrue(content.contains("sbom", ignoreCase = true), "Workflow must generate SBOM")
        assertTrue(content.contains("sha256", ignoreCase = true), "Workflow must calculate SHA-256 digest")
        assertFalse(content.contains("password:"), "Workflow must not hardcode passwords")
    }

    // =========================================================================
    // 2. CRYPTOGRAPHIC PROVENANCE & MANIFEST VERIFICATION
    // =========================================================================

    @Test
    fun `TC041-03 valid release evidence manifest passes provenance verification`() {
        val keyPair = TestSigningAuthority.generateKeyPair()
        val trustStore = SigningTrustStore(
            trustedKeys = mapOf("bao-transit-key-1" to keyPair.publicKey),
            allowTestKeysInProduction = false,
        )
        val verifier = ProvenanceVerifier(trustStore = trustStore, clock = clock)

        val manifest = createSampleManifest(
            keyAlias = "bao-transit-key-1",
            privateKey = keyPair.privateKey,
        )

        val result = verifier.verify(manifest, targetEnvironment = Environment.STAGING)
        assertTrue(result.isValid, "Valid signed manifest must pass verification: ${result.reasons}")
    }

    @Test
    fun `TC041-04 provenance verification fails closed when artifact digest is tampered`() {
        val keyPair = TestSigningAuthority.generateKeyPair()
        val trustStore = SigningTrustStore(
            trustedKeys = mapOf("bao-transit-key-1" to keyPair.publicKey),
            allowTestKeysInProduction = false,
        )
        val verifier = ProvenanceVerifier(trustStore = trustStore, clock = clock)

        val manifest = createSampleManifest(
            keyAlias = "bao-transit-key-1",
            privateKey = keyPair.privateKey,
        ).copy(
            artifact = ArtifactEvidence(
                digest = "sha256:tampered000000000000000000000000000000000000000000000000000000000",
                artifactName = "slotting_admin.jar",
                sizeBytes = 45_000_000L,
            )
        )

        val result = verifier.verify(manifest, targetEnvironment = Environment.STAGING)
        assertFalse(result.isValid)
        assertTrue(result.reasons.any { it.contains("Signature or digest mismatch") || it.contains("tampered") })
    }

    @Test
    fun `TC041-05 provenance verification fails closed when SBOM digest is mismatched`() {
        val keyPair = TestSigningAuthority.generateKeyPair()
        val trustStore = SigningTrustStore(
            trustedKeys = mapOf("bao-transit-key-1" to keyPair.publicKey),
            allowTestKeysInProduction = false,
        )
        val verifier = ProvenanceVerifier(trustStore = trustStore, clock = clock)

        val manifest = createSampleManifest(
            keyAlias = "bao-transit-key-1",
            privateKey = keyPair.privateKey,
        ).copy(
            sbom = SbomEvidence(
                digest = "sha256:mismatched_sbom_digest_000000000000000000000000000000000000000000",
                format = "CycloneDX-JSON",
                componentCount = 142,
            )
        )

        val result = verifier.verify(manifest, targetEnvironment = Environment.STAGING)
        assertFalse(result.isValid)
        assertTrue(result.reasons.any { it.contains("Signature or digest mismatch") || it.contains("SBOM") })
    }

    @Test
    fun `TC041-06 provenance verification rejects dirty or foreign git repository`() {
        val keyPair = TestSigningAuthority.generateKeyPair()
        val trustStore = SigningTrustStore(
            trustedKeys = mapOf("bao-transit-key-1" to keyPair.publicKey),
            allowTestKeysInProduction = false,
        )
        val verifier = ProvenanceVerifier(
            trustStore = trustStore,
            expectedRepository = "slot_app/slotting_admin",
            clock = clock,
        )

        val dirtyManifest = createSampleManifest(
            keyAlias = "bao-transit-key-1",
            privateKey = keyPair.privateKey,
        ).copy(
            commit = CommitEvidence(
                commitSha = "c0ffee1234567890abcdef1234567890abcdef12",
                repository = "foreign_fork/slotting_admin",
                isClean = false,
            )
        )

        val result = verifier.verify(dirtyManifest, targetEnvironment = Environment.STAGING)
        assertFalse(result.isValid)
        assertTrue(result.reasons.any { it.contains("dirty") || it.contains("repository mismatch") })
    }

    @Test
    fun `TC041-07 production provenance verification strictly rejects test-only signing authority`() {
        val testKeyPair = TestSigningAuthority.generateKeyPair(isTestOnly = true)
        val trustStore = SigningTrustStore(
            trustedKeys = mapOf("test-dev-key" to testKeyPair.publicKey),
            testKeyAliases = setOf("test-dev-key"),
            allowTestKeysInProduction = false,
        )
        val verifier = ProvenanceVerifier(trustStore = trustStore, clock = clock)

        val manifest = createSampleManifest(
            keyAlias = "test-dev-key",
            privateKey = testKeyPair.privateKey,
        )

        // Staging allows test keys in non-prod test mode
        val stagingResult = verifier.verify(manifest, targetEnvironment = Environment.STAGING)
        assertTrue(stagingResult.isValid)

        // Production strictly rejects test keys
        val prodResult = verifier.verify(manifest, targetEnvironment = Environment.PRODUCTION)
        assertFalse(prodResult.isValid)
        assertTrue(prodResult.reasons.any { it.contains("Test signing authority prohibited in production") })
    }

    // =========================================================================
    // 3. TRUSTED ISSUER & RECEIPT INTEGRITY (NO SELF-ASSERTED RECEIPTS)
    // =========================================================================

    @Test
    fun `TC041-08 provenance verifier rejects self-asserted or untrusted restore drill receipt`() {
        val keyPair = TestSigningAuthority.generateKeyPair()
        val trustStore = SigningTrustStore(mapOf("bao-transit-key-1" to keyPair.publicKey))
        val verifier = ProvenanceVerifier(trustStore = trustStore, clock = clock)

        val fakeReceipt = RestoreDrillEvidenceReceipt(
            drillId = UUID.randomUUID(),
            issuerSubsystem = "UNTRUSTED_CALLER_DECLARATION", // Not authoritative recovery engine!
            executedAt = fixedNow.minusSeconds(3600),
            ledgerReconciled = true,
            receiptSignature = "self-signed-string",
        )

        val manifest = createSampleManifest(
            keyAlias = "bao-transit-key-1",
            privateKey = keyPair.privateKey,
            restoreDrill = fakeReceipt,
        )

        val result = verifier.verify(manifest, targetEnvironment = Environment.PRODUCTION)
        assertFalse(result.isValid)
        assertTrue(result.reasons.any { it.contains("Untrusted issuer for restore drill receipt") })
    }

    // =========================================================================
    // 4. HUMAN APPROVALS, DUAL-CONTROL, AND DIGEST BINDING
    // =========================================================================

    @Test
    fun `TC041-09 production gate requires distinct dual-control approvals bound to exact artifact digest`() {
        val gateService = StagedDeploymentGateService(clock = clock)
        val baseManifest = createSampleManifest()

        // 1. Missing approvals -> FAILS CLOSED
        val noApprovalResult = gateService.evaluateStagedPromotion(
            manifest = baseManifest,
            targetEnvironment = Environment.PRODUCTION,
            approvals = emptyList(),
        )
        assertFalse(noApprovalResult.canPromote)
        assertEquals(StagedGateDecision.REJECTED_MISSING_APPROVALS, noApprovalResult.decision)

        // 2. Single approval when dual-control required -> FAILS CLOSED
        val operatorApproval = ApprovalEvidence(
            approvalId = UUID.randomUUID(),
            approverId = "admin-operator-1",
            role = ReleaseRole.OPERATOR,
            artifactDigest = baseManifest.artifact.digest,
            approvedAt = fixedNow,
        )
        val singleApprovalResult = gateService.evaluateStagedPromotion(
            manifest = baseManifest,
            targetEnvironment = Environment.PRODUCTION,
            approvals = listOf(operatorApproval),
        )
        assertFalse(singleApprovalResult.canPromote)
        assertEquals(StagedGateDecision.REJECTED_MISSING_APPROVALS, singleApprovalResult.decision)

        // 3. Duplicate same-user approval trying to satisfy dual control -> FAILS CLOSED
        val fakeComplianceApproval = operatorApproval.copy(
            approvalId = UUID.randomUUID(),
            role = ReleaseRole.COMPLIANCE, // Same approver trying to dual-sign!
        )
        val duplicateUserResult = gateService.evaluateStagedPromotion(
            manifest = baseManifest,
            targetEnvironment = Environment.PRODUCTION,
            approvals = listOf(operatorApproval, fakeComplianceApproval),
        )
        assertFalse(duplicateUserResult.canPromote)
        assertEquals(StagedGateDecision.REJECTED_DUAL_CONTROL_VIOLATION, duplicateUserResult.decision)

        // 4. Distinct operator + compliance approvals -> PASSES
        val genuineComplianceApproval = ApprovalEvidence(
            approvalId = UUID.randomUUID(),
            approverId = "compliance-officer-2",
            role = ReleaseRole.COMPLIANCE,
            artifactDigest = baseManifest.artifact.digest,
            approvedAt = fixedNow,
        )
        val validDualApprovalResult = gateService.evaluateStagedPromotion(
            manifest = baseManifest,
            targetEnvironment = Environment.PRODUCTION,
            approvals = listOf(operatorApproval, genuineComplianceApproval),
        )
        assertTrue(validDualApprovalResult.canPromote)
        assertEquals(StagedGateDecision.PROMOTION_APPROVED, validDualApprovalResult.decision)
    }

    @Test
    fun `TC041-10 approvals become invalid if artifact digest changes`() {
        val gateService = StagedDeploymentGateService(clock = clock)
        val originalManifest = createSampleManifest()
        val newArtifactManifest = originalManifest.copy(
            artifact = ArtifactEvidence(
                digest = "sha256:new_artifact_digest_after_code_change_99999999999999999999999999",
                artifactName = "slotting_admin.jar",
                sizeBytes = 46_000_000L,
            )
        )

        val previousApprovals = listOf(
            ApprovalEvidence(
                approvalId = UUID.randomUUID(),
                approverId = "admin-operator-1",
                role = ReleaseRole.OPERATOR,
                artifactDigest = originalManifest.artifact.digest, // Old digest!
                approvedAt = fixedNow,
            ),
            ApprovalEvidence(
                approvalId = UUID.randomUUID(),
                approverId = "compliance-officer-2",
                role = ReleaseRole.COMPLIANCE,
                artifactDigest = originalManifest.artifact.digest, // Old digest!
                approvedAt = fixedNow,
            ),
        )

        val result = gateService.evaluateStagedPromotion(
            manifest = newArtifactManifest,
            targetEnvironment = Environment.PRODUCTION,
            approvals = previousApprovals,
        )
        assertFalse(result.canPromote)
        assertEquals(StagedGateDecision.REJECTED_APPROVAL_DIGEST_MISMATCH, result.decision)
    }

    // =========================================================================
    // 5. STAGED PROMOTION LIFECYCLE & CANARY HEALTH
    // =========================================================================

    @Test
    fun `TC041-11 staged promotion enforces strict state machine progression`() {
        val gateService = StagedDeploymentGateService(clock = clock)

        // Cannot skip directly from BUILT to PRODUCTION_DEPLOYED
        val invalidTransition = gateService.validateStateTransition(
            from = PromotionStage.BUILT,
            to = PromotionStage.PRODUCTION_DEPLOYED,
        )
        assertFalse(invalidTransition, "Cannot skip intermediate stages directly to production")

        // Valid staged progression
        assertTrue(gateService.validateStateTransition(PromotionStage.BUILT, PromotionStage.BUILD_VERIFIED))
        assertTrue(gateService.validateStateTransition(PromotionStage.BUILD_VERIFIED, PromotionStage.SIGNED))
        assertTrue(gateService.validateStateTransition(PromotionStage.SIGNED, PromotionStage.STAGING_APPROVED))
        assertTrue(gateService.validateStateTransition(PromotionStage.STAGING_APPROVED, PromotionStage.STAGING_DEPLOYED))
        assertTrue(gateService.validateStateTransition(PromotionStage.STAGING_DEPLOYED, PromotionStage.STAGING_VERIFIED))
        assertTrue(gateService.validateStateTransition(PromotionStage.STAGING_VERIFIED, PromotionStage.CANARY))
        assertTrue(gateService.validateStateTransition(PromotionStage.CANARY, PromotionStage.CANARY_HEALTHY))
        assertTrue(gateService.validateStateTransition(PromotionStage.CANARY_HEALTHY, PromotionStage.PRODUCTION_APPROVED))
        assertTrue(gateService.validateStateTransition(PromotionStage.PRODUCTION_APPROVED, PromotionStage.PRODUCTION_DEPLOYED))
        assertTrue(gateService.validateStateTransition(PromotionStage.PRODUCTION_DEPLOYED, PromotionStage.PRODUCTION_VERIFIED))
    }

    @Test
    fun `TC041-12 canary health evaluation marks unhealthy metrics as rollback pending`() {
        val gateService = StagedDeploymentGateService(clock = clock)

        val unhealthyMetrics = CanaryHealthMetrics(
            errorRatePercent = 4.5, // Exceeds 1.0% threshold
            latencyP99Ms = 850L,
            databaseErrorsCount = 12,
            financialReconciliationErrorsCount = 1, // CRITICAL: any reconciliation error fails canary!
        )

        val evaluation = gateService.evaluateCanaryHealth(unhealthyMetrics)
        assertFalse(evaluation.isHealthy)
        assertEquals(PromotionStage.ROLLBACK_PENDING, evaluation.suggestedNextStage)
        assertTrue(evaluation.breachReasons.any { it.contains("Financial reconciliation errors detected") })
    }

    // =========================================================================
    // 6. ROLLBACK COMPATIBILITY & FINANCIAL LEDGER IMMUTABILITY
    // =========================================================================

    @Test
    fun `TC041-13 rollback gate rejects destructive database rollback preserving ledger immutability`() {
        val rollbackGate = RollbackCompatibilityGateService()

        // Attempting to rollback by deleting ledger transactions is strictly forbidden
        val destructiveRollbackAttempt = FinancialLedgerRollbackProtection.validateRollbackMethod(
            RollbackMethod.DATABASE_SNAPSHOT_RESTORE_OVERWRITING_LEDGER
        )
        assertFalse(destructiveRollbackAttempt.isPermitted)
        assertEquals(
            "Destructive ledger rollbacks prohibited. All financial corrections must proceed via compensating double-entry journal postings.",
            destructiveRollbackAttempt.reason
        )

        // Compensating reversal is permitted
        val compensatingRollback = FinancialLedgerRollbackProtection.validateRollbackMethod(
            RollbackMethod.APPLICATION_BINARY_ROLLBACK_WITH_COMPENSATING_JOURNAL
        )
        assertTrue(compensatingRollback.isPermitted)
    }

    @Test
    fun `TC041-14 rollback gate detects backward-incompatible schema migrations and requires roll-forward`() {
        val rollbackGate = RollbackCompatibilityGateService()

        // Release introduced a destructive column drop or breaking constraint that older binary cannot read
        val incompatibleSchemaEvidence = MigrationCompatibilityEvidence(
            hasDestructiveDrop = true,
            isBackwardCompatible = false,
            supportedPreviousBinaryVersion = "0.0.9", // Current rollback target is 0.0.8 -> incompatible!
            targetRollbackBinaryVersion = "0.0.8",
        )

        val decision = rollbackGate.evaluateRollback(incompatibleSchemaEvidence)
        assertFalse(decision.isRollbackSafe)
        assertEquals(RollbackDecision.ROLLBACK_UNSAFE_FORWARD_FIX_REQUIRED, decision.decision)
    }

    // =========================================================================
    // 7. CONFIGURATION SECURITY & AUDIT LOG SANITIZATION
    // =========================================================================

    @Test
    fun `TC041-15 registry and deployment credentials are write-only and redacted from audit logs`() {
        val auditLogger = ReleaseAuditLogger()

        val config = RegistryConfiguration(
            provider = "HARBOR",
            endpoint = "https://harbor.internal.slotting.com",
            project = "slotting",
            username = "robot-ci",
            secretToken = "write-only-token-abc-12345",
        )

        val logEntry = auditLogger.formatAuditLog(
            action = "REGISTRY_CONFIGURATION_UPDATED",
            details = config.toSafeAuditDetails(),
            actor = "admin-sec-1",
        )

        assertFalse(logEntry.contains("write-only-token-abc-12345"), "Secrets must never appear in audit logs")
        assertTrue(logEntry.contains("[REDACTED]"), "Secret tokens must be explicitly redacted in audit logs")
        assertTrue(logEntry.contains("https://harbor.internal.slotting.com"))
    }

    // =========================================================================
    // HELPER FIXTURES
    // =========================================================================

    private fun createSampleManifest(
        keyAlias: String = "bao-transit-key-1",
        privateKey: String = "test-private-key",
        restoreDrill: RestoreDrillEvidenceReceipt = RestoreDrillEvidenceReceipt(
            drillId = UUID.randomUUID(),
            issuerSubsystem = "AUTHORITATIVE_BACKUP_RECOVERY_ENGINE",
            executedAt = fixedNow.minusSeconds(1800),
            ledgerReconciled = true,
            receiptSignature = "valid-drill-signature",
        ),
    ): ReleaseEvidenceManifest {
        val artifactDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val sbomDigest = "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"

        val signature = TestSigningAuthority.sign(
            data = "$artifactDigest:$sbomDigest:slot_app/slotting_admin:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
            privateKey = privateKey,
        )

        return ReleaseEvidenceManifest(
            releaseId = UUID.randomUUID(),
            commit = CommitEvidence(
                commitSha = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
                repository = "slot_app/slotting_admin",
                isClean = true,
            ),
            artifact = ArtifactEvidence(
                digest = artifactDigest,
                artifactName = "slotting_admin.jar",
                sizeBytes = 45_000_000L,
            ),
            sbom = SbomEvidence(
                digest = sbomDigest,
                format = "CycloneDX-JSON",
                componentCount = 142,
            ),
            migration = MigrationEvidenceReceipt(
                migrationRange = "V1..V37",
                allVerified = true,
                testedAgainstEphemeralPostgres = true,
            ),
            restoreDrill = restoreDrill,
            signature = ReleaseSignature(
                keyAlias = keyAlias,
                signatureValue = signature,
                algorithm = "RSA-SHA256",
            ),
            createdAt = fixedNow,
        )
    }
}
