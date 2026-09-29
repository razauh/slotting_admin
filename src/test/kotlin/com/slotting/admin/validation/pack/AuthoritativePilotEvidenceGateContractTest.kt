package com.slotting.admin.validation.pack

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.recovery.RestoreDrillStatus
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * TC-044: Full-Stack Authoritative Pilot Evidence Gate & External Prerequisites Contract Tests.
 *
 * Verifies BE-032 (non-simulated evidence, authoritative receipts) and AND-018 (artifact binding,
 * truthful readiness, explicit separation between technical readiness and external/regulatory approvals).
 */
class AuthoritativePilotEvidenceGateContractTest {

    private lateinit var clock: Clock
    private val fixedNow = Instant.parse("2026-09-27T10:00:00Z")

    private val tenantId = "tenant-pilot-ops"
    private val securityAdmin = AuthenticatedPrincipal(
        id = "security-admin-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
        tenantId = tenantId
    )
    private val complianceAdmin = AuthenticatedPrincipal(
        id = "compliance-admin-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
        tenantId = tenantId
    )
    private val superAdmin = AuthenticatedPrincipal(
        id = "super-admin-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
        tenantId = tenantId
    )

    private lateinit var prerequisiteRegister: ExternalPrerequisiteRegister
    private lateinit var evidenceStore: AuthoritativePilotEvidenceStore
    private lateinit var gateService: AuthoritativePilotEvidenceGateService

    private val validCandidate = CandidateArtifactDescriptor(
        backendCommitSha = "794dbc16dc6b882f3102574f241fee436e9d9987",
        backendArtifactDigest = "sha256:4a7b3c2e1f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c",
        androidConnectedAabSha256 = "sha256:d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7",
        androidGitCommitSha = "794dbc16dc6b882f3102574f241fee436e9d9987",
        androidSignerFingerprint = "SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        androidVariant = "connectedRelease",
        androidApplicationId = "com.slotting.game.connected"
    )

    private fun createValidLedgerReceipt(): LedgerReconciliationReceipt {
        return LedgerReconciliationReceipt(
            reconciledCurrencies = mapOf(
                "USD" to CurrencyBalanceSummary(
                    totalDebitsMinor = 50_000_000L,
                    totalCreditsMinor = 50_000_000L,
                    netImbalanceMinor = 0L
                ),
                "PKR" to CurrencyBalanceSummary(
                    totalDebitsMinor = 150_000_000L,
                    totalCreditsMinor = 150_000_000L,
                    netImbalanceMinor = 0L
                )
            ),
            postedEntriesImmutable = true,
            hasAmbiguousPayouts = false,
            unconfirmedWagersCount = 0,
            evaluatedAt = fixedNow.minus(1, ChronoUnit.HOURS)
        )
    }

    private fun createValidRecoveryReceipt(): AuthoritativeRecoveryReceipt {
        return AuthoritativeRecoveryReceipt(
            drillId = UUID.randomUUID(),
            issuerSubsystem = "AUTHORITATIVE_BACKUP_RECOVERY_ENGINE",
            targetEnvironment = "ISOLATED_RECOVERY_TARGET",
            artifactDigestVerified = true,
            decryptionVerified = true,
            postgresStartupVerified = true,
            flywayMigrationVerified = true,
            ledgerReconciled = true,
            rpoBreached = false,
            rtoBreached = false,
            status = RestoreDrillStatus.RESTORED_AND_RECONCILED,
            completedAt = fixedNow.minus(2, ChronoUnit.HOURS)
        )
    }

    private fun createValidProviderReadiness(): AuthoritativeProviderReadinessReceipt {
        return AuthoritativeProviderReadinessReceipt(
            providerStatuses = mapOf(
                "CASHIER_PAYMENT_GATEWAY" to ProviderHealthState.READY,
                "IDENTITY_KYC_PROVIDER" to ProviderHealthState.READY,
                "AVIATOR_CASINO_PROVIDER" to ProviderHealthState.READY,
                "WORKER_CLUSTER" to ProviderHealthState.READY
            ),
            evaluatedAt = fixedNow.minus(30, ChronoUnit.MINUTES)
        )
    }

    private fun createValidSecurityReceipt(): AuthoritativeSecurityTelemetryReceipt {
        return AuthoritativeSecurityTelemetryReceipt(
            siemDeliveryVerified = true,
            auditLogDispatchVerified = true,
            rateLimiterReady = true,
            tokenRevocationVerified = true,
            syntheticAcksDetected = false,
            evaluatedAt = fixedNow.minus(15, ChronoUnit.MINUTES)
        )
    }

    private fun createValidMobileEvidenceReceipt(): AuthoritativeMobileEvidenceReceipt {
        return AuthoritativeMobileEvidenceReceipt(
            artifactSha256 = validCandidate.androidConnectedAabSha256,
            gitCommitSha = validCandidate.androidGitCommitSha,
            buildVariant = validCandidate.androidVariant,
            minSdkVerified = 26,
            targetSdkVerified = 34,
            securityScenariosVerified = setOf(
                "DEEP_LINK_INJECTION",
                "WRONG_PIN_REJECTION",
                "KEYSTORE_INVALIDATION",
                "NOTIFICATION_PRIVACY",
                "FLAG_SECURE_SCREENSHOT_PROTECTION"
            ),
            accessibilityScenariosVerified = setOf(
                "TALKBACK_SEMANTICS",
                "LARGE_FONT_200_SCALING"
            ),
            isVerified = true,
            evaluatedAt = fixedNow.minus(1, ChronoUnit.HOURS)
        )
    }

    private fun createValidRestrictionSessionReceipt(): AuthoritativeRestrictionSessionReceipt {
        return AuthoritativeRestrictionSessionReceipt(
            banBypassAttemptBlocked = true,
            selfExclusionBypassBlocked = true,
            staleSocketGenerationFenced = true,
            reconnectActiveGenerationAuthorized = true,
            evaluatedAt = fixedNow.minus(20, ChronoUnit.MINUTES)
        )
    }

    private fun createValidTechnicalEvidencePack(): FullStackTechnicalEvidencePack {
        return FullStackTechnicalEvidencePack(
            candidate = validCandidate,
            ledgerReceipt = createValidLedgerReceipt(),
            recoveryReceipt = createValidRecoveryReceipt(),
            providerReadiness = createValidProviderReadiness(),
            securityTelemetry = createValidSecurityReceipt(),
            mobileEvidence = createValidMobileEvidenceReceipt(),
            restrictionSession = createValidRestrictionSessionReceipt()
        )
    }

    @BeforeEach
    fun setUp() {
        clock = Clock.fixed(fixedNow, ZoneOffset.UTC)
        prerequisiteRegister = InMemoryExternalPrerequisiteRegister(clock = clock)
        evidenceStore = InMemoryAuthoritativePilotEvidenceStore()
        gateService = AuthoritativePilotEvidenceGateService(
            prerequisiteRegister = prerequisiteRegister,
            evidenceStore = evidenceStore,
            clock = clock
        )
    }

    @Test
    @DisplayName("Scenario 1: Missing provider approval results in TECHNICAL_READY with externals pending")
    fun testScenario1_MissingProviderApproval_LeavesTechnicalReadyWithExternalsPending() {
        val techPack = createValidTechnicalEvidencePack()

        // Prerequisite register has GAMING_LICENSE verified, but PAYMENT_PROVIDER_APPROVAL is UNRESOLVED
        prerequisiteRegister.registerPrerequisite(
            ExternalPrerequisiteItem(
                prerequisiteId = UUID.randomUUID(),
                prerequisiteType = ExternalPrerequisiteType.GAMING_LICENSE,
                category = ExternalPrerequisiteCategory.LEGAL_LICENSING,
                name = "State Gaming Control Board Wagering License",
                applicableEnvironment = "production",
                applicableProduct = "connected",
                owner = "Chief Legal Officer",
                issuer = "State Gaming Board",
                referenceId = "LIC-GAMING-2026-09",
                status = ExternalPrerequisiteStatus.VERIFIED,
                verifiedBy = "compliance-director-1",
                verifiedAt = fixedNow.minus(5, ChronoUnit.DAYS),
                expiresAt = fixedNow.plus(300, ChronoUnit.DAYS)
            )
        )

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(
                requiredExternalTypes = setOf(
                    ExternalPrerequisiteType.GAMING_LICENSE,
                    ExternalPrerequisiteType.PAYMENT_PROVIDER_APPROVAL
                )
            ),
            correlationId = "corr-pilot-001"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_READY, report.technicalReadiness)
        assertEquals(ExternalPrerequisiteReadinessStatus.EXTERNAL_PREREQUISITES_PENDING, report.externalReadiness)
        assertEquals(PilotGateDecision.TECHNICAL_READY_EXTERNALS_PENDING, report.decision)
        assertFalse(report.isLegallyApproved)
        assertTrue(report.unresolvedExternalTypes.contains(ExternalPrerequisiteType.PAYMENT_PROVIDER_APPROVAL))
    }

    @Test
    @DisplayName("Scenario 2: Failed restore drill strictly blocks technical readiness")
    fun testScenario2_FailedRestoreDrill_BlocksTechnicalReadiness() {
        val failedRecovery = createValidRecoveryReceipt().copy(
            status = RestoreDrillStatus.RESTORE_FAILED,
            decryptionVerified = false
        )
        val techPack = createValidTechnicalEvidencePack().copy(recoveryReceipt = failedRecovery)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-002"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertEquals(PilotGateDecision.TECHNICAL_BLOCKED, report.decision)
        assertTrue(report.blockerReasons.any { it.contains("RESTORE_DRILL_FAILED") || it.contains("decryptionVerified") })
    }

    @Test
    @DisplayName("Scenario 3: Multi-currency ledger imbalance blocks technical readiness")
    fun testScenario3_LedgerImbalance_BlocksTechnicalReadiness() {
        val imbalancedLedger = createValidLedgerReceipt().copy(
            reconciledCurrencies = mapOf(
                "USD" to CurrencyBalanceSummary(10_000L, 10_000L, 0L),
                "PKR" to CurrencyBalanceSummary(50_000L, 49_000L, 1_000L) // Imbalance!
            )
        )
        val techPack = createValidTechnicalEvidencePack().copy(ledgerReceipt = imbalancedLedger)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-003"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertEquals(PilotGateDecision.TECHNICAL_BLOCKED, report.decision)
        assertTrue(report.blockerReasons.any { it.contains("PKR") && it.contains("IMBALANCE") })
    }

    @Test
    @DisplayName("Scenario 4: Posted ledger mutation detected blocks technical readiness")
    fun testScenario4_PostedLedgerMutation_BlocksTechnicalReadiness() {
        val tamperedLedger = createValidLedgerReceipt().copy(
            postedEntriesImmutable = false
        )
        val techPack = createValidTechnicalEvidencePack().copy(ledgerReceipt = tamperedLedger)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-004"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("POSTED_LEDGER_MUTATION_DETECTED") })
    }

    @Test
    @DisplayName("Scenario 5: Artifact digest or commit mismatch blocks gate")
    fun testScenario5_ArtifactDigestOrCommitMismatch_BlocksGate() {
        val mismatchedCandidate = validCandidate.copy(
            backendArtifactDigest = "sha256:corrupted-backend-hash"
        )
        val techPack = createValidTechnicalEvidencePack().copy(candidate = mismatchedCandidate)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            expectedBackendDigest = validCandidate.backendArtifactDigest,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-005"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("BACKEND_DIGEST_MISMATCH") })
    }

    @Test
    @DisplayName("Scenario 6: Android localGames artifact strictly rejected for connected pilot")
    fun testScenario6_LocalGamesArtifact_RejectedForConnectedPilot() {
        val localGamesCandidate = validCandidate.copy(
            androidVariant = "localGamesRelease",
            androidApplicationId = "com.slotting.game.local"
        )
        val techPack = createValidTechnicalEvidencePack().copy(candidate = localGamesCandidate)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-006"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("LOCAL_GAMES_ARTIFACT_PROHIBITED") })
    }

    @Test
    @DisplayName("Scenario 7: SIEM unavailable or synthetic acknowledgement blocks technical readiness")
    fun testScenario7_SiemUnavailableOrSyntheticAck_BlocksTechnicalReadiness() {
        val siemDownReceipt = createValidSecurityReceipt().copy(
            siemDeliveryVerified = false,
            syntheticAcksDetected = true
        )
        val techPack = createValidTechnicalEvidencePack().copy(securityTelemetry = siemDownReceipt)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(requireSiemReady = true),
            correlationId = "corr-pilot-007"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("SIEM_UNAVAILABLE") || it.contains("SYNTHETIC_ACK_DETECTED") })
    }

    @Test
    @DisplayName("Scenario 8: Stale KYC or ineligible account status blocks technical readiness")
    fun testScenario8_StaleKycOrIneligibleAccount_BlocksTechnicalReadiness() {
        val staleKycReadiness = createValidProviderReadiness().copy(
            providerStatuses = mapOf(
                "IDENTITY_KYC_PROVIDER" to ProviderHealthState.STALE_KYC_DETECTED,
                "CASHIER_PAYMENT_GATEWAY" to ProviderHealthState.READY
            )
        )
        val techPack = createValidTechnicalEvidencePack().copy(providerReadiness = staleKycReadiness)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-008"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("STALE_KYC") || it.contains("IDENTITY_KYC_PROVIDER") })
    }

    @Test
    @DisplayName("Scenario 9: Ambiguous payout or unconfirmed wager blocks technical readiness")
    fun testScenario9_AmbiguousPayoutOrUnconfirmedWager_BlocksTechnicalReadiness() {
        val ambiguousLedger = createValidLedgerReceipt().copy(
            hasAmbiguousPayouts = true,
            unconfirmedWagersCount = 2
        )
        val techPack = createValidTechnicalEvidencePack().copy(ledgerReceipt = ambiguousLedger)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-009"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("AMBIGUOUS_PAYOUTS_EXIST") || it.contains("UNCONFIRMED_WAGERS") })
    }

    @Test
    @DisplayName("Scenario 10: Stale socket generation or session fencing failure blocks technical readiness")
    fun testScenario10_StaleSocketGeneration_BlocksTechnicalReadiness() {
        val brokenFencing = createValidRestrictionSessionReceipt().copy(
            staleSocketGenerationFenced = false
        )
        val techPack = createValidTechnicalEvidencePack().copy(restrictionSession = brokenFencing)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-010"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("SESSION_FENCING_FAILURE") })
    }

    @Test
    @DisplayName("Scenario 11: Ban or self-exclusion bypass attempt blocks technical readiness")
    fun testScenario11_BanOrSelfExclusionBypass_BlocksTechnicalReadiness() {
        val bypassAllowed = createValidRestrictionSessionReceipt().copy(
            selfExclusionBypassBlocked = false
        )
        val techPack = createValidTechnicalEvidencePack().copy(restrictionSession = bypassAllowed)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(),
            correlationId = "corr-pilot-011"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertTrue(report.blockerReasons.any { it.contains("SELF_EXCLUSION_BYPASS_NOT_BLOCKED") })
    }

    @Test
    @DisplayName("Scenario 12: Expired external approval dynamically evaluated at gate time")
    fun testScenario12_ExpiredExternalApproval_EvaluatedAtGateTime() {
        val expiredPrereq = ExternalPrerequisiteItem(
            prerequisiteId = UUID.randomUUID(),
            prerequisiteType = ExternalPrerequisiteType.GAMING_LICENSE,
            category = ExternalPrerequisiteCategory.LEGAL_LICENSING,
            name = "State Gaming License",
            applicableEnvironment = "production",
            applicableProduct = "connected",
            owner = "Legal",
            issuer = "Gaming Authority",
            referenceId = "LIC-EXPIRED-999",
            status = ExternalPrerequisiteStatus.VERIFIED,
            verifiedBy = "admin-verifier-1",
            verifiedAt = fixedNow.minus(365, ChronoUnit.DAYS),
            expiresAt = fixedNow.minus(1, ChronoUnit.DAYS) // Expired yesterday!
        )
        prerequisiteRegister.registerPrerequisite(expiredPrereq)

        val techPack = createValidTechnicalEvidencePack()
        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(
                requiredExternalTypes = setOf(ExternalPrerequisiteType.GAMING_LICENSE)
            ),
            correlationId = "corr-pilot-012"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_READY, report.technicalReadiness)
        assertEquals(ExternalPrerequisiteReadinessStatus.EXTERNAL_PREREQUISITES_EXPIRED, report.externalReadiness)
        assertEquals(PilotGateDecision.TECHNICAL_READY_EXTERNALS_PENDING, report.decision)
        assertTrue(report.expiredExternalTypes.contains(ExternalPrerequisiteType.GAMING_LICENSE))
    }

    @Test
    @DisplayName("Scenario 13: Maker-checker strictly enforced for external prerequisites")
    fun testScenario13_MakerChecker_EnforcedForExternalPrerequisites() {
        val prereqId = UUID.randomUUID()
        prerequisiteRegister.registerPrerequisite(
            ExternalPrerequisiteItem(
                prerequisiteId = prereqId,
                prerequisiteType = ExternalPrerequisiteType.SECURITY_ASSESSMENT,
                category = ExternalPrerequisiteCategory.SECURITY_ASSESSMENT,
                name = "Third-Party Penetration Test Audit Report",
                applicableEnvironment = "production",
                applicableProduct = "connected",
                owner = "Security Lead",
                issuer = "Independent Pentest Lab Ltd",
                referenceId = "SEC-PENTEST-2026-Q3",
                status = ExternalPrerequisiteStatus.UNRESOLVED
            )
        )

        // Submitter submits evidence
        prerequisiteRegister.submitEvidence(
            prerequisiteId = prereqId,
            evidenceReference = "docs/security/pentest-report-2026.pdf",
            expiresAt = fixedNow.plus(180, ChronoUnit.DAYS),
            notes = "Clean audit zero critical/high findings",
            principal = securityAdmin
        )

        val submitted = prerequisiteRegister.getPrerequisite(prereqId)!!
        assertEquals(ExternalPrerequisiteStatus.SUBMITTED, submitted.status)
        assertEquals(securityAdmin.id, submitted.submittedBy)

        // Submitter cannot verify their own submission (Maker/Checker violation)
        val ex = assertThrows<MakerCheckerViolationException> {
            prerequisiteRegister.verifyEvidence(
                prerequisiteId = prereqId,
                verificationNotes = "Self-approval attempt",
                principal = securityAdmin
            )
        }
        assertTrue(ex.message!!.contains("cannot verify their own submission"))

        // Independent auditor verifies
        prerequisiteRegister.verifyEvidence(
            prerequisiteId = prereqId,
            verificationNotes = "Independent audit verified by compliance officer",
            principal = complianceAdmin
        )

        val verified = prerequisiteRegister.getPrerequisite(prereqId)!!
        assertEquals(ExternalPrerequisiteStatus.VERIFIED, verified.status)
        assertEquals(complianceAdmin.id, verified.verifiedBy)
    }

    @Test
    @DisplayName("Scenario 14: External approvals CANNOT override technical failures")
    fun testScenario14_ExternalApprovals_CannotOverrideTechnicalFailure() {
        // Register all external prerequisites as verified
        val requiredTypes = setOf(
            ExternalPrerequisiteType.GAMING_LICENSE,
            ExternalPrerequisiteType.PAYMENT_PROVIDER_APPROVAL,
            ExternalPrerequisiteType.KYC_PROVIDER_APPROVAL,
            ExternalPrerequisiteType.RNG_CERTIFICATION,
            ExternalPrerequisiteType.SECURITY_ASSESSMENT
        )
        for (type in requiredTypes) {
            prerequisiteRegister.registerPrerequisite(
                ExternalPrerequisiteItem(
                    prerequisiteId = UUID.randomUUID(),
                    prerequisiteType = type,
                    category = ExternalPrerequisiteCategory.LEGAL_LICENSING,
                    name = "Verified $type",
                    applicableEnvironment = "production",
                    applicableProduct = "connected",
                    owner = "Compliance",
                    issuer = "Authority",
                    referenceId = "REF-$type",
                    status = ExternalPrerequisiteStatus.VERIFIED,
                    verifiedBy = complianceAdmin.id,
                    verifiedAt = fixedNow.minus(1, ChronoUnit.DAYS),
                    expiresAt = fixedNow.plus(90, ChronoUnit.DAYS)
                )
            )
        }

        // But technical recovery drill failed!
        val failedRecovery = createValidRecoveryReceipt().copy(status = RestoreDrillStatus.RESTORE_FAILED)
        val techPack = createValidTechnicalEvidencePack().copy(recoveryReceipt = failedRecovery)

        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(requiredExternalTypes = requiredTypes),
            correlationId = "corr-pilot-014"
        )

        // Technical failure ALWAYS blocks the gate! External approvals cannot paper over technical failure.
        assertEquals(TechnicalReadinessStatus.TECHNICAL_BLOCKED, report.technicalReadiness)
        assertEquals(ExternalPrerequisiteReadinessStatus.ALL_EXTERNAL_PREREQUISITES_VERIFIED, report.externalReadiness)
        assertEquals(PilotGateDecision.TECHNICAL_BLOCKED, report.decision)
        assertFalse(report.isLegallyApproved)
        assertTrue(report.blockerReasons.any { it.contains("RESTORE_DRILL_FAILED") })
    }

    @Test
    @DisplayName("Scenario 15: All technical passed + all external verified = PILOT_PREREQUISITES_VERIFIED")
    fun testScenario15_TechnicalReadyAndExternalsVerified_YieldsPilotPrerequisitesVerified() {
        val requiredTypes = setOf(
            ExternalPrerequisiteType.GAMING_LICENSE,
            ExternalPrerequisiteType.PAYMENT_PROVIDER_APPROVAL
        )
        for (type in requiredTypes) {
            prerequisiteRegister.registerPrerequisite(
                ExternalPrerequisiteItem(
                    prerequisiteId = UUID.randomUUID(),
                    prerequisiteType = type,
                    category = ExternalPrerequisiteCategory.LEGAL_LICENSING,
                    name = "Verified $type",
                    applicableEnvironment = "production",
                    applicableProduct = "connected",
                    owner = "Compliance",
                    issuer = "Authority",
                    referenceId = "REF-$type",
                    status = ExternalPrerequisiteStatus.VERIFIED,
                    verifiedBy = complianceAdmin.id,
                    verifiedAt = fixedNow.minus(1, ChronoUnit.DAYS),
                    expiresAt = fixedNow.plus(90, ChronoUnit.DAYS)
                )
            )
        }

        val techPack = createValidTechnicalEvidencePack()
        val report = gateService.evaluatePilotReadiness(
            principal = securityAdmin,
            tenantId = tenantId,
            technicalEvidence = techPack,
            policy = PilotReadinessPolicy(requiredExternalTypes = requiredTypes),
            correlationId = "corr-pilot-015"
        )

        assertEquals(TechnicalReadinessStatus.TECHNICAL_READY, report.technicalReadiness)
        assertEquals(ExternalPrerequisiteReadinessStatus.ALL_EXTERNAL_PREREQUISITES_VERIFIED, report.externalReadiness)
        assertEquals(PilotGateDecision.PILOT_PREREQUISITES_VERIFIED, report.decision)
        // Note: technical + prerequisite verification still explicitly notes it is not final legal signoff without formal organizational signoff
        assertFalse(report.isLegallyApproved)
        assertTrue(report.summary.contains("Technical invariants verified and all mandatory external prerequisites current"))
    }
}
