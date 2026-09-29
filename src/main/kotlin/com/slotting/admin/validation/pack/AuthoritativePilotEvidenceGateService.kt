package com.slotting.admin.validation.pack

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.recovery.RestoreDrillStatus
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * Full-Stack Authoritative Pilot Evidence Gate Service (TC-044).
 *
 * Implements authoritative validation across:
 * 1. Exact candidate artifact & commit provenance
 * 2. Multi-currency ledger reconciliation (zero imbalance, immutable posted entries)
 * 3. Authoritative backup & PITR recovery drill verification
 * 4. Provider integration health (cashier, KYC, casino, workers)
 * 5. Security & SIEM telemetry readiness (zero synthetic acknowledgements)
 * 6. Mobile device, accessibility, and security scenario evidence (TC-043)
 * 7. Authoritative restriction engine & session generation fencing (TC-026)
 * 8. External prerequisite register tracking (licensing, merchant agreements, lab certs)
 *
 * Distinct dimensions:
 * - Technical readiness (code-controlled invariants)
 * - External prerequisite readiness (governance/regulatory evidence)
 * - Gate decision (never claims legal/pilot approval merely on technical pass)
 */
class AuthoritativePilotEvidenceGateService(
    private val prerequisiteRegister: ExternalPrerequisiteRegister,
    private val evidenceStore: AuthoritativePilotEvidenceStore = InMemoryAuthoritativePilotEvidenceStore(),
    private val clock: Clock = Clock.systemUTC()
) {

    private val authorizedRoles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY, AdminRole.AUDITOR)

    fun evaluatePilotReadiness(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        technicalEvidence: FullStackTechnicalEvidencePack,
        expectedBackendDigest: String? = null,
        policy: PilotReadinessPolicy = PilotReadinessPolicy(),
        correlationId: String = UUID.randomUUID().toString()
    ): AuthoritativePilotReadinessReport {
        validatePrincipal(principal, tenantId)
        val now = clock.instant()
        val blockerReasons = mutableListOf<String>()

        val candidate = technicalEvidence.candidate

        // 1. Exact Artifact & Variant Binding
        if (expectedBackendDigest != null && candidate.backendArtifactDigest != expectedBackendDigest) {
            blockerReasons.add("BACKEND_DIGEST_MISMATCH: expected $expectedBackendDigest but candidate asserted ${candidate.backendArtifactDigest}")
        }
        if (candidate.backendCommitSha.isBlank()) {
            blockerReasons.add("BACKEND_COMMIT_BLANK: commit SHA cannot be empty")
        }
        if (candidate.androidVariant.equals("localGamesRelease", ignoreCase = true) ||
            candidate.androidApplicationId.equals("com.slotting.game.local", ignoreCase = true)) {
            blockerReasons.add("LOCAL_GAMES_ARTIFACT_PROHIBITED: Connected wagering pilot requires connected variant, found ${candidate.androidVariant}")
        }
        if (!candidate.androidVariant.equals("connectedRelease", ignoreCase = true)) {
            blockerReasons.add("INVALID_ANDROID_VARIANT: expected connectedRelease, found ${candidate.androidVariant}")
        }
        if (candidate.androidConnectedAabSha256 != technicalEvidence.mobileEvidence.artifactSha256) {
            blockerReasons.add("ANDROID_AAB_DIGEST_MISMATCH: candidate AAB digest does not match mobile evidence digest")
        }

        // 2. Multi-Currency Ledger Reconciliation
        val ledger = technicalEvidence.ledgerReceipt
        if (!ledger.postedEntriesImmutable) {
            blockerReasons.add("POSTED_LEDGER_MUTATION_DETECTED: Immutable ledger journal has been tampered with or modified")
        }
        if (ledger.hasAmbiguousPayouts) {
            blockerReasons.add("AMBIGUOUS_PAYOUTS_EXIST: Unsettled ambiguous payouts must be reconciled before pilot gate")
        }
        if (ledger.unconfirmedWagersCount > 0) {
            blockerReasons.add("UNCONFIRMED_WAGERS_EXIST: Found ${ledger.unconfirmedWagersCount} unconfirmed wagers requiring backend settlement")
        }
        for ((currency, balance) in ledger.reconciledCurrencies) {
            if (balance.netImbalanceMinor != 0L) {
                blockerReasons.add("LEDGER_IMBALANCE_DETECTED: Currency $currency has net imbalance of ${balance.netImbalanceMinor} minor units (debits=${balance.totalDebitsMinor}, credits=${balance.totalCreditsMinor})")
            }
        }

        // 3. Authoritative Recovery Drill Verification
        val recovery = technicalEvidence.recoveryReceipt
        if (recovery.status != RestoreDrillStatus.RESTORED_AND_RECONCILED) {
            blockerReasons.add("RESTORE_DRILL_FAILED: Recovery drill reported status ${recovery.status}")
        }
        if (!recovery.artifactDigestVerified) {
            blockerReasons.add("RECOVERY_ARTIFACT_DIGEST_FAILED: Backup artifact digest verification failed")
        }
        if (!recovery.decryptionVerified) {
            blockerReasons.add("RECOVERY_DECRYPTION_FAILED: Backup decryption verification failed")
        }
        if (!recovery.postgresStartupVerified) {
            blockerReasons.add("POSTGRES_STARTUP_FAILED: Isolated recovery target database failed to start")
        }
        if (!recovery.flywayMigrationVerified) {
            blockerReasons.add("FLYWAY_MIGRATION_FAILED: Schema migration failed on recovery target")
        }
        if (!recovery.ledgerReconciled) {
            blockerReasons.add("RECOVERY_LEDGER_RECONCILIATION_FAILED: Ledger failed to balance on restored database")
        }
        if (recovery.rpoBreached) {
            blockerReasons.add("RPO_BREACHED: Recovery point objective breached during drill")
        }
        if (recovery.rtoBreached) {
            blockerReasons.add("RTO_BREACHED: Recovery time objective breached during drill")
        }
        val recoveryAgeDays = ChronoUnit.DAYS.between(recovery.completedAt, now)
        if (recoveryAgeDays > policy.maxRestoreAgeDays) {
            blockerReasons.add("STALE_RECOVERY_EVIDENCE: Recovery drill is $recoveryAgeDays days old (max allowed: ${policy.maxRestoreAgeDays})")
        }

        // 4. Provider Readiness
        val providers = technicalEvidence.providerReadiness.providerStatuses
        for ((providerName, state) in providers) {
            if (state == ProviderHealthState.STALE_KYC_DETECTED) {
                blockerReasons.add("STALE_KYC_DETECTED: Provider $providerName detected unverified or stale customer KYC records")
            } else if (state != ProviderHealthState.READY) {
                blockerReasons.add("PROVIDER_NOT_READY: Provider $providerName reported state $state")
            }
        }

        // 5. Security & SIEM Telemetry
        val security = technicalEvidence.securityTelemetry
        if (security.syntheticAcksDetected) {
            blockerReasons.add("SYNTHETIC_ACK_DETECTED: Synthetic/mock acknowledgements detected in security telemetry stream")
        }
        if (policy.requireSiemReady && !security.siemDeliveryVerified) {
            blockerReasons.add("SIEM_UNAVAILABLE: SIEM log aggregation delivery could not be verified")
        }
        if (!security.auditLogDispatchVerified) {
            blockerReasons.add("AUDIT_DISPATCH_FAILED: Security audit log forwarding pipeline failed")
        }
        if (!security.rateLimiterReady) {
            blockerReasons.add("RATE_LIMITER_NOT_READY: API rate limiting defense engine not ready")
        }
        if (!security.tokenRevocationVerified) {
            blockerReasons.add("TOKEN_REVOCATION_VERIFICATION_FAILED: Revoked tokens could not be verified invalidated")
        }

        // 6. Mobile Journey Evidence
        val mobile = technicalEvidence.mobileEvidence
        if (policy.requireMobileEvidence) {
            if (!mobile.isVerified) {
                blockerReasons.add("MOBILE_EVIDENCE_NOT_VERIFIED: Android connected device evidence failed verification")
            }
            if (mobile.minSdkVerified > 26) {
                blockerReasons.add("MIN_SDK_BASELINE_UNVERIFIED: Mandatory minimum SDK 26 test run was not executed")
            }
        }

        // 7. Restriction Engine & Session Fencing
        val restrictions = technicalEvidence.restrictionSession
        if (!restrictions.banBypassAttemptBlocked) {
            blockerReasons.add("BAN_BYPASS_NOT_BLOCKED: Administrative ban bypass was not prevented")
        }
        if (!restrictions.selfExclusionBypassBlocked) {
            blockerReasons.add("SELF_EXCLUSION_BYPASS_NOT_BLOCKED: Responsible gaming self-exclusion bypass attempt was not blocked")
        }
        if (!restrictions.staleSocketGenerationFenced) {
            blockerReasons.add("SESSION_FENCING_FAILURE: Stale realtime socket session retained authority after replacement")
        }
        if (!restrictions.reconnectActiveGenerationAuthorized) {
            blockerReasons.add("RECONNECT_GENERATION_FAILED: Active session reconnect could not be authorized")
        }

        // 8. External Prerequisites Evaluation
        val allPrereqs = prerequisiteRegister.getAllPrerequisites()
        val prereqsByType = allPrereqs.associateBy { it.prerequisiteType }

        val unresolvedExternalTypes = mutableListOf<ExternalPrerequisiteType>()
        val expiredExternalTypes = mutableListOf<ExternalPrerequisiteType>()
        val rejectedExternalTypes = mutableListOf<ExternalPrerequisiteType>()

        for (requiredType in policy.requiredExternalTypes) {
            val prereq = prereqsByType[requiredType]
            if (prereq == null || prereq.status == ExternalPrerequisiteStatus.UNRESOLVED || prereq.status == ExternalPrerequisiteStatus.SUBMITTED) {
                unresolvedExternalTypes.add(requiredType)
            } else if (prereq.status == ExternalPrerequisiteStatus.EXPIRED) {
                expiredExternalTypes.add(requiredType)
            } else if (prereq.status == ExternalPrerequisiteStatus.REJECTED || prereq.status == ExternalPrerequisiteStatus.REVOKED) {
                rejectedExternalTypes.add(requiredType)
            }
        }

        val technicalReadiness = if (blockerReasons.isEmpty()) {
            TechnicalReadinessStatus.TECHNICAL_READY
        } else {
            TechnicalReadinessStatus.TECHNICAL_BLOCKED
        }

        val externalReadiness = when {
            expiredExternalTypes.isNotEmpty() -> ExternalPrerequisiteReadinessStatus.EXTERNAL_PREREQUISITES_EXPIRED
            unresolvedExternalTypes.isNotEmpty() -> ExternalPrerequisiteReadinessStatus.EXTERNAL_PREREQUISITES_PENDING
            rejectedExternalTypes.isNotEmpty() -> ExternalPrerequisiteReadinessStatus.EXTERNAL_PREREQUISITES_REJECTED
            else -> ExternalPrerequisiteReadinessStatus.ALL_EXTERNAL_PREREQUISITES_VERIFIED
        }

        // Technical failure ALWAYS blocks the decision, regardless of external approvals
        val decision = when {
            technicalReadiness == TechnicalReadinessStatus.TECHNICAL_BLOCKED -> PilotGateDecision.TECHNICAL_BLOCKED
            externalReadiness == ExternalPrerequisiteReadinessStatus.ALL_EXTERNAL_PREREQUISITES_VERIFIED -> PilotGateDecision.PILOT_PREREQUISITES_VERIFIED
            else -> PilotGateDecision.TECHNICAL_READY_EXTERNALS_PENDING
        }

        val summary = when (decision) {
            PilotGateDecision.TECHNICAL_BLOCKED ->
                "Pilot technical readiness BLOCKED: ${blockerReasons.size} code-controlled invariant failures detected."
            PilotGateDecision.TECHNICAL_READY_EXTERNALS_PENDING ->
                "Technical readiness VERIFIED. External prerequisites pending: unresolved=${unresolvedExternalTypes.map { it.name }}, expired=${expiredExternalTypes.map { it.name }}. NOTE: Technical readiness does NOT constitute legal, store, or regulatory pilot authorization."
            PilotGateDecision.PILOT_PREREQUISITES_VERIFIED ->
                "Technical invariants verified and all mandatory external prerequisites current. Ready for organizational final signoff."
            PilotGateDecision.PILOT_AUTHORIZED ->
                "Pilot authorized by formal organizational leadership."
        }

        val report = AuthoritativePilotReadinessReport(
            reportId = UUID.randomUUID(),
            tenantId = tenantId,
            technicalReadiness = technicalReadiness,
            externalReadiness = externalReadiness,
            decision = decision,
            isLegallyApproved = false, // Strictly false: technical gate cannot determine legal compliance on its own
            summary = summary,
            blockerReasons = blockerReasons,
            unresolvedExternalTypes = unresolvedExternalTypes,
            expiredExternalTypes = expiredExternalTypes,
            technicalPack = technicalEvidence,
            policyVersion = policy.policyVersion,
            evaluatedAt = now,
            correlationId = correlationId
        )

        evidenceStore.saveReport(report)
        return report
    }

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String) {
        if (principal == null) {
            throw SecurityException("Unauthenticated pilot readiness evaluation request")
        }
        if (principal.kind != PrincipalKind.ADMIN) {
            throw SecurityException("Principal ${principal.id} is not an administrator")
        }
        if (principal.tenantId != tenantId) {
            throw SecurityException("Cross-tenant pilot readiness evaluation forbidden: ${principal.tenantId} != $tenantId")
        }
        if (principal.roles.none { it in authorizedRoles }) {
            throw SecurityException("Principal ${principal.id} lacks authorization for pilot gate evaluation")
        }
    }
}
