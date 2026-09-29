package com.slotting.admin.privacy

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class ComplianceGovernanceService(
    private val rbacPolicy: AdminRbacPolicy,
    private val clock: Clock = Clock.systemUTC(),
    private val auditSink: ((AuditEvent) -> Unit)? = null,
) {
    private val policies = ConcurrentHashMap<UUID, RetentionPolicyConfig>()
    private val legalHolds = ConcurrentHashMap<UUID, ScopedLegalHoldRecord>()
    private val jurisdictions = ConcurrentHashMap<String, JurisdictionConfig>()
    private val externalProviders = ConcurrentHashMap<String, ExternalPrivacyProviderConfig>()

    // --- Retention Policy Management ---

    fun createPolicy(principal: AuthenticatedPrincipal, config: RetentionPolicyConfig): RetentionPolicyConfig {
        requirePermission(principal, AdminPermission.CREATE_PRIVACY_POLICY)
        val policy = config.copy(
            policyId = UUID.randomUUID(),
            version = 1L,
            approvalStatus = PolicyApprovalStatus.DRAFT,
            createdBy = principal.id,
            approvedBy = null,
            activatedBy = null,
            retiredBy = null,
        )
        policies[policy.policyId] = policy
        recordAudit(principal, "CREATE_PRIVACY_POLICY", "Created draft policy ${policy.policyReference} for ${policy.dataCategory}")
        return policy
    }

    fun editPolicy(
        principal: AuthenticatedPrincipal,
        policyId: UUID,
        updater: (RetentionPolicyConfig) -> RetentionPolicyConfig
    ): RetentionPolicyConfig {
        requirePermission(principal, AdminPermission.EDIT_PRIVACY_POLICY)
        val existing = policies[policyId] ?: throw IllegalArgumentException("Policy $policyId not found")
        val updated = updater(existing).copy(
            policyId = existing.policyId,
            version = existing.version + 1,
            approvalStatus = PolicyApprovalStatus.PENDING_APPROVAL,
            createdBy = principal.id, // Maker updated
            approvedBy = null,
            activatedBy = null,
        )
        policies[policyId] = updated
        recordAudit(principal, "EDIT_PRIVACY_POLICY", "Edited policy ${updated.policyReference} to version ${updated.version}")
        return updated
    }

    fun approvePolicy(principal: AuthenticatedPrincipal, policyId: UUID): RetentionPolicyConfig {
        requirePermission(principal, AdminPermission.APPROVE_PRIVACY_POLICY)
        val policy = policies[policyId] ?: throw IllegalArgumentException("Policy $policyId not found")

        // Maker-Checker enforcement: Maker cannot approve own policy!
        if (policy.createdBy == principal.id) {
            throw IllegalStateException("Maker-checker violation: Policy creator '${policy.createdBy}' cannot approve their own policy")
        }

        val approved = policy.copy(
            approvalStatus = PolicyApprovalStatus.APPROVED,
            approvedBy = principal.id,
        )
        policies[policyId] = approved
        recordAudit(principal, "APPROVE_PRIVACY_POLICY", "Approved policy ${approved.policyReference} v${approved.version}")
        return approved
    }

    fun activatePolicy(principal: AuthenticatedPrincipal, policyId: UUID): RetentionPolicyConfig {
        requirePermission(principal, AdminPermission.ACTIVATE_PRIVACY_POLICY)
        val policy = policies[policyId] ?: throw IllegalArgumentException("Policy $policyId not found")

        // Maker-Checker enforcement: Maker cannot activate own policy!
        if (policy.createdBy == principal.id) {
            throw IllegalStateException("Maker-checker violation: Policy creator '${policy.createdBy}' cannot activate their own policy")
        }

        val activated = policy.copy(
            approvalStatus = PolicyApprovalStatus.ACTIVE,
            activatedBy = principal.id,
            effectiveFrom = Instant.now(clock),
        )
        policies[policyId] = activated
        recordAudit(principal, "ACTIVATE_PRIVACY_POLICY", "Activated policy ${activated.policyReference} v${activated.version}")
        return activated
    }

    fun retirePolicy(principal: AuthenticatedPrincipal, policyId: UUID): RetentionPolicyConfig {
        requirePermission(principal, AdminPermission.RETIRE_PRIVACY_POLICY)
        val policy = policies[policyId] ?: throw IllegalArgumentException("Policy $policyId not found")
        val retired = policy.copy(
            approvalStatus = PolicyApprovalStatus.RETIRED,
            retiredBy = principal.id,
            effectiveUntil = Instant.now(clock),
        )
        policies[policyId] = retired
        recordAudit(principal, "RETIRE_PRIVACY_POLICY", "Retired policy ${retired.policyReference} v${retired.version}")
        return retired
    }

    fun listPolicies(principal: AuthenticatedPrincipal): List<RetentionPolicyConfig> {
        requirePermission(principal, AdminPermission.VIEW_PRIVACY_POLICY)
        return policies.values.toList().sortedByDescending { it.priority }
    }

    fun findActivePolicy(
        dataCategory: DataCategory,
        jurisdiction: String = "GLOBAL",
        trigger: RetentionTrigger = RetentionTrigger.RECORD_CREATED,
    ): RetentionPolicyConfig? {
        return policies.values
            .filter { it.approvalStatus == PolicyApprovalStatus.ACTIVE }
            .filter { it.dataCategory == dataCategory }
            .filter { it.jurisdiction.equals(jurisdiction, ignoreCase = true) || it.jurisdiction.equals("GLOBAL", ignoreCase = true) }
            .filter { it.retentionStartTrigger == trigger }
            .maxByOrNull { it.priority }
    }

    // --- Legal Hold Management ---

    fun placeHold(principal: AuthenticatedPrincipal, hold: ScopedLegalHoldRecord): ScopedLegalHoldRecord {
        requirePermission(principal, AdminPermission.MANAGE_LEGAL_HOLDS)
        val record = hold.copy(
            holdId = UUID.randomUUID(),
            placedBy = principal.id,
            placedAt = Instant.now(clock),
            active = true,
        )
        legalHolds[record.holdId] = record
        recordAudit(principal, "PLACE_LEGAL_HOLD", "Placed legal hold ${record.holdReference} on subject ${record.subjectId} for categories ${record.targetCategories}")
        return record
    }

    fun releaseHold(
        principal: AuthenticatedPrincipal,
        holdId: UUID,
        justification: String,
    ): ScopedLegalHoldRecord {
        requirePermission(principal, AdminPermission.RELEASE_LEGAL_HOLDS)
        val hold = legalHolds[holdId] ?: throw IllegalArgumentException("Hold $holdId not found")
        val released = hold.copy(
            active = false,
            releasedBy = principal.id,
            releasedAt = Instant.now(clock),
            releaseJustification = justification,
        )
        legalHolds[holdId] = released
        recordAudit(principal, "RELEASE_LEGAL_HOLD", "Released legal hold ${hold.holdReference}: $justification")
        return released
    }

    fun isHeld(subjectId: String, category: DataCategory): Boolean {
        return legalHolds.values.any { hold ->
            hold.active &&
                hold.subjectId == subjectId &&
                (hold.targetCategories.isEmpty() || category in hold.targetCategories)
        }
    }

    fun getActiveHolds(subjectId: String): List<ScopedLegalHoldRecord> {
        return legalHolds.values.filter { it.active && it.subjectId == subjectId }
    }

    // --- Jurisdictions & External Providers ---

    fun registerJurisdiction(principal: AuthenticatedPrincipal, config: JurisdictionConfig): JurisdictionConfig {
        requirePermission(principal, AdminPermission.MANAGE_JURISDICTIONS)
        jurisdictions[config.jurisdictionCode] = config
        recordAudit(principal, "MANAGE_JURISDICTIONS", "Registered jurisdiction ${config.jurisdictionCode}")
        return config
    }

    fun registerExternalProvider(principal: AuthenticatedPrincipal, config: ExternalPrivacyProviderConfig): ExternalPrivacyProviderConfig {
        requirePermission(principal, AdminPermission.MANAGE_EXTERNAL_PRIVACY_INTEGRATIONS)
        externalProviders[config.providerId] = config
        recordAudit(principal, "MANAGE_EXTERNAL_PRIVACY_INTEGRATIONS", "Registered external privacy provider ${config.providerId}")
        return config
    }

    fun listProviders(principal: AuthenticatedPrincipal): List<ExternalPrivacyProviderConfig> {
        requirePermission(principal, AdminPermission.MANAGE_EXTERNAL_PRIVACY_INTEGRATIONS)
        // Redact encrypted secrets when viewing
        return externalProviders.values.map {
            it.copy(encryptedApiKey = ByteArray(0), iv = ByteArray(0))
        }
    }

    private fun requirePermission(principal: AuthenticatedPrincipal, permission: AdminPermission) {
        if (!rbacPolicy.isPermitted(principal, permission)) {
            throw SecurityException("Principal ${principal.id} lacks required permission: ${permission.name}")
        }
    }

    private fun recordAudit(principal: AuthenticatedPrincipal, action: String, details: String) {
        val event = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = UUID.randomUUID(),
            tenantId = principal.tenantId,
            type = action,
            occurredAt = Instant.now(clock),
            correlationId = UUID.randomUUID().toString(),
            causationId = principal.id,
        )
        auditSink?.invoke(event)
    }
}
