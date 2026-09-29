package com.slotting.admin.privacy

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID

enum class DurationUnit {
    DAYS,
    MONTHS,
    YEARS,
}

enum class RetentionTrigger {
    RECORD_CREATED,
    ACCOUNT_CLOSED,
    CASE_CLOSED,
    INVESTIGATION_CLOSED,
    CONSENT_WITHDRAWN,
    LAST_ACTIVITY,
    MANUAL_TRIGGER,
}

enum class PostRetentionAction {
    DELETE,
    PSEUDONYMIZE,
    REDACT,
    RETAIN,
    ARCHIVE,
    REVIEW_REQUIRED,
    HOLD,
}

enum class PolicyApprovalStatus {
    DRAFT,
    PENDING_APPROVAL,
    APPROVED,
    ACTIVE,
    RETIRED,
}

data class RetentionPolicyConfig(
    val policyId: UUID = UUID.randomUUID(),
    val dataCategory: DataCategory,
    val jurisdiction: String = "GLOBAL",
    val purpose: String,
    val policyReference: String,
    val retentionDuration: Long,
    val durationUnit: DurationUnit = DurationUnit.DAYS,
    val retentionStartTrigger: RetentionTrigger = RetentionTrigger.RECORD_CREATED,
    val postRetentionAction: PostRetentionAction = PostRetentionAction.DELETE,
    val priority: Int = 100,
    val effectiveFrom: Instant = Instant.now(),
    val effectiveUntil: Instant? = null,
    val version: Long = 1L,
    val approvalStatus: PolicyApprovalStatus = PolicyApprovalStatus.DRAFT,
    val createdBy: String,
    val approvedBy: String? = null,
    val activatedBy: String? = null,
    val retiredBy: String? = null,
    val notes: String? = null,
)

data class JurisdictionConfig(
    val jurisdictionCode: String,
    val displayName: String,
    val defaultPolicyReference: String? = null,
    val active: Boolean = true,
)

data class ScopedLegalHoldRecord(
    val holdId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val holdReference: String,
    val subjectId: String,
    val matterId: String,
    val jurisdiction: String = "GLOBAL",
    val targetCategories: Set<DataCategory> = emptySet(),
    val reason: String,
    val placedBy: String,
    val placedAt: Instant = Instant.now(),
    val active: Boolean = true,
    val releasedBy: String? = null,
    val releasedAt: Instant? = null,
    val releaseJustification: String? = null,
)

enum class StoreActionStatus {
    COMPLETED,
    HELD,
    STATUTORY_OVERRIDE,
    RETRYABLE_FAILURE,
    PERMANENT_FAILURE,
    MANUAL_ACTION_REQUIRED,
    NOT_APPLICABLE,
}

enum class PrivacyOperation {
    EXPORT,
    DELETE,
    PSEUDONYMIZE,
    REDACT,
    RETAIN,
}

data class StoreActionCommand(
    val tenantId: String,
    val subjectId: String,
    val dataCategory: DataCategory,
    val requestedAction: PostRetentionAction,
    val policyReference: String,
    val correlationId: String,
    val causationId: String,
)

data class StoreActionReceipt(
    val receiptId: UUID = UUID.randomUUID(),
    val dsarId: UUID? = null,
    val storeId: String,
    val dataCategory: DataCategory,
    val requestedAction: PostRetentionAction,
    val executedAction: PostRetentionAction,
    val status: StoreActionStatus,
    val recordCount: Int,
    val details: String,
    val occurredAt: Instant = Instant.now(),
    val manualConfirmationBy: String? = null,
    val manualConfirmationNotes: String? = null,
)

data class StoreDataExportReceipt(
    val storeId: String,
    val dataCategory: DataCategory,
    val recordCount: Int,
    val dataDigestSha256: String,
    val recordsJson: String? = null,
)

interface StorePrivacyAdapter {
    val storeId: String
    val supportedCategories: Set<DataCategory>
    val supportedOperations: Set<PrivacyOperation>
    fun executeAction(command: StoreActionCommand): StoreActionReceipt
    fun queryData(tenantId: String, subjectId: String, category: DataCategory): StoreDataExportReceipt
}

enum class OverallDsarStatus {
    FULFILLED,
    COMPLETED_WITH_RETENTION,
    COMPLETED_PARTIAL,
    RESTRICTED_BY_HOLD,
    FAILED_PARTIAL,
}

data class PrivacyDsarExecutionRecord(
    val dsarId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val subjectId: String,
    val requestedAction: PostRetentionAction,
    val overallStatus: OverallDsarStatus,
    val receipts: List<StoreActionReceipt>,
    val submittedBy: String,
    val executedAt: Instant = Instant.now(),
    val completedAt: Instant? = null,
    val notes: String? = null,
)

data class ExternalPrivacyProviderConfig(
    val providerId: String,
    val providerType: String,
    val endpointUrl: String,
    val encryptedApiKey: ByteArray,
    val iv: ByteArray,
    val active: Boolean = true,
    val supportsAutomatedErasure: Boolean = true,
)
