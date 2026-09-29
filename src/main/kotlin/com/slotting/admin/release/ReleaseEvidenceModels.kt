package com.slotting.admin.release

import java.time.Instant
import java.util.UUID

enum class Environment {
    DEVELOPMENT,
    TEST,
    STAGING,
    CANARY,
    PRODUCTION,
}

enum class PromotionStage {
    BUILT,
    BUILD_VERIFIED,
    SIGNED,
    STAGING_APPROVED,
    STAGING_DEPLOYED,
    STAGING_VERIFIED,
    CANARY,
    CANARY_HEALTHY,
    PRODUCTION_APPROVED,
    PRODUCTION_DEPLOYED,
    PRODUCTION_VERIFIED,
    UNHEALTHY,
    ROLLBACK_PENDING,
    ROLLED_BACK,
    FAILED,
}

enum class ReleaseRole {
    OPERATOR,
    COMPLIANCE,
    SECURITY,
    AUDITOR,
}

data class CommitEvidence(
    val commitSha: String,
    val repository: String,
    val isClean: Boolean,
)

data class ArtifactEvidence(
    val digest: String,
    val artifactName: String,
    val sizeBytes: Long,
)

data class SbomEvidence(
    val digest: String,
    val format: String, // e.g. "CycloneDX-JSON"
    val componentCount: Int,
)

data class MigrationEvidenceReceipt(
    val migrationRange: String,
    val allVerified: Boolean,
    val testedAgainstEphemeralPostgres: Boolean,
)

data class RestoreDrillEvidenceReceipt(
    val drillId: UUID,
    val issuerSubsystem: String, // Must match "AUTHORITATIVE_BACKUP_RECOVERY_ENGINE"
    val executedAt: Instant,
    val ledgerReconciled: Boolean,
    val receiptSignature: String,
)

data class ApprovalEvidence(
    val approvalId: UUID,
    val approverId: String,
    val role: ReleaseRole,
    val artifactDigest: String,
    val approvedAt: Instant,
)

data class ReleaseSignature(
    val keyAlias: String,
    val signatureValue: String,
    val algorithm: String = "RSA-SHA256",
)

data class ReleaseEvidenceManifest(
    val releaseId: UUID,
    val commit: CommitEvidence,
    val artifact: ArtifactEvidence,
    val sbom: SbomEvidence,
    val migration: MigrationEvidenceReceipt,
    val restoreDrill: RestoreDrillEvidenceReceipt?,
    val signature: ReleaseSignature,
    val createdAt: Instant,
) {
    /**
     * Immutable string payload representation that is signed.
     */
    fun toSigningPayload(): String {
        return "${artifact.digest}:${sbom.digest}:${commit.repository}:${commit.commitSha}"
    }
}
