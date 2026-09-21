package com.slotting.admin.validation.release

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Authoritative service implementing SYS-007: Connected release CI/artifact.
 *
 * Core invariant:
 * - Outcome contract: "P0/P1 suites unskippable; signer/KMS audit; reproducible artifact comparison."
 * - Protected risk: "pipeline accepts missing evidence"
 * - Multi-tenant, authenticated release gating ensuring unskippable test suites, dual-custody KMS signing,
 *   and bit-for-bit reproducible artifacts before production artifact release.
 * - Enforces zero Android lifecycle surface (hasAndroidLifecycleClaim = false, hasAndroidDbImpact = false).
 */
class ConnectedReleaseCiArtifactService(
    private val evidenceStore: ReleasePipelineEvidenceStore = InMemoryReleasePipelineEvidenceStore(),
    private val alertSink: ReleasePipelineAlertSink = InMemoryReleasePipelineAlertSink(),
    private val observability: ReleasePipelineObservability = InMemoryReleasePipelineObservability(),
    private val clock: Clock = Clock.systemUTC(),
    var scenarioFaults: MutableMap<String, String> = ConcurrentHashMap()
) {

    private val allowedRoles = setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY)
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, ReleasePipelineReport>>()
    private val pipelineLocks = ConcurrentHashMap<String, Any>()

    private fun validateReleasePrincipal(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        if (principal == null) {
            throw UnauthorizedReleasePipelineException("Unauthenticated: principal is null")
        }
        if (principal.kind != PrincipalKind.ADMIN) {
            throw UnauthorizedReleasePipelineException("Principal ${principal.id} is not an ADMIN")
        }
        if (principal.tenantId != tenantId) {
            throw UnauthorizedReleasePipelineException("Cross-tenant release pipeline operation forbidden: ${principal.tenantId} != $tenantId")
        }
        if (principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedReleasePipelineException("Principal ${principal.id} lacks SUPER_ADMIN or SECURITY role for release certification")
        }
        return principal
    }

    private fun computePayloadDigest(cmd: RunReleasePipelineCommand): String {
        val suitesStr = cmd.suiteRecords.entries.sortedBy { it.key.name }
            .joinToString(",") { "${it.key.name}:${it.value.status}:${it.value.evidenceDigest}" }
        val kmsStr = "${cmd.kmsSignerRecord.kmsKeyArn}:${cmd.kmsSignerRecord.cloudTrailAuditId}"
        val reproStr = "${cmd.reproducibleRecord.candidateDigest}:${cmd.reproducibleRecord.referenceDigest}"
        val payload = "${cmd.tenantId}:$suitesStr:$kmsStr:$reproStr:${cmd.manifest.commitHash}"
        val bytes = MessageDigest.getInstance("SHA-256").digest(payload.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun runReleasePipelineValidation(cmd: RunReleasePipelineCommand): ReleasePipelineReport {
        ConnectedReleaseCiArtifactBinding.checkBound()

        val principal = validateReleasePrincipal(cmd.principal, cmd.tenantId)
        val now = clock.instant()
        val startTime = System.currentTimeMillis()

        // 1. Input validation
        if (cmd.tenantId.isBlank()) throw InvalidReleasePipelineInputException("tenantId must not be blank")
        if (cmd.idempotencyKey.isBlank()) throw InvalidReleasePipelineInputException("idempotencyKey must not be blank")
        if (cmd.correlationId.isBlank()) throw InvalidReleasePipelineInputException("correlationId must not be blank")
        if (cmd.causationId.isBlank()) throw InvalidReleasePipelineInputException("causationId must not be blank")
        if (cmd.suiteRecords.isEmpty()) throw InvalidReleasePipelineInputException("suiteRecords must not be empty")

        // 2. Manifest validation
        if (!cmd.manifest.isValid(now)) {
            val alert = ReleasePipelineAlert(
                alertId = UUID.randomUUID(),
                tenantId = cmd.tenantId,
                releaseId = null,
                suite = null,
                message = "Release artifact manifest is invalid or expired: expiry=${cmd.manifest.expiry}, now=$now",
                occurredAt = now
            )
            alertSink.emitAlert(alert)
            throw InvalidReleaseManifestException("Release artifact manifest is invalid or expired: expiry=${cmd.manifest.expiry}")
        }

        // 3. Dependency failure check
        val depFault = scenarioFaults["DEPENDENCY_FAILURE"]
        if (depFault != null) {
            val alert = ReleasePipelineAlert(
                alertId = UUID.randomUUID(),
                tenantId = cmd.tenantId,
                releaseId = null,
                suite = null,
                message = "Dependency failure during release pipeline validation: $depFault",
                occurredAt = now
            )
            alertSink.emitAlert(alert)
            throw ReleasePipelineValidationException("Dependency failure: $depFault")
        }

        // 4. Idempotency handling
        val currentDigest = computePayloadDigest(cmd)
        val existing = idempotencyStore[cmd.idempotencyKey]
        if (existing != null) {
            if (existing.first == currentDigest) {
                return existing.second
            } else {
                throw IdempotencyConflictException("Idempotency key '${cmd.idempotencyKey}' was already used with conflicting payload")
            }
        }

        val lock = pipelineLocks.computeIfAbsent(cmd.tenantId) { Any() }
        synchronized(lock) {
            val recheck = idempotencyStore[cmd.idempotencyKey]
            if (recheck != null) {
                if (recheck.first == currentDigest) return recheck.second
                else throw IdempotencyConflictException("Idempotency key '${cmd.idempotencyKey}' was already used with conflicting payload")
            }

            val releaseId = UUID.randomUUID()
            val missingEvidenceDefects = mutableListOf<String>()

            // 5. Unskippable P0/P1 test suites verification
            val mandatorySuites = ReleaseTestSuite.values().toSet()
            for (suite in mandatorySuites) {
                val record = cmd.suiteRecords[suite]
                if (record == null) {
                    missingEvidenceDefects.add("Mandatory suite missing from execution: $suite")
                } else if (record.status == SuiteExecutionStatus.SKIPPED) {
                    missingEvidenceDefects.add("Mandatory suite was skipped (unskippable policy violated): $suite")
                } else if (record.status == SuiteExecutionStatus.FAILED) {
                    missingEvidenceDefects.add("Mandatory suite failed execution: $suite")
                } else {
                    observability.recordSuiteVerified(cmd.tenantId, suite)
                }
            }

            // 6. Signer / KMS audit verification
            val isKmsAuditValid = cmd.kmsSignerRecord.isValid()
            if (!isKmsAuditValid) {
                missingEvidenceDefects.add("KMS signer audit invalid: dual-custody or HSM verification missing")
            }

            // 7. Reproducible artifact comparison verification
            val isArtifactReproducible = cmd.reproducibleRecord.isValid()
            if (!isArtifactReproducible) {
                missingEvidenceDefects.add("Reproducible artifact comparison failed or SBOM/SCA defects detected")
            }

            val hasDefects = missingEvidenceDefects.isNotEmpty()
            val status = if (hasDefects) {
                ReleasePipelineStatus.BLOCKED_REJECTED
            } else {
                ReleasePipelineStatus.CERTIFIED_APPROVED
            }

            val failureReason = if (hasDefects) {
                "pipeline accepts missing evidence: ${missingEvidenceDefects.joinToString("; ")}"
            } else null

            val report = ReleasePipelineReport(
                releaseId = releaseId,
                tenantId = cmd.tenantId,
                semanticContract = CONNECTED_RELEASE_CI_ARTIFACT_CONTRACT,
                status = status,
                manifest = cmd.manifest,
                suiteExecutions = cmd.suiteRecords,
                kmsAudit = cmd.kmsSignerRecord,
                reproducibility = cmd.reproducibleRecord,
                isAllMandatorySuitesPassed = missingEvidenceDefects.none { it.contains("suite") },
                isKmsAuditValid = isKmsAuditValid,
                isArtifactReproducible = isArtifactReproducible,
                hasAndroidLifecycleClaim = false,
                hasAndroidDbImpact = false,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                evidenceReference = "ev-release-$releaseId",
                evaluatedAt = clock.instant(),
                failureReason = failureReason
            )

            evidenceStore.saveReport(report)
            idempotencyStore[cmd.idempotencyKey] = Pair(currentDigest, report)

            val durationMs = System.currentTimeMillis() - startTime
            observability.recordEvaluation(cmd.tenantId, report.status, durationMs)

            if (hasDefects) {
                val alert = ReleasePipelineAlert(
                    alertId = UUID.randomUUID(),
                    tenantId = cmd.tenantId,
                    releaseId = releaseId,
                    suite = null,
                    message = "Release pipeline blocked due to missing evidence: $failureReason",
                    occurredAt = clock.instant()
                )
                alertSink.emitAlert(alert)
                throw ReleasePipelineMissingEvidenceException("pipeline accepts missing evidence: $failureReason")
            }

            return report
        }
    }
}
