package com.slotting.admin.fraud

import com.slotting.admin.auth.*
import com.slotting.admin.restriction.DurableServerRestrictionStore
import com.slotting.admin.restriction.RestrictionScope
import com.slotting.admin.restriction.RestrictionSource
import com.slotting.admin.restriction.ServerRestrictionRecord
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

class FraudCaseService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val caseStore: FraudCaseStore,
    private val restrictionStore: DurableServerRestrictionStore,
    private val clock: Clock = Clock.systemUTC(),
    private val claimLeaseDuration: Duration = Duration.ofMinutes(15),
    private val requireDualControlForCritical: Boolean = true,
) {

    @Synchronized
    fun openOrMergeCase(command: OpenOrMergeCaseCommand): FraudCaseRecord {
        val now = clock.instant()

        val existingActive = caseStore.findActiveCaseForSubject(command.tenantId, command.subjectReference)
        if (existingActive != null) {
            // Case merge policy:
            // 1. If duplicate signal (decisionReference already attached), return existing case
            if (command.decisionReference in existingActive.riskDecisionReferences) {
                return existingActive
            }

            // 2. Otherwise attach new decision reference and reasons, escalate severity if higher
            val updatedDecisions = (existingActive.riskDecisionReferences + command.decisionReference).distinct()
            val updatedReasons = (existingActive.detectedReasons + command.detectedReasons).distinct()
            val maxSeverity = maxOf(existingActive.severity, command.severity)

            val restrictionId = existingActive.restrictionId ?: if (command.requiresRestriction) {
                val newRestId = UUID.randomUUID()
                val record = ServerRestrictionRecord(
                    restrictionId = newRestId,
                    tenantId = command.tenantId,
                    subjectReference = command.subjectReference,
                    source = RestrictionSource.FRAUD_SECURITY,
                    reasonCode = updatedReasons.firstOrNull() ?: "FRAUD_SUSPECTED",
                    safeUserMessage = "Account security review in progress.",
                    scope = RestrictionScope.WholeAccount,
                    effectiveFrom = now,
                    expiresAt = command.restrictionDuration?.let { now.plus(it) },
                    evidenceReference = "FRAUD-REST-$newRestId",
                    ruleVersion = 1L,
                    issuer = "FRAUD_CASE_SUBSYSTEM",
                    active = true,
                )
                restrictionStore.saveRestriction(record)
                newRestId
            } else {
                null
            }

            val mergedCase = existingActive.copy(
                severity = maxSeverity,
                riskDecisionReferences = updatedDecisions,
                detectedReasons = updatedReasons,
                restrictionId = restrictionId,
                updatedAt = now,
            )

            caseStore.updateCaseWithCas(mergedCase, existingActive.serverVersion)
            return caseStore.findCaseByReference(command.tenantId, existingActive.caseReference) ?: mergedCase
        }

        // No active case: create new open case
        val restrictionId = if (command.requiresRestriction) {
            val newRestId = UUID.randomUUID()
            val record = ServerRestrictionRecord(
                restrictionId = newRestId,
                tenantId = command.tenantId,
                subjectReference = command.subjectReference,
                source = RestrictionSource.FRAUD_SECURITY,
                reasonCode = command.detectedReasons.firstOrNull() ?: "FRAUD_SUSPECTED",
                safeUserMessage = "Account security review in progress.",
                scope = RestrictionScope.WholeAccount,
                effectiveFrom = now,
                expiresAt = command.restrictionDuration?.let { now.plus(it) },
                evidenceReference = "FRAUD-REST-$newRestId",
                ruleVersion = 1L,
                issuer = "FRAUD_CASE_SUBSYSTEM",
                active = true,
            )
            restrictionStore.saveRestriction(record)
            newRestId
        } else {
            null
        }

        val caseRef = "FRAUD-CASE-${command.tenantId}-${command.subjectReference}-${UUID.randomUUID().toString().take(8)}"
        val newCase = FraudCaseRecord(
            caseId = UUID.randomUUID(),
            tenantId = command.tenantId,
            subjectReference = command.subjectReference,
            caseReference = caseRef,
            state = FraudCaseState.OPEN,
            severity = command.severity,
            riskDecisionReferences = listOf(command.decisionReference),
            detectedReasons = command.detectedReasons,
            restrictionId = restrictionId,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )

        caseStore.saveCase(newCase)
        return newCase
    }

    @Synchronized
    fun operateCase(command: OperateFraudCaseCommand): FraudCaseRecord {
        val now = clock.instant()

        // 1. Principal & Tenant checks
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Permission check: FRAUD_CASE_MANAGE required
        if (!policy.isPermitted(principal, AdminPermission.FRAUD_CASE_MANAGE)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Session & Current MFA check
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(now)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!session.mfaVerified || (session.mfaExpiresAt != null && session.mfaExpiresAt.isBefore(now))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 4. Case lookup
        val caseRecord = caseStore.findCaseByReference(command.tenantId, command.caseReference)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // 5. Version check
        if (caseRecord.serverVersion != command.expectedVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 6. Idempotency check
        caseStore.findActionByIdempotency(command.tenantId, command.idempotencyKey)?.let {
            return caseRecord
        }

        // 7. Transition logic
        val (nextState, claimedBy, claimExpiresAt, dispositionReason, disposedBy, disposedAt, secondApproverId) =
            when (command.action) {
                FraudCaseAction.CLAIM -> {
                    val canClaim = caseRecord.state in setOf(
                        FraudCaseState.OPEN,
                        FraudCaseState.EVIDENCE_REQUESTED,
                        FraudCaseState.ESCALATED,
                    ) || (caseRecord.state == FraudCaseState.CLAIMED && caseRecord.claimExpiresAt?.isBefore(now) == true)

                    if (!canClaim) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                    }

                    Septuple(
                        FraudCaseState.CLAIMED,
                        principal.id,
                        now.plus(claimLeaseDuration),
                        caseRecord.dispositionReason,
                        caseRecord.disposedBy,
                        caseRecord.disposedAt,
                        caseRecord.secondApproverId,
                    )
                }

                FraudCaseAction.RELEASE -> {
                    if (caseRecord.state != FraudCaseState.CLAIMED || caseRecord.claimedBy != principal.id) {
                        throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                    }
                    Septuple(
                        FraudCaseState.OPEN,
                        null,
                        null,
                        caseRecord.dispositionReason,
                        caseRecord.disposedBy,
                        caseRecord.disposedAt,
                        caseRecord.secondApproverId,
                    )
                }

                FraudCaseAction.REQUEST_EVIDENCE -> {
                    Septuple(
                        FraudCaseState.EVIDENCE_REQUESTED,
                        principal.id,
                        now.plus(claimLeaseDuration),
                        caseRecord.dispositionReason,
                        caseRecord.disposedBy,
                        caseRecord.disposedAt,
                        caseRecord.secondApproverId,
                    )
                }

                FraudCaseAction.ESCALATE -> {
                    Septuple(
                        FraudCaseState.ESCALATED,
                        null,
                        null,
                        caseRecord.dispositionReason,
                        caseRecord.disposedBy,
                        caseRecord.disposedAt,
                        caseRecord.secondApproverId,
                    )
                }

                FraudCaseAction.CONFIRM_RESTRICTION -> {
                    if (requireDualControlForCritical && caseRecord.severity == FraudCaseSeverity.CRITICAL) {
                        validateDualControl(principal, command)
                    }
                    Septuple(
                        FraudCaseState.DISPOSED_RESTRICTED,
                        null,
                        null,
                        command.reason ?: "CONFIRMED_FRAUD_RESTRICTION",
                        principal.id,
                        now,
                        command.secondApproverId,
                    )
                }

                FraudCaseAction.DISPOSE_CLEAR -> {
                    if (requireDualControlForCritical && caseRecord.severity == FraudCaseSeverity.CRITICAL) {
                        validateDualControl(principal, command)
                    }

                    // Audited disposition: lift the active fraud restriction
                    if (caseRecord.restrictionId != null) {
                        restrictionStore.revokeRestriction(
                            tenantId = command.tenantId,
                            restrictionId = caseRecord.restrictionId,
                            revokedBy = principal.id,
                            now = now,
                        )
                    }

                    Septuple(
                        FraudCaseState.DISPOSED_CLEARED,
                        null,
                        null,
                        command.reason ?: "CLEARED_FALSE_POSITIVE",
                        principal.id,
                        now,
                        command.secondApproverId,
                    )
                }
            }

        val updatedNotes = if (!command.note.isNullOrBlank()) {
            caseRecord.adminNotes + FraudCaseNote(
                adminId = principal.id,
                content = command.note,
                timestamp = now,
            )
        } else {
            caseRecord.adminNotes
        }

        val updatedCase = caseRecord.copy(
            state = nextState,
            claimedBy = claimedBy,
            claimExpiresAt = claimExpiresAt,
            dispositionReason = dispositionReason,
            disposedBy = disposedBy,
            disposedAt = disposedAt,
            secondApproverId = secondApproverId,
            adminNotes = updatedNotes,
            updatedAt = now,
        )

        val casSuccess = caseStore.updateCaseWithCas(updatedCase, command.expectedVersion)
        if (!casSuccess) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val actionRecord = FraudCaseActionRecord(
            caseId = caseRecord.caseId,
            tenantId = command.tenantId,
            caseReference = command.caseReference,
            action = command.action,
            actorId = principal.id,
            secondApproverId = command.secondApproverId,
            fromState = caseRecord.state,
            toState = nextState,
            reason = command.reason,
            occurredAt = now,
            idempotencyKey = command.idempotencyKey,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        caseStore.recordAction(actionRecord)

        return caseStore.findCaseByReference(command.tenantId, command.caseReference) ?: updatedCase
    }

    private fun validateDualControl(principal: AuthenticatedPrincipal, command: OperateFraudCaseCommand) {
        if (command.dualControlReceipt != null && command.dualControlReceipt.status == DualControlStatus.APPROVED) {
            return
        }
        val second = command.secondApproverId
        if (second.isNullOrBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        // Self-approval strictly forbidden
        if (second == principal.id) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    private data class Septuple<A, B, C, D, E, F, G>(
        val first: A, val second: B, val third: C, val fourth: D, val fifth: E, val sixth: F, val seventh: G
    )
}
