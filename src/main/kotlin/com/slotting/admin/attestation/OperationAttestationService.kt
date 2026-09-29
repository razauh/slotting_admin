package com.slotting.admin.attestation

import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.UUID

/**
 * Authoritative Server Engine for operation-bound attestation, replay protection, and policy evaluation.
 *
 * Enforces provider-independent security invariants:
 * - One-time cryptographically secure challenges bound to tenant, user, session, and operation
 * - Strict 5-minute TTL and single-use consumption (atomic CAS)
 * - Durable replay resistance surviving backend restarts and cache loss
 * - Session, operation, user, tenant, and package identity enforcement (resolving XREP-004)
 * - Clock skew, malformed payload, and rate abuse guardrails
 * - Production composition rejection of test-only fake verifiers
 * - Provider-independent baseline policy when no external hardware attestation provider is bound
 */
class OperationAttestationService(
    private val challengeStore: DurableOperationChallengeStore,
    private val appIdentityConfig: AttestationAppIdentityConfig = AttestationAppIdentityConfig(),
    private val verifier: OperationAttestationVerifier = ProviderIndependentAttestationVerifier(),
    private val clock: Clock = Clock.systemUTC(),
    private val isProduction: Boolean = false,
) {

    companion object {
        val CHALLENGE_TTL: Duration = Duration.ofMinutes(5)
        const val MAX_ALLOWED_CLOCK_SKEW_SECONDS = 120L
    }

    /**
     * Issues an authoritative, operation-bound, single-use challenge.
     */
    fun issueChallenge(
        tenantId: String,
        userId: String,
        sessionId: String,
        operation: ProtectedOperation,
    ): OperationChallengeRecord {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(userId.isNotBlank()) { "userId must not be blank" }
        require(sessionId.isNotBlank()) { "sessionId must not be blank" }

        val now = clock.instant()

        // Rate limit: prevent challenge flooding
        val activeCount = challengeStore.countActiveChallenges(tenantId, userId, sessionId, now)
        if (activeCount >= appIdentityConfig.maxActiveChallengesPerUserSession) {
            throw IllegalStateException("Rate limit exceeded: too many active challenges for user session (active=$activeCount, max=${appIdentityConfig.maxActiveChallengesPerUserSession})")
        }

        val rawEntropy = "$tenantId:$userId:$sessionId:${operation.name}:${UUID.randomUUID()}:$now"
        val nonceValue = sha256(rawEntropy)

        val challenge = OperationChallengeRecord(
            challengeId = UUID.randomUUID(),
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = operation,
            nonceValue = nonceValue,
            issuedAt = now,
            expiresAt = now.plus(CHALLENGE_TTL),
            consumed = false,
            createdAt = now,
        )

        val saved = challengeStore.saveChallenge(challenge)
        if (!saved) {
            throw IllegalStateException("Failed to persist challenge: duplicate nonce collision")
        }

        return challenge
    }

    /**
     * Authoritatively verifies an operation attestation payload submitted by the client.
     */
    fun verifyOperationAttestation(
        tenantId: String,
        userId: String,
        sessionId: String,
        operation: ProtectedOperation,
        payload: OperationAttestationPayload,
        operationRef: String,
        idempotencyKey: String,
        correlationId: String,
        causationId: String,
    ): AttestationVerificationResult {
        // Production guardrail: reject test-only verifiers in production
        if (isProduction && verifier is TestOnlyVerifierMarker) {
            throw IllegalStateException("Unapproved test-only attestation verifier selected in production")
        }

        val now = clock.instant()

        // 1. Idempotency check
        challengeStore.findAuditByIdempotency(tenantId, idempotencyKey)?.let { existingAudit ->
            return AttestationVerificationResult(
                verificationId = existingAudit.auditId,
                tenantId = existingAudit.tenantId,
                userId = existingAudit.userId,
                sessionId = existingAudit.sessionId,
                operation = existingAudit.operation,
                decision = existingAudit.decision,
                reason = existingAudit.reason,
                evaluatedAt = existingAudit.occurredAt,
                evidenceReference = existingAudit.evidenceReference,
                detailsRedacted = existingAudit.detailsRedacted,
            )
        }

        // 2. Malformed payload check
        if (payload.nonceValue.isBlank()) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.MALFORMED_PAYLOAD,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Nonce value is blank or missing",
            )
        }

        // 3. Challenge lookup
        val challenge = challengeStore.findChallengeByNonce(payload.nonceValue)
        if (challenge == null) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.CHALLENGE_NOT_FOUND,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Challenge not found for tenant and nonce",
            )
        }

        // 4. Tenant binding check
        if (challenge.tenantId != tenantId) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.TENANT_MISMATCH,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Challenge tenant mismatch: expected ${challenge.tenantId}, got $tenantId",
            )
        }

        // 5. User binding check
        if (challenge.userId != userId) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.USER_MISMATCH,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Challenge user mismatch: expected ${challenge.userId}, got $userId",
            )
        }

        // 6. Session binding check
        if (challenge.sessionId != sessionId) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.SESSION_MISMATCH,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Challenge session mismatch: expected ${challenge.sessionId}, got $sessionId",
            )
        }

        // 7. Operation binding check
        if (challenge.operation != operation) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.OPERATION_MISMATCH,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Challenge operation mismatch: expected ${challenge.operation}, got $operation",
            )
        }

        // 8. Expiry check
        if (challenge.expiresAt.isBefore(now)) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.CHALLENGE_EXPIRED,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Challenge expired at ${challenge.expiresAt} (now: $now)",
            )
        }

        // 9. Clock skew check
        if (payload.clientTimestamp != null) {
            val skewSeconds = Math.abs(Duration.between(payload.clientTimestamp, now).seconds)
            if (skewSeconds > MAX_ALLOWED_CLOCK_SKEW_SECONDS) {
                return recordAndReturn(
                    tenantId = tenantId,
                    userId = userId,
                    sessionId = sessionId,
                    operation = operation,
                    decision = AttestationDecision.DENY,
                    reason = AttestationFailureReason.CLOCK_SKEW_EXCESSIVE,
                    nonceValue = payload.nonceValue,
                    payload = payload,
                    now = now,
                    idempotencyKey = idempotencyKey,
                    correlationId = correlationId,
                    causationId = causationId,
                    details = "Client clock skew excessive: ${skewSeconds}s exceeds ${MAX_ALLOWED_CLOCK_SKEW_SECONDS}s",
                )
            }
        }

        // 10. Single-use consumption (atomic CAS)
        val consumed = challengeStore.consumeChallenge(tenantId, payload.nonceValue, operationRef, now)
        if (!consumed) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.CHALLENGE_ALREADY_CONSUMED,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Challenge was already consumed; replay attempt rejected",
            )
        }

        // 11. App identity check (fixes XREP-004)
        if (payload.clientReportedPackageName != null &&
            payload.clientReportedPackageName != appIdentityConfig.expectedPackageName
        ) {
            return recordAndReturn(
                tenantId = tenantId,
                userId = userId,
                sessionId = sessionId,
                operation = operation,
                decision = AttestationDecision.DENY,
                reason = AttestationFailureReason.PACKAGE_MISMATCH,
                nonceValue = payload.nonceValue,
                payload = payload,
                now = now,
                idempotencyKey = idempotencyKey,
                correlationId = correlationId,
                causationId = causationId,
                details = "Package name mismatch: expected ${appIdentityConfig.expectedPackageName}, got ${payload.clientReportedPackageName}",
            )
        }

        // 12. Signer digest check
        if (appIdentityConfig.requireSignerVerification) {
            if (payload.clientReportedSignerDigest == null ||
                !appIdentityConfig.allowedSignerDigests.contains(payload.clientReportedSignerDigest)
            ) {
                return recordAndReturn(
                    tenantId = tenantId,
                    userId = userId,
                    sessionId = sessionId,
                    operation = operation,
                    decision = AttestationDecision.DENY,
                    reason = AttestationFailureReason.SIGNER_DIGEST_MISMATCH,
                    nonceValue = payload.nonceValue,
                    payload = payload,
                    now = now,
                    idempotencyKey = idempotencyKey,
                    correlationId = correlationId,
                    causationId = causationId,
                    details = "Signer digest unapproved or mismatch",
                )
            }
        }

        // 13. External verifier evaluation (pluggable)
        val externalVerdict = verifier.verify(challenge, payload)
        val (decision, reason, details) = when (externalVerdict) {
            is ExternalAttestationVerdict.NotConfigured -> {
                // Provider-independent approved baseline
                if (appIdentityConfig.enforceExternalAttestation) {
                    Triple(AttestationDecision.DENY, AttestationFailureReason.EXTERNAL_PROVIDER_UNAVAILABLE, "External attestation is required by policy but not configured")
                } else {
                    Triple(AttestationDecision.ALLOW, AttestationFailureReason.CHALLENGE_VALID, "Challenge and session verified under provider-independent policy")
                }
            }
            is ExternalAttestationVerdict.Verified -> {
                Triple(AttestationDecision.ALLOW, AttestationFailureReason.CHALLENGE_VALID, "External attestation verified: provider=${externalVerdict.providerName} trust=${externalVerdict.trustLevel}")
            }
            is ExternalAttestationVerdict.Rejected -> {
                Triple(AttestationDecision.DENY, AttestationFailureReason.EXTERNAL_PROVIDER_FAILED, "External attestation rejected: reason=${externalVerdict.reason}")
            }
            is ExternalAttestationVerdict.Unavailable -> {
                if (appIdentityConfig.enforceExternalAttestation) {
                    Triple(AttestationDecision.DENY, AttestationFailureReason.EXTERNAL_PROVIDER_UNAVAILABLE, "External attestation unavailable: fail-closed")
                } else {
                    Triple(AttestationDecision.ALLOW, AttestationFailureReason.CHALLENGE_VALID, "External provider unavailable; falling back to provider-independent operation policy")
                }
            }
        }

        return recordAndReturn(
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = operation,
            decision = decision,
            reason = reason,
            nonceValue = payload.nonceValue,
            payload = payload,
            now = now,
            idempotencyKey = idempotencyKey,
            correlationId = correlationId,
            causationId = causationId,
            details = details,
        )
    }

    private fun recordAndReturn(
        tenantId: String,
        userId: String,
        sessionId: String,
        operation: ProtectedOperation,
        decision: AttestationDecision,
        reason: AttestationFailureReason,
        nonceValue: String,
        payload: OperationAttestationPayload,
        now: Instant,
        idempotencyKey: String,
        correlationId: String,
        causationId: String,
        details: String,
    ): AttestationVerificationResult {
        val verificationId = UUID.randomUUID()
        val evidenceReference = sha256("$tenantId:$userId:$sessionId:${operation.name}:${reason.name}:$now:$verificationId")

        // Privacy rule: NEVER include raw tokens or secret payloads in audit log
        val sanitizedDetails = details.replace(Regex("(?i)token(=|:)\\s*[^,; ]+"), "token=[REDACTED]")

        val audit = OperationAttestationAuditRecord(
            auditId = verificationId,
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = operation,
            nonceValue = nonceValue,
            decision = decision,
            reason = reason,
            appPackageName = payload.clientReportedPackageName,
            appVersionCode = payload.clientReportedVersionCode,
            clientReportedFingerprint = payload.clientReportedSignerDigest,
            occurredAt = now,
            idempotencyKey = idempotencyKey,
            correlationId = correlationId,
            causationId = causationId,
            evidenceReference = evidenceReference,
            detailsRedacted = sanitizedDetails,
        )

        challengeStore.recordAudit(audit)

        return AttestationVerificationResult(
            verificationId = verificationId,
            tenantId = tenantId,
            userId = userId,
            sessionId = sessionId,
            operation = operation,
            decision = decision,
            reason = reason,
            evaluatedAt = now,
            evidenceReference = evidenceReference,
            detailsRedacted = sanitizedDetails,
        )
    }

    private fun sha256(input: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(input.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
