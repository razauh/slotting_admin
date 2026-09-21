package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Authoritative service managing payout destination ownership verification,
 * name matching, closed-loop enforcement, and anti-repudiation controls.
 *
 * Implements WITHDRAW-001-02:
 * Semantic contract: "Fee/rate/expiry disclosed; ownership/limits server checked."
 * Protected risk assertion: "stale quote/unverified destination/no step-up"
 */
class PayoutDestinationService(
    private val destinationStore: PayoutDestinationStore,
    private val clock: Clock = Clock.systemUTC(),
    private val observability: PayoutDestinationObservability = InMemoryPayoutDestinationObservability()
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, PayoutDestinationResult>>()

    // =========================================================================
    // 1. Register Payout Destination
    // =========================================================================

    fun registerDestination(command: RegisterPayoutDestinationCommand): PayoutDestinationResult {
        PayoutDestinationVerificationBinding.checkBound()

        observability.recordMetric(
            PayoutDestinationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                destinationId = null,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "REGISTER", "method" to command.paymentMethod.name)
            )
        )

        // 1. Authentication & Tenant Security
        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required for payout destination registration"
        )
        if (principal.tenantId != command.tenantId) {
            observability.recordMetric(
                PayoutDestinationMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    destinationId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "CROSS_TENANT_ACCESS_DENIED")
                )
            )
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant payout destination access denied: principal ${principal.tenantId} != command ${command.tenantId}"
            )
        }

        // 2. IDOR Prevention: Only the owner (or admin) can register destinations
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.ownerId.toString()) {
            observability.recordMetric(
                PayoutDestinationMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    destinationId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "IDOR_FORBIDDEN")
                )
            )
            throw IdorWithdrawalForbiddenException(
                "stale quote/unverified destination/no step-up: cross-owner destination registration forbidden for ${principal.id}"
            )
        }

        // 3. Format and Boundary Validations
        if (command.destinationReference.isBlank()) {
            throw InvalidDestinationException(
                "stale quote/unverified destination/no step-up: destination reference must not be blank"
            )
        }
        if (command.accountHolderName.isBlank()) {
            throw InvalidDestinationException(
                "stale quote/unverified destination/no step-up: account holder name must not be blank"
            )
        }

        // Validate destination reference format based on payment method
        validateDestinationFormat(command.paymentMethod, command.destinationReference)

        // 4. Idempotency Check
        val payloadHash = hashRegisterPayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    PayoutDestinationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        destinationId = cachedResult.destination.destinationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                observability.recordMetric(
                    PayoutDestinationMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        destinationId = null,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                throw IdempotencyConflictException(
                    "stale quote/unverified destination/no step-up: payload mismatch for idempotency key ${command.idempotencyKey}"
                )
            }
        }

        // 5. Ownership & Name Matching Check
        val now = clock.instant()
        val isAutoVerified: Boolean
        val verificationEvidence: String?
        val status: DestinationVerificationStatus

        if (command.autoVerifyIfNameMatches && command.playerKycVerifiedName != null) {
            val normalizedHolder = command.accountHolderName.trim().lowercase()
            val normalizedKyc = command.playerKycVerifiedName.trim().lowercase()
            if (normalizedHolder != normalizedKyc) {
                observability.recordMetric(
                    PayoutDestinationMetricEvent(
                        eventType = "reject",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        destinationId = null,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = now,
                        details = mapOf("reason" to "NAME_MISMATCH")
                    )
                )
                throw DestinationOwnershipMismatchException(
                    "stale quote/unverified destination/no step-up: account holder name '${command.accountHolderName}' does not match KYC verified name '${command.playerKycVerifiedName}'"
                )
            }
            status = DestinationVerificationStatus.VERIFIED
            isAutoVerified = true
            verificationEvidence = "EVID-AUTO-NAME-MATCH-${UUID.randomUUID()}"
        } else {
            status = DestinationVerificationStatus.PENDING_VERIFICATION
            isAutoVerified = false
            verificationEvidence = null
        }

        val destinationId = UUID.randomUUID()
        val destinationRecord = PayoutDestinationRecord(
            destinationId = destinationId,
            tenantId = command.tenantId,
            ownerId = command.ownerId,
            paymentMethod = command.paymentMethod,
            destinationReference = command.destinationReference,
            accountHolderName = command.accountHolderName,
            verificationMethod = command.verificationMethod,
            status = status,
            registeredAt = now,
            verifiedAt = if (isAutoVerified) now else null,
            verificationEvidenceReference = verificationEvidence,
            idempotencyKey = command.idempotencyKey,
            correlationId = command.correlationId,
            causationId = command.causationId,
            version = 1L
        )

        destinationStore.save(destinationRecord)

        val eventType = if (isAutoVerified) "PAYOUT_DESTINATION_VERIFIED" else "PAYOUT_DESTINATION_REGISTERED"
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = destinationId,
            tenantId = command.tenantId,
            type = eventType,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = destinationId,
            tenantId = command.tenantId,
            type = eventType,
            createdAt = now
        )

        val result = PayoutDestinationResult(
            resultId = UUID.randomUUID(),
            destination = destinationRecord,
            isVerified = isAutoVerified,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = verificationEvidence ?: "EVID-DEST-REG-$destinationId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent,
            hasAndroidDbImpact = false,
            hasAndroidLifecycleClaim = false
        )

        idempotencyStore[command.idempotencyKey] = payloadHash to result

        observability.recordMetric(
            PayoutDestinationMetricEvent(
                eventType = "accept",
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                destinationId = destinationId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = now,
                details = mapOf("status" to status.name, "isVerified" to isAutoVerified)
            )
        )

        return result
    }

    // =========================================================================
    // 2. Verify Payout Destination (Step-Up / Micro-deposit / Open Banking)
    // =========================================================================

    fun verifyDestination(command: VerifyPayoutDestinationCommand): PayoutDestinationResult {
        PayoutDestinationVerificationBinding.checkBound()

        observability.recordMetric(
            PayoutDestinationMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                ownerId = null,
                destinationId = command.destinationId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "VERIFY")
            )
        )

        // 1. Authentication
        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required for payout destination verification"
        )
        if (principal.tenantId != command.tenantId) {
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant payout destination verification denied: principal ${principal.tenantId} != command ${command.tenantId}"
            )
        }

        // 2. Retrieve Existing Destination
        val destination = destinationStore.findById(command.destinationId)
            ?: throw DestinationNotFoundException(
                "stale quote/unverified destination/no step-up: destination not found for id ${command.destinationId}"
            )

        if (destination.tenantId != command.tenantId) {
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant destination access denied: record ${destination.tenantId} != command ${command.tenantId}"
            )
        }

        // 3. IDOR Prevention
        if (principal.kind == PrincipalKind.PLAYER && principal.id != destination.ownerId.toString()) {
            throw IdorWithdrawalForbiddenException(
                "stale quote/unverified destination/no step-up: cross-owner destination verification forbidden for ${principal.id}"
            )
        }

        // 4. Idempotency Check
        val payloadHash = hashVerifyPayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    PayoutDestinationMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = destination.ownerId,
                        destinationId = command.destinationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                observability.recordMetric(
                    PayoutDestinationMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        ownerId = destination.ownerId,
                        destinationId = command.destinationId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                throw IdempotencyConflictException(
                    "stale quote/unverified destination/no step-up: payload mismatch for idempotency key ${command.idempotencyKey}"
                )
            }
        }

        // 5. Proof Verification & Name Match
        if (command.proofReference.isBlank()) {
            throw InvalidDestinationException(
                "stale quote/unverified destination/no step-up: verification proof required"
            )
        }

        val normalizedHolder = destination.accountHolderName.trim().lowercase()
        val normalizedKyc = command.ownerKycFullName.trim().lowercase()
        if (normalizedHolder != normalizedKyc) {
            val rejectedRecord = destination.copy(
                status = DestinationVerificationStatus.REJECTED,
                rejectionReason = "Name mismatch: holder '${destination.accountHolderName}' != KYC '${command.ownerKycFullName}'",
                version = destination.version + 1
            )
            destinationStore.save(rejectedRecord)

            observability.recordMetric(
                PayoutDestinationMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = destination.ownerId,
                    destinationId = destination.destinationId,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "NAME_MISMATCH")
                )
            )

            throw DestinationOwnershipMismatchException(
                "stale quote/unverified destination/no step-up: destination account holder '${destination.accountHolderName}' does not match KYC owner name '${command.ownerKycFullName}'"
            )
        }

        // 6. Transition to VERIFIED
        val now = clock.instant()
        val updatedRecord = destination.copy(
            status = DestinationVerificationStatus.VERIFIED,
            verifiedAt = now,
            verificationEvidenceReference = command.proofReference,
            version = destination.version + 1
        )
        destinationStore.save(updatedRecord)

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = destination.destinationId,
            tenantId = command.tenantId,
            type = "PAYOUT_DESTINATION_VERIFIED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = destination.destinationId,
            tenantId = command.tenantId,
            type = "PAYOUT_DESTINATION_VERIFIED",
            createdAt = now
        )

        val result = PayoutDestinationResult(
            resultId = UUID.randomUUID(),
            destination = updatedRecord,
            isVerified = true,
            serverTime = now,
            serverVersion = updatedRecord.version,
            evidenceReference = command.proofReference,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent,
            hasAndroidDbImpact = false,
            hasAndroidLifecycleClaim = false
        )

        idempotencyStore[command.idempotencyKey] = payloadHash to result

        observability.recordMetric(
            PayoutDestinationMetricEvent(
                eventType = "accept",
                tenantId = command.tenantId,
                ownerId = destination.ownerId,
                destinationId = destination.destinationId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = now,
                details = mapOf("status" to DestinationVerificationStatus.VERIFIED.name, "isVerified" to true)
            )
        )

        return result
    }

    // =========================================================================
    // 3. Authoritative Destination Ownership Query (Fail-Closed)
    // =========================================================================

    fun checkDestinationOwnership(query: CheckDestinationOwnershipQuery): PayoutDestinationRecord {
        PayoutDestinationVerificationBinding.checkBound()

        val principal = query.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required to check destination ownership"
        )
        if (principal.tenantId != query.tenantId) {
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant check destination ownership denied: principal ${principal.tenantId} != query ${query.tenantId}"
            )
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != query.ownerId.toString()) {
            throw IdorWithdrawalForbiddenException(
                "stale quote/unverified destination/no step-up: cross-owner destination check forbidden for ${principal.id}"
            )
        }

        val destination = destinationStore.findByOwnerAndReference(
            tenantId = query.tenantId,
            ownerId = query.ownerId,
            destinationReference = query.destinationReference
        ) ?: throw DestinationNotFoundException(
            "stale quote/unverified destination/no step-up: destination ${query.destinationReference} not found for owner ${query.ownerId}"
        )

        if (destination.status != DestinationVerificationStatus.VERIFIED) {
            throw UnverifiedDestinationException(
                "stale quote/unverified destination/no step-up: destination ${query.destinationReference} is not verified (status: ${destination.status})"
            )
        }

        return destination
    }

    // =========================================================================
    // 4. Revoke Destination (Lifecycle / Disable)
    // =========================================================================

    fun revokeDestination(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        destinationId: UUID,
        reason: String,
        correlationId: String,
        causationId: String
    ): PayoutDestinationRecord {
        PayoutDestinationVerificationBinding.checkBound()

        val p = principal ?: throw UnauthorizedWithdrawalAccessException("Authentication required")
        if (p.tenantId != tenantId) throw CrossTenantWithdrawalAccessException("Cross-tenant access denied")

        val destination = destinationStore.findById(destinationId)
            ?: throw DestinationNotFoundException("Destination not found: $destinationId")

        if (destination.tenantId != tenantId) throw CrossTenantWithdrawalAccessException("Cross-tenant access denied")
        if (p.kind == PrincipalKind.PLAYER && p.id != destination.ownerId.toString()) {
            throw IdorWithdrawalForbiddenException("Cross-owner destination revocation forbidden")
        }

        val updated = destination.copy(
            status = DestinationVerificationStatus.REVOKED,
            rejectionReason = reason,
            version = destination.version + 1
        )
        destinationStore.save(updated)
        return updated
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun validateDestinationFormat(method: WithdrawalPaymentMethod, reference: String) {
        when (method) {
            WithdrawalPaymentMethod.SEPA_INSTANT, WithdrawalPaymentMethod.BANK_TRANSFER -> {
                // Must look like an IBAN: at least 15 chars, alphanumeric
                val clean = reference.replace("\\s".toRegex(), "")
                if (clean.length < 15 || !clean.matches("^[A-Z]{2}[0-9A-Z]{13,}$".toRegex(RegexOption.IGNORE_CASE))) {
                    throw InvalidDestinationException(
                        "stale quote/unverified destination/no step-up: invalid IBAN format for $reference"
                    )
                }
            }
            WithdrawalPaymentMethod.CRYPTO_USDT -> {
                // Tron or Ethereum address: at least 26 chars
                val clean = reference.trim()
                if (clean.length < 26 || clean.contains(" ")) {
                    throw InvalidDestinationException(
                        "stale quote/unverified destination/no step-up: invalid crypto wallet address format for $reference"
                    )
                }
            }
            WithdrawalPaymentMethod.CARD_OCT -> {
                // Masked or tokenized card PAN: e.g. 411111******1111 (16 chars minimum)
                val clean = reference.replace("\\s".toRegex(), "")
                if (clean.length < 16) {
                    throw InvalidDestinationException(
                        "stale quote/unverified destination/no step-up: invalid card token reference for $reference"
                    )
                }
            }
        }
    }

    private fun hashRegisterPayload(command: RegisterPayoutDestinationCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.ownerId}:${command.paymentMethod}:${command.destinationReference}:${command.accountHolderName}:${command.verificationMethod}:${command.playerKycVerifiedName}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun hashVerifyPayload(command: VerifyPayoutDestinationCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.destinationId}:${command.ownerKycFullName}:${command.proofReference}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
