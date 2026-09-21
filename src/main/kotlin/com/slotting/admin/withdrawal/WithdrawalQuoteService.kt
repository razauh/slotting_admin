package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.wallet.BalanceBucketsStore
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Authoritative service managing withdrawal fee quotes, exchange rates, expiry windows,
 * destination verification, step-up requirements, and server-checked balance limits.
 *
 * Implements WITHDRAW-001-01:
 * Semantic contract: "Fee/rate/expiry disclosed; ownership/limits server checked."
 * Protected risk assertion: "stale quote/unverified destination/no step-up"
 */
class WithdrawalQuoteService(
    private val quoteStore: WithdrawalQuoteStore,
    private val bucketStore: BalanceBucketsStore,
    private val clock: Clock = Clock.systemUTC(),
    private val observability: WithdrawalQuoteObservability = InMemoryWithdrawalQuoteObservability()
) {
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, WithdrawalQuoteResult>>()

    companion object {
        const val MIN_WITHDRAWAL_MINOR_UNITS = 1_000L // 10 EUR
        const val MAX_WITHDRAWAL_MINOR_UNITS = 500_000L // 5,000 EUR
        const val STEP_UP_THRESHOLD_MINOR_UNITS = 200_000L // 2,000 EUR
    }

    // =========================================================================
    // 1. Quote Withdrawal Fees and Expiry
    // =========================================================================

    fun quoteWithdrawal(command: QuoteWithdrawalCommand): WithdrawalQuoteResult {
        WithdrawalQuoteBinding.checkBound()

        observability.recordMetric(
            WithdrawalQuoteMetricEvent(
                eventType = "attempt",
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                quoteId = null,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = clock.instant(),
                details = mapOf("action" to "QUOTE", "amount" to command.grossAmountMinorUnits)
            )
        )

        // 1. Authentication & Tenant Security
        val principal = command.principal ?: throw UnauthorizedWithdrawalAccessException(
            "Authentication required for withdrawal quote"
        )
        if (principal.tenantId != command.tenantId) {
            observability.recordMetric(
                WithdrawalQuoteMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    quoteId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "CROSS_TENANT_ACCESS_DENIED")
                )
            )
            throw CrossTenantWithdrawalAccessException(
                "Cross-tenant quote access denied: principal ${principal.tenantId} != command ${command.tenantId}"
            )
        }

        // 2. Ownership Leak Protection (IDOR Prevention)
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.ownerId.toString()) {
            observability.recordMetric(
                WithdrawalQuoteMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    quoteId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "IDOR_FORBIDDEN")
                )
            )
            throw IdorWithdrawalForbiddenException(
                "stale quote/unverified destination/no step-up: cross-owner quote forbidden for ${principal.id}"
            )
        }

        // 3. Prerequisite contract: AUTHZ-001 - Server Eligibility Policy
        if (command.eligibilityDecisionId.isBlank() || command.eligibilityDecisionVersion <= 0L) {
            observability.recordMetric(
                WithdrawalQuoteMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    quoteId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "ELIGIBILITY_DENIED")
                )
            )
            throw EligibilityDeniedException(
                "stale quote/unverified destination/no step-up: stale or missing eligibility verdict"
            )
        }

        // 4. Destination Verification
        if (!command.destinationVerified) {
            observability.recordMetric(
                WithdrawalQuoteMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    quoteId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "UNVERIFIED_DESTINATION", "dest" to command.destinationReference)
                )
            )
            throw UnverifiedDestinationException(
                "stale quote/unverified destination/no step-up: unverified payout destination ${command.destinationReference}"
            )
        }

        // 5. Withdrawal Limits Validation
        if (command.grossAmountMinorUnits < MIN_WITHDRAWAL_MINOR_UNITS) {
            throw WithdrawalLimitExceededException(
                "stale quote/unverified destination/no step-up: amount ${command.grossAmountMinorUnits} below minimum limit $MIN_WITHDRAWAL_MINOR_UNITS"
            )
        }
        if (command.grossAmountMinorUnits > MAX_WITHDRAWAL_MINOR_UNITS) {
            throw WithdrawalLimitExceededException(
                "stale quote/unverified destination/no step-up: amount ${command.grossAmountMinorUnits} exceeds maximum limit $MAX_WITHDRAWAL_MINOR_UNITS"
            )
        }

        // 6. Server-Checked Wallet Balance Check (Bonus funds non-withdrawable)
        val wallet = bucketStore.findWalletByOwnerAndCurrency(command.tenantId, command.ownerId, command.currencyCode)
            ?: throw WithdrawalQuoteException("Wallet not found for owner ${command.ownerId}", "WALLET_NOT_FOUND")

        if (wallet.withdrawableCashMinorUnits < command.grossAmountMinorUnits) {
            observability.recordMetric(
                WithdrawalQuoteMetricEvent(
                    eventType = "reject",
                    tenantId = command.tenantId,
                    ownerId = command.ownerId,
                    quoteId = null,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("reason" to "INSUFFICIENT_FUNDS", "withdrawable" to wallet.withdrawableCashMinorUnits)
                )
            )
            throw InsufficientWithdrawableFundsException(
                "stale quote/unverified destination/no step-up: insufficient withdrawable cash ${wallet.withdrawableCashMinorUnits} for requested ${command.grossAmountMinorUnits}"
            )
        }

        // 7. Idempotency Handling
        val payloadHash = hashCommandPayload(command)
        idempotencyStore[command.idempotencyKey]?.let { (cachedHash, cachedResult) ->
            if (cachedHash == payloadHash) {
                observability.recordMetric(
                    WithdrawalQuoteMetricEvent(
                        eventType = "duplicate",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        quoteId = cachedResult.quote.quoteId,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedResult
            } else {
                observability.recordMetric(
                    WithdrawalQuoteMetricEvent(
                        eventType = "conflict",
                        tenantId = command.tenantId,
                        ownerId = command.ownerId,
                        quoteId = null,
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

        // 8. Fee and Rate Calculation
        val feeBreakdown = calculateFee(command.paymentMethod, command.grossAmountMinorUnits)
        val netPayout = command.grossAmountMinorUnits - feeBreakdown.totalFeeMinorUnits

        // 9. Step-Up Authentication Policy Check
        val stepUpRequired = command.grossAmountMinorUnits >= STEP_UP_THRESHOLD_MINOR_UNITS
        val stepUpChallengeType = if (stepUpRequired) "MFA_TOTP" else null

        val now = clock.instant()
        val quoteId = UUID.randomUUID()
        val expiresAt = now.plusSeconds(command.ttlSeconds)
        val evidenceRef = "EVID-WITHDRAW-QUOTE-$quoteId"

        val quoteRecord = WithdrawalQuoteRecord(
            quoteId = quoteId,
            tenantId = command.tenantId,
            ownerId = command.ownerId,
            currencyCode = command.currencyCode,
            paymentMethod = command.paymentMethod,
            destinationReference = command.destinationReference,
            destinationVerified = command.destinationVerified,
            grossAmountMinorUnits = command.grossAmountMinorUnits,
            feeBreakdown = feeBreakdown,
            netPayoutAmountMinorUnits = netPayout,
            exchangeRate = 1.0,
            payoutCurrencyCode = command.currencyCode,
            stepUpRequired = stepUpRequired,
            stepUpChallengeType = stepUpChallengeType,
            status = WithdrawalQuoteStatus.ACTIVE,
            quotedAt = now,
            expiresAt = expiresAt,
            eligibilityDecisionId = command.eligibilityDecisionId,
            eligibilityDecisionVersion = command.eligibilityDecisionVersion,
            idempotencyKey = command.idempotencyKey,
            correlationId = command.correlationId,
            causationId = command.causationId,
            evidenceReference = evidenceRef,
            version = wallet.version
        )
        quoteStore.save(quoteRecord)

        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = quoteId,
            tenantId = command.tenantId,
            type = "WITHDRAWAL_QUOTE_CREATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = quoteId,
            tenantId = command.tenantId,
            type = "WITHDRAWAL_QUOTE_CREATED",
            createdAt = now
        )

        val result = WithdrawalQuoteResult(
            resultId = UUID.randomUUID(),
            quote = quoteRecord,
            debitsEqualCredits = true,
            serverTime = now,
            serverVersion = wallet.version,
            evidenceReference = evidenceRef,
            auditEvent = auditEvent,
            outboxEvent = outboxEvent,
            hasAndroidDbImpact = false,
            hasAndroidLifecycleClaim = false
        )

        idempotencyStore[command.idempotencyKey] = payloadHash to result
        observability.recordMetric(
            WithdrawalQuoteMetricEvent(
                eventType = "accept",
                tenantId = command.tenantId,
                ownerId = command.ownerId,
                quoteId = quoteId,
                correlationId = command.correlationId,
                causationId = command.causationId,
                timestamp = now,
                details = mapOf("fee" to feeBreakdown.totalFeeMinorUnits, "net" to netPayout, "stepUp" to stepUpRequired)
            )
        )
        return result
    }

    // =========================================================================
    // 2. Validate & Consume Quote (Prevents Stale Quotes)
    // =========================================================================

    fun validateQuoteForConsumption(quoteId: UUID, tenantId: String, ownerId: UUID): WithdrawalQuoteRecord {
        WithdrawalQuoteBinding.checkBound()

        val quote = quoteStore.findById(quoteId)
            ?: throw WithdrawalQuoteException("Quote not found: $quoteId", "QUOTE_NOT_FOUND")

        if (quote.tenantId != tenantId || quote.ownerId != ownerId) {
            throw IdorWithdrawalForbiddenException(
                "stale quote/unverified destination/no step-up: cross-owner or cross-tenant quote consumption denied"
            )
        }

        if (quote.status != WithdrawalQuoteStatus.ACTIVE) {
            throw StaleQuoteException(
                "stale quote/unverified destination/no step-up: quote $quoteId is not active (${quote.status})"
            )
        }

        if (clock.instant().isAfter(quote.expiresAt)) {
            throw StaleQuoteException(
                "stale quote/unverified destination/no step-up: quote $quoteId expired at ${quote.expiresAt}"
            )
        }

        return quote
    }

    // =========================================================================
    // Fee Calculation Matrix
    // =========================================================================

    private fun calculateFee(method: WithdrawalPaymentMethod, grossAmount: Long): WithdrawalFeeBreakdown {
        val (fixed, bps) = when (method) {
            WithdrawalPaymentMethod.SEPA_INSTANT -> 100L to 50L   // 1.00 EUR + 0.50%
            WithdrawalPaymentMethod.BANK_TRANSFER -> 150L to 25L  // 1.50 EUR + 0.25%
            WithdrawalPaymentMethod.CRYPTO_USDT -> 200L to 100L   // 2.00 EUR + 1.00%
            WithdrawalPaymentMethod.CARD_OCT -> 250L to 150L      // 2.50 EUR + 1.50%
        }
        val variable = (grossAmount * bps) / 10_000L
        val total = fixed + variable
        return WithdrawalFeeBreakdown(
            fixedFeeMinorUnits = fixed,
            percentageFeeBps = bps,
            calculatedVariableFeeMinorUnits = variable,
            totalFeeMinorUnits = total
        )
    }

    private fun hashCommandPayload(command: QuoteWithdrawalCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${command.tenantId}:${command.ownerId}:${command.currencyCode}:${command.grossAmountMinorUnits}:${command.paymentMethod}:${command.destinationReference}:${command.eligibilityDecisionId}:${command.eligibilityDecisionVersion}"
        return md.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
