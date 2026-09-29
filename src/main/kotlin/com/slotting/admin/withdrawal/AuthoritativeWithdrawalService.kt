package com.slotting.admin.withdrawal

import com.slotting.admin.auth.*
import com.slotting.admin.provider.PaymentMethodConfig
import com.slotting.admin.provider.PaymentMethodStatus
import com.slotting.admin.provider.PaymentMethodStore
import com.slotting.admin.provider.PaymentMethodUnavailableException
import com.slotting.admin.provider.MethodAvailabilityCode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.util.UUID

open class AuthoritativeWithdrawalService(
    private val withdrawalStore: AuthoritativeWithdrawalStore,
    private val paymentMethodStore: PaymentMethodStore,
    private val sessions: AdminSessionDirectory,
    private val restrictionPolicy: (tenantId: String, ownerId: UUID) -> Boolean = { _, _ -> false },
    private val clock: Clock = Clock.systemUTC(),
) {

    private fun sha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    open fun createQuote(command: CreateAuthoritativeQuoteCommand): AuthoritativeWithdrawalQuote {
        // 1. Authentication check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        // 2. Tenant isolation
        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. IDOR check
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.ownerId.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 4. Session validation
        val session = sessions.find(principal.tenantId, principal.id, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        // 5. Overflow and bounds check
        if (command.grossAmountMinorUnits <= 0L) {
            throw IllegalArgumentException("Gross amount must be strictly positive: ${command.grossAmountMinorUnits}")
        }

        // 6. Restriction check
        if (restrictionPolicy(command.tenantId, command.ownerId)) {
            throw RestrictedAccountException("Player ${command.ownerId} has active withdrawal restrictions")
        }

        // 7. Method revalidation
        val method = paymentMethodStore.findMethod(command.tenantId, command.methodId)
            ?: throw PaymentMethodUnavailableException(
                code = MethodAvailabilityCode.INACTIVE,
                methodId = command.methodId,
                serverVersion = null,
                message = "Payment method '${command.methodId}' does not exist",
            )
        if (method.status != PaymentMethodStatus.ACTIVE || !method.allowsWithdrawal) {
            throw PaymentMethodUnavailableException(
                code = MethodAvailabilityCode.INACTIVE,
                methodId = command.methodId,
                serverVersion = method.serverVersion,
                message = "Payment method '${command.methodId}' is not active or does not allow withdrawals",
            )
        }
        if (command.grossAmountMinorUnits < method.minWithdrawalMinorUnits) {
            throw PaymentMethodUnavailableException(
                code = MethodAvailabilityCode.AMOUNT_BELOW_MINIMUM,
                methodId = command.methodId,
                serverVersion = method.serverVersion,
                message = "Amount is below minimum withdrawal limit (${method.minWithdrawalMinorUnits})",
            )
        }
        if (command.grossAmountMinorUnits > method.maxWithdrawalMinorUnits) {
            throw PaymentMethodUnavailableException(
                code = MethodAvailabilityCode.AMOUNT_ABOVE_MAXIMUM,
                methodId = command.methodId,
                serverVersion = method.serverVersion,
                message = "Amount exceeds maximum withdrawal limit (${method.maxWithdrawalMinorUnits})",
            )
        }

        // 8. Destination validation
        val dest = withdrawalStore.findDestination(command.tenantId, command.destinationId)
            ?: throw IllegalArgumentException("Destination ${command.destinationId} not found")
        if (dest.ownerId != command.ownerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (dest.status != DestinationVerificationStatus.VERIFIED) {
            throw UnverifiedDestinationException("Destination ${dest.destinationReference} is not verified (status: ${dest.status})")
        }

        // 9. Fee calculation & fee boundary check
        val fixedFee = method.feeFlatMinorUnits
        val variableFee = Math.multiplyExact(command.grossAmountMinorUnits, method.feePercentageBps.toLong()) / 10000L
        val totalFee = Math.addExact(fixedFee, variableFee)
        if (command.grossAmountMinorUnits <= totalFee) {
            throw InvalidFeeBoundaryException("Gross amount (${command.grossAmountMinorUnits}) must be strictly greater than total fees ($totalFee)")
        }
        val netPayout = Math.subtractExact(command.grossAmountMinorUnits, totalFee)

        // 10. Authoritative available balance check
        val available = withdrawalStore.getAuthoritativeBalance(command.tenantId, command.ownerId, command.currencyCode)
        if (available < command.grossAmountMinorUnits) {
            throw InsufficientWithdrawableFundsException("Insufficient available balance ($available) for requested withdrawal (${command.grossAmountMinorUnits})")
        }

        val now = clock.instant()
        val quoteId = UUID.randomUUID()
        val quote = AuthoritativeWithdrawalQuote(
            quoteId = quoteId,
            tenantId = command.tenantId,
            ownerId = command.ownerId,
            currencyCode = command.currencyCode,
            methodId = command.methodId,
            destinationId = command.destinationId,
            destinationReference = dest.destinationReference,
            grossAmountMinorUnits = command.grossAmountMinorUnits,
            fixedFeeMinorUnits = fixedFee,
            percentageFeeBps = method.feePercentageBps.toLong(),
            totalFeeMinorUnits = totalFee,
            netPayoutMinorUnits = netPayout,
            stepUpRequired = command.grossAmountMinorUnits >= 10_000L,
            status = WithdrawalQuoteStatus.ACTIVE,
            quotedAt = now,
            expiresAt = now.plus(Duration.ofMinutes(15)),
            consumedAt = null,
            idempotencyKey = command.idempotencyKey,
            serverVersion = 1L,
        )

        withdrawalStore.saveQuote(quote)
        return quote
    }

    open fun issueStepUpAssertion(command: IssueStepUpAssertionCommand): StepUpAssertionRecord {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.ownerId.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = sessions.find(principal.tenantId, principal.id, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        val quote = withdrawalStore.findQuote(command.tenantId, command.quoteId)
            ?: throw IllegalArgumentException("Quote ${command.quoteId} not found")
        if (quote.ownerId != command.ownerId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (quote.status != WithdrawalQuoteStatus.ACTIVE || clock.instant().isAfter(quote.expiresAt)) {
            throw StaleQuoteException("Quote ${command.quoteId} is not active or expired")
        }

        val boundDigest = sha256("${command.tenantId}:${command.ownerId}:${command.sessionId}:${quote.destinationReference}:${quote.grossAmountMinorUnits}:${quote.currencyCode}:${quote.methodId}:WITHDRAWAL")
        val token = "STEPUP-ASSERTION-${UUID.randomUUID()}"
        val now = clock.instant()
        val assertion = StepUpAssertionRecord(
            assertionId = UUID.randomUUID(),
            tenantId = command.tenantId,
            ownerId = command.ownerId,
            sessionId = command.sessionId,
            destinationReference = quote.destinationReference,
            grossAmountMinorUnits = quote.grossAmountMinorUnits,
            currencyCode = quote.currencyCode,
            methodId = quote.methodId,
            operationType = "WITHDRAWAL",
            boundDigest = boundDigest,
            token = token,
            isConsumed = false,
            issuedAt = now,
            expiresAt = now.plus(Duration.ofMinutes(5)),
            consumedAt = null,
        )

        withdrawalStore.saveStepUpAssertion(assertion)
        return assertion
    }

    open fun createWithdrawalRequest(command: CreateAuthoritativeWithdrawalRequestCommand): AuthoritativeWithdrawalRequestResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (principal.kind == PrincipalKind.PLAYER && principal.id != command.ownerId.toString()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = sessions.find(principal.tenantId, principal.id, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        // Idempotency check
        withdrawalStore.findRequestByIdempotency(command.tenantId, command.idempotencyKey)?.let { existing ->
            return AuthoritativeWithdrawalRequestResult(
                requestId = existing.requestId,
                tenantId = existing.tenantId,
                ownerId = existing.ownerId,
                quoteId = existing.quoteId,
                reservationId = existing.reservationId,
                methodId = existing.methodId,
                destinationReference = existing.destinationReference,
                grossAmountMinorUnits = existing.grossAmountMinorUnits,
                feeMinorUnits = existing.feeMinorUnits,
                netPayoutAmountMinorUnits = existing.netPayoutAmountMinorUnits,
                currencyCode = existing.currencyCode,
                status = existing.status,
                reviewState = existing.reviewState,
                immutableDigest = existing.immutableDigest,
                requestVersion = existing.requestVersion,
                serverTime = existing.createdAt,
            )
        }

        val quote = withdrawalStore.findQuote(command.tenantId, command.quoteId)
            ?: throw StaleQuoteException("Quote ${command.quoteId} not found")
        if (quote.ownerId != command.ownerId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (quote.status != WithdrawalQuoteStatus.ACTIVE || clock.instant().isAfter(quote.expiresAt)) {
            throw StaleQuoteException("Quote ${command.quoteId} is not active or has expired")
        }

        val dest = withdrawalStore.findDestination(command.tenantId, command.destinationId)
            ?: throw DestinationMismatchException("Destination ${command.destinationId} not found")
        if (dest.ownerId != command.ownerId || dest.destinationReference != quote.destinationReference) {
            throw DestinationMismatchException("Destination does not match quote destination (${dest.destinationReference} != ${quote.destinationReference})")
        }
        if (dest.status != DestinationVerificationStatus.VERIFIED) {
            throw UnverifiedDestinationException("Destination is not verified")
        }

        // Step-up verification
        var stepUpAssertionId: UUID? = null
        if (quote.stepUpRequired) {
            val token = command.stepUpToken
                ?: throw StepUpAuthenticationRequiredException("Step-up authentication required for quote ${command.quoteId}")
            val assertion = withdrawalStore.findStepUpAssertion(command.tenantId, token)
                ?: throw StepUpAuthenticationRequiredException("Invalid or forged step-up token")

            if (assertion.isConsumed) {
                throw StepUpReplayException("Step-up assertion has already been consumed")
            }
            if (clock.instant().isAfter(assertion.expiresAt)) {
                throw StepUpAuthenticationRequiredException("Step-up assertion has expired")
            }

            val expectedDigest = sha256("${command.tenantId}:${command.ownerId}:${command.sessionId}:${quote.destinationReference}:${quote.grossAmountMinorUnits}:${quote.currencyCode}:${quote.methodId}:WITHDRAWAL")
            if (assertion.boundDigest != expectedDigest ||
                assertion.ownerId != command.ownerId ||
                assertion.destinationReference != dest.destinationReference ||
                assertion.grossAmountMinorUnits != quote.grossAmountMinorUnits
            ) {
                throw StepUpBindingMismatchException("Step-up token parameters do not match request parameters")
            }

            val consumed = withdrawalStore.consumeStepUpAssertion(command.tenantId, token, clock.instant())
            if (!consumed) {
                throw StepUpReplayException("Step-up assertion has already been consumed")
            }
            stepUpAssertionId = assertion.assertionId
        }

        // Atomically reserve available ledger funds
        val reserved = withdrawalStore.tryReserveBalance(
            command.tenantId,
            command.ownerId,
            quote.currencyCode,
            quote.grossAmountMinorUnits,
        )
        if (!reserved) {
            throw InsufficientWithdrawableFundsException("Insufficient withdrawable balance to reserve ${quote.grossAmountMinorUnits} ${quote.currencyCode}")
        }

        val requestId = UUID.randomUUID()
        val reservationId = UUID.randomUUID()
        val now = clock.instant()

        val reservationRecord = AuthoritativeWithdrawalReservation(
            reservationId = reservationId,
            tenantId = command.tenantId,
            ownerId = command.ownerId,
            requestId = requestId,
            amountMinorUnits = quote.grossAmountMinorUnits,
            currencyCode = quote.currencyCode,
            status = AuthoritativeReservationStatus.RESERVED,
            ledgerJournalReference = "RES-WITHDRAW-$reservationId",
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )
        withdrawalStore.saveReservation(reservationRecord)

        // Invalidate quote
        withdrawalStore.saveQuote(
            quote.copy(
                status = WithdrawalQuoteStatus.CONSUMED,
                consumedAt = now,
                serverVersion = quote.serverVersion + 1,
            )
        )

        // Calculate immutable digest bound to exact payout details
        val immutableDigest = sha256("${command.tenantId}:$requestId:${command.ownerId}:${quote.quoteId}:$reservationId:${quote.methodId}:${dest.destinationReference}:${quote.grossAmountMinorUnits}:${quote.totalFeeMinorUnits}:${quote.netPayoutMinorUnits}:${quote.currencyCode}:1")

        val requestRecord = AuthoritativeWithdrawalRequest(
            requestId = requestId,
            tenantId = command.tenantId,
            ownerId = command.ownerId,
            quoteId = quote.quoteId,
            reservationId = reservationId,
            methodId = quote.methodId,
            destinationId = command.destinationId,
            destinationReference = dest.destinationReference,
            grossAmountMinorUnits = quote.grossAmountMinorUnits,
            feeMinorUnits = quote.totalFeeMinorUnits,
            netPayoutAmountMinorUnits = quote.netPayoutMinorUnits,
            currencyCode = quote.currencyCode,
            stepUpAssertionId = stepUpAssertionId,
            immutableDigest = immutableDigest,
            status = WithdrawalRequestStatus.REQUESTED,
            reviewState = WithdrawalReviewState.QUEUED,
            idempotencyKey = command.idempotencyKey,
            requestVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )
        withdrawalStore.saveRequest(requestRecord)

        return AuthoritativeWithdrawalRequestResult(
            requestId = requestId,
            tenantId = command.tenantId,
            ownerId = command.ownerId,
            quoteId = quote.quoteId,
            reservationId = reservationId,
            methodId = quote.methodId,
            destinationReference = dest.destinationReference,
            grossAmountMinorUnits = quote.grossAmountMinorUnits,
            feeMinorUnits = quote.totalFeeMinorUnits,
            netPayoutAmountMinorUnits = quote.netPayoutMinorUnits,
            currencyCode = quote.currencyCode,
            status = WithdrawalRequestStatus.REQUESTED,
            reviewState = WithdrawalReviewState.QUEUED,
            immutableDigest = immutableDigest,
            requestVersion = 1L,
            serverTime = now,
        )
    }

    open fun reviewWithdrawal(command: ReviewWithdrawalCommand): AuthoritativeWithdrawalReviewResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.tenantId != command.tenantId || principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.roles.contains(AdminRole.AUDITOR)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = sessions.find(principal.tenantId, principal.id, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }

        val request = withdrawalStore.findRequest(command.tenantId, command.requestId)
            ?: throw IllegalArgumentException("Withdrawal request ${command.requestId} not found")

        val now = clock.instant()
        val previousState = request.reviewState

        val newReviewState = when (command.action) {
            WithdrawalReviewAction.CLAIM -> WithdrawalReviewState.CLAIMED
            WithdrawalReviewAction.RELEASE -> WithdrawalReviewState.QUEUED
            WithdrawalReviewAction.APPROVE -> {
                val receipt = command.dualControlReceipt
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

                if (receipt.tenantId != command.tenantId ||
                    receipt.status != DualControlStatus.APPROVED ||
                    !receipt.expiresAt.isAfter(now)
                ) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Self-approval prohibition
                if (receipt.maker.principalId == receipt.checker.principalId) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Read-only auditor prohibition
                if (receipt.maker.roles.contains(AdminRole.AUDITOR) || receipt.checker.roles.contains(AdminRole.AUDITOR)) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Bound to exact immutable request digest
                if (receipt.payloadDigest != request.immutableDigest) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                // Bound to exact request version
                if (receipt.targetVersion != request.requestVersion) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }

                WithdrawalReviewState.APPROVED
            }
            WithdrawalReviewAction.REJECT -> WithdrawalReviewState.REJECTED
        }

        val updated = request.copy(
            reviewState = newReviewState,
            status = if (newReviewState == WithdrawalReviewState.REJECTED) WithdrawalRequestStatus.REJECTED else request.status,
            dualControlReceiptId = command.dualControlReceipt?.receiptId,
            requestVersion = request.requestVersion + 1,
            updatedAt = now,
        )
        withdrawalStore.updateRequest(updated, expectedVersion = request.requestVersion)

        return AuthoritativeWithdrawalReviewResult(
            requestId = request.requestId,
            previousState = previousState,
            newState = newReviewState,
            dualControlReceiptId = command.dualControlReceipt?.receiptId,
            serverTime = now,
            serverVersion = updated.requestVersion,
        )
    }

    open fun getRequest(tenantId: String, requestId: UUID, ownerId: UUID): AuthoritativeWithdrawalRequest? {
        val req = withdrawalStore.findRequest(tenantId, requestId) ?: return null
        if (req.ownerId != ownerId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return req
    }
}
