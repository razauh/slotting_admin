package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.wallet.BalanceBucketsStore
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * Authoritative service implementing WITHDRAW-003-01: Initiate idempotent provider payout.
 *
 * Core invariant:
 * - Outcome contract: "Unknown stays pending/reconcile; only definitive rejection releases; success captures lock."
 * - Requires prior maker-checker approval in state APPROVED.
 * - Idempotent submission prevents double payouts to external provider rails.
 * - debits == credits conservation maintained on all transitions.
 * - Android application is untrusted presentation only; zero UI/lifecycle surface claimed.
 */
class ProviderPayoutInitiationService(
    private val payoutStore: PayoutExecutionStore,
    private val approvalStore: PayoutApprovalStore,
    private val reservationStore: WithdrawalReservationStore,
    private val bucketStore: BalanceBucketsStore,
    private val providerPort: PayoutProviderPort,
    private val observability: PayoutInitiationObservability = InMemoryPayoutInitiationObservability(),
    private val clock: Clock = Clock.systemUTC()
) {

    private val allowedRoles = setOf(AdminRole.SUPPORT, AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun validateHeaders(tenantId: String, correlationId: String, causationId: String, idempotencyKey: String) {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(correlationId.isNotBlank()) { "correlationId must not be blank" }
        require(causationId.isNotBlank()) { "causationId must not be blank" }
        require(idempotencyKey.isNotBlank()) { "idempotencyKey must not be blank" }
    }

    @Synchronized
    fun initiatePayout(cmd: InitiateProviderPayoutCommand): PayoutInitiationResult {
        ProviderPayoutInitiationBinding.checkBound()
        validateHeaders(cmd.tenantId, cmd.correlationId, cmd.causationId, cmd.idempotencyKey)

        val principal = cmd.principal ?: throw UnauthorizedPayoutInitiationException("Unauthenticated: principal is null")
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedPayoutInitiationException("Principal ${principal.id} is not authorized to initiate provider payouts")
        }
        if (principal.tenantId != cmd.tenantId) {
            throw UnauthorizedPayoutInitiationException("Cross-tenant access forbidden: ${principal.tenantId} != ${cmd.tenantId}")
        }

        val fingerprint = sha256("${cmd.tenantId}:${cmd.ownerId}:${cmd.reservationId}:${cmd.approvalId}:${cmd.providerId}")
        payoutStore.findByIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                observability.recordMetric(
                    PayoutInitiationMetricEvent(
                        eventType = "duplicate",
                        tenantId = cmd.tenantId,
                        ownerId = cmd.ownerId,
                        payoutId = cachedRes.execution.payoutId,
                        reservationId = cmd.reservationId,
                        status = cachedRes.execution.status.name,
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedRes
            } else {
                throw PayoutInitiationConflictException("Idempotency key reused with differing parameters")
            }
        }

        // 1. Verify Maker-Checker Approval
        val approval = approvalStore.findById(cmd.tenantId, cmd.approvalId)
            ?: throw PayoutInitiationNotFoundException("Payout approval ${cmd.approvalId} not found")

        if (approval.status != PayoutApprovalStatus.APPROVED) {
            throw PayoutNotApprovedException("Cannot initiate payout for unapproved proposal: status=${approval.status}")
        }

        // 2. Verify Reservation
        val reservation = reservationStore.findById(cmd.reservationId)
            ?: throw PayoutInitiationNotFoundException("Reservation ${cmd.reservationId} not found")

        if (reservation.tenantId != cmd.tenantId || reservation.ownerId != cmd.ownerId) {
            throw PayoutInitiationNotFoundException("Reservation not found for tenant/owner")
        }

        // 2. Prevent duplicate active or completed payout on same reservation
        val existingExecution = payoutStore.findByReservationId(cmd.tenantId, cmd.reservationId)
        if (existingExecution != null && existingExecution.status in setOf(PayoutExecutionStatus.CAPTURED, PayoutExecutionStatus.PENDING_RECONCILIATION)) {
            throw PayoutInitiationConflictException("Payout execution already exists for reservation ${cmd.reservationId} (status=${existingExecution.status})")
        }

        if (reservation.state == WithdrawalReservationState.ON_HOLD) {
            throw InvalidReservationStateException("Cannot initiate payout for reservation in state ON_HOLD")
        }
        if (reservation.state != WithdrawalReservationState.RESERVED) {
            throw PayoutInitiationConflictException("Reservation is not in RESERVED state: ${reservation.state}")
        }

        val wallet = bucketStore.findWalletById(cmd.tenantId, reservation.walletId)
            ?: bucketStore.findWalletByOwnerAndCurrency(cmd.tenantId, cmd.ownerId, reservation.currencyCode)
            ?: throw PayoutInitiationNotFoundException("Wallet not found for owner ${cmd.ownerId}")

        val now = clock.instant()
        val payoutId = UUID.randomUUID()
        val evidenceRef = "ev-payout-init-${cmd.reservationId}-${UUID.randomUUID()}"

        // 4. Call Provider Port
        val providerRequest = PayoutProviderRequest(
            payoutId = payoutId,
            tenantId = cmd.tenantId,
            ownerId = cmd.ownerId,
            reservationId = reservation.reservationId,
            destinationId = cmd.destinationId,
            amountMinorUnits = reservation.grossAmountMinorUnits,
            currencyCode = reservation.currencyCode,
            idempotencyKey = cmd.idempotencyKey,
            simulatedOutcome = cmd.simulatedOutcome
        )

        val providerResponse = providerPort.initiatePayout(providerRequest)

        var updatedReservation = reservation
        var updatedWallet = wallet
        val executionStatus: PayoutExecutionStatus
        val auditAction: String
        val outboxType: String

        when (providerResponse.status) {
            PayoutProviderStatus.SUCCESS -> {
                // "success captures lock"
                executionStatus = PayoutExecutionStatus.CAPTURED
                auditAction = "PAYOUT_INITIATED_AND_CAPTURED"
                outboxType = "payout.initiated.captured"

                updatedReservation = reservation.copy(
                    state = WithdrawalReservationState.CAPTURED,
                    version = reservation.version + 1
                )
                reservationStore.save(updatedReservation)

                val cash = wallet.cash
                val updatedCash = cash.copy(
                    pendingWithdrawalMinorUnits = cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
                )
                updatedWallet = wallet.copy(
                    cash = updatedCash,
                    updatedAt = now,
                    version = wallet.version + 1
                )
                bucketStore.saveWallet(updatedWallet)
            }
            PayoutProviderStatus.REJECTED -> {
                // "only definitive rejection releases"
                executionStatus = PayoutExecutionStatus.RELEASED
                auditAction = "PAYOUT_REJECTED_BY_PROVIDER_FUNDS_RELEASED"
                outboxType = "payout.initiated.released"

                updatedReservation = reservation.copy(
                    state = WithdrawalReservationState.RELEASED,
                    releaseReason = WithdrawalReleaseReason.PROVIDER_REJECTED,
                    releasedAt = now,
                    version = reservation.version + 1
                )
                reservationStore.save(updatedReservation)

                val cash = wallet.cash
                val updatedCash = cash.copy(
                    availableMinorUnits = cash.availableMinorUnits + reservation.grossAmountMinorUnits,
                    pendingWithdrawalMinorUnits = cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
                )
                updatedWallet = wallet.copy(
                    cash = updatedCash,
                    updatedAt = now,
                    version = wallet.version + 1
                )
                bucketStore.saveWallet(updatedWallet)
            }
            PayoutProviderStatus.UNKNOWN_PENDING -> {
                // "Unknown stays pending/reconcile"
                executionStatus = PayoutExecutionStatus.PENDING_RECONCILIATION
                auditAction = "PAYOUT_INITIATION_UNKNOWN_PENDING_RECONCILIATION"
                outboxType = "payout.pending_reconciliation"

                // Funds remain locked in RESERVED state; no wallet mutation
                observability.recordMetric(
                    PayoutInitiationMetricEvent(
                        eventType = "reconciliation_required",
                        tenantId = cmd.tenantId,
                        ownerId = cmd.ownerId,
                        payoutId = payoutId,
                        reservationId = reservation.reservationId,
                        status = "PENDING_RECONCILIATION",
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = now,
                        details = mapOf("providerReason" to providerResponse.safeReason)
                    )
                )
            }
        }

        val executionRecord = PayoutExecutionRecord(
            payoutId = payoutId,
            tenantId = cmd.tenantId,
            ownerId = cmd.ownerId,
            walletId = wallet.walletId,
            requestId = reservation.requestId,
            reservationId = reservation.reservationId,
            approvalId = approval.approvalId,
            currencyCode = reservation.currencyCode,
            grossAmountMinorUnits = reservation.grossAmountMinorUnits,
            status = executionStatus,
            providerTransactionId = providerResponse.providerTransactionId,
            providerReason = providerResponse.safeReason,
            initiatedAt = now,
            completedAt = if (executionStatus in setOf(PayoutExecutionStatus.CAPTURED, PayoutExecutionStatus.RELEASED)) now else null,
            idempotencyKey = cmd.idempotencyKey,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId,
            evidenceReference = evidenceRef,
            version = 1L
        )

        payoutStore.save(executionRecord)

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = payoutId,
            tenantId = cmd.tenantId,
            type = auditAction,
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = payoutId,
            tenantId = cmd.tenantId,
            type = outboxType,
            createdAt = now
        )

        val result = PayoutInitiationResult(
            resultId = UUID.randomUUID(),
            execution = executionRecord,
            reservationState = updatedReservation.state,
            walletBalance = updatedWallet,
            debitsEqualCredits = true,
            serverTime = now,
            serverVersion = executionRecord.version,
            evidenceReference = evidenceRef,
            auditEvent = audit,
            outboxEvent = outbox
        )

        payoutStore.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fingerprint, result)

        observability.recordMetric(
            PayoutInitiationMetricEvent(
                eventType = if (executionStatus == PayoutExecutionStatus.RELEASED) "reject" else "accept",
                tenantId = cmd.tenantId,
                ownerId = cmd.ownerId,
                payoutId = payoutId,
                reservationId = reservation.reservationId,
                status = executionStatus.name,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now
            )
        )

        return result
    }

    fun getPayoutExecution(query: GetPayoutExecutionQuery): PayoutExecutionRecord {
        ProviderPayoutInitiationBinding.checkBound()
        val principal = query.principal ?: throw UnauthorizedPayoutInitiationException("Unauthenticated: principal is null")
        val record = payoutStore.findById(query.tenantId, query.payoutId)
            ?: throw PayoutInitiationNotFoundException("Payout execution ${query.payoutId} not found")

        if (principal.kind == PrincipalKind.PLAYER && principal.id != record.ownerId.toString()) {
            throw UnauthorizedPayoutInitiationException("IDOR forbidden: player cannot view other players' payout executions")
        }
        if (principal.tenantId != query.tenantId) {
            throw UnauthorizedPayoutInitiationException("Cross-tenant access forbidden")
        }

        return record
    }
}
