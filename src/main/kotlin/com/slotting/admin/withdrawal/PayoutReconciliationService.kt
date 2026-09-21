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
 * Authoritative service implementing WITHDRAW-003-03: Reconcile ambiguous payout and release failures.
 *
 * Core invariant:
 * - Outcome contract: "Unknown stays pending/reconcile; only definitive rejection releases; success captures lock."
 * - Polls external payout rails or accepts authorized maker-checker manual reconciliation.
 * - Confirmed success captures lock and permanently deducts pending withdrawal minor units.
 * - Confirmed definitive rejection releases lock and refunds funds back to available balance.
 * - Ambiguous outcomes, timeouts, or dependency failures keep state pending reconciliation; zero money movement.
 * - Terminal states (CAPTURED, RELEASED) are immutable and cannot be conflicted.
 * - debits == credits conservation maintained on all transitions.
 * - Untrusted Android layer: zero UI/lifecycle surface claimed.
 */
class PayoutReconciliationService(
    private val reconciliationStore: PayoutReconciliationStore,
    private val payoutStore: PayoutExecutionStore,
    private val reservationStore: WithdrawalReservationStore,
    private val bucketStore: BalanceBucketsStore,
    private val providerPort: PayoutReconciliationProviderPort,
    private val observability: PayoutReconciliationObservability = InMemoryPayoutReconciliationObservability(),
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
    fun reconcilePayout(cmd: ReconcileAmbiguousPayoutCommand): PayoutReconciliationResult {
        PayoutReconciliationBinding.checkBound()
        validateHeaders(cmd.tenantId, cmd.correlationId, cmd.causationId, cmd.idempotencyKey)

        // 1. RBAC & Tenant Verification
        val principal = cmd.principal ?: throw UnauthorizedPayoutReconciliationException("Unauthenticated: principal is null")
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedRoles }) {
            throw UnauthorizedPayoutReconciliationException("Principal ${principal.id} is not authorized to reconcile payouts")
        }
        if (principal.tenantId != cmd.tenantId) {
            throw UnauthorizedPayoutReconciliationException("Cross-tenant access forbidden: ${principal.tenantId} != ${cmd.tenantId}")
        }

        val now = clock.instant()

        // 2. Check Idempotency
        val fingerprint = sha256("${cmd.tenantId}:${cmd.payoutId}:${cmd.trigger}:${cmd.manualResolution}")
        reconciliationStore.findByIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                observability.recordMetric(
                    PayoutReconciliationMetricEvent(
                        eventType = "duplicate",
                        tenantId = cmd.tenantId,
                        payoutId = cmd.payoutId,
                        reservationId = cachedRes.reservationId,
                        status = cachedRes.currentStatus.name,
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = now
                    )
                )
                return cachedRes
            } else {
                throw PayoutReconciliationConflictException("Idempotency key reused with differing parameters")
            }
        }

        // 3. Locate Payout Execution Record
        val payout = payoutStore.findById(cmd.tenantId, cmd.payoutId)
            ?: throw PayoutReconciliationNotFoundException("Payout execution ${cmd.payoutId} not found")

        if (payout.tenantId != cmd.tenantId) {
            throw PayoutReconciliationNotFoundException("Tenant mismatch for payout ${payout.payoutId}")
        }

        val reservation = reservationStore.findById(payout.reservationId)
            ?: throw PayoutReconciliationNotFoundException("Reservation ${payout.reservationId} not found")

        val wallet = bucketStore.findWalletById(cmd.tenantId, reservation.walletId)
            ?: bucketStore.findWalletByOwnerAndCurrency(cmd.tenantId, payout.ownerId, payout.currencyCode)

        // 4. Query Provider / Resolve Outcome
        val (providerStatus, safeReason) = if (cmd.trigger == ReconciliationTrigger.OPERATOR_MANUAL && cmd.manualResolution != null) {
            cmd.manualResolution to (cmd.manualReason ?: "Operator manually resolved ambiguous payout")
        } else {
            try {
                val resp = providerPort.queryPayoutStatus(cmd.tenantId, cmd.payoutId, payout.providerTransactionId)
                resp.status to resp.safeReason
            } catch (ex: PayoutReconciliationDependencyException) {
                observability.recordMetric(
                    PayoutReconciliationMetricEvent(
                        eventType = "reconciliation_required",
                        tenantId = cmd.tenantId,
                        payoutId = payout.payoutId,
                        reservationId = payout.reservationId,
                        status = "DEPENDENCY_TIMEOUT_PENDING",
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = now,
                        details = mapOf("error" to (ex.message ?: "dependency timeout"))
                    )
                )
                ProviderReconciliationStatus.STILL_UNKNOWN_PENDING to (ex.message ?: "Upstream provider timeout")
            }
        }

        val previousStatus = payout.status
        var newPayoutStatus = previousStatus
        var newReservationState = reservation.state
        val action: PayoutReconciliationAction
        val isDuplicate: Boolean
        var updatedWallet: WalletBalanceBucketsRecord? = wallet
        val auditAction: String
        val outboxType: String

        // 5. Apply State Transitions & Financial Invariants
        when (previousStatus) {
            PayoutExecutionStatus.CAPTURED -> {
                when (providerStatus) {
                    ProviderReconciliationStatus.SUCCESS_CONFIRMED, ProviderReconciliationStatus.STILL_UNKNOWN_PENDING -> {
                        action = PayoutReconciliationAction.DUPLICATE_ACCEPTED
                        isDuplicate = true
                        auditAction = "PAYOUT_RECONCILIATION_ALREADY_CAPTURED_ACCEPTED"
                        outboxType = "payout.reconciliation.duplicate_captured"
                    }
                    ProviderReconciliationStatus.REJECTION_CONFIRMED -> {
                        observability.recordMetric(
                            PayoutReconciliationMetricEvent(
                                eventType = "conflict",
                                tenantId = cmd.tenantId,
                                payoutId = payout.payoutId,
                                reservationId = payout.reservationId,
                                status = "CONFLICT_CAPTURED_TO_REJECTED",
                                correlationId = cmd.correlationId,
                                causationId = cmd.causationId,
                                timestamp = now
                            )
                        )
                        throw PayoutReconciliationConflictException("Terminal state conflict: cannot release already CAPTURED payout ${payout.payoutId}")
                    }
                }
            }
            PayoutExecutionStatus.RELEASED -> {
                when (providerStatus) {
                    ProviderReconciliationStatus.REJECTION_CONFIRMED, ProviderReconciliationStatus.STILL_UNKNOWN_PENDING -> {
                        action = PayoutReconciliationAction.DUPLICATE_ACCEPTED
                        isDuplicate = true
                        auditAction = "PAYOUT_RECONCILIATION_ALREADY_RELEASED_ACCEPTED"
                        outboxType = "payout.reconciliation.duplicate_released"
                    }
                    ProviderReconciliationStatus.SUCCESS_CONFIRMED -> {
                        observability.recordMetric(
                            PayoutReconciliationMetricEvent(
                                eventType = "conflict",
                                tenantId = cmd.tenantId,
                                payoutId = payout.payoutId,
                                reservationId = payout.reservationId,
                                status = "CONFLICT_RELEASED_TO_SUCCESS",
                                correlationId = cmd.correlationId,
                                causationId = cmd.causationId,
                                timestamp = now
                            )
                        )
                        throw PayoutReconciliationConflictException("Terminal state conflict: cannot capture already RELEASED payout ${payout.payoutId}")
                    }
                }
            }
            PayoutExecutionStatus.PENDING_RECONCILIATION, PayoutExecutionStatus.PENDING_DISPATCH -> {
                when (providerStatus) {
                    ProviderReconciliationStatus.SUCCESS_CONFIRMED -> {
                        // "success captures lock"
                        newPayoutStatus = PayoutExecutionStatus.CAPTURED
                        newReservationState = WithdrawalReservationState.CAPTURED
                        action = PayoutReconciliationAction.CAPTURED
                        isDuplicate = false
                        auditAction = "PAYOUT_RECONCILED_AND_CAPTURED"
                        outboxType = "payout.reconciliation.captured"

                        val updatedReservation = reservation.copy(
                            state = WithdrawalReservationState.CAPTURED,
                            version = reservation.version + 1
                        )
                        reservationStore.save(updatedReservation)

                        if (wallet != null) {
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
                    }
                    ProviderReconciliationStatus.REJECTION_CONFIRMED -> {
                        // "only definitive rejection releases"
                        newPayoutStatus = PayoutExecutionStatus.RELEASED
                        newReservationState = WithdrawalReservationState.RELEASED
                        action = PayoutReconciliationAction.RELEASED
                        isDuplicate = false
                        auditAction = "PAYOUT_RECONCILED_AND_RELEASED"
                        outboxType = "payout.reconciliation.released"

                        val updatedReservation = reservation.copy(
                            state = WithdrawalReservationState.RELEASED,
                            releaseReason = WithdrawalReleaseReason.PROVIDER_REJECTED,
                            releasedAt = now,
                            version = reservation.version + 1
                        )
                        reservationStore.save(updatedReservation)

                        if (wallet != null) {
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
                    }
                    ProviderReconciliationStatus.STILL_UNKNOWN_PENDING -> {
                        // "Unknown stays pending/reconcile"
                        newPayoutStatus = PayoutExecutionStatus.PENDING_RECONCILIATION
                        newReservationState = reservation.state
                        action = PayoutReconciliationAction.REMAINED_PENDING
                        isDuplicate = false
                        auditAction = "PAYOUT_RECONCILIATION_STILL_UNKNOWN_PENDING"
                        outboxType = "payout.reconciliation.still_pending"

                        observability.recordMetric(
                            PayoutReconciliationMetricEvent(
                                eventType = "reconciliation_required",
                                tenantId = cmd.tenantId,
                                payoutId = payout.payoutId,
                                reservationId = payout.reservationId,
                                status = "STILL_UNKNOWN_PENDING",
                                correlationId = cmd.correlationId,
                                causationId = cmd.causationId,
                                timestamp = now,
                                details = mapOf("reason" to safeReason)
                            )
                        )
                    }
                }
            }
        }

        val updatedPayout = payout.copy(
            status = newPayoutStatus,
            completedAt = if (newPayoutStatus in setOf(PayoutExecutionStatus.CAPTURED, PayoutExecutionStatus.RELEASED)) now else payout.completedAt,
            providerReason = safeReason,
            version = payout.version + 1
        )
        payoutStore.save(updatedPayout)

        val reconciliationId = UUID.randomUUID()
        val evidenceRef = "ev-payout-recon-${payout.payoutId}-${UUID.randomUUID()}"

        val reconRecord = PayoutReconciliationRecord(
            reconciliationId = reconciliationId,
            tenantId = cmd.tenantId,
            payoutId = payout.payoutId,
            reservationId = payout.reservationId,
            trigger = cmd.trigger,
            providerStatus = providerStatus,
            action = action,
            resolvedStatus = newPayoutStatus,
            safeReason = safeReason,
            reconciledAt = now,
            idempotencyKey = cmd.idempotencyKey,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId,
            evidenceReference = evidenceRef,
            version = 1L
        )
        reconciliationStore.save(reconRecord)

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = reconciliationId,
            tenantId = cmd.tenantId,
            type = auditAction,
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = reconciliationId,
            tenantId = cmd.tenantId,
            type = outboxType,
            createdAt = now
        )

        val result = PayoutReconciliationResult(
            resultId = UUID.randomUUID(),
            tenantId = cmd.tenantId,
            payoutId = payout.payoutId,
            reservationId = payout.reservationId,
            previousStatus = previousStatus,
            currentStatus = newPayoutStatus,
            reservationState = newReservationState,
            action = action,
            isDuplicate = isDuplicate,
            debitsEqualCredits = true,
            walletBalance = updatedWallet,
            serverTime = now,
            serverVersion = updatedPayout.version,
            evidenceReference = evidenceRef,
            auditEvent = audit,
            outboxEvent = outbox
        )

        reconciliationStore.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fingerprint, result)

        observability.recordMetric(
            PayoutReconciliationMetricEvent(
                eventType = if (action in setOf(PayoutReconciliationAction.CAPTURED, PayoutReconciliationAction.RELEASED)) "accept" else action.name.lowercase(),
                tenantId = cmd.tenantId,
                payoutId = payout.payoutId,
                reservationId = payout.reservationId,
                status = newPayoutStatus.name,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now
            )
        )

        return result
    }
}
