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
 * Authoritative service implementing WITHDRAW-002-03: Apply maker-checker payout approval.
 *
 * Core invariant:
 * - Four-eyes dual control: maker cannot self-approve payout (`checkerPrincipal.id != makerPrincipal.id`).
 * - Payout approvals require active locked funds (`RESERVED` state) and clearance from AML/risk holds.
 * - Rejection or cancellation triggers explicit, audited release of locked funds back to available balance.
 * - debits == credits conservation preserved on all transitions.
 * - Android application is untrusted presentation only; zero UI/lifecycle surface claimed.
 */
class MakerCheckerPayoutApprovalService(
    private val approvalStore: PayoutApprovalStore,
    private val reservationStore: WithdrawalReservationStore,
    private val bucketStore: BalanceBucketsStore,
    private val observability: PayoutApprovalObservability = InMemoryPayoutApprovalObservability(),
    private val clock: Clock = Clock.systemUTC()
) {

    private val allowedMakerRoles = setOf(AdminRole.SUPPORT, AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)
    private val allowedCheckerRoles = setOf(AdminRole.AUDITOR, AdminRole.SUPER_ADMIN)

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
    fun proposePayout(cmd: ProposePayoutApprovalCommand): PayoutApprovalResult {
        MakerCheckerPayoutApprovalBinding.checkBound()
        validateHeaders(cmd.tenantId, cmd.correlationId, cmd.causationId, cmd.idempotencyKey)

        val principal = cmd.principal ?: throw UnauthorizedApprovalAccessException("Unauthenticated: principal is null")
        if (principal.kind != PrincipalKind.ADMIN || principal.roles.none { it in allowedMakerRoles }) {
            throw UnauthorizedApprovalAccessException("Principal ${principal.id} is not authorized to propose payout approvals")
        }
        if (principal.tenantId != cmd.tenantId) {
            throw UnauthorizedApprovalAccessException("Cross-tenant access forbidden: ${principal.tenantId} != ${cmd.tenantId}")
        }
        require(cmd.makerNotes.isNotBlank()) { "makerNotes must not be blank" }
        require(cmd.ttlSeconds > 0L) { "ttlSeconds must be positive" }

        val fingerprint = sha256("${cmd.tenantId}:${cmd.ownerId}:${cmd.reservationId}:${cmd.makerNotes}:${cmd.ttlSeconds}")
        approvalStore.findByIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                observability.recordMetric(
                    PayoutApprovalMetricEvent(
                        eventType = "duplicate",
                        tenantId = cmd.tenantId,
                        ownerId = cmd.ownerId,
                        approvalId = cachedRes.approval.approvalId,
                        reservationId = cmd.reservationId,
                        makerId = principal.id,
                        checkerId = null,
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedRes
            } else {
                throw PayoutApprovalConflictException("Idempotency key reused with differing parameters")
            }
        }

        val reservation = reservationStore.findById(cmd.reservationId)
            ?: throw PayoutApprovalNotFoundException("Reservation ${cmd.reservationId} not found")

        if (reservation.tenantId != cmd.tenantId || reservation.ownerId != cmd.ownerId) {
            throw PayoutApprovalNotFoundException("Reservation not found for tenant/owner")
        }

        if (reservation.state == WithdrawalReservationState.ON_HOLD) {
            throw InvalidReservationStateException("Cannot propose payout for reservation in state ON_HOLD; compliance hold must be cleared first")
        }
        if (reservation.state != WithdrawalReservationState.RESERVED) {
            throw InvalidReservationStateException("Cannot propose payout for reservation in state ${reservation.state}")
        }

        val existingApproval = approvalStore.findByReservationId(cmd.tenantId, cmd.reservationId)
        if (existingApproval != null && existingApproval.status in setOf(PayoutApprovalStatus.PENDING_REVIEW, PayoutApprovalStatus.APPROVED)) {
            throw PayoutApprovalConflictException("An active or approved proposal already exists for reservation ${cmd.reservationId}")
        }

        val wallet = bucketStore.findWalletById(cmd.tenantId, reservation.walletId)
            ?: bucketStore.findWalletByOwnerAndCurrency(cmd.tenantId, cmd.ownerId, reservation.currencyCode)
            ?: throw PayoutApprovalNotFoundException("Wallet not found for owner ${cmd.ownerId}")

        val now = clock.instant()
        val approvalId = UUID.randomUUID()
        val evidenceRef = "ev-payout-prop-${cmd.reservationId}-${UUID.randomUUID()}"

        val record = PayoutApprovalRecord(
            approvalId = approvalId,
            tenantId = cmd.tenantId,
            ownerId = cmd.ownerId,
            walletId = wallet.walletId,
            requestId = reservation.requestId,
            reservationId = reservation.reservationId,
            currencyCode = reservation.currencyCode,
            grossAmountMinorUnits = reservation.grossAmountMinorUnits,
            status = PayoutApprovalStatus.PENDING_REVIEW,
            makerPrincipal = principal,
            makerNotes = cmd.makerNotes,
            checkerPrincipal = null,
            checkerNotes = null,
            createdAt = now,
            decidedAt = null,
            expiresAt = now.plusSeconds(cmd.ttlSeconds),
            idempotencyKey = cmd.idempotencyKey,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId,
            evidenceReference = evidenceRef,
            version = 1L
        )

        approvalStore.save(record)

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = approvalId,
            tenantId = cmd.tenantId,
            type = "PAYOUT_APPROVAL_PROPOSED",
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = approvalId,
            tenantId = cmd.tenantId,
            type = "payout.approval.proposed",
            createdAt = now
        )

        val result = PayoutApprovalResult(
            resultId = UUID.randomUUID(),
            approval = record,
            reservationState = reservation.state,
            walletBalance = wallet,
            debitsEqualCredits = true,
            serverTime = now,
            serverVersion = record.version,
            evidenceReference = evidenceRef,
            auditEvent = audit,
            outboxEvent = outbox
        )

        approvalStore.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fingerprint, result)

        observability.recordMetric(
            PayoutApprovalMetricEvent(
                eventType = "accept",
                tenantId = cmd.tenantId,
                ownerId = cmd.ownerId,
                approvalId = approvalId,
                reservationId = reservation.reservationId,
                makerId = principal.id,
                checkerId = null,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now
            )
        )

        return result
    }

    @Synchronized
    fun reviewPayout(cmd: ReviewPayoutApprovalCommand): PayoutApprovalResult {
        MakerCheckerPayoutApprovalBinding.checkBound()
        validateHeaders(cmd.tenantId, cmd.correlationId, cmd.causationId, cmd.idempotencyKey)

        val principal = cmd.principal ?: throw UnauthorizedApprovalAccessException("Unauthenticated: principal is null")
        if (principal.kind != PrincipalKind.ADMIN) {
            throw UnauthorizedApprovalAccessException("Principal ${principal.id} is not authorized to review payout approvals")
        }
        if (principal.tenantId != cmd.tenantId) {
            throw UnauthorizedApprovalAccessException("Cross-tenant access forbidden: ${principal.tenantId} != ${cmd.tenantId}")
        }
        require(cmd.checkerNotes.isNotBlank()) { "checkerNotes must not be blank" }

        val proposal = approvalStore.findById(cmd.tenantId, cmd.approvalId)
            ?: throw PayoutApprovalNotFoundException("Payout approval ${cmd.approvalId} not found")

        // FOUR-EYES PRINCIPLE: Maker cannot be Checker
        if (principal.id == proposal.makerPrincipal.id) {
            observability.recordMetric(
                PayoutApprovalMetricEvent(
                    eventType = "violation",
                    tenantId = cmd.tenantId,
                    ownerId = proposal.ownerId,
                    approvalId = proposal.approvalId,
                    reservationId = proposal.reservationId,
                    makerId = proposal.makerPrincipal.id,
                    checkerId = principal.id,
                    correlationId = cmd.correlationId,
                    causationId = cmd.causationId,
                    timestamp = clock.instant(),
                    details = mapOf("violation" to "maker self-approval prohibited")
                )
            )
            throw MakerSelfApprovalForbiddenException("Four-eyes violation: maker ${proposal.makerPrincipal.id} cannot act as checker")
        }

        // Check checker role authorization
        if (principal.roles.none { it in allowedCheckerRoles }) {
            throw UnauthorizedApprovalAccessException("Principal ${principal.id} is not authorized to review payout approvals as checker")
        }

        val fingerprint = sha256("${cmd.tenantId}:${cmd.approvalId}:${cmd.action}:${cmd.checkerNotes}:${principal.id}")
        approvalStore.findByIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                observability.recordMetric(
                    PayoutApprovalMetricEvent(
                        eventType = "duplicate",
                        tenantId = cmd.tenantId,
                        ownerId = cachedRes.approval.ownerId,
                        approvalId = cmd.approvalId,
                        reservationId = cachedRes.approval.reservationId,
                        makerId = cachedRes.approval.makerPrincipal.id,
                        checkerId = principal.id,
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedRes
            } else {
                throw PayoutApprovalConflictException("Idempotency key reused with differing parameters")
            }
        }

        if (proposal.status != PayoutApprovalStatus.PENDING_REVIEW) {
            throw PayoutApprovalConflictException("Proposal ${cmd.approvalId} is not pending review (status=${proposal.status})")
        }

        val now = clock.instant()
        if (now.isAfter(proposal.expiresAt)) {
            val expiredRecord = proposal.copy(
                status = PayoutApprovalStatus.EXPIRED,
                decidedAt = now,
                version = proposal.version + 1
            )
            approvalStore.save(expiredRecord)
            throw PayoutApprovalConflictException("Payout approval proposal ${cmd.approvalId} has expired")
        }

        val reservation = reservationStore.findById(proposal.reservationId)
            ?: throw PayoutApprovalNotFoundException("Reservation ${proposal.reservationId} not found")

        if (reservation.state == WithdrawalReservationState.ON_HOLD) {
            throw InvalidReservationStateException("Cannot review payout for reservation in state ON_HOLD")
        }

        var updatedReservation = reservation
        var updatedWallet = bucketStore.findWalletById(proposal.tenantId, proposal.walletId)
            ?: bucketStore.findWalletByOwnerAndCurrency(proposal.tenantId, proposal.ownerId, proposal.currencyCode)
            ?: throw PayoutApprovalNotFoundException("Wallet not found for owner ${proposal.ownerId}")

        val newStatus = when (cmd.action) {
            PayoutDecisionAction.APPROVE -> {
                if (reservation.state != WithdrawalReservationState.RESERVED) {
                    throw InvalidReservationStateException("Cannot approve payout for reservation in state ${reservation.state}")
                }
                PayoutApprovalStatus.APPROVED
            }
            PayoutDecisionAction.REJECT -> {
                // Explicit release policy: refund locked funds back to available balance
                if (reservation.state == WithdrawalReservationState.RESERVED) {
                    updatedReservation = reservation.copy(
                        state = WithdrawalReservationState.RELEASED,
                        releaseReason = WithdrawalReleaseReason.MAKER_CHECKER_REJECTED,
                        releasedAt = now,
                        version = reservation.version + 1
                    )
                    reservationStore.save(updatedReservation)

                    val cash = updatedWallet.cash
                    val updatedCash = cash.copy(
                        availableMinorUnits = cash.availableMinorUnits + reservation.grossAmountMinorUnits,
                        pendingWithdrawalMinorUnits = cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
                    )

                    updatedWallet = updatedWallet.copy(
                        cash = updatedCash,
                        updatedAt = now,
                        version = updatedWallet.version + 1
                    )
                    bucketStore.saveWallet(updatedWallet)
                }
                PayoutApprovalStatus.REJECTED
            }
        }

        val decidedRecord = proposal.copy(
            status = newStatus,
            checkerPrincipal = principal,
            checkerNotes = cmd.checkerNotes,
            decidedAt = now,
            version = proposal.version + 1
        )
        approvalStore.save(decidedRecord)

        val actionName = if (cmd.action == PayoutDecisionAction.APPROVE) "PAYOUT_APPROVED_BY_CHECKER" else "PAYOUT_REJECTED_BY_CHECKER_FUNDS_RELEASED"
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = cmd.approvalId,
            tenantId = cmd.tenantId,
            type = actionName,
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = cmd.approvalId,
            tenantId = cmd.tenantId,
            type = if (cmd.action == PayoutDecisionAction.APPROVE) "payout.approved" else "payout.rejected",
            createdAt = now
        )

        val result = PayoutApprovalResult(
            resultId = UUID.randomUUID(),
            approval = decidedRecord,
            reservationState = updatedReservation.state,
            walletBalance = updatedWallet,
            debitsEqualCredits = true,
            serverTime = now,
            serverVersion = decidedRecord.version,
            evidenceReference = proposal.evidenceReference,
            auditEvent = audit,
            outboxEvent = outbox
        )

        approvalStore.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fingerprint, result)

        observability.recordMetric(
            PayoutApprovalMetricEvent(
                eventType = "accept",
                tenantId = cmd.tenantId,
                ownerId = proposal.ownerId,
                approvalId = cmd.approvalId,
                reservationId = proposal.reservationId,
                makerId = proposal.makerPrincipal.id,
                checkerId = principal.id,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now,
                details = mapOf("status" to newStatus.name)
            )
        )

        return result
    }

    @Synchronized
    fun cancelPayoutProposal(cmd: CancelPayoutApprovalCommand): PayoutApprovalResult {
        MakerCheckerPayoutApprovalBinding.checkBound()
        validateHeaders(cmd.tenantId, cmd.correlationId, cmd.causationId, cmd.idempotencyKey)

        val principal = cmd.principal ?: throw UnauthorizedApprovalAccessException("Unauthenticated: principal is null")
        if (principal.kind != PrincipalKind.ADMIN) {
            throw UnauthorizedApprovalAccessException("Only administrators can cancel payout proposals")
        }
        if (principal.tenantId != cmd.tenantId) {
            throw UnauthorizedApprovalAccessException("Cross-tenant access forbidden: ${principal.tenantId} != ${cmd.tenantId}")
        }
        require(cmd.cancellationReason.isNotBlank()) { "cancellationReason must not be blank" }

        val fingerprint = sha256("${cmd.tenantId}:${cmd.approvalId}:${cmd.cancellationReason}:${principal.id}")
        approvalStore.findByIdempotency(cmd.tenantId, cmd.idempotencyKey)?.let { (cachedFp, cachedRes) ->
            if (cachedFp == fingerprint) {
                observability.recordMetric(
                    PayoutApprovalMetricEvent(
                        eventType = "duplicate",
                        tenantId = cmd.tenantId,
                        ownerId = cachedRes.approval.ownerId,
                        approvalId = cmd.approvalId,
                        reservationId = cachedRes.approval.reservationId,
                        makerId = cachedRes.approval.makerPrincipal.id,
                        checkerId = principal.id,
                        correlationId = cmd.correlationId,
                        causationId = cmd.causationId,
                        timestamp = clock.instant()
                    )
                )
                return cachedRes
            } else {
                throw PayoutApprovalConflictException("Idempotency key reused with differing parameters")
            }
        }

        val proposal = approvalStore.findById(cmd.tenantId, cmd.approvalId)
            ?: throw PayoutApprovalNotFoundException("Payout approval ${cmd.approvalId} not found")

        if (proposal.status != PayoutApprovalStatus.PENDING_REVIEW) {
            throw PayoutApprovalConflictException("Cannot cancel proposal in status ${proposal.status}")
        }

        // Only original maker or super admin can cancel
        if (principal.id != proposal.makerPrincipal.id && AdminRole.SUPER_ADMIN !in principal.roles) {
            throw UnauthorizedApprovalAccessException("Only the original maker or super admin can cancel this proposal")
        }

        val reservation = reservationStore.findById(proposal.reservationId)
            ?: throw PayoutApprovalNotFoundException("Reservation ${proposal.reservationId} not found")

        val now = clock.instant()
        val cancelledRecord = proposal.copy(
            status = PayoutApprovalStatus.CANCELLED,
            decidedAt = now,
            checkerNotes = "Cancelled by ${principal.id}: ${cmd.cancellationReason}",
            version = proposal.version + 1
        )
        approvalStore.save(cancelledRecord)

        var updatedReservation = reservation
        var updatedWallet = bucketStore.findWalletById(proposal.tenantId, proposal.walletId)
            ?: bucketStore.findWalletByOwnerAndCurrency(proposal.tenantId, proposal.ownerId, proposal.currencyCode)
            ?: throw PayoutApprovalNotFoundException("Wallet not found for owner ${proposal.ownerId}")

        // Explicit release policy upon operator cancellation
        if (reservation.state == WithdrawalReservationState.RESERVED) {
            updatedReservation = reservation.copy(
                state = WithdrawalReservationState.RELEASED,
                releaseReason = WithdrawalReleaseReason.OPERATOR_CANCELLED,
                releasedAt = now,
                version = reservation.version + 1
            )
            reservationStore.save(updatedReservation)

            val cash = updatedWallet.cash
            val updatedCash = cash.copy(
                availableMinorUnits = cash.availableMinorUnits + reservation.grossAmountMinorUnits,
                pendingWithdrawalMinorUnits = cash.pendingWithdrawalMinorUnits - reservation.grossAmountMinorUnits
            )

            updatedWallet = updatedWallet.copy(
                cash = updatedCash,
                updatedAt = now,
                version = updatedWallet.version + 1
            )
            bucketStore.saveWallet(updatedWallet)
        }

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = cmd.approvalId,
            tenantId = cmd.tenantId,
            type = "PAYOUT_CANCELLED_BY_OPERATOR_FUNDS_RELEASED",
            occurredAt = now,
            correlationId = cmd.correlationId,
            causationId = cmd.causationId
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = cmd.approvalId,
            tenantId = cmd.tenantId,
            type = "payout.cancelled",
            createdAt = now
        )

        val result = PayoutApprovalResult(
            resultId = UUID.randomUUID(),
            approval = cancelledRecord,
            reservationState = updatedReservation.state,
            walletBalance = updatedWallet,
            debitsEqualCredits = true,
            serverTime = now,
            serverVersion = cancelledRecord.version,
            evidenceReference = proposal.evidenceReference,
            auditEvent = audit,
            outboxEvent = outbox
        )

        approvalStore.saveIdempotency(cmd.tenantId, cmd.idempotencyKey, fingerprint, result)

        observability.recordMetric(
            PayoutApprovalMetricEvent(
                eventType = "accept",
                tenantId = cmd.tenantId,
                ownerId = proposal.ownerId,
                approvalId = cmd.approvalId,
                reservationId = proposal.reservationId,
                makerId = proposal.makerPrincipal.id,
                checkerId = principal.id,
                correlationId = cmd.correlationId,
                causationId = cmd.causationId,
                timestamp = now,
                details = mapOf("status" to PayoutApprovalStatus.CANCELLED.name)
            )
        )

        return result
    }

    fun getPayoutApproval(query: GetPayoutApprovalQuery): PayoutApprovalRecord {
        MakerCheckerPayoutApprovalBinding.checkBound()
        val principal = query.principal ?: throw UnauthorizedApprovalAccessException("Unauthenticated: principal is null")
        val record = approvalStore.findById(query.tenantId, query.approvalId)
            ?: throw PayoutApprovalNotFoundException("Payout approval ${query.approvalId} not found")

        if (principal.kind == PrincipalKind.PLAYER && principal.id != record.ownerId.toString()) {
            throw UnauthorizedApprovalAccessException("IDOR forbidden: player cannot view other players' payout approvals")
        }
        if (principal.tenantId != query.tenantId) {
            throw UnauthorizedApprovalAccessException("Cross-tenant access forbidden")
        }

        return record
    }
}
