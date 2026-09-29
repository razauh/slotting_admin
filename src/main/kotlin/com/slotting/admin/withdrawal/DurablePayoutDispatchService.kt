package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.provider.port.PaymentProviderPort
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.ProviderOutcome
import com.slotting.admin.provider.port.ProviderOutcomeStatus
import com.slotting.admin.provider.port.ProviderPayoutCommand
import com.slotting.admin.provider.port.ProviderStatusQuery
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.Duration
import java.util.UUID

@Service
class DurablePayoutDispatchService(
    private val dispatchStore: PayoutDispatchStore,
    private val withdrawalStore: AuthoritativeWithdrawalStore,
    private val ledgerPostingService: LedgerPostingService,
    private val providerPorts: Map<String, PaymentProviderPort> = emptyMap(),
    private val credentialsResolver: (tenantId: String, providerId: String) -> ProviderCredentials? = { _, _ -> null },
    private val configResolver: (tenantId: String, providerId: String) -> ProviderConfiguration? = { _, _ -> null },
    private val clock: Clock = Clock.systemUTC(),
) {
    private val log = LoggerFactory.getLogger(DurablePayoutDispatchService::class.java)

    /**
     * Stage an approved withdrawal for payout dispatch.
     * Persists the intent record in DISPATCH_READY before any network call.
     */
    fun stageDispatchIntent(command: StagePayoutDispatchCommand): PayoutDispatchIntentRecord {
        // Idempotency check by idempotencyKey
        dispatchStore.findIntentByIdempotency(command.tenantId, command.idempotencyKey)?.let { existing ->
            return existing
        }

        // Idempotency check by requestId
        dispatchStore.findIntentByRequestId(command.tenantId, command.requestId)?.let { existing ->
            return existing
        }

        val request = withdrawalStore.findRequest(command.tenantId, command.requestId)
            ?: throw IllegalArgumentException("Withdrawal request ${command.requestId} not found for tenant ${command.tenantId}")

        if (request.reviewState != WithdrawalReviewState.APPROVED) {
            throw IllegalStateException("Cannot stage payout for withdrawal request ${command.requestId}: review state is ${request.reviewState}, expected APPROVED")
        }

        val now = clock.instant()
        val intent = PayoutDispatchIntentRecord(
            intentId = UUID.randomUUID(),
            tenantId = command.tenantId,
            requestId = request.requestId,
            ownerId = request.ownerId,
            reservationId = request.reservationId,
            methodId = request.methodId,
            providerId = command.providerId,
            destinationReference = request.destinationReference,
            grossAmountMinorUnits = request.grossAmountMinorUnits,
            feeMinorUnits = request.feeMinorUnits,
            netPayoutAmountMinorUnits = request.netPayoutAmountMinorUnits,
            currencyCode = request.currencyCode,
            idempotencyKey = command.idempotencyKey,
            status = PayoutDispatchStatus.DISPATCH_READY,
            attemptCount = 0,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
        )

        return dispatchStore.saveIntent(intent)
    }

    /**
     * Leased recoverable worker dispatch:
     * Atomically claims the next dispatchable intent, marks it SENT_PENDING,
     * and executes the provider payout call.
     */
    fun dispatchNext(workerId: String, leaseDuration: Duration): PayoutDispatchResult? {
        val now = clock.instant()
        val leaseExpiresAt = now.plus(leaseDuration)

        val intent = dispatchStore.findNextDispatchable(workerId, leaseExpiresAt, now) ?: return null

        val port = providerPorts[intent.providerId]
            ?: throw IllegalStateException("Payment provider port not found for providerId: ${intent.providerId}")

        val config = configResolver(intent.tenantId, intent.providerId)
            ?: ProviderConfiguration(
                providerId = intent.providerId,
                environment = ProviderEnvironment.SANDBOX,
                baseUrl = "https://sandbox.api.test/v1",
            )
        val credentials = credentialsResolver(intent.tenantId, intent.providerId)

        val payoutCmd = ProviderPayoutCommand(
            tenantId = intent.tenantId,
            operationId = intent.intentId,
            idempotencyKey = "PAYOUT-DISPATCH-${intent.intentId}",
            providerId = intent.providerId,
            methodId = intent.methodId,
            amountMinorUnits = intent.netPayoutAmountMinorUnits,
            currency = intent.currencyCode,
            destinationAccount = intent.destinationReference,
            destinationTitle = null,
            destinationBankCode = null,
            correlationId = "corr-${intent.intentId}",
            metadata = mapOf(
                "tenantId" to intent.tenantId,
                "requestId" to intent.requestId.toString(),
                "intentId" to intent.intentId.toString(),
            ),
        )

        try {
            val outcome = port.payout(payoutCmd, config, credentials)
            return handleOutcome(intent, outcome)
        } catch (e: Exception) {
            log.warn("Network drop or provider failure during dispatch for intent {}: {}", intent.intentId, e.message)
            val updated = intent.copy(
                status = PayoutDispatchStatus.AMBIGUOUS_RECONCILING,
                failureReason = "Dispatch error: ${e.message}",
                updatedAt = clock.instant(),
                serverVersion = intent.serverVersion + 1,
            )
            dispatchStore.updateIntent(updated, intent.serverVersion)
            return PayoutDispatchResult(
                intentId = intent.intentId,
                requestId = intent.requestId,
                status = PayoutDispatchStatus.AMBIGUOUS_RECONCILING,
                providerReference = null,
                ledgerTransactionReference = null,
                failureReason = e.message,
                completedAt = clock.instant(),
            )
        }
    }

    /**
     * Authoritative reconciliation workflow:
     * Inquires provider status to resolve pending/ambiguous payout intents without duplicate ledger postings.
     */
    fun reconcilePayout(tenantId: String, intentId: UUID, actorId: String): PayoutDispatchReconciliationResult {
        val intent = dispatchStore.findIntent(tenantId, intentId)
            ?: throw IllegalArgumentException("Intent $intentId not found for tenant $tenantId")

        if (intent.status == PayoutDispatchStatus.SUCCEEDED) {
            return PayoutDispatchReconciliationResult(
                intentId = intent.intentId,
                previousStatus = PayoutDispatchStatus.SUCCEEDED,
                newStatus = PayoutDispatchStatus.SUCCEEDED,
                actionTaken = "ALREADY_FINALIZED_SUCCESS",
                ledgerTransactionReference = intent.ledgerTransactionReference,
            )
        }

        if (intent.status == PayoutDispatchStatus.FAILED_FINAL) {
            return PayoutDispatchReconciliationResult(
                intentId = intent.intentId,
                previousStatus = PayoutDispatchStatus.FAILED_FINAL,
                newStatus = PayoutDispatchStatus.FAILED_FINAL,
                actionTaken = "ALREADY_FINALIZED_FAILURE",
                ledgerTransactionReference = intent.ledgerTransactionReference,
            )
        }

        val port = providerPorts[intent.providerId]
            ?: throw IllegalStateException("Payment provider port not found for providerId: ${intent.providerId}")

        val config = configResolver(intent.tenantId, intent.providerId)
            ?: ProviderConfiguration(
                providerId = intent.providerId,
                environment = ProviderEnvironment.SANDBOX,
                baseUrl = "https://sandbox.api.test/v1",
            )
        val credentials = credentialsResolver(intent.tenantId, intent.providerId)

        val query = ProviderStatusQuery(
            tenantId = intent.tenantId,
            operationId = intent.intentId,
            providerId = intent.providerId,
            providerReference = intent.providerReference,
            idempotencyKey = "PAYOUT-QUERY-${intent.intentId}",
        )

        val outcome = port.queryStatus(query, config, credentials)

        return when (outcome.status) {
            ProviderOutcomeStatus.ACCEPTED -> {
                val ledgerTxRef = postSuccessLedgerTransaction(intent)
                val updated = intent.copy(
                    status = PayoutDispatchStatus.SUCCEEDED,
                    providerReference = outcome.providerReference ?: intent.providerReference,
                    ledgerTransactionReference = ledgerTxRef,
                    failureReason = null,
                    updatedAt = clock.instant(),
                    serverVersion = intent.serverVersion + 1,
                )
                dispatchStore.updateIntent(updated, intent.serverVersion)
                dispatchStore.recordAudit(
                    PayoutReconciliationAuditRecord(
                        auditId = UUID.randomUUID(),
                        tenantId = tenantId,
                        intentId = intentId,
                        actionType = "RECONCILE_ACCEPTED",
                        previousStatus = intent.status,
                        newStatus = PayoutDispatchStatus.SUCCEEDED,
                        operatorId = actorId,
                        notes = "Reconciliation confirmed accepted outcome",
                        occurredAt = clock.instant(),
                    )
                )
                PayoutDispatchReconciliationResult(
                    intentId = intent.intentId,
                    previousStatus = intent.status,
                    newStatus = PayoutDispatchStatus.SUCCEEDED,
                    actionTaken = "RESOLVED_ACCEPTED",
                    ledgerTransactionReference = ledgerTxRef,
                )
            }
            ProviderOutcomeStatus.DECLINED, ProviderOutcomeStatus.FAILED -> {
                // Compensating release of reserved funds back to available balance
                withdrawalStore.releaseReservedBalance(
                    intent.tenantId,
                    intent.ownerId,
                    intent.currencyCode,
                    intent.grossAmountMinorUnits,
                )
                val ledgerTxRef = postCompensatingLedgerTransaction(intent, outcome.safeReason ?: "Provider query declined payout")
                val updated = intent.copy(
                    status = PayoutDispatchStatus.FAILED_FINAL,
                    providerReference = outcome.providerReference ?: intent.providerReference,
                    ledgerTransactionReference = ledgerTxRef,
                    failureReason = outcome.safeReason ?: "Provider confirmed failure",
                    updatedAt = clock.instant(),
                    serverVersion = intent.serverVersion + 1,
                )
                dispatchStore.updateIntent(updated, intent.serverVersion)
                dispatchStore.recordAudit(
                    PayoutReconciliationAuditRecord(
                        auditId = UUID.randomUUID(),
                        tenantId = tenantId,
                        intentId = intentId,
                        actionType = "RECONCILE_FAILED",
                        previousStatus = intent.status,
                        newStatus = PayoutDispatchStatus.FAILED_FINAL,
                        operatorId = actorId,
                        notes = outcome.safeReason ?: "Reconciliation confirmed failed outcome",
                        occurredAt = clock.instant(),
                    )
                )
                PayoutDispatchReconciliationResult(
                    intentId = intent.intentId,
                    previousStatus = intent.status,
                    newStatus = PayoutDispatchStatus.FAILED_FINAL,
                    actionTaken = "RESOLVED_FAILED",
                    ledgerTransactionReference = ledgerTxRef,
                )
            }
            else -> {
                // Still ambiguous or pending
                PayoutDispatchReconciliationResult(
                    intentId = intent.intentId,
                    previousStatus = intent.status,
                    newStatus = intent.status,
                    actionTaken = "STILL_AMBIGUOUS",
                    ledgerTransactionReference = null,
                )
            }
        }
    }

    /**
     * Escalate stuck ambiguous payout intent to MANUAL_REVIEW.
     */
    fun escalateStuckIntent(intentId: UUID, tenantId: String): PayoutDispatchIntentRecord {
        val intent = dispatchStore.findIntent(tenantId, intentId)
            ?: throw IllegalArgumentException("Intent $intentId not found for tenant $tenantId")

        val updated = intent.copy(
            status = PayoutDispatchStatus.MANUAL_REVIEW,
            updatedAt = clock.instant(),
            serverVersion = intent.serverVersion + 1,
        )
        dispatchStore.updateIntent(updated, intent.serverVersion)
        dispatchStore.recordAudit(
            PayoutReconciliationAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = tenantId,
                intentId = intentId,
                actionType = "ESCALATE_MANUAL_REVIEW",
                previousStatus = intent.status,
                newStatus = PayoutDispatchStatus.MANUAL_REVIEW,
                operatorId = "system-escalation",
                notes = "Intent escalated to manual review due to retry exhaustion",
                occurredAt = clock.instant(),
            )
        )
        return updated
    }

    /**
     * Audited operator escalation:
     * Resolves stuck MANUAL_REVIEW payouts strictly through double-entry ledger postings.
     * Auditor role is forbidden from resolving.
     */
    fun operatorResolveManualReview(command: OperatorPayoutResolutionCommand): PayoutDispatchIntentRecord {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (principal.roles.contains(AdminRole.AUDITOR) || principal.roles.none { it in setOf(AdminRole.SUPER_ADMIN, AdminRole.SECURITY) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val intent = dispatchStore.findIntent(command.tenantId, command.intentId)
            ?: throw IllegalArgumentException("Intent ${command.intentId} not found for tenant ${command.tenantId}")

        if (intent.status != PayoutDispatchStatus.MANUAL_REVIEW) {
            throw IllegalStateException("Intent ${intent.intentId} is not in MANUAL_REVIEW state (current: ${intent.status})")
        }

        return when (command.resolution) {
            OperatorResolutionAction.FORCE_SUCCESS -> {
                val ledgerTxRef = postSuccessLedgerTransaction(intent, principal)
                val updated = intent.copy(
                    status = PayoutDispatchStatus.SUCCEEDED,
                    ledgerTransactionReference = ledgerTxRef,
                    updatedAt = clock.instant(),
                    serverVersion = intent.serverVersion + 1,
                )
                dispatchStore.updateIntent(updated, intent.serverVersion)
                dispatchStore.recordAudit(
                    PayoutReconciliationAuditRecord(
                        auditId = UUID.randomUUID(),
                        tenantId = command.tenantId,
                        intentId = command.intentId,
                        actionType = "OPERATOR_FORCE_SUCCESS",
                        previousStatus = PayoutDispatchStatus.MANUAL_REVIEW,
                        newStatus = PayoutDispatchStatus.SUCCEEDED,
                        operatorId = principal.id,
                        notes = command.notes,
                        occurredAt = clock.instant(),
                    )
                )
                updated
            }
            OperatorResolutionAction.FORCE_FAILURE -> {
                withdrawalStore.releaseReservedBalance(
                    intent.tenantId,
                    intent.ownerId,
                    intent.currencyCode,
                    intent.grossAmountMinorUnits,
                )
                val ledgerTxRef = postCompensatingLedgerTransaction(intent, command.notes, principal)
                val updated = intent.copy(
                    status = PayoutDispatchStatus.FAILED_FINAL,
                    ledgerTransactionReference = ledgerTxRef,
                    failureReason = command.notes,
                    updatedAt = clock.instant(),
                    serverVersion = intent.serverVersion + 1,
                )
                dispatchStore.updateIntent(updated, intent.serverVersion)
                dispatchStore.recordAudit(
                    PayoutReconciliationAuditRecord(
                        auditId = UUID.randomUUID(),
                        tenantId = command.tenantId,
                        intentId = command.intentId,
                        actionType = "OPERATOR_FORCE_FAILURE",
                        previousStatus = PayoutDispatchStatus.MANUAL_REVIEW,
                        newStatus = PayoutDispatchStatus.FAILED_FINAL,
                        operatorId = principal.id,
                        notes = command.notes,
                        occurredAt = clock.instant(),
                    )
                )
                updated
            }
        }
    }

    private fun handleOutcome(intent: PayoutDispatchIntentRecord, outcome: ProviderOutcome): PayoutDispatchResult {
        return when (outcome.status) {
            ProviderOutcomeStatus.ACCEPTED -> {
                val ledgerTxRef = postSuccessLedgerTransaction(intent)
                val updated = intent.copy(
                    status = PayoutDispatchStatus.SUCCEEDED,
                    providerReference = outcome.providerReference,
                    ledgerTransactionReference = ledgerTxRef,
                    failureReason = null,
                    updatedAt = clock.instant(),
                    serverVersion = intent.serverVersion + 1,
                )
                dispatchStore.updateIntent(updated, intent.serverVersion)
                PayoutDispatchResult(
                    intentId = intent.intentId,
                    requestId = intent.requestId,
                    status = PayoutDispatchStatus.SUCCEEDED,
                    providerReference = outcome.providerReference,
                    ledgerTransactionReference = ledgerTxRef,
                    completedAt = clock.instant(),
                )
            }
            ProviderOutcomeStatus.DECLINED, ProviderOutcomeStatus.FAILED -> {
                withdrawalStore.releaseReservedBalance(
                    intent.tenantId,
                    intent.ownerId,
                    intent.currencyCode,
                    intent.grossAmountMinorUnits,
                )
                val ledgerTxRef = postCompensatingLedgerTransaction(intent, outcome.safeReason ?: "Provider declined payout")
                val updated = intent.copy(
                    status = PayoutDispatchStatus.FAILED_FINAL,
                    providerReference = outcome.providerReference,
                    ledgerTransactionReference = ledgerTxRef,
                    failureReason = outcome.safeReason ?: "Provider declined payout",
                    updatedAt = clock.instant(),
                    serverVersion = intent.serverVersion + 1,
                )
                dispatchStore.updateIntent(updated, intent.serverVersion)
                PayoutDispatchResult(
                    intentId = intent.intentId,
                    requestId = intent.requestId,
                    status = PayoutDispatchStatus.FAILED_FINAL,
                    providerReference = outcome.providerReference,
                    ledgerTransactionReference = ledgerTxRef,
                    failureReason = outcome.safeReason,
                    completedAt = clock.instant(),
                )
            }
            else -> {
                // Ambiguous / pending
                val updated = intent.copy(
                    status = PayoutDispatchStatus.AMBIGUOUS_RECONCILING,
                    providerReference = outcome.providerReference,
                    failureReason = outcome.safeReason ?: "Ambiguous outcome: ${outcome.status}",
                    updatedAt = clock.instant(),
                    serverVersion = intent.serverVersion + 1,
                )
                dispatchStore.updateIntent(updated, intent.serverVersion)
                PayoutDispatchResult(
                    intentId = intent.intentId,
                    requestId = intent.requestId,
                    status = PayoutDispatchStatus.AMBIGUOUS_RECONCILING,
                    providerReference = outcome.providerReference,
                    ledgerTransactionReference = null,
                    failureReason = outcome.safeReason,
                    completedAt = clock.instant(),
                )
            }
        }
    }

    private fun postSuccessLedgerTransaction(
        intent: PayoutDispatchIntentRecord,
        customPrincipal: AuthenticatedPrincipal? = null,
    ): String {
        val principal = customPrincipal ?: AuthenticatedPrincipal(
            id = "system-payout-dispatcher",
            tenantId = intent.tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )

        val entries = mutableListOf(
            JournalEntryDraft(
                accountReference = "gateway:clearing:${intent.providerId}",
                direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = intent.netPayoutAmountMinorUnits,
                currencyCode = intent.currencyCode,
                narration = "Payout settlement gateway clearing credit for intent ${intent.intentId}",
            ),
            JournalEntryDraft(
                accountReference = "settlement:payout:${intent.requestId}",
                direction = JournalEntryDirection.DEBIT,
                amountMinorUnits = intent.netPayoutAmountMinorUnits,
                currencyCode = intent.currencyCode,
                narration = "Payout settlement debit for intent ${intent.intentId}",
            )
        )

        if (intent.feeMinorUnits > 0L) {
            entries.add(
                JournalEntryDraft(
                    accountReference = "platform:fee:withdrawal",
                    direction = JournalEntryDirection.CREDIT,
                    amountMinorUnits = intent.feeMinorUnits,
                    currencyCode = intent.currencyCode,
                    narration = "Payout fee revenue credit for intent ${intent.intentId}",
                )
            )
            entries.add(
                JournalEntryDraft(
                    accountReference = "settlement:payout:${intent.requestId}",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = intent.feeMinorUnits,
                    currencyCode = intent.currencyCode,
                    narration = "Payout fee debit for intent ${intent.intentId}",
                )
            )
        }

        val txRef = "TX-PAYOUT-${intent.intentId}"
        val postCmd = PostTransactionCommand(
            principal = principal,
            tenantId = intent.tenantId,
            transactionReference = txRef,
            currencyCode = intent.currencyCode,
            entries = entries,
            idempotencyKey = "LEDGER-PAYOUT-SETTLE-${intent.intentId}",
            correlationId = "corr-payout-${intent.intentId}",
            causationId = "caus-payout-${intent.intentId}",
        )
        val result = ledgerPostingService.postTransaction(postCmd)
        return result.transactionReference
    }

    private fun postCompensatingLedgerTransaction(
        intent: PayoutDispatchIntentRecord,
        reason: String,
        customPrincipal: AuthenticatedPrincipal? = null,
    ): String {
        val principal = customPrincipal ?: AuthenticatedPrincipal(
            id = "system-payout-dispatcher",
            tenantId = intent.tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )

        val entries = listOf(
            JournalEntryDraft(
                accountReference = "settlement:payout:${intent.requestId}",
                direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = intent.grossAmountMinorUnits,
                currencyCode = intent.currencyCode,
                narration = "Compensating payout settlement release: $reason",
            ),
            JournalEntryDraft(
                accountReference = "player:wallet:${intent.ownerId}",
                direction = JournalEntryDirection.DEBIT,
                amountMinorUnits = intent.grossAmountMinorUnits,
                currencyCode = intent.currencyCode,
                narration = "Compensating player wallet restoration for failed payout ${intent.intentId}",
            ),
        )

        val txRef = "TX-COMP-PAYOUT-${intent.intentId}"
        val postCmd = PostTransactionCommand(
            principal = principal,
            tenantId = intent.tenantId,
            transactionReference = txRef,
            currencyCode = intent.currencyCode,
            entries = entries,
            idempotencyKey = "LEDGER-PAYOUT-COMP-${intent.intentId}",
            correlationId = "corr-comp-${intent.intentId}",
            causationId = "caus-comp-${intent.intentId}",
        )
        val result = ledgerPostingService.postTransaction(postCmd)
        return result.transactionReference
    }
}
