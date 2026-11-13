package com.slotting.admin.rails

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.security.SecurityAuthenticationFilter
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.util.UUID

data class FundingAccountAdminView(
    val id: String,
    val type: String,
    val accountTitle: String,
    val accountNumber: String,
    val instructions: String?,
    val sortOrder: Int,
    val visible: Boolean,
)

data class FundingAccountCreateRequest(
    val type: String,
    val accountTitle: String,
    val accountNumber: String,
    val instructions: String? = null,
    val sortOrder: Int = 0,
    val visible: Boolean = true,
)

data class FundingAccountVisibilityRequest(val visible: Boolean)

data class ManualRailsSettingsRequest(
    val depositRatePkrPerUsd: BigDecimal,
    val payoutRatePkrPerUsd: BigDecimal,
    val withdrawalFeePercent: BigDecimal,
    val payoutSlaWorkingDays: Int,
)

data class ManualRailsSettingsView(
    val depositRatePkrPerUsd: String,
    val payoutRatePkrPerUsd: String,
    val withdrawalFeePercent: String,
    val payoutSlaWorkingDays: Int,
)

data class DepositQueueItemView(
    val id: String,
    val playerId: String,
    val amountPkr: String,
    val transferReference: String,
    val transferredUtc: String,
    val fundingAccountTitle: String,
    val fundingAccountNumber: String,
    val status: String,
    val receiptUrl: String,
)

data class DepositDecisionResponse(
    val id: String,
    val status: String,
    val amountUsd: String?,
    val rateApplied: String?,
)

@RestController
@RequestMapping("/admin/rails")
class AdminFundingController(
    private val accounts: RailsFundingAccountStore,
    private val settings: ManualRailsSettingsStore,
    private val submissions: DepositSubmissionRepository,
    private val queue: DepositQueueStore,
    private val ledgerPostingService: LedgerPostingService,
    private val receipts: ManualRailsReceiptService,
    private val audit: RailsAuditRecorder,
    private val clock: Clock = Clock.systemUTC(),
    private val rbac: AdminRbacPolicy = AdminRbacPolicy(true),
) {
    @GetMapping("/accounts")
    fun listAccounts(
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): List<FundingAccountAdminView> {
        val admin = requireAdmin(principal)
        return accounts.listAll(admin.tenantId).map { it.toAdminView() }
    }

    @PostMapping("/accounts")
    fun createAccount(
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody request: FundingAccountCreateRequest,
    ): ResponseEntity<FundingAccountAdminView> {
        val admin = requireAdmin(principal)
        if (request.type !in setOf("BANK", "RAAST", "EASYPAISA", "JAZZCASH")) {
            throw RailsHttpException("INVALID_ACCOUNT_TYPE", HttpStatus.BAD_REQUEST, "account type is invalid")
        }
        if (request.accountTitle.isBlank() || request.accountNumber.isBlank()) {
            throw RailsHttpException("INVALID_ACCOUNT", HttpStatus.BAD_REQUEST, "account title and number are required")
        }
        val account = FundingAccount(
            id = UUID.randomUUID().toString(),
            tenantId = admin.tenantId,
            type = request.type,
            accountTitle = request.accountTitle,
            accountNumber = request.accountNumber,
            instructions = request.instructions,
            sortOrder = request.sortOrder,
            visible = request.visible,
        )
        accounts.insert(account)
        audit.record(RailsAuditEntry(admin.tenantId, admin.id, "FUNDING_ACCOUNT_CREATED", account.id, null, "${account.type}:${account.accountTitle}", Instant.now(clock)))
        return ResponseEntity.status(HttpStatus.CREATED).body(account.toAdminView())
    }

    @PutMapping("/accounts/{id}")
    fun updateAccountVisibility(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody request: Map<String, Boolean>,
    ): FundingAccountAdminView {
        val admin = requireAdmin(principal)
        val visible = request["visible"] ?: throw RailsHttpException("INVALID_VISIBILITY", HttpStatus.BAD_REQUEST, "visible is required")
        val before = accounts.find(id) ?: throw RailsHttpException("FUNDING_ACCOUNT_NOT_FOUND", HttpStatus.NOT_FOUND, "funding account not found")
        if (before.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (!accounts.updateVisibility(id, visible)) {
            throw RailsHttpException("FUNDING_ACCOUNT_NOT_FOUND", HttpStatus.NOT_FOUND, "funding account not found")
        }
        audit.record(RailsAuditEntry(admin.tenantId, admin.id, "FUNDING_ACCOUNT_VISIBILITY", id, before.visible.toString(), visible.toString(), Instant.now(clock)))
        return (accounts.find(id) ?: before.copy(visible = visible)).toAdminView()
    }

    @DeleteMapping("/accounts/{id}")
    fun deleteAccount(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): Map<String, Any> {
        val admin = requireAdmin(principal)
        val before = accounts.find(id) ?: throw RailsHttpException("FUNDING_ACCOUNT_NOT_FOUND", HttpStatus.NOT_FOUND, "funding account not found")
        if (before.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (!accounts.deleteIfUnreferenced(id)) {
            throw RailsHttpException("FUNDING_ACCOUNT_REFERENCED", HttpStatus.CONFLICT, "funding account is referenced by a deposit submission")
        }
        audit.record(RailsAuditEntry(admin.tenantId, admin.id, "FUNDING_ACCOUNT_DELETED", id, before.accountTitle, null, Instant.now(clock)))
        return mapOf("id" to id, "deleted" to true)
    }

    @GetMapping("/settings")
    fun getSettings(
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): ManualRailsSettingsView {
        requireAdmin(principal)
        return settings.get().toView()
    }

    @PutMapping("/settings")
    fun updateSettings(
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody request: ManualRailsSettingsRequest,
    ): ManualRailsSettingsView {
        val admin = requireAdmin(principal)
        if (request.depositRatePkrPerUsd <= BigDecimal.ZERO || request.payoutRatePkrPerUsd <= BigDecimal.ZERO) {
            throw RailsHttpException("INVALID_RATE", HttpStatus.BAD_REQUEST, "rates must be positive")
        }
        if (request.withdrawalFeePercent < BigDecimal.ZERO || request.withdrawalFeePercent > BigDecimal(100)) {
            throw RailsHttpException("INVALID_FEE", HttpStatus.BAD_REQUEST, "fee percent must be between 0 and 100")
        }
        if (request.payoutSlaWorkingDays !in 1..30) {
            throw RailsHttpException("INVALID_SLA", HttpStatus.BAD_REQUEST, "SLA must be between 1 and 30 working days")
        }
        val before = settings.get()
        val after = ManualRailsSettings(request.depositRatePkrPerUsd, request.payoutRatePkrPerUsd, request.withdrawalFeePercent, request.payoutSlaWorkingDays)
        settings.update(after, admin.id)
        audit.record(RailsAuditEntry(admin.tenantId, admin.id, "MANUAL_RAILS_SETTINGS", "settings", before.toString(), after.toString(), Instant.now(clock)))
        return after.toView()
    }

    @GetMapping("/deposit-submissions")
    fun depositQueue(
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestParam(required = false, defaultValue = "SUBMITTED") status: String,
    ): List<DepositQueueItemView> {
        val admin = requireAdmin(principal)
        if (status != "SUBMITTED") {
            throw RailsHttpException("INVALID_QUEUE_STATUS", HttpStatus.BAD_REQUEST, "only SUBMITTED is supported")
        }
        return queue.listSubmitted(admin.tenantId).map {
            DepositQueueItemView(
                id = it.id,
                playerId = it.playerId,
                amountPkr = it.amountPkr.toPlainString(),
                transferReference = it.transferReference,
                transferredUtc = it.transferredUtc.toString(),
                fundingAccountTitle = it.fundingAccountTitle,
                fundingAccountNumber = it.fundingAccountNumber,
                status = it.status.name,
                receiptUrl = receipts.readUrl(it.tenantId, it.playerId, it.receiptObject).url,
            )
        }
    }

    @PostMapping("/deposit-submissions/{id}/approve")
    fun approve(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): DepositDecisionResponse {
        val admin = requireAdmin(principal)
        val row = queue.find(id) ?: throw RailsHttpException("DEPOSIT_SUBMISSION_NOT_FOUND", HttpStatus.NOT_FOUND, "deposit submission not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val current = submissions.find(id)
        if (current?.status == SubmissionStatus.APPROVED) {
            runApproval(id, admin.id)
            throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "deposit submission was already approved")
        }
        if (current?.status == SubmissionStatus.REJECTED) {
            throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "deposit submission was already rejected")
        }
        val result = runApproval(id, admin.id)
        when (result.outcome) {
            ApprovalOutcome.APPROVED -> {
                audit.record(RailsAuditEntry(admin.tenantId, admin.id, "DEPOSIT_APPROVED", id, row.status.name, "${result.rateApplied}:${result.amountUsd}", Instant.now(clock)))
                return DepositDecisionResponse(
                    id = id,
                    status = SubmissionStatus.APPROVED.name,
                    amountUsd = result.amountUsd?.toPlainString(),
                    rateApplied = result.rateApplied?.toPlainString(),
                )
            }
            ApprovalOutcome.ALREADY_DECIDED -> throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "deposit submission was already decided")
            ApprovalOutcome.NOT_FOUND -> throw RailsHttpException("DEPOSIT_SUBMISSION_NOT_FOUND", HttpStatus.NOT_FOUND, "deposit submission not found")
        }
    }

    @PostMapping("/deposit-submissions/{id}/reject")
    fun reject(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody request: Map<String, String>,
    ): DepositDecisionResponse {
        val admin = requireAdmin(principal)
        val reason = request["reason"]?.trim().orEmpty()
        if (reason.isBlank()) {
            throw RailsHttpException("REJECT_REASON_REQUIRED", HttpStatus.BAD_REQUEST, "reason is required")
        }
        val row = queue.find(id) ?: throw RailsHttpException("DEPOSIT_SUBMISSION_NOT_FOUND", HttpStatus.NOT_FOUND, "deposit submission not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (row.status != SubmissionStatus.SUBMITTED) {
            throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "deposit submission was already decided")
        }
        val service = ManualRailsService(submissions, { settings.get().depositRate }) { _, _ -> }
        val result = service.reject(id, reason, admin.id)
        if (result.outcome != ApprovalOutcome.APPROVED) {
            throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "deposit submission was already decided")
        }
        audit.record(RailsAuditEntry(admin.tenantId, admin.id, "DEPOSIT_REJECTED", id, row.status.name, reason, Instant.now(clock)))
        return DepositDecisionResponse(id, SubmissionStatus.REJECTED.name, null, null)
    }

    @GetMapping("/deposit-submissions/{id}/receipt")
    fun depositReceipt(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): Map<String, Any> {
        val admin = requireAdmin(principal)
        val row = queue.find(id) ?: throw RailsHttpException("DEPOSIT_SUBMISSION_NOT_FOUND", HttpStatus.NOT_FOUND, "deposit submission not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val signed = receipts.readUrl(row.tenantId, row.playerId, row.receiptObject)
        return mapOf("id" to id, "url" to signed.url, "expiresInSeconds" to signed.expiresInSeconds)
    }

    private fun runApproval(id: String, adminId: String): ApprovalResult {
        val row = submissions.find(id) ?: return ApprovalResult(ApprovalOutcome.NOT_FOUND)
        val poster = LedgerDepositCreditPoster(ledgerPostingService)
        val service = ManualRailsService(submissions, { settings.get().depositRate }) { playerId, usd ->
            poster.post(row.tenantId, playerId, usd, id)
        }
        val flow = ManualRailsApprovalFlow(submissions, service, poster)
        return flow.approve(id, adminId)
    }

    private fun requireAdmin(principal: AuthenticatedPrincipal?): AuthenticatedPrincipal {
        val caller = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (caller.kind != PrincipalKind.ADMIN) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (!rbac.isPermitted(caller, AdminPermission.OPERATIONS_MANAGE)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return caller
    }

    private fun FundingAccount.toAdminView() = FundingAccountAdminView(id, type, accountTitle, accountNumber, instructions, sortOrder, visible)
    private fun ManualRailsSettings.toView() = ManualRailsSettingsView(
        depositRate.stripTrailingZeros().toPlainString(),
        payoutRate.stripTrailingZeros().toPlainString(),
        feePercent.stripTrailingZeros().toPlainString(),
        slaWorkingDays,
    )
}
