package com.slotting.admin.rails

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.security.SecurityAuthenticationFilter
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.math.BigDecimal
import java.math.RoundingMode
import java.time.Instant
import java.util.UUID

data class FundingAccountsView(
    val accounts: List<FundingAccountView>,
    val depositRatePkrPerUsd: String,
    val slaWorkingDays: Int,
    val slaText: String,
)

data class FundingAccountView(
    val id: String,
    val type: String,
    val accountTitle: String,
    val accountNumber: String,
    val instructions: String?,
    val sortOrder: Int,
)

data class UploadUrlRequest(
    val fileName: String,
    val contentType: String,
)

data class UploadUrlView(
    val uploadUrl: String,
    val objectPath: String,
    val expiresInSeconds: Long,
)

data class ManualDepositSubmissionRequest(
    val amountPkr: BigDecimal,
    val transferReference: String,
    val transferredUtc: String,
    val fundingAccountId: String,
    val receiptObject: String,
)

data class ManualDepositSubmissionView(
    val id: String,
    val amountPkr: String,
    val status: String,
    val amountUsd: String?,
    val rateApplied: String?,
    val rejectReason: String?,
    val estimateUsd: String?,
)

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/deposits")
class PlayerFundingController(
    private val accounts: RailsFundingAccountStore,
    private val settings: ManualRailsSettingsStore,
    private val submissions: DepositSubmissionRepository,
    private val receipts: ManualRailsReceiptService,
) {
    @GetMapping("/accounts")
    fun accounts(
        @PathVariable tenantId: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): FundingAccountsView {
        val player = requirePlayer(principal, tenantId)
        val current = settings.get()
        return FundingAccountsView(
            accounts = accounts.listVisible(tenantId).map {
                FundingAccountView(it.id, it.type, it.accountTitle, it.accountNumber, it.instructions, it.sortOrder)
            },
            depositRatePkrPerUsd = current.depositRate.stripTrailingZeros().toPlainString(),
            slaWorkingDays = current.slaWorkingDays,
            slaText = "Deposits are reviewed manually; credit appears after admin approval.",
        ).also { player }
    }

    @PostMapping("/manual-submissions/upload-url")
    fun uploadUrl(
        @PathVariable tenantId: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody request: UploadUrlRequest,
    ): UploadUrlView {
        val player = requirePlayer(principal, tenantId)
        receipts.requireImage(request.fileName, request.contentType)
        val path = receipts.depositObjectPath(tenantId, player.id, request.fileName)
        val signed = receipts.uploadUrl(tenantId, player.id, path)
        return UploadUrlView(signed.url, path, signed.expiresInSeconds)
    }

    @PostMapping("/manual-submissions")
    fun submit(
        @PathVariable tenantId: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody request: ManualDepositSubmissionRequest,
    ): ResponseEntity<ManualDepositSubmissionView> {
        val player = requirePlayer(principal, tenantId)
        if (request.amountPkr <= BigDecimal.ZERO) {
            throw RailsHttpException("INVALID_AMOUNT", HttpStatus.BAD_REQUEST, "amountPkr must be positive")
        }
        if (request.transferReference.isBlank()) {
            throw RailsHttpException("INVALID_REFERENCE", HttpStatus.BAD_REQUEST, "transferReference is required")
        }
        val account = accounts.find(request.fundingAccountId)
            ?: throw RailsHttpException("FUNDING_ACCOUNT_NOT_FOUND", HttpStatus.NOT_FOUND, "funding account not found")
        if (!account.visible || account.tenantId != tenantId) {
            throw RailsHttpException("FUNDING_ACCOUNT_NOT_AVAILABLE", HttpStatus.BAD_REQUEST, "funding account is not available")
        }
        if (!request.receiptObject.startsWith("$tenantId/${player.id}/deposit-receipts/")) {
            throw RailsHttpException("INVALID_RECEIPT_PATH", HttpStatus.BAD_REQUEST, "receipt path is outside the player deposit scope")
        }
        val transferred = try {
            Instant.parse(request.transferredUtc)
        } catch (_: Exception) {
            throw RailsHttpException("INVALID_TRANSFERRED_TIME", HttpStatus.BAD_REQUEST, "transferredUtc must be an ISO instant")
        }
        val id = UUID.randomUUID().toString()
        val submission = DepositSubmission(
            id = id,
            tenantId = tenantId,
            playerId = player.id,
            amountPkr = request.amountPkr,
            status = SubmissionStatus.SUBMITTED,
        )
        submissions.insert(submission, account.id, request.transferReference, transferred, request.receiptObject)
        return ResponseEntity.status(HttpStatus.CREATED).body(
            ManualDepositSubmissionView(id, request.amountPkr.toPlainString(), SubmissionStatus.SUBMITTED.name, null, null, null, estimate(request.amountPkr, settings.get())),
        )
    }

    @GetMapping("/manual-submissions/mine")
    fun mine(
        @PathVariable tenantId: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): List<ManualDepositSubmissionView> {
        val player = requirePlayer(principal, tenantId)
        val current = settings.get()
        return submissions.listMine(tenantId, player.id).map { row ->
            ManualDepositSubmissionView(
                id = row.id,
                amountPkr = row.amountPkr.toPlainString(),
                status = row.status.name,
                amountUsd = row.amountUsd?.toPlainString(),
                rateApplied = row.rateApplied?.toPlainString(),
                rejectReason = row.rejectReason,
                estimateUsd = if (row.status == SubmissionStatus.SUBMITTED) estimate(row.amountPkr, current) else null,
            )
        }
    }

    private fun estimate(amountPkr: BigDecimal, current: ManualRailsSettings): String =
        amountPkr.divide(current.depositRate, 2, RoundingMode.HALF_UP).toPlainString()

    private fun requirePlayer(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        val caller = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (caller.tenantId != tenantId || caller.kind != PrincipalKind.PLAYER) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return caller
    }
}
