package com.slotting.admin.rails

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.security.SecurityAuthenticationFilter
import com.slotting.admin.wallet.AuthoritativeWalletStore
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.math.BigDecimal
import java.math.RoundingMode

data class ManualWithdrawalQuoteView(
    val amountUsd: String,
    val feeUsd: String,
    val netUsd: String,
    val payoutPkr: String,
    val payoutRatePkrPerUsd: String,
    val slaWorkingDays: Int,
    val slaText: String,
)

data class ManualWithdrawalRequest(
    val amountUsd: BigDecimal,
    val destType: String,
    val destTitle: String,
    val destNumber: String,
)

data class ManualWithdrawalView(
    val id: String,
    val amountUsd: String,
    val feeUsd: String,
    val netUsd: String,
    val payoutPkr: String,
    val status: String,
    val rejectReason: String?,
    val paidUtc: String?,
    val receiptUrl: String?,
)

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/withdrawals/manual-requests")
class PlayerManualWithdrawalController(
    private val settings: ManualRailsSettingsStore,
    private val requests: PayoutRequestRepository,
    private val queue: PayoutQueueStore,
    private val walletStore: AuthoritativeWalletStore,
    private val receipts: ManualRailsReceiptService,
) {
    @GetMapping("/quote")
    fun quote(
        @PathVariable tenantId: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestParam amount: BigDecimal,
    ): ManualWithdrawalQuoteView {
        requirePlayer(principal, tenantId)
        if (amount <= BigDecimal.ZERO) {
            throw RailsHttpException("INVALID_AMOUNT", HttpStatus.BAD_REQUEST, "amount must be positive")
        }
        return quoteFor(amount, settings.get())
    }

    @PostMapping
    fun request(
        @PathVariable tenantId: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody body: ManualWithdrawalRequest,
    ): ResponseEntity<Any> {
        val player = requirePlayer(principal, tenantId)
        if (body.amountUsd <= BigDecimal.ZERO) {
            throw RailsHttpException("INVALID_AMOUNT", HttpStatus.BAD_REQUEST, "amountUsd must be positive")
        }
        if (body.destType !in setOf("BANK", "RAAST", "EASYPAISA", "JAZZCASH")) {
            throw RailsHttpException("INVALID_DESTINATION_TYPE", HttpStatus.BAD_REQUEST, "destination type is invalid")
        }
        if (body.destTitle.isBlank() || body.destNumber.isBlank()) {
            throw RailsHttpException("INVALID_DESTINATION", HttpStatus.BAD_REQUEST, "destination title and number are required")
        }
        val current = settings.get()
        val availableMinor = walletStore.findBalance(tenantId, "PLAYER:${player.id}", "USD")
        val availableUsd = BigDecimal.valueOf(availableMinor).movePointLeft(2)
        val flow = ManualPayoutFlow(requests, PayoutSettings(current.payoutRate, current.feePercent))
        val result = flow.request(
            tenantId = tenantId,
            playerId = player.id,
            amountUsd = body.amountUsd.setScale(2, RoundingMode.HALF_UP),
            availableUsd = availableUsd,
            destType = body.destType,
            destTitle = body.destTitle,
            destNumber = body.destNumber,
        )
        return when (result.outcome) {
            PayoutOutcome.CREATED -> ResponseEntity.status(HttpStatus.CREATED).body(quoteFor(body.amountUsd, current))
            PayoutOutcome.INSUFFICIENT_AVAILABLE_BALANCE ->
                throw RailsHttpException("INSUFFICIENT_AVAILABLE_BALANCE", HttpStatus.UNPROCESSABLE_ENTITY, "insufficient available balance")
            PayoutOutcome.NOT_FOUND -> throw RailsHttpException("NOT_FOUND", HttpStatus.NOT_FOUND, "request not found")
            else -> throw RailsHttpException("INVALID_STATE", HttpStatus.CONFLICT, "withdrawal request is not in a valid state")
        }
    }

    @GetMapping("/mine")
    fun mine(
        @PathVariable tenantId: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): List<ManualWithdrawalView> {
        val player = requirePlayer(principal, tenantId)
        return queue.listMine(tenantId, player.id).map {
            ManualWithdrawalView(
                id = it.id,
                amountUsd = it.amountUsd.toPlainString(),
                feeUsd = it.feeUsd.toPlainString(),
                netUsd = it.netUsd.toPlainString(),
                payoutPkr = it.payoutPkr.toPlainString(),
                status = it.status.name,
                rejectReason = it.rejectReason,
                paidUtc = it.paidUtc?.toString(),
                receiptUrl = it.receiptObject?.let { path -> receipts.readUrl(it.tenantId, it.playerId, path).url },
            )
        }
    }

    private fun quoteFor(amount: BigDecimal, current: ManualRailsSettings): ManualWithdrawalQuoteView {
        val fee = amount.multiply(current.feePercent).divide(BigDecimal(100), 2, RoundingMode.HALF_UP)
        val net = amount.subtract(fee)
        val pkr = net.multiply(current.payoutRate).setScale(2, RoundingMode.HALF_UP)
        return ManualWithdrawalQuoteView(
            amountUsd = amount.setScale(2, RoundingMode.HALF_UP).toPlainString(),
            feeUsd = fee.toPlainString(),
            netUsd = net.toPlainString(),
            payoutPkr = pkr.toPlainString(),
            payoutRatePkrPerUsd = current.payoutRate.stripTrailingZeros().toPlainString(),
            slaWorkingDays = current.slaWorkingDays,
            slaText = "Manual payout; allow up to ${current.slaWorkingDays} working days after admin verification.",
        )
    }

    private fun requirePlayer(principal: AuthenticatedPrincipal?, tenantId: String): AuthenticatedPrincipal {
        val caller = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (caller.tenantId != tenantId || caller.kind != PrincipalKind.PLAYER) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return caller
    }
}
