package com.slotting.admin.rails

import java.math.BigDecimal
import java.math.RoundingMode
import java.util.UUID

enum class PayoutStatus {
    PENDING,
    APPROVED_FUNDS_LOCKED,
    PAID,
    REJECTED,
}

data class PayoutRequest(
    val id: String,
    val tenantId: String,
    val playerId: String,
    val amountUsd: BigDecimal,
    val feeUsd: BigDecimal,
    val netUsd: BigDecimal,
    val payoutRate: BigDecimal,
    val payoutPkr: BigDecimal,
    val destType: String,
    val destTitle: String,
    val destNumber: String,
    val status: PayoutStatus,
    val receiptObject: String? = null,
)

interface PayoutRequestRepository {
    fun insert(request: PayoutRequest): Boolean

    fun find(id: String): PayoutRequest?

    fun lockedTotal(tenantId: String, playerId: String): BigDecimal

    fun markLocked(id: String, by: String): Boolean

    fun markPaid(id: String, by: String): Boolean

    fun markRejected(id: String, reason: String, by: String): Boolean
}

data class PayoutSettings(
    val payoutRate: BigDecimal,
    val feePercent: BigDecimal,
)

data class PayoutQuote(
    val feeUsd: BigDecimal,
    val netUsd: BigDecimal,
    val payoutPkr: BigDecimal,
    val rate: BigDecimal,
)

enum class PayoutOutcome {
    CREATED,
    INSUFFICIENT_AVAILABLE_BALANCE,
    NOT_FOUND,
    LOCKED,
    PAID,
    REJECTED,
    ALREADY_DECIDED,
    RECEIPT_REQUIRED,
    INVALID_STATE,
}

data class PayoutResult(
    val outcome: PayoutOutcome,
    val message: String? = null,
    val quote: PayoutQuote? = null,
)

class ManualPayoutFlow(
    private val repository: PayoutRequestRepository,
    private val settings: PayoutSettings,
) {
    fun request(
        tenantId: String,
        playerId: String,
        amountUsd: BigDecimal,
        availableUsd: BigDecimal,
        destType: String,
        destTitle: String,
        destNumber: String,
    ): PayoutResult {
        val fee = amountUsd.multiply(settings.feePercent).divide(BigDecimal(100), 2, RoundingMode.HALF_UP)
        val net = amountUsd.subtract(fee)
        val rate = settings.payoutRate
        val pkr = net.multiply(rate).setScale(2, RoundingMode.HALF_UP)
        val available = availableUsd.subtract(repository.lockedTotal(tenantId, playerId))
        if (available < amountUsd) {
            return PayoutResult(PayoutOutcome.INSUFFICIENT_AVAILABLE_BALANCE, "insufficient available balance")
        }
        val row = PayoutRequest(
            id = UUID.randomUUID().toString(),
            tenantId = tenantId,
            playerId = playerId,
            amountUsd = amountUsd,
            feeUsd = fee,
            netUsd = net,
            payoutRate = rate,
            payoutPkr = pkr,
            destType = destType,
            destTitle = destTitle,
            destNumber = destNumber,
            status = PayoutStatus.PENDING,
        )
        repository.insert(row)
        return PayoutResult(PayoutOutcome.CREATED, quote = PayoutQuote(fee, net, pkr, rate))
    }

    fun lock(id: String, by: String): PayoutResult =
        if (repository.markLocked(id, by)) PayoutResult(PayoutOutcome.LOCKED) else PayoutResult(PayoutOutcome.ALREADY_DECIDED)

    fun reject(id: String, reason: String, by: String): PayoutResult =
        if (repository.markRejected(id, reason, by)) PayoutResult(PayoutOutcome.REJECTED) else PayoutResult(PayoutOutcome.ALREADY_DECIDED)
}
