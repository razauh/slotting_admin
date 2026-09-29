package com.slotting.admin.provider

import com.slotting.admin.auth.*
import java.time.Instant
import java.util.UUID

enum class PaymentMethodStatus { ACTIVE, INACTIVE, MAINTENANCE }

enum class PaymentMethodAction { REGISTER, UPDATE_CONFIG, ACTIVATE, DEACTIVATE, SET_MAINTENANCE }

enum class PaymentMethodType { MOBILE_WALLET, BANK_TRANSFER, INSTANT_PAYMENT }

data class PaymentMethodCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val methodId: String,
    val providerId: String,
    val action: PaymentMethodAction,
    val displayName: String,
    val methodType: PaymentMethodType = PaymentMethodType.MOBILE_WALLET,
    val instructions: String? = null,
    val safeAccountTitle: String? = null,
    val safeAccountNumber: String? = null,
    val iconUrl: String? = null,
    val supportedCurrencies: List<String> = listOf("PKR"),
    val allowsDeposit: Boolean = true,
    val allowsWithdrawal: Boolean = true,
    val minDepositMinorUnits: Long = 0L,
    val maxDepositMinorUnits: Long = 0L,
    val minWithdrawalMinorUnits: Long = 0L,
    val maxWithdrawalMinorUnits: Long = 0L,
    val feeFlatMinorUnits: Long = 0L,
    val feePercentageBps: Int = 0,
    val displayOrder: Int = 0,
    val maintenanceReason: String? = null,
    val changeReason: String? = null,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class PaymentMethodConfig(
    val tenantId: String,
    val methodId: String,
    val providerId: String,
    val methodType: PaymentMethodType,
    val displayName: String,
    val instructions: String?,
    val safeAccountTitle: String?,
    val safeAccountNumber: String?,
    val iconUrl: String?,
    val supportedCurrencies: List<String>,
    val allowsDeposit: Boolean,
    val allowsWithdrawal: Boolean,
    val minDepositMinorUnits: Long,
    val maxDepositMinorUnits: Long,
    val minWithdrawalMinorUnits: Long,
    val maxWithdrawalMinorUnits: Long,
    val feeFlatMinorUnits: Long,
    val feePercentageBps: Int,
    val displayOrder: Int,
    val status: PaymentMethodStatus,
    val maintenanceReason: String?,
    val serverVersion: Long,
    val createdAt: Instant,
    val updatedAt: Instant,
    val updatedBy: String,
)

data class PaymentMethodResult(
    val resultId: UUID,
    val method: PaymentMethodConfig,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class PaymentMethodHistoryRecord(
    val historyId: UUID,
    val tenantId: String,
    val methodId: String,
    val providerId: String,
    val displayName: String,
    val status: PaymentMethodStatus,
    val snapshotPayload: String,
    val changeReason: String,
    val changedBy: String,
    val serverVersion: Long,
    val changedAt: Instant,
)

interface PaymentMethodStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, PaymentMethodResult>?
    fun findMethod(tenantId: String, methodId: String): PaymentMethodConfig?
    fun listMethods(tenantId: String): List<PaymentMethodConfig>
    fun listHistory(tenantId: String, methodId: String): List<PaymentMethodHistoryRecord>
    fun save(
        result: PaymentMethodResult,
        queryFingerprint: String,
        idempotencyKey: String,
        action: PaymentMethodAction,
        changeReason: String,
        changedBy: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}
