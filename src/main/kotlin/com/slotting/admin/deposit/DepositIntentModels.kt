package com.slotting.admin.deposit

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.time.Instant
import java.util.UUID

enum class DepositIntentStatus {
    CREATED,
    DISPATCH_PENDING,
    PROVIDER_PENDING,
    SETTLED,
    FAILED,
    EXPIRED,
    AMBIGUOUS_RECONCILING,
}

data class DepositIntentRecord(
    val intentId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val methodId: String,
    val providerId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: DepositIntentStatus,
    val idempotencyKey: String,
    val requestFingerprint: String,
    val providerReference: String? = null,
    val redirectUrl: String? = null,
    val clientSecret: String? = null,
    val failureReason: String? = null,
    val ledgerTransactionReference: String? = null,
    val settledAt: Instant? = null,
    val expiresAt: Instant,
    val serverVersion: Long = 1L,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class DepositInboxRecord(
    val inboxId: UUID,
    val tenantId: String,
    val providerId: String,
    val providerEventId: String,
    val intentId: UUID?,
    val status: String, // "RECEIVED", "PROCESSED", "IGNORED"
    val signatureVerified: Boolean,
    val payloadHash: String,
    val receivedAt: Instant,
    val processedAt: Instant? = null,
)

data class DepositReconciliationRecord(
    val reconciliationId: UUID,
    val tenantId: String,
    val intentId: UUID,
    val actionType: String,
    val previousStatus: DepositIntentStatus,
    val newStatus: DepositIntentStatus,
    val performedBy: String,
    val occurredAt: Instant,
    val notes: String? = null,
)

data class CreateDepositIntentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val playerId: UUID,
    val methodId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val customerIdentifier: String,
    val methodExpectedVersion: Long = 1L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val clientIp: String? = null,
    val userAgent: String? = null,
    val clientReturnUrl: String? = null,
)

data class CreateDepositIntentResult(
    val intentId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val methodId: String,
    val providerId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: DepositIntentStatus,
    val providerReference: String?,
    val redirectUrl: String? = null,
    val expiresAt: Instant,
    val createdAt: Instant,
)

data class DepositCallbackCommand(
    val tenantId: String,
    val providerId: String,
    val providerEventId: String,
    val rawBody: String,
    val headers: Map<String, String> = emptyMap(),
    val queryParams: Map<String, String> = emptyMap(),
)

data class DepositCallbackResult(
    val intentId: UUID,
    val providerTransactionId: String?,
    val status: DepositIntentStatus,
    val alreadyProcessed: Boolean,
    val ledgerTransactionReference: String?,
)

data class DepositReconciliationCommand(
    val tenantId: String,
    val intentId: UUID,
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val reason: String = "Manual or automated reconciliation",
)

data class DepositReconciliationResult(
    val intentId: UUID,
    val previousStatus: DepositIntentStatus,
    val status: DepositIntentStatus,
    val actionTaken: String,
    val ledgerTransactionReference: String?,
)
