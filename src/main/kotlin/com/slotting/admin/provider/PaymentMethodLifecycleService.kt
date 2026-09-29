package com.slotting.admin.provider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

class PaymentMethodLifecycleService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: PaymentMethodStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val forbiddenSecretKeywords = listOf(
        "apikeysecret", "secretkey", "password=", "token=",
        "private_key", "sk_live_", "client_secret"
    )

    private val currencyRegex = Regex("^[A-Z]{3}$")
    private val methodIdRegex = Regex("^[a-zA-Z0-9_-]+$")

    @Synchronized
    fun operate(command: PaymentMethodCommand): PaymentMethodResult {
        // 1. Authorization before replay (TC-006)
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        if (session == null || !session.active || !session.expiresAt.isAfter(now) || !session.mfaVerified) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.PAYMENT_CONFIGURATION)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 2. Idempotency replay check after authorization
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
            return replay.second
        }

        // 3. Validation: Identifiers, Bounds, Currencies, and Formats
        if (command.methodId.isBlank() || command.methodId.length > 64 || !methodIdRegex.matches(command.methodId)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.providerId.isBlank() || command.providerId.length > 128) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.displayName.isBlank() || command.displayName.length > 128) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.supportedCurrencies.isEmpty() || command.supportedCurrencies.any { !currencyRegex.matches(it) }) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.minDepositMinorUnits < 0 || command.maxDepositMinorUnits < command.minDepositMinorUnits) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.minWithdrawalMinorUnits < 0 || command.maxWithdrawalMinorUnits < command.minWithdrawalMinorUnits) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.feeFlatMinorUnits < 0 || command.feePercentageBps < 0 || command.feePercentageBps > 10000) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.displayOrder < 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.safeAccountTitle != null && command.safeAccountTitle.length > 128) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.safeAccountNumber != null && command.safeAccountNumber.length > 64) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.instructions != null && command.instructions.length > 4096) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (command.iconUrl != null) {
            if (command.iconUrl.length > 512 || (!command.iconUrl.startsWith("http://") && !command.iconUrl.startsWith("https://"))) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 4. Reject credential leakage
        val inspectableStrings = listOfNotNull(
            command.instructions,
            command.safeAccountTitle,
            command.safeAccountNumber,
            command.displayName,
            command.iconUrl,
            command.changeReason,
            command.maintenanceReason,
        )
        for (str in inspectableStrings) {
            val lower = str.lowercase()
            if (forbiddenSecretKeywords.any { lower.contains(it) }) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 5. State transitions and CAS checks
        val existing = store.findMethod(command.tenantId, command.methodId)
        val (nextMethod, changeReason) = when (command.action) {
            PaymentMethodAction.REGISTER -> {
                if (existing != null) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                }
                if (command.expectedVersion != 0L) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                }
                val created = PaymentMethodConfig(
                    tenantId = command.tenantId,
                    methodId = command.methodId,
                    providerId = command.providerId,
                    methodType = command.methodType,
                    displayName = command.displayName,
                    instructions = command.instructions,
                    safeAccountTitle = command.safeAccountTitle,
                    safeAccountNumber = command.safeAccountNumber,
                    iconUrl = command.iconUrl,
                    supportedCurrencies = command.supportedCurrencies,
                    allowsDeposit = command.allowsDeposit,
                    allowsWithdrawal = command.allowsWithdrawal,
                    minDepositMinorUnits = command.minDepositMinorUnits,
                    maxDepositMinorUnits = command.maxDepositMinorUnits,
                    minWithdrawalMinorUnits = command.minWithdrawalMinorUnits,
                    maxWithdrawalMinorUnits = command.maxWithdrawalMinorUnits,
                    feeFlatMinorUnits = command.feeFlatMinorUnits,
                    feePercentageBps = command.feePercentageBps,
                    displayOrder = command.displayOrder,
                    status = PaymentMethodStatus.ACTIVE,
                    maintenanceReason = null,
                    serverVersion = 1L,
                    createdAt = now,
                    updatedAt = now,
                    updatedBy = principal.id,
                )
                created to (command.changeReason ?: "Initial registration")
            }
            PaymentMethodAction.UPDATE_CONFIG -> {
                if (existing == null) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                if (existing.serverVersion != command.expectedVersion) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                }
                val updated = existing.copy(
                    providerId = command.providerId,
                    methodType = command.methodType,
                    displayName = command.displayName,
                    instructions = command.instructions,
                    safeAccountTitle = command.safeAccountTitle,
                    safeAccountNumber = command.safeAccountNumber,
                    iconUrl = command.iconUrl,
                    supportedCurrencies = command.supportedCurrencies,
                    allowsDeposit = command.allowsDeposit,
                    allowsWithdrawal = command.allowsWithdrawal,
                    minDepositMinorUnits = command.minDepositMinorUnits,
                    maxDepositMinorUnits = command.maxDepositMinorUnits,
                    minWithdrawalMinorUnits = command.minWithdrawalMinorUnits,
                    maxWithdrawalMinorUnits = command.maxWithdrawalMinorUnits,
                    feeFlatMinorUnits = command.feeFlatMinorUnits,
                    feePercentageBps = command.feePercentageBps,
                    displayOrder = command.displayOrder,
                    serverVersion = existing.serverVersion + 1,
                    updatedAt = now,
                    updatedBy = principal.id,
                )
                updated to (command.changeReason ?: "Update payment method configuration")
            }
            PaymentMethodAction.ACTIVATE -> {
                if (existing == null) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                if (existing.serverVersion != command.expectedVersion) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                }
                val updated = existing.copy(
                    status = PaymentMethodStatus.ACTIVE,
                    maintenanceReason = null,
                    serverVersion = existing.serverVersion + 1,
                    updatedAt = now,
                    updatedBy = principal.id,
                )
                updated to (command.changeReason ?: "Activate payment method")
            }
            PaymentMethodAction.DEACTIVATE -> {
                if (existing == null) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                if (existing.serverVersion != command.expectedVersion) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                }
                val updated = existing.copy(
                    status = PaymentMethodStatus.INACTIVE,
                    serverVersion = existing.serverVersion + 1,
                    updatedAt = now,
                    updatedBy = principal.id,
                )
                updated to (command.changeReason ?: "Deactivate payment method")
            }
            PaymentMethodAction.SET_MAINTENANCE -> {
                if (existing == null) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                if (existing.serverVersion != command.expectedVersion) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                }
                val updated = existing.copy(
                    status = PaymentMethodStatus.MAINTENANCE,
                    maintenanceReason = command.maintenanceReason,
                    serverVersion = existing.serverVersion + 1,
                    updatedAt = now,
                    updatedBy = principal.id,
                )
                updated to (command.changeReason ?: "Set maintenance mode")
            }
        }

        val resultId = UUID.randomUUID()
        val result = PaymentMethodResult(
            resultId = resultId,
            method = nextMethod,
            serverTime = now,
            evidenceReference = "payment-method:$resultId",
        )

        val actionName = command.action.name
        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_METHOD_$actionName",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_METHOD_$actionName",
            createdAt = now,
        )

        store.save(
            result = result,
            queryFingerprint = fingerprint,
            idempotencyKey = command.idempotencyKey,
            action = command.action,
            changeReason = changeReason,
            changedBy = principal.id,
            audit = audit,
            outbox = outbox,
        )

        return result
    }

    fun listMethods(tenantId: String): List<PaymentMethodConfig> {
        return store.listMethods(tenantId)
    }

    fun listHistory(tenantId: String, methodId: String): List<PaymentMethodHistoryRecord> {
        return store.listHistory(tenantId, methodId)
    }

    private fun fingerprint(command: PaymentMethodCommand): String = listOf(
        command.tenantId,
        command.methodId,
        command.providerId,
        command.action,
        command.displayName,
        command.methodType,
        command.supportedCurrencies.joinToString(","),
        command.allowsDeposit,
        command.allowsWithdrawal,
        command.minDepositMinorUnits,
        command.maxDepositMinorUnits,
        command.minWithdrawalMinorUnits,
        command.maxWithdrawalMinorUnits,
        command.feeFlatMinorUnits,
        command.feePercentageBps,
        command.displayOrder,
        command.safeAccountTitle,
        command.safeAccountNumber,
        command.instructions,
        command.iconUrl,
        command.maintenanceReason,
        command.expectedVersion,
    ).joinToString("|") { sha256(it?.toString() ?: "") }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
