package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class PaymentPortOperation {
    AUTHORIZE,
    CAPTURE,
    REFUND,
    VOID,
}

enum class PaymentTransactionStatus {
    PENDING,
    AUTHORIZED,
    CAPTURED,
    REFUNDED,
    VOIDED,
    FAILED,
}

enum class PaymentMethodType {
    CARD,
    BANK_TRANSFER,
    E_WALLET,
    CRYPTO,
}

data class PaymentPortCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val paymentReference: String,
    val operation: PaymentPortOperation,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val providerId: String,
    val paymentMethod: PaymentMethodType,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class CanonicalWebhookCommand(
    val tenantId: String,
    val providerId: String,
    val signatureHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class PaymentPortResult(
    val resultId: UUID,
    val paymentReference: String,
    val tenantId: String,
    val providerId: String,
    val operation: PaymentPortOperation,
    val status: PaymentTransactionStatus,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val externalTransactionReference: String,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class CanonicalPaymentWebhookEvent(
    val paymentReference: String,
    val status: PaymentTransactionStatus,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val externalTransactionReference: String,
)

interface PaymentProviderAdapter {
    val providerId: String
    fun execute(command: PaymentPortCommand): Pair<PaymentTransactionStatus, String>
    fun verifyWebhook(signature: String, rawPayload: String): CanonicalPaymentWebhookEvent?
}

interface PaymentPortStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, PaymentPortResult>?
    fun save(
        result: PaymentPortResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class PaymentPortService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: PaymentPortStore,
    private val adapters: Map<String, PaymentProviderAdapter>,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun executeOperation(command: PaymentPortCommand): PaymentPortResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!command.currencyCode.matches(Regex("^[A-Z]{3}$")) ||
            command.amountMinorUnits <= 0L ||
            command.paymentReference.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprintCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val adapter = adapters[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val (status, extRef) = try {
            adapter.execute(command)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "PAY-EVID-$resultId"

        val result = PaymentPortResult(
            resultId = resultId,
            paymentReference = command.paymentReference,
            tenantId = command.tenantId,
            providerId = command.providerId,
            operation = command.operation,
            status = status,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            externalTransactionReference = extRef,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_PORT_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_PORT_${command.operation.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun processWebhook(command: CanonicalWebhookCommand): PaymentPortResult {
        if (command.providerId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintWebhook(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val adapter = adapters[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val webhookEvent = try {
            adapter.verifyWebhook(command.signatureHeader, command.rawPayload)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "WEBHOOK-EVID-$resultId"

        val result = PaymentPortResult(
            resultId = resultId,
            paymentReference = webhookEvent.paymentReference,
            tenantId = command.tenantId,
            providerId = command.providerId,
            operation = PaymentPortOperation.CAPTURE,
            status = webhookEvent.status,
            amountMinorUnits = webhookEvent.amountMinorUnits,
            currencyCode = webhookEvent.currencyCode,
            externalTransactionReference = webhookEvent.externalTransactionReference,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_WEBHOOK_${webhookEvent.status.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "PAYMENT_WEBHOOK_${webhookEvent.status.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprintCommand(cmd: PaymentPortCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.paymentReference}:${cmd.operation}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.providerId}:${cmd.expectedVersion}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintWebhook(cmd: CanonicalWebhookCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.signatureHeader}:${cmd.rawPayload}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
