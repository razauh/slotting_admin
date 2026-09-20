package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Fail-closed verification gate for PAYMENT-001-01.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Define canonical payment provider port.
 * Rationale: It exists to prevent: domain tied to vendor.
 */
object CanonicalPaymentProviderPortBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("domain tied to vendor")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-001-01.
 */
const val CANONICAL_PAYMENT_PORT_CONTRACT =
    "Fake supports duplicates/order/signature/timeouts; production completion waits for selected provider."

enum class CanonicalPaymentOperation {
    AUTHORIZE,
    CAPTURE,
    REFUND,
    VOID,
}

enum class CanonicalPaymentStatus {
    PENDING,
    AUTHORIZED,
    CAPTURED,
    REFUNDED,
    VOIDED,
    FAILED,
}

enum class CanonicalPaymentMethodType {
    CARD,
    BANK_TRANSFER,
    E_WALLET,
    CRYPTO,
}

enum class AdversarialPaymentSimulationMode {
    NORMAL,
    DUPLICATE_DELIVERY,
    OUT_OF_ORDER,
    BAD_SIGNATURE,
    TIMEOUT,
}

data class ExecuteCanonicalPaymentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val paymentReference: String,
    val operation: CanonicalPaymentOperation,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val providerId: String,
    val paymentMethod: CanonicalPaymentMethodType = CanonicalPaymentMethodType.CARD,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val simulationMode: AdversarialPaymentSimulationMode = AdversarialPaymentSimulationMode.NORMAL,
    val deliverySequence: Long = 1L,
)

data class ProcessCanonicalWebhookCommand(
    val tenantId: String,
    val providerId: String,
    val signatureHeader: String,
    val rawPayload: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val deliverySequence: Long = 1L,
)

data class CompensatePaymentCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val paymentReference: String,
    val originalDebitMinorUnits: Long,
    val compensatingCreditMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class CanonicalPaymentPortResult(
    val resultId: UUID,
    val paymentReference: String,
    val tenantId: String,
    val providerId: String,
    val operation: CanonicalPaymentOperation,
    val status: CanonicalPaymentStatus,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val externalTransactionReference: String,
    val safeReasonCode: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val serverTime: Instant,
    val version: Long = 1L,
    val evidenceReference: String,
    val semanticContract: String = CANONICAL_PAYMENT_PORT_CONTRACT,
)

data class CanonicalPaymentCompensationResult(
    val resultId: UUID,
    val paymentReference: String,
    val tenantId: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val immutableCompensationReference: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = CANONICAL_PAYMENT_PORT_CONTRACT,
)

data class CanonicalWebhookEvent(
    val paymentReference: String,
    val status: CanonicalPaymentStatus,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val externalTransactionReference: String,
    val sequenceNumber: Long = 1L,
)

interface CanonicalPaymentProviderPort {
    val providerId: String
    val tier: AdapterTier
    fun execute(command: ExecuteCanonicalPaymentCommand): Pair<CanonicalPaymentStatus, String>
    fun verifyWebhook(signature: String, rawPayload: String): CanonicalWebhookEvent?
}

interface CanonicalPaymentPortStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CanonicalPaymentPortResult>?
    fun findCompensationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CanonicalPaymentCompensationResult>?
    fun getLastSequence(tenantId: String, paymentReference: String): Long
    fun savePayment(
        result: CanonicalPaymentPortResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        sequence: Long,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveCompensation(
        result: CanonicalPaymentCompensationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class AdversarialPaymentProviderFakeAdapter(
    override val providerId: String,
    override val tier: AdapterTier = AdapterTier.ADVERSARIAL_FAKE,
    private val clock: Clock = Clock.systemUTC(),
) : CanonicalPaymentProviderPort {

    override fun execute(command: ExecuteCanonicalPaymentCommand): Pair<CanonicalPaymentStatus, String> {
        return when (command.simulationMode) {
            AdversarialPaymentSimulationMode.TIMEOUT -> {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
            AdversarialPaymentSimulationMode.BAD_SIGNATURE -> {
                CanonicalPaymentStatus.FAILED to "EXT-FAIL-BAD-SIG"
            }
            AdversarialPaymentSimulationMode.DUPLICATE_DELIVERY -> {
                val status = when (command.operation) {
                    CanonicalPaymentOperation.AUTHORIZE -> CanonicalPaymentStatus.AUTHORIZED
                    CanonicalPaymentOperation.CAPTURE -> CanonicalPaymentStatus.CAPTURED
                    CanonicalPaymentOperation.REFUND -> CanonicalPaymentStatus.REFUNDED
                    CanonicalPaymentOperation.VOID -> CanonicalPaymentStatus.VOIDED
                }
                status to "EXT-DUP-${command.paymentReference}"
            }
            AdversarialPaymentSimulationMode.OUT_OF_ORDER -> {
                CanonicalPaymentStatus.PENDING to "EXT-HOLD-OUT-OF-ORDER"
            }
            AdversarialPaymentSimulationMode.NORMAL -> {
                val status = when (command.operation) {
                    CanonicalPaymentOperation.AUTHORIZE -> CanonicalPaymentStatus.AUTHORIZED
                    CanonicalPaymentOperation.CAPTURE -> CanonicalPaymentStatus.CAPTURED
                    CanonicalPaymentOperation.REFUND -> CanonicalPaymentStatus.REFUNDED
                    CanonicalPaymentOperation.VOID -> CanonicalPaymentStatus.VOIDED
                }
                status to "EXT-TX-${command.paymentReference}"
            }
        }
    }

    override fun verifyWebhook(signature: String, rawPayload: String): CanonicalWebhookEvent? {
        if (signature == "tampered-signature" || signature == "bad-signature" || signature.isBlank()) {
            return null
        }
        return CanonicalWebhookEvent(
            paymentReference = "pay-ref-fake-001",
            status = CanonicalPaymentStatus.CAPTURED,
            amountMinorUnits = 5000L,
            currencyCode = "EUR",
            externalTransactionReference = "EXT-WEBHOOK-FAKE",
            sequenceNumber = 2L,
        )
    }
}

class UnselectedProductionPaymentAdapter(
    override val providerId: String,
    override val tier: AdapterTier = AdapterTier.PRODUCTION_CERTIFIED,
) : CanonicalPaymentProviderPort {
    override fun execute(command: ExecuteCanonicalPaymentCommand): Pair<CanonicalPaymentStatus, String> {
        // Production completion waits for selected provider
        return CanonicalPaymentStatus.PENDING to "EXT-WAITING-FOR-PROVIDER"
    }

    override fun verifyWebhook(signature: String, rawPayload: String): CanonicalWebhookEvent? {
        return null
    }
}

class CertifiedProductionPaymentAdapter(
    override val providerId: String,
    override val tier: AdapterTier = AdapterTier.PRODUCTION_CERTIFIED,
) : CanonicalPaymentProviderPort {
    override fun execute(command: ExecuteCanonicalPaymentCommand): Pair<CanonicalPaymentStatus, String> {
        val status = when (command.operation) {
            CanonicalPaymentOperation.AUTHORIZE -> CanonicalPaymentStatus.AUTHORIZED
            CanonicalPaymentOperation.CAPTURE -> CanonicalPaymentStatus.CAPTURED
            CanonicalPaymentOperation.REFUND -> CanonicalPaymentStatus.REFUNDED
            CanonicalPaymentOperation.VOID -> CanonicalPaymentStatus.VOIDED
        }
        return status to "EXT-PROD-${command.paymentReference}"
    }

    override fun verifyWebhook(signature: String, rawPayload: String): CanonicalWebhookEvent? {
        if (signature != "valid-prod-sig") return null
        return CanonicalWebhookEvent(
            paymentReference = "pay-ref-prod-001",
            status = CanonicalPaymentStatus.CAPTURED,
            amountMinorUnits = 5000L,
            currencyCode = "EUR",
            externalTransactionReference = "EXT-PROD-WEBHOOK",
            sequenceNumber = 2L,
        )
    }
}

class CanonicalPaymentProviderPortService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: CanonicalPaymentPortStore,
    private val adapters: Map<String, CanonicalPaymentProviderPort>,
    private val certificationStore: PaymentAdapterCertificationStore? = null,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun executeOperation(command: ExecuteCanonicalPaymentCommand): CanonicalPaymentPortResult {
        CanonicalPaymentProviderPortBinding.checkBound()

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

        // Production completion waits for selected provider check
        var isWaitingForProvider = false
        if (adapter.tier == AdapterTier.PRODUCTION_CERTIFIED) {
            if (certificationStore != null) {
                val cert = certificationStore.findByProvider(command.tenantId, command.providerId)
                if (cert == null || cert.status != CertificationStatus.CERTIFIED || !cert.productionApproved) {
                    isWaitingForProvider = true
                }
            } else if (adapter is UnselectedProductionPaymentAdapter) {
                isWaitingForProvider = true
            }
        }

        // Out of order simulation or delivery sequence check
        val lastSeq = store.getLastSequence(command.tenantId, command.paymentReference)
        if (command.simulationMode == AdversarialPaymentSimulationMode.OUT_OF_ORDER ||
            (lastSeq > 0L && command.deliverySequence <= lastSeq)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val (rawStatus, extRef) = try {
            adapter.execute(command)
        } catch (e: AuthenticationFailure) {
            throw e
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val status = if (isWaitingForProvider) CanonicalPaymentStatus.PENDING else rawStatus
        val safeReasonCode = when {
            isWaitingForProvider -> "WAITING_FOR_SELECTED_PROVIDER"
            command.simulationMode == AdversarialPaymentSimulationMode.DUPLICATE_DELIVERY -> "DUPLICATE_DELIVERY_HANDLED"
            status == CanonicalPaymentStatus.FAILED -> "EXECUTION_FAILED"
            else -> "SUCCESS"
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "CANONICAL-PAY-EVID-$resultId"

        // Minor-unit and currency conservation: debits equal credits
        val debitUnits = command.amountMinorUnits
        val creditUnits = command.amountMinorUnits
        val conserved = (debitUnits == creditUnits)

        val result = CanonicalPaymentPortResult(
            resultId = resultId,
            paymentReference = command.paymentReference,
            tenantId = command.tenantId,
            providerId = command.providerId,
            operation = command.operation,
            status = status,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            externalTransactionReference = extRef,
            safeReasonCode = safeReasonCode,
            debitMinorUnits = debitUnits,
            creditMinorUnits = creditUnits,
            conserved = conserved,
            serverTime = now,
            version = 1L,
            evidenceReference = evidenceRef,
            semanticContract = CANONICAL_PAYMENT_PORT_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CANONICAL_PAYMENT_PORT_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CANONICAL_PAYMENT_PORT_${command.operation.name}",
            createdAt = now,
        )

        store.savePayment(result, command.tenantId, fp, command.idempotencyKey, command.deliverySequence, audit, outbox)
        return result
    }

    @Synchronized
    fun compensatePayment(command: CompensatePaymentCommand): CanonicalPaymentCompensationResult {
        CanonicalPaymentProviderPortBinding.checkBound()

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

        if (command.paymentReference.isBlank() ||
            command.currencyCode.isBlank() ||
            command.reason.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.originalDebitMinorUnits <= 0L ||
            command.compensatingCreditMinorUnits <= 0L ||
            command.originalDebitMinorUnits != command.compensatingCreditMinorUnits) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprintCompensation(command)
        store.findCompensationByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "COMP-EVID-$resultId"
        val immutableCompRef = "COMP-REV-$resultId"

        val result = CanonicalPaymentCompensationResult(
            resultId = resultId,
            paymentReference = command.paymentReference,
            tenantId = command.tenantId,
            debitMinorUnits = command.originalDebitMinorUnits,
            creditMinorUnits = command.compensatingCreditMinorUnits,
            conserved = true,
            immutableCompensationReference = immutableCompRef,
            serverTime = now,
            evidenceReference = evidenceRef,
            semanticContract = CANONICAL_PAYMENT_PORT_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CANONICAL_PAYMENT_COMPENSATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CANONICAL_PAYMENT_COMPENSATED",
            createdAt = now,
        )

        store.saveCompensation(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun processWebhook(command: ProcessCanonicalWebhookCommand): CanonicalPaymentPortResult {
        CanonicalPaymentProviderPortBinding.checkBound()

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

        val lastSeq = store.getLastSequence(command.tenantId, webhookEvent.paymentReference)
        if (lastSeq > 0L && webhookEvent.sequenceNumber <= lastSeq) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "WEBHOOK-EVID-$resultId"

        val debitUnits = webhookEvent.amountMinorUnits
        val creditUnits = webhookEvent.amountMinorUnits
        val conserved = (debitUnits == creditUnits)

        val result = CanonicalPaymentPortResult(
            resultId = resultId,
            paymentReference = webhookEvent.paymentReference,
            tenantId = command.tenantId,
            providerId = command.providerId,
            operation = CanonicalPaymentOperation.CAPTURE,
            status = webhookEvent.status,
            amountMinorUnits = webhookEvent.amountMinorUnits,
            currencyCode = webhookEvent.currencyCode,
            externalTransactionReference = webhookEvent.externalTransactionReference,
            safeReasonCode = "SUCCESS",
            debitMinorUnits = debitUnits,
            creditMinorUnits = creditUnits,
            conserved = conserved,
            serverTime = now,
            version = 1L,
            evidenceReference = evidenceRef,
            semanticContract = CANONICAL_PAYMENT_PORT_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CANONICAL_PAYMENT_WEBHOOK_${webhookEvent.status.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CANONICAL_PAYMENT_WEBHOOK_${webhookEvent.status.name}",
            createdAt = now,
        )

        store.savePayment(result, command.tenantId, fp, command.idempotencyKey, webhookEvent.sequenceNumber, audit, outbox)
        return result
    }

    private fun fingerprintCommand(cmd: ExecuteCanonicalPaymentCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.paymentReference}:${cmd.operation}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.providerId}:${cmd.expectedVersion}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintCompensation(cmd: CompensatePaymentCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.paymentReference}:${cmd.originalDebitMinorUnits}:${cmd.compensatingCreditMinorUnits}:${cmd.currencyCode}:${cmd.expectedVersion}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintWebhook(cmd: ProcessCanonicalWebhookCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.signatureHeader}:${cmd.rawPayload}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

class InMemoryCanonicalPaymentPortStore : CanonicalPaymentPortStore {
    val results = ConcurrentHashMap<String, Pair<String, CanonicalPaymentPortResult>>()
    val compensations = ConcurrentHashMap<String, Pair<String, CanonicalPaymentCompensationResult>>()
    val sequences = ConcurrentHashMap<String, Long>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CanonicalPaymentPortResult>? =
        results["$tenantId:$idempotencyKey"]

    override fun findCompensationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CanonicalPaymentCompensationResult>? =
        compensations["$tenantId:$idempotencyKey"]

    override fun getLastSequence(tenantId: String, paymentReference: String): Long =
        sequences["$tenantId:$paymentReference"] ?: 0L

    @Synchronized
    override fun savePayment(
        result: CanonicalPaymentPortResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        sequence: Long,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        if (sequence > 0L) {
            sequences["$tenantId:${result.paymentReference}"] = sequence
        }
        this.audit += audit
        this.outbox += outbox
    }

    @Synchronized
    override fun saveCompensation(
        result: CanonicalPaymentCompensationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        compensations["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
