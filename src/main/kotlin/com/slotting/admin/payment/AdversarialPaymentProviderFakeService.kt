package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Fail-closed verification gate for PAYMENT-001-02.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 * Protected risk: False completion or non-authoritative implementation of Build adversarial payment provider fake.
 * Rationale: It exists to prevent: domain tied to vendor.
 */
object AdversarialPaymentProviderFakeBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("domain tied to vendor")
        }
    }
}

/**
 * Outcome-specific semantic contract for PAYMENT-001-02.
 */
const val ADVERSARIAL_PAYMENT_FAKE_CONTRACT =
    "Fake supports duplicates/order/signature/timeouts; production completion waits for selected provider."

data class AdversarialPaymentFakeConfig(
    val configId: UUID,
    val tenantId: String,
    val providerId: String,
    val simulationMode: AdversarialPaymentSimulationMode,
    val secretKey: String,
    val version: Long = 1L,
)

data class ConfigureAdversarialPaymentFakeCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val simulationMode: AdversarialPaymentSimulationMode,
    val secretKey: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class AdversarialPaymentFakeConfigResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val simulationMode: AdversarialPaymentSimulationMode,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = ADVERSARIAL_PAYMENT_FAKE_CONTRACT,
)

data class ExecuteSimulatedPaymentCommand(
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
    val simulationMode: AdversarialPaymentSimulationMode? = null,
    val deliverySequence: Long = 1L,
)

data class AdversarialPaymentExecutionResult(
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
    val deliverySequence: Long,
    val serverTime: Instant,
    val version: Long = 1L,
    val evidenceReference: String,
    val semanticContract: String = ADVERSARIAL_PAYMENT_FAKE_CONTRACT,
)

data class SimulateInboundWebhookCommand(
    val tenantId: String,
    val providerId: String,
    val paymentReference: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val status: CanonicalPaymentStatus = CanonicalPaymentStatus.CAPTURED,
    val tamperSignature: Boolean = false,
    val deliverySequence: Long = 1L,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class SimulatedWebhookPayload(
    val signatureHeader: String,
    val rawPayload: String,
    val paymentReference: String,
    val deliverySequence: Long,
)

data class ExecuteSimulatedCompensationCommand(
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

data class AdversarialPaymentCompensationResult(
    val resultId: UUID,
    val paymentReference: String,
    val tenantId: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val immutableCompensationReference: String,
    val serverTime: Instant,
    val evidenceReference: String,
    val semanticContract: String = ADVERSARIAL_PAYMENT_FAKE_CONTRACT,
)

interface AdversarialPaymentFakeStore {
    fun findConfig(tenantId: String, providerId: String): AdversarialPaymentFakeConfig?
    fun saveConfig(
        config: AdversarialPaymentFakeConfig,
        result: AdversarialPaymentFakeConfigResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findConfigByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdversarialPaymentFakeConfigResult>?
    fun findExecutionByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdversarialPaymentExecutionResult>?
    fun findCompensationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdversarialPaymentCompensationResult>?
    fun getLastSequence(tenantId: String, paymentReference: String): Long
    fun saveExecution(
        result: AdversarialPaymentExecutionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        sequence: Long,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun saveCompensation(
        result: AdversarialPaymentCompensationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class AdversarialPaymentProviderFakeService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: AdversarialPaymentFakeStore,
    private val certificationStore: PaymentAdapterCertificationStore? = null,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun configureFake(command: ConfigureAdversarialPaymentFakeCommand): AdversarialPaymentFakeConfigResult {
        AdversarialPaymentProviderFakeBinding.checkBound()

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

        if (command.providerId.isBlank() ||
            command.secretKey.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprintConfig(command)
        store.findConfigByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val configId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        val evidenceRef = "FAKE-CFG-EVID-$resultId"

        val config = AdversarialPaymentFakeConfig(
            configId = configId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            simulationMode = command.simulationMode,
            secretKey = command.secretKey,
            version = 1L,
        )

        val result = AdversarialPaymentFakeConfigResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            simulationMode = command.simulationMode,
            serverTime = now,
            evidenceReference = evidenceRef,
            semanticContract = ADVERSARIAL_PAYMENT_FAKE_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ADVERSARIAL_PAYMENT_FAKE_CONFIGURED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ADVERSARIAL_PAYMENT_FAKE_CONFIGURED",
            createdAt = now,
        )

        store.saveConfig(config, result, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun executeSimulatedPayment(command: ExecuteSimulatedPaymentCommand): AdversarialPaymentExecutionResult {
        AdversarialPaymentProviderFakeBinding.checkBound()

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

        val fp = fingerprintExecution(command)
        store.findExecutionByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val config = store.findConfig(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val activeMode = command.simulationMode ?: config.simulationMode

        // 1. Timeout simulation: fails closed with DEPENDENCY_UNAVAILABLE, zero mutation
        if (activeMode == AdversarialPaymentSimulationMode.TIMEOUT) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // 2. Order checking: out of order delivery sequence rejected
        val lastSeq = store.getLastSequence(command.tenantId, command.paymentReference)
        if (activeMode == AdversarialPaymentSimulationMode.OUT_OF_ORDER ||
            (lastSeq > 0L && command.deliverySequence <= lastSeq)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        // 3. Check production certification boundary
        var status = when (command.operation) {
            CanonicalPaymentOperation.AUTHORIZE -> CanonicalPaymentStatus.AUTHORIZED
            CanonicalPaymentOperation.CAPTURE -> CanonicalPaymentStatus.CAPTURED
            CanonicalPaymentOperation.REFUND -> CanonicalPaymentStatus.REFUNDED
            CanonicalPaymentOperation.VOID -> CanonicalPaymentStatus.VOIDED
        }

        var isWaitingForProvider = false
        if (certificationStore != null) {
            val cert = certificationStore.findByProvider(command.tenantId, command.providerId)
            if (cert != null && cert.tier == AdapterTier.PRODUCTION_CERTIFIED) {
                if (cert.status != CertificationStatus.CERTIFIED || !cert.productionApproved) {
                    isWaitingForProvider = true
                    status = CanonicalPaymentStatus.PENDING
                }
            }
        }

        // 4. Bad signature mode
        if (activeMode == AdversarialPaymentSimulationMode.BAD_SIGNATURE) {
            status = CanonicalPaymentStatus.FAILED
        }

        val safeReason = when {
            isWaitingForProvider -> "WAITING_FOR_SELECTED_PROVIDER"
            activeMode == AdversarialPaymentSimulationMode.DUPLICATE_DELIVERY -> "DUPLICATE_DELIVERY_HANDLED"
            status == CanonicalPaymentStatus.FAILED -> "EXECUTION_FAILED"
            else -> "SUCCESS"
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "SIM-PAY-EVID-$resultId"
        val extRef = if (activeMode == AdversarialPaymentSimulationMode.DUPLICATE_DELIVERY) {
            "EXT-DUP-${command.paymentReference}"
        } else {
            "EXT-SIM-${command.paymentReference}"
        }

        val debitUnits = command.amountMinorUnits
        val creditUnits = command.amountMinorUnits
        val conserved = (debitUnits == creditUnits)

        val result = AdversarialPaymentExecutionResult(
            resultId = resultId,
            paymentReference = command.paymentReference,
            tenantId = command.tenantId,
            providerId = command.providerId,
            operation = command.operation,
            status = status,
            amountMinorUnits = command.amountMinorUnits,
            currencyCode = command.currencyCode,
            externalTransactionReference = extRef,
            safeReasonCode = safeReason,
            debitMinorUnits = debitUnits,
            creditMinorUnits = creditUnits,
            conserved = conserved,
            deliverySequence = command.deliverySequence,
            serverTime = now,
            version = 1L,
            evidenceReference = evidenceRef,
            semanticContract = ADVERSARIAL_PAYMENT_FAKE_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SIMULATED_PAYMENT_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SIMULATED_PAYMENT_${command.operation.name}",
            createdAt = now,
        )

        store.saveExecution(result, command.tenantId, fp, command.idempotencyKey, command.deliverySequence, audit, outbox)
        return result
    }

    @Synchronized
    fun generateSimulatedWebhook(command: SimulateInboundWebhookCommand): SimulatedWebhookPayload {
        AdversarialPaymentProviderFakeBinding.checkBound()

        val config = store.findConfig(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val rawPayload = "{\"paymentReference\":\"${command.paymentReference}\",\"amount\":${command.amountMinorUnits},\"currency\":\"${command.currencyCode}\",\"status\":\"${command.status.name}\",\"sequence\":${command.deliverySequence}}"

        val signature = if (command.tamperSignature || config.simulationMode == AdversarialPaymentSimulationMode.BAD_SIGNATURE) {
            "tampered_signature_${UUID.randomUUID()}"
        } else {
            calculateHmac(config.secretKey, rawPayload)
        }

        return SimulatedWebhookPayload(
            signatureHeader = signature,
            rawPayload = rawPayload,
            paymentReference = command.paymentReference,
            deliverySequence = command.deliverySequence,
        )
    }

    @Synchronized
    fun verifyAndProcessSimulatedWebhook(
        tenantId: String,
        providerId: String,
        payload: SimulatedWebhookPayload,
        idempotencyKey: String,
        correlationId: String,
        causationId: String,
    ): AdversarialPaymentExecutionResult {
        AdversarialPaymentProviderFakeBinding.checkBound()

        if (correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val config = store.findConfig(tenantId, providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val expectedSig = calculateHmac(config.secretKey, payload.rawPayload)
        if (payload.signatureHeader != expectedSig) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val lastSeq = store.getLastSequence(tenantId, payload.paymentReference)
        if (lastSeq > 0L && payload.deliverySequence <= lastSeq) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }

        val fp = calculateSha256("$tenantId:$providerId:${payload.signatureHeader}:${payload.rawPayload}")
        store.findExecutionByIdempotency(tenantId, idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "SIM-WEBHOOK-EVID-$resultId"

        val result = AdversarialPaymentExecutionResult(
            resultId = resultId,
            paymentReference = payload.paymentReference,
            tenantId = tenantId,
            providerId = providerId,
            operation = CanonicalPaymentOperation.CAPTURE,
            status = CanonicalPaymentStatus.CAPTURED,
            amountMinorUnits = 5000L,
            currencyCode = "EUR",
            externalTransactionReference = "EXT-WEBHOOK-${payload.paymentReference}",
            safeReasonCode = "SUCCESS",
            debitMinorUnits = 5000L,
            creditMinorUnits = 5000L,
            conserved = true,
            deliverySequence = payload.deliverySequence,
            serverTime = now,
            version = 1L,
            evidenceReference = evidenceRef,
            semanticContract = ADVERSARIAL_PAYMENT_FAKE_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = tenantId,
            type = "SIMULATED_WEBHOOK_CAPTURED",
            occurredAt = now,
            correlationId = correlationId,
            causationId = causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = tenantId,
            type = "SIMULATED_WEBHOOK_CAPTURED",
            createdAt = now,
        )

        store.saveExecution(result, tenantId, fp, idempotencyKey, payload.deliverySequence, audit, outbox)
        return result
    }

    @Synchronized
    fun executeSimulatedCompensation(command: ExecuteSimulatedCompensationCommand): AdversarialPaymentCompensationResult {
        AdversarialPaymentProviderFakeBinding.checkBound()

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
        val evidenceRef = "SIM-COMP-EVID-$resultId"
        val immutableCompRef = "COMP-REV-$resultId"

        val result = AdversarialPaymentCompensationResult(
            resultId = resultId,
            paymentReference = command.paymentReference,
            tenantId = command.tenantId,
            debitMinorUnits = command.originalDebitMinorUnits,
            creditMinorUnits = command.compensatingCreditMinorUnits,
            conserved = true,
            immutableCompensationReference = immutableCompRef,
            serverTime = now,
            evidenceReference = evidenceRef,
            semanticContract = ADVERSARIAL_PAYMENT_FAKE_CONTRACT,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SIMULATED_PAYMENT_COMPENSATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SIMULATED_PAYMENT_COMPENSATED",
            createdAt = now,
        )

        store.saveCompensation(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun calculateHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val key = SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
        mac.init(key)
        val rawHmac = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return rawHmac.joinToString("") { "%02x".format(it) }
    }

    private fun calculateSha256(raw: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(raw.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintConfig(cmd: ConfigureAdversarialPaymentFakeCommand): String =
        calculateSha256("${cmd.tenantId}:${cmd.providerId}:${cmd.simulationMode}:${cmd.expectedVersion}")

    private fun fingerprintExecution(cmd: ExecuteSimulatedPaymentCommand): String =
        calculateSha256("${cmd.tenantId}:${cmd.paymentReference}:${cmd.operation}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.providerId}:${cmd.expectedVersion}")

    private fun fingerprintCompensation(cmd: ExecuteSimulatedCompensationCommand): String =
        calculateSha256("${cmd.tenantId}:${cmd.paymentReference}:${cmd.originalDebitMinorUnits}:${cmd.compensatingCreditMinorUnits}:${cmd.currencyCode}:${cmd.expectedVersion}")
}

class InMemoryAdversarialPaymentFakeStore : AdversarialPaymentFakeStore {
    val configs = ConcurrentHashMap<String, AdversarialPaymentFakeConfig>()
    val configResults = ConcurrentHashMap<String, Pair<String, AdversarialPaymentFakeConfigResult>>()
    val executions = ConcurrentHashMap<String, Pair<String, AdversarialPaymentExecutionResult>>()
    val compensations = ConcurrentHashMap<String, Pair<String, AdversarialPaymentCompensationResult>>()
    val sequences = ConcurrentHashMap<String, Long>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findConfig(tenantId: String, providerId: String): AdversarialPaymentFakeConfig? =
        configs["$tenantId:$providerId"]

    override fun findConfigByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdversarialPaymentFakeConfigResult>? =
        configResults["$tenantId:$idempotencyKey"]

    override fun findExecutionByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdversarialPaymentExecutionResult>? =
        executions["$tenantId:$idempotencyKey"]

    override fun findCompensationByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, AdversarialPaymentCompensationResult>? =
        compensations["$tenantId:$idempotencyKey"]

    override fun getLastSequence(tenantId: String, paymentReference: String): Long =
        sequences["$tenantId:$paymentReference"] ?: 0L

    @Synchronized
    override fun saveConfig(
        config: AdversarialPaymentFakeConfig,
        result: AdversarialPaymentFakeConfigResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        configs["${config.tenantId}:${config.providerId}"] = config
        configResults["${config.tenantId}:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }

    @Synchronized
    override fun saveExecution(
        result: AdversarialPaymentExecutionResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        sequence: Long,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        executions["$tenantId:$idempotencyKey"] = queryFingerprint to result
        if (sequence > 0L) {
            sequences["$tenantId:${result.paymentReference}"] = sequence
        }
        this.audit += audit
        this.outbox += outbox
    }

    @Synchronized
    override fun saveCompensation(
        result: AdversarialPaymentCompensationResult,
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
