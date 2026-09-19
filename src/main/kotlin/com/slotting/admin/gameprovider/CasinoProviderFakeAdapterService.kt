package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Fail-closed verification gate for GAME-001-02.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object CasinoProviderFakeAdapterBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("bad creds/signature/replay")
        }
    }
}

enum class CasinoProviderAdapterTier {
    PORT_ONLY,
    ADVERSARIAL_FAKE,
    SANDBOX,
    PRODUCTION_CERTIFIED,
}

enum class AdversarialSimulationMode {
    NORMAL,
    BAD_CREDENTIALS,
    BAD_SIGNATURE,
    REPLAY_ATTACK,
    OUTAGE_SIMULATION,
    ROTATION_SIMULATION,
}

data class CasinoProviderAdapterConfig(
    val configId: UUID,
    val tenantId: String,
    val providerId: String,
    val tier: CasinoProviderAdapterTier,
    val simulationMode: AdversarialSimulationMode,
    val version: Long = 1L,
)

data class SimulatedRoundOutcome(
    val roundReference: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val currencyCode: String,
    val rawPayload: String,
    val keyId: String,
    val signature: String,
    val timestamp: Long,
    val simulationMode: AdversarialSimulationMode,
)

data class SimulatedRollbackRequest(
    val roundReference: String,
    val originalDebitMinorUnits: Long,
    val compensatingCreditMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
)

data class SimulatedRollbackResult(
    val rollbackId: UUID,
    val roundReference: String,
    val success: Boolean,
    val immutableCompensationReference: String,
    val conserved: Boolean,
    val serverTime: Instant,
)

interface CasinoProviderPort {
    fun simulateCallback(
        tenantId: String,
        providerId: String,
        roundReference: String,
        debitMinorUnits: Long,
        creditMinorUnits: Long,
        currencyCode: String,
        mode: AdversarialSimulationMode,
    ): SimulatedRoundOutcome

    fun executeRollback(
        tenantId: String,
        providerId: String,
        request: SimulatedRollbackRequest,
    ): SimulatedRollbackResult
}

data class ConfigureCasinoAdapterCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val tier: CasinoProviderAdapterTier,
    val simulationMode: AdversarialSimulationMode,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class ExecuteSimulatedRollbackCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val currencyCode: String,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class DispatchSimulatedCallbackCommand(
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class CasinoAdapterConfigResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val tier: CasinoProviderAdapterTier,
    val simulationMode: AdversarialSimulationMode,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class CasinoRollbackCompensationResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val debitMinorUnits: Long,
    val creditMinorUnits: Long,
    val conserved: Boolean,
    val compensationReference: String,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class SimulatedCallbackDispatchResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val verificationResult: ProviderCallbackVerificationResult?,
    val failureCode: AuthErrorCode?,
    val simulationMode: AdversarialSimulationMode,
    val rotationObservable: Boolean,
    val outageObservable: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface CasinoProviderAdapterStore {
    fun findConfig(tenantId: String, providerId: String): CasinoProviderAdapterConfig?
    fun findConfigByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoAdapterConfigResult>?
    fun saveConfig(
        config: CasinoProviderAdapterConfig,
        result: CasinoAdapterConfigResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findRollbackByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoRollbackCompensationResult>?
    fun saveRollback(
        result: CasinoRollbackCompensationResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findDispatchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, SimulatedCallbackDispatchResult>?
    fun saveDispatch(
        result: SimulatedCallbackDispatchResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class CasinoProviderFakeAdapter(
    private val contractStore: CanonicalCasinoProviderContractStore,
    private val secretResolver: ProviderSecretResolver,
    private val clock: Clock = Clock.systemUTC(),
) : CasinoProviderPort {

    private val lastSignatures = ConcurrentHashMap<String, String>()
    private val lastTimestamps = ConcurrentHashMap<String, Long>()

    override fun simulateCallback(
        tenantId: String,
        providerId: String,
        roundReference: String,
        debitMinorUnits: Long,
        creditMinorUnits: Long,
        currencyCode: String,
        mode: AdversarialSimulationMode,
    ): SimulatedRoundOutcome {
        CasinoProviderFakeAdapterBinding.checkBound()

        val schema = contractStore.findSchema(tenantId, providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        // Outage simulation: if provider health is OUTAGE_TRIPPED or mode is OUTAGE_SIMULATION
        if (schema.healthState == ProviderHealthState.OUTAGE_TRIPPED || mode == AdversarialSimulationMode.OUTAGE_SIMULATION) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        val now = clock.instant().epochSecond
        val rawPayload = """{"roundId":"$roundReference","debit":$debitMinorUnits,"credit":$creditMinorUnits,"currency":"$currencyCode"}"""

        return when (mode) {
            AdversarialSimulationMode.BAD_CREDENTIALS -> {
                // Emits invalid/unknown key ID
                val badKeyId = "fake-unknown-key-999"
                val fakeSig = computeHmac("fake-bad-secret", "$now.$rawPayload")
                SimulatedRoundOutcome(
                    roundReference = roundReference,
                    debitMinorUnits = debitMinorUnits,
                    creditMinorUnits = creditMinorUnits,
                    currencyCode = currencyCode,
                    rawPayload = rawPayload,
                    keyId = badKeyId,
                    signature = fakeSig,
                    timestamp = now,
                    simulationMode = mode,
                )
            }
            AdversarialSimulationMode.BAD_SIGNATURE -> {
                // Emits correct key ID but forged/tampered signature
                val activeKeyId = schema.activeKey.keyId
                val corruptedSig = "deadbeef00000000111122223333444455556666777788889999aaaabbbbcccc"
                SimulatedRoundOutcome(
                    roundReference = roundReference,
                    debitMinorUnits = debitMinorUnits,
                    creditMinorUnits = creditMinorUnits,
                    currencyCode = currencyCode,
                    rawPayload = rawPayload,
                    keyId = activeKeyId,
                    signature = corruptedSig,
                    timestamp = now,
                    simulationMode = mode,
                )
            }
            AdversarialSimulationMode.REPLAY_ATTACK -> {
                // Replays previously recorded signature & timestamp if available, else creates one and repeats
                val providerKey = "$tenantId:$providerId"
                val cachedSig = lastSignatures[providerKey]
                val cachedTs = lastTimestamps[providerKey] ?: now
                val activeKeyId = schema.activeKey.keyId
                val rawSecret = try {
                    secretResolver.resolveRawSecret(tenantId, providerId, activeKeyId)
                } catch (_: Exception) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
                } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)

                val replaySig = cachedSig ?: computeHmac(rawSecret, "$cachedTs.$rawPayload")
                SimulatedRoundOutcome(
                    roundReference = roundReference,
                    debitMinorUnits = debitMinorUnits,
                    creditMinorUnits = creditMinorUnits,
                    currencyCode = currencyCode,
                    rawPayload = rawPayload,
                    keyId = activeKeyId,
                    signature = replaySig,
                    timestamp = cachedTs,
                    simulationMode = mode,
                )
            }
            AdversarialSimulationMode.ROTATION_SIMULATION -> {
                // Uses next rotating key if available
                val rotatingKey = schema.nextKey
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                val rawSecret = try {
                    secretResolver.resolveRawSecret(tenantId, providerId, rotatingKey.keyId)
                } catch (_: Exception) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
                } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
                val sig = computeHmac(rawSecret, "$now.$rawPayload")
                lastSignatures["$tenantId:$providerId"] = sig
                lastTimestamps["$tenantId:$providerId"] = now

                SimulatedRoundOutcome(
                    roundReference = roundReference,
                    debitMinorUnits = debitMinorUnits,
                    creditMinorUnits = creditMinorUnits,
                    currencyCode = currencyCode,
                    rawPayload = rawPayload,
                    keyId = rotatingKey.keyId,
                    signature = sig,
                    timestamp = now,
                    simulationMode = mode,
                )
            }
            AdversarialSimulationMode.NORMAL -> {
                val activeKeyId = schema.activeKey.keyId
                val rawSecret = try {
                    secretResolver.resolveRawSecret(tenantId, providerId, activeKeyId)
                } catch (_: Exception) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
                } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
                val sig = computeHmac(rawSecret, "$now.$rawPayload")
                lastSignatures["$tenantId:$providerId"] = sig
                lastTimestamps["$tenantId:$providerId"] = now

                SimulatedRoundOutcome(
                    roundReference = roundReference,
                    debitMinorUnits = debitMinorUnits,
                    creditMinorUnits = creditMinorUnits,
                    currencyCode = currencyCode,
                    rawPayload = rawPayload,
                    keyId = activeKeyId,
                    signature = sig,
                    timestamp = now,
                    simulationMode = mode,
                )
            }
            AdversarialSimulationMode.OUTAGE_SIMULATION -> {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
        }
    }

    override fun executeRollback(
        tenantId: String,
        providerId: String,
        request: SimulatedRollbackRequest,
    ): SimulatedRollbackResult {
        CasinoProviderFakeAdapterBinding.checkBound()

        val schema = contractStore.findSchema(tenantId, providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (schema.healthState == ProviderHealthState.OUTAGE_TRIPPED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }

        // Conservation check: originalDebit must equal compensatingCredit
        if (request.originalDebitMinorUnits < 0 || request.compensatingCreditMinorUnits < 0 ||
            request.originalDebitMinorUnits != request.compensatingCreditMinorUnits ||
            !request.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val rollbackId = UUID.randomUUID()
        return SimulatedRollbackResult(
            rollbackId = rollbackId,
            roundReference = request.roundReference,
            success = true,
            immutableCompensationReference = "COMP-ROLLBACK-${tenantId}-$rollbackId",
            conserved = true,
            serverTime = clock.instant(),
        )
    }

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

class CasinoProviderAdapterService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val adapter: CasinoProviderPort,
    private val contractService: CanonicalCasinoProviderContractService,
    private val contractStore: CanonicalCasinoProviderContractStore,
    private val adapterStore: CasinoProviderAdapterStore,
    private val clock: Clock = Clock.systemUTC(),
) {

    @Synchronized
    fun configureAdapter(command: ConfigureCasinoAdapterCommand): CasinoAdapterConfigResult {
        CasinoProviderFakeAdapterBinding.checkBound()

        // 1. Validation
        if (command.providerId.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Tenancy & Principal Check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Idempotency Check
        val fp = fingerprintConfig(command)
        adapterStore.findConfigByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 4. Session authorization
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Version check
        val existing = adapterStore.findConfig(command.tenantId, command.providerId)
        val targetVersion = if (existing != null) existing.version + 1L else 1L

        if (command.expectedVersion != targetVersion) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 6. Canonical schema verification
        val schema = contractStore.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val now = clock.instant()
        val config = CasinoProviderAdapterConfig(
            configId = UUID.randomUUID(),
            tenantId = command.tenantId,
            providerId = command.providerId,
            tier = command.tier,
            simulationMode = command.simulationMode,
            version = targetVersion,
        )

        val resultId = UUID.randomUUID()
        val result = CasinoAdapterConfigResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            tier = command.tier,
            simulationMode = command.simulationMode,
            rotationObservable = schema.nextKey != null,
            outageObservable = schema.healthState != ProviderHealthState.HEALTHY,
            serverTime = now,
            evidenceReference = "EVID-CASINO-ADAPTER-CONFIG-${command.tenantId}-${command.providerId}-v$targetVersion",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_ADAPTER_CONFIGURED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_ADAPTER_CONFIGURED",
            createdAt = now,
        )

        adapterStore.saveConfig(config, result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun executeRollback(command: ExecuteSimulatedRollbackCommand): CasinoRollbackCompensationResult {
        CasinoProviderFakeAdapterBinding.checkBound()

        if (command.providerId.isBlank() ||
            command.roundReference.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.debitMinorUnits < 0 ||
            command.creditMinorUnits < 0 ||
            command.debitMinorUnits != command.creditMinorUnits ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprintRollback(command)
        adapterStore.findRollbackByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val rollbackReq = SimulatedRollbackRequest(
            roundReference = command.roundReference,
            originalDebitMinorUnits = command.debitMinorUnits,
            compensatingCreditMinorUnits = command.creditMinorUnits,
            currencyCode = command.currencyCode,
            reason = command.reason,
        )

        val adapterResult = adapter.executeRollback(command.tenantId, command.providerId, rollbackReq)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val result = CasinoRollbackCompensationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            roundReference = command.roundReference,
            debitMinorUnits = command.debitMinorUnits,
            creditMinorUnits = command.creditMinorUnits,
            conserved = adapterResult.conserved,
            compensationReference = adapterResult.immutableCompensationReference,
            serverTime = now,
            evidenceReference = "EVID-CASINO-ROLLBACK-${command.tenantId}-${command.roundReference}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_ROLLBACK_COMPENSATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "CASINO_PROVIDER_ROLLBACK_COMPENSATED",
            createdAt = now,
        )

        adapterStore.saveRollback(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun dispatchSimulatedCallback(command: DispatchSimulatedCallbackCommand): SimulatedCallbackDispatchResult {
        CasinoProviderFakeAdapterBinding.checkBound()

        if (command.providerId.isBlank() ||
            command.roundReference.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.debitMinorUnits < 0 ||
            command.creditMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintDispatch(command)
        adapterStore.findDispatchByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val config = adapterStore.findConfig(command.tenantId, command.providerId)
        val mode = config?.simulationMode ?: AdversarialSimulationMode.NORMAL

        val now = clock.instant()
        var verificationResult: ProviderCallbackVerificationResult? = null
        var failureCode: AuthErrorCode? = null

        try {
            val simulation = adapter.simulateCallback(
                tenantId = command.tenantId,
                providerId = command.providerId,
                roundReference = command.roundReference,
                debitMinorUnits = command.debitMinorUnits,
                creditMinorUnits = command.creditMinorUnits,
                currencyCode = command.currencyCode,
                mode = mode,
            )

            val verifyCmd = VerifyCasinoCallbackCommand(
                tenantId = command.tenantId,
                providerId = command.providerId,
                keyId = simulation.keyId,
                signature = simulation.signature,
                timestamp = simulation.timestamp,
                roundReference = simulation.roundReference,
                rawPayload = simulation.rawPayload,
                debitMinorUnits = simulation.debitMinorUnits,
                creditMinorUnits = simulation.creditMinorUnits,
                currencyCode = simulation.currencyCode,
                idempotencyKey = "${command.idempotencyKey}-verify",
                correlationId = command.correlationId,
                causationId = command.causationId,
                expectedVersion = 1L,
            )

            verificationResult = contractService.verifyCallback(verifyCmd)
        } catch (ex: AuthenticationFailure.Rejected) {
            failureCode = ex.code
        }

        val resultId = UUID.randomUUID()
        val result = SimulatedCallbackDispatchResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            roundReference = command.roundReference,
            verificationResult = verificationResult,
            failureCode = failureCode,
            simulationMode = mode,
            rotationObservable = true,
            outageObservable = true,
            serverTime = now,
            evidenceReference = "EVID-CASINO-DISPATCH-${command.tenantId}-${command.roundReference}",
        )

        val eventType = if (verificationResult != null) {
            "CASINO_PROVIDER_CALLBACK_DISPATCHED"
        } else {
            "CASINO_PROVIDER_CALLBACK_REJECTED_${failureCode?.name ?: "UNKNOWN"}"
        }

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = eventType,
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = eventType,
            createdAt = now,
        )

        adapterStore.saveDispatch(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)

        // If verification produced a failure code, re-throw for the public caller boundary when fail-closed
        if (failureCode != null) {
            throw AuthenticationFailure.Rejected(failureCode)
        }

        return result
    }

    private fun fingerprintConfig(cmd: ConfigureCasinoAdapterCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.tier}:${cmd.simulationMode}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintRollback(cmd: ExecuteSimulatedRollbackCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.roundReference}:${cmd.debitMinorUnits}:${cmd.creditMinorUnits}:${cmd.currencyCode}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintDispatch(cmd: DispatchSimulatedCallbackCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.roundReference}:${cmd.debitMinorUnits}:${cmd.creditMinorUnits}:${cmd.currencyCode}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
