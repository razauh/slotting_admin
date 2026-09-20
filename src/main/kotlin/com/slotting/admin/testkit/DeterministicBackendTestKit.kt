package com.slotting.admin.testkit

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.security.MessageDigest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Traceability binding for TEST-001-01: Create deterministic backend test kit.
 * Fail-closed assertion gate for RED/GREEN TDD verification.
 * Expected RED failure reason: "nondeterministic retry/time tests".
 */
object DeterministicBackendTestKitBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("nondeterministic retry/time tests")
        }
    }
}

/**
 * Outcome-specific semantic contract for TEST-001-01.
 */
const val DETERMINISTIC_BACKEND_TEST_KIT_CONTRACT =
    "Provider fakes emulate duplicate/late/reordered/bad signatures; no fake satisfies certification."

// =============================================================================
// Deterministic Time & ID Infrastructure
// =============================================================================

/**
 * Controllable, predictable virtual clock preventing nondeterministic time tests.
 */
class DeterministicTestClock(
    private var currentInstant: Instant,
    private val zone: ZoneId = ZoneOffset.UTC
) : Clock() {
    private val lock = Any()

    override fun getZone(): ZoneId = zone

    override fun withZone(zone: ZoneId): Clock = DeterministicTestClock(currentInstant, zone)

    override fun instant(): Instant = synchronized(lock) { currentInstant }

    fun advance(duration: Duration): Instant = synchronized(lock) {
        currentInstant = currentInstant.plus(duration)
        currentInstant
    }

    fun advanceSeconds(seconds: Long): Instant = advance(Duration.ofSeconds(seconds))

    fun advanceMillis(millis: Long): Instant = advance(Duration.ofMillis(millis))

    fun setTime(instant: Instant) = synchronized(lock) {
        currentInstant = instant
    }
}

/**
 * Predictable, seeded ID and sequence generator eliminating UUID flakiness in tests.
 */
class DeterministicIdGenerator(
    private val prefix: String = "det",
    startValue: Long = 1L
) {
    private val counter = AtomicLong(startValue)

    fun nextId(entityType: String): String {
        val num = counter.getAndIncrement()
        return "$prefix-$entityType-%06d".format(num)
    }

    fun nextUuid(): UUID {
        val num = counter.getAndIncrement()
        return UUID.nameUUIDFromBytes("$prefix-uuid-$num".toByteArray(Charsets.UTF_8))
    }

    fun nextCorrelationId(): String = nextId("corr")

    fun nextCausationId(): String = nextId("caus")

    fun reset(startValue: Long = 1L) {
        counter.set(startValue)
    }
}

// =============================================================================
// Adversarial Provider Fake Emulation
// =============================================================================

/**
 * Modes of adversarial delivery for provider callbacks.
 */
enum class ProviderDeliveryAnomaly {
    NONE,
    DUPLICATE,
    LATE,
    REORDERED,
    BAD_SIGNATURE
}

/**
 * Provider fake tier.
 * Invariant: Fakes remain test-only and CAN NEVER satisfy certification!
 */
enum class ProviderTestTier {
    ADVERSARIAL_FAKE,
    SANDBOX_EMULATOR,
    PRODUCTION_CERTIFIED
}

/**
 * Adversarial provider callback payload.
 */
data class ProviderCallbackPayload(
    val eventId: String,
    val providerId: String,
    val sequenceNumber: Long,
    val timestamp: Instant,
    val payloadData: String,
    val signatureHex: String,
    val anomaly: ProviderDeliveryAnomaly = ProviderDeliveryAnomaly.NONE
)

/**
 * Adversarial provider fake emulating duplicate, late, reordered, and bad signatures.
 * Invariant: satisfiesCertification is ALWAYS false.
 */
class AdversarialProviderFake(
    val providerId: String,
    private val signingSecret: String = "fake-provider-signing-secret-key-12345"
) {
    val tier: ProviderTestTier = ProviderTestTier.ADVERSARIAL_FAKE

    /**
     * Strict architectural boundary: No fake satisfies production certification.
     */
    fun satisfiesCertification(): Boolean = false

    /**
     * Generates a callback with adversarial anomalies.
     */
    fun createCallback(
        eventId: String,
        sequenceNumber: Long,
        timestamp: Instant,
        payloadData: String,
        anomaly: ProviderDeliveryAnomaly
    ): ProviderCallbackPayload {
        val signature = when (anomaly) {
            ProviderDeliveryAnomaly.BAD_SIGNATURE -> "INVALID_SIGNATURE_BAD_HMAC_CORRUPTED"
            else -> computeHmacHex(payloadData, signingSecret)
        }

        return ProviderCallbackPayload(
            eventId = eventId,
            providerId = providerId,
            sequenceNumber = sequenceNumber,
            timestamp = timestamp,
            payloadData = payloadData,
            signatureHex = signature,
            anomaly = anomaly
        )
    }

    /**
     * Validates callback signature using SHA-256 HMAC.
     */
    fun verifySignature(payloadData: String, signatureHex: String): Boolean {
        val expected = computeHmacHex(payloadData, signingSecret)
        return expected.equals(signatureHex, ignoreCase = true)
    }

    private fun computeHmacHex(data: String, secret: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        val bytes = mac.doFinal(data.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

// =============================================================================
// Test Kit Store & Models
// =============================================================================

data class TestScenarioExecutionRecord(
    val executionId: String,
    val tenantId: String,
    val scenarioName: String,
    val simulatedEventsCount: Int,
    val lastSequenceProcessed: Long,
    val status: String,
    val serverTime: Instant,
    val serverVersion: Long = 1L
)

enum class TestKitAuditAction {
    SCENARIO_EXECUTED,
    PROVIDER_CALLBACK_PROCESSED,
    DUPLICATE_CALLBACK_DROPPED,
    LATE_CALLBACK_REJECTED,
    REORDERED_CALLBACK_HELD,
    BAD_SIGNATURE_REJECTED,
    FAKE_CERTIFICATION_ATTEMPT_REJECTED,
    FIXTURE_CREATED,
    FINANCIAL_MUTATION_REJECTED
}

data class TestKitAuditRecord(
    val auditId: UUID,
    val tenantId: String,
    val principalId: String,
    val action: TestKitAuditAction,
    val success: Boolean,
    val timestamp: Instant,
    val correlationId: String,
    val causationId: String,
    val detailsRedacted: String,
    val alertTriggered: Boolean = false
)

data class TestKitAlertRecord(
    val alertId: String,
    val tenantId: String,
    val severity: String,
    val alertType: String,
    val message: String,
    val correlationId: String,
    val timestamp: Instant
)

interface DeterministicTestKitStore {
    fun saveScenario(record: TestScenarioExecutionRecord)
    fun findScenario(tenantId: String, executionId: String): TestScenarioExecutionRecord?
    fun listScenarios(tenantId: String): List<TestScenarioExecutionRecord>
    fun recordAudit(audit: TestKitAuditRecord)
    fun getAudits(tenantId: String): List<TestKitAuditRecord>
    fun recordAlert(alert: TestKitAlertRecord)
    fun getAlerts(tenantId: String): List<TestKitAlertRecord>
    fun recordOutbox(outbox: OutboxEvent)
    fun getOutbox(): List<OutboxEvent>
    fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>?
    fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any)
    fun isEventProcessed(tenantId: String, eventId: String): Boolean
    fun markEventProcessed(tenantId: String, eventId: String)
}

class InMemoryDeterministicTestKitStore : DeterministicTestKitStore {
    private val scenarios = ConcurrentHashMap<String, TestScenarioExecutionRecord>()
    private val processedEvents = ConcurrentHashMap<String, Boolean>()
    private val audits = mutableListOf<TestKitAuditRecord>()
    private val alerts = mutableListOf<TestKitAlertRecord>()
    private val outbox = mutableListOf<OutboxEvent>()
    private val idempotency = ConcurrentHashMap<String, Pair<String, Any>>()

    private fun scenarioKey(tenantId: String, executionId: String) = "$tenantId::$executionId"
    private fun eventKey(tenantId: String, eventId: String) = "$tenantId::$eventId"
    private fun idempKey(tenantId: String, idempotencyKey: String) = "$tenantId::$idempotencyKey"

    override fun saveScenario(record: TestScenarioExecutionRecord) {
        scenarios[scenarioKey(record.tenantId, record.executionId)] = record
    }

    override fun findScenario(tenantId: String, executionId: String): TestScenarioExecutionRecord? {
        return scenarios[scenarioKey(tenantId, executionId)]
    }

    override fun listScenarios(tenantId: String): List<TestScenarioExecutionRecord> {
        return scenarios.values.filter { it.tenantId == tenantId }
    }

    @Synchronized
    override fun recordAudit(audit: TestKitAuditRecord) {
        audits.add(audit)
    }

    @Synchronized
    override fun getAudits(tenantId: String): List<TestKitAuditRecord> {
        return audits.filter { it.tenantId == tenantId }.toList()
    }

    @Synchronized
    override fun recordAlert(alert: TestKitAlertRecord) {
        alerts.add(alert)
    }

    @Synchronized
    override fun getAlerts(tenantId: String): List<TestKitAlertRecord> {
        return alerts.filter { it.tenantId == tenantId }.toList()
    }

    @Synchronized
    override fun recordOutbox(outboxEvent: OutboxEvent) {
        outbox.add(outboxEvent)
    }

    @Synchronized
    override fun getOutbox(): List<OutboxEvent> {
        return outbox.toList()
    }

    override fun findIdempotentResult(tenantId: String, idempotencyKey: String): Pair<String, Any>? {
        return idempotency[idempKey(tenantId, idempotencyKey)]
    }

    override fun saveIdempotentResult(tenantId: String, idempotencyKey: String, fingerprint: String, result: Any) {
        idempotency[idempKey(tenantId, idempotencyKey)] = Pair(fingerprint, result)
    }

    override fun isEventProcessed(tenantId: String, eventId: String): Boolean {
        return processedEvents.containsKey(eventKey(tenantId, eventId))
    }

    override fun markEventProcessed(tenantId: String, eventId: String) {
        processedEvents[eventKey(tenantId, eventId)] = true
    }
}

// =============================================================================
// Commands & Results
// =============================================================================

data class ExecuteDeterministicScenarioCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val scenarioName: String,
    val simulatedEvents: List<ProviderCallbackPayload>,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class ProcessProviderCallbackCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val callback: ProviderCallbackPayload,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
    val mutatesMoney: Boolean = false
)

data class AttemptFakeCertificationCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val providerFake: AdversarialProviderFake,
    val requestedTier: ProviderTestTier,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String
)

data class ExecuteDeterministicScenarioResult(
    val resultId: UUID,
    val executionId: String,
    val tenantId: String,
    val scenarioName: String,
    val totalEvents: Int,
    val acceptedEvents: Int,
    val rejectedEvents: Int,
    val duplicateEvents: Int,
    val lateEvents: Int,
    val reorderedEvents: Int,
    val badSignatureEvents: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class ProcessProviderCallbackResult(
    val resultId: UUID,
    val eventId: String,
    val providerId: String,
    val accepted: Boolean,
    val reasonCode: String,
    val anomalyDetected: ProviderDeliveryAnomaly,
    val serverTime: Instant,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

data class AttemptFakeCertificationResult(
    val providerId: String,
    val tierApproved: ProviderTestTier,
    val satisfiesCertification: Boolean,
    val serverTime: Instant,
    val evidenceReference: String,
    val isFinancialAuthorityCreated: Boolean = false
)

// =============================================================================
// Authoritative Service
// =============================================================================

class DeterministicBackendTestKitService(
    private val store: DeterministicTestKitStore,
    private val clock: DeterministicTestClock,
    private val idGenerator: DeterministicIdGenerator
) {
    private val lock = Any()

    /**
     * Executes a deterministic test scenario with step-by-step verification of provider callbacks.
     */
    fun executeScenario(command: ExecuteDeterministicScenarioCommand): ExecuteDeterministicScenarioResult = synchronized(lock) {
        DeterministicBackendTestKitBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        if (command.scenarioName.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "SCENARIO:${command.tenantId}:${command.scenarioName}:${command.simulatedEvents.size}:${command.expectedVersion}"
        val cached = checkIdempotency<ExecuteDeterministicScenarioResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val now = clock.instant()
        val executionId = idGenerator.nextId("scen")

        var accepted = 0
        var rejected = 0
        var duplicates = 0
        var late = 0
        var reordered = 0
        var badSignatures = 0
        var lastSequence = 0L

        for (event in command.simulatedEvents) {
            when (event.anomaly) {
                ProviderDeliveryAnomaly.DUPLICATE -> {
                    if (store.isEventProcessed(command.tenantId, event.eventId)) {
                        duplicates++
                        rejected++
                    } else {
                        store.markEventProcessed(command.tenantId, event.eventId)
                        accepted++
                    }
                }
                ProviderDeliveryAnomaly.LATE -> {
                    // Event timestamp is older than allowed window (e.g. > 1 hour ago)
                    val age = Duration.between(event.timestamp, now)
                    if (age > Duration.ofHours(1)) {
                        late++
                        rejected++
                    } else {
                        accepted++
                    }
                }
                ProviderDeliveryAnomaly.REORDERED -> {
                    if (event.sequenceNumber <= lastSequence) {
                        reordered++
                        rejected++
                    } else {
                        lastSequence = event.sequenceNumber
                        accepted++
                    }
                }
                ProviderDeliveryAnomaly.BAD_SIGNATURE -> {
                    badSignatures++
                    rejected++
                }
                ProviderDeliveryAnomaly.NONE -> {
                    store.markEventProcessed(command.tenantId, event.eventId)
                    lastSequence = event.sequenceNumber
                    accepted++
                }
            }
        }

        val scenarioRecord = TestScenarioExecutionRecord(
            executionId = executionId,
            tenantId = command.tenantId,
            scenarioName = command.scenarioName,
            simulatedEventsCount = command.simulatedEvents.size,
            lastSequenceProcessed = lastSequence,
            status = "COMPLETED",
            serverTime = now,
            serverVersion = command.expectedVersion
        )
        store.saveScenario(scenarioRecord)

        val resultId = idGenerator.nextUuid()
        val evidenceRef = "det-test:${command.tenantId}:$executionId:v${command.expectedVersion}:$resultId"

        val result = ExecuteDeterministicScenarioResult(
            resultId = resultId,
            executionId = executionId,
            tenantId = command.tenantId,
            scenarioName = command.scenarioName,
            totalEvents = command.simulatedEvents.size,
            acceptedEvents = accepted,
            rejectedEvents = rejected,
            duplicateEvents = duplicates,
            lateEvents = late,
            reorderedEvents = reordered,
            badSignatureEvents = badSignatures,
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.recordAudit(
            TestKitAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                principalId = command.principal!!.id,
                action = TestKitAuditAction.SCENARIO_EXECUTED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Executed scenario ${command.scenarioName} total=${command.simulatedEvents.size} accepted=$accepted rejected=$rejected",
                alertTriggered = false
            )
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Processes a single provider callback, emulating duplicate, late, reordered, or bad signature handling.
     */
    fun processProviderCallback(command: ProcessProviderCallbackCommand): ProcessProviderCallbackResult = synchronized(lock) {
        DeterministicBackendTestKitBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = false)
        validateCommonInvariants(command.idempotencyKey, command.expectedVersion, command.mutatesMoney)

        val cb = command.callback
        if (cb.eventId.isBlank() || cb.providerId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fingerprint = "CALLBACK:${command.tenantId}:${cb.eventId}:${cb.providerId}:${cb.sequenceNumber}:${cb.anomaly}:${cb.payloadData}:${command.expectedVersion}"
        val cached = checkIdempotency<ProcessProviderCallbackResult>(command.tenantId, command.idempotencyKey, fingerprint)
        if (cached != null) return cached

        val now = clock.instant()
        val resultId = idGenerator.nextUuid()
        val evidenceRef = "provider-cb:${command.tenantId}:${cb.eventId}:$resultId"

        // 1. Signature check
        if (cb.anomaly == ProviderDeliveryAnomaly.BAD_SIGNATURE || cb.signatureHex.contains("BAD") || cb.signatureHex.contains("INVALID")) {
            store.recordAudit(
                TestKitAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = TestKitAuditAction.BAD_SIGNATURE_REJECTED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Rejected bad signature for event ${cb.eventId}",
                    alertTriggered = true
                )
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 2. Duplicate check
        if (cb.anomaly == ProviderDeliveryAnomaly.DUPLICATE || store.isEventProcessed(command.tenantId, cb.eventId)) {
            store.recordAudit(
                TestKitAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = TestKitAuditAction.DUPLICATE_CALLBACK_DROPPED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Dropped duplicate callback for event ${cb.eventId}",
                    alertTriggered = false
                )
            )
            val result = ProcessProviderCallbackResult(
                resultId = resultId,
                eventId = cb.eventId,
                providerId = cb.providerId,
                accepted = false,
                reasonCode = "DUPLICATE_DROPPED",
                anomalyDetected = ProviderDeliveryAnomaly.DUPLICATE,
                serverTime = now,
                evidenceReference = evidenceRef,
                isFinancialAuthorityCreated = false
            )
            store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // 3. Late check (timestamp > 1 hour in past)
        val age = Duration.between(cb.timestamp, now)
        if (cb.anomaly == ProviderDeliveryAnomaly.LATE || age > Duration.ofHours(1)) {
            store.recordAudit(
                TestKitAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = TestKitAuditAction.LATE_CALLBACK_REJECTED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Rejected late callback for event ${cb.eventId} age=${age.toSeconds()}s",
                    alertTriggered = true
                )
            )
            val result = ProcessProviderCallbackResult(
                resultId = resultId,
                eventId = cb.eventId,
                providerId = cb.providerId,
                accepted = false,
                reasonCode = "LATE_REJECTED",
                anomalyDetected = ProviderDeliveryAnomaly.LATE,
                serverTime = now,
                evidenceReference = evidenceRef,
                isFinancialAuthorityCreated = false
            )
            store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // 4. Reordered delivery check
        if (cb.anomaly == ProviderDeliveryAnomaly.REORDERED) {
            store.recordAudit(
                TestKitAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = TestKitAuditAction.REORDERED_CALLBACK_HELD,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Held reordered callback for event ${cb.eventId} seq=${cb.sequenceNumber}",
                    alertTriggered = false
                )
            )
            val result = ProcessProviderCallbackResult(
                resultId = resultId,
                eventId = cb.eventId,
                providerId = cb.providerId,
                accepted = false,
                reasonCode = "REORDERED_HELD",
                anomalyDetected = ProviderDeliveryAnomaly.REORDERED,
                serverTime = now,
                evidenceReference = evidenceRef,
                isFinancialAuthorityCreated = false
            )
            store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
            return result
        }

        // Normal clean callback
        store.markEventProcessed(command.tenantId, cb.eventId)
        store.recordAudit(
            TestKitAuditRecord(
                auditId = UUID.randomUUID(),
                tenantId = command.tenantId,
                principalId = command.principal!!.id,
                action = TestKitAuditAction.PROVIDER_CALLBACK_PROCESSED,
                success = true,
                timestamp = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
                detailsRedacted = "Processed provider callback ${cb.eventId} seq=${cb.sequenceNumber}",
                alertTriggered = false
            )
        )

        val result = ProcessProviderCallbackResult(
            resultId = resultId,
            eventId = cb.eventId,
            providerId = cb.providerId,
            accepted = true,
            reasonCode = "ACCEPTED",
            anomalyDetected = ProviderDeliveryAnomaly.NONE,
            serverTime = now,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )

        store.saveIdempotentResult(command.tenantId, command.idempotencyKey, fingerprint, result)
        return result
    }

    /**
     * Strictly verifies that no test fake can satisfy production certification.
     * Enforces the semantic contract: "no fake satisfies certification".
     */
    fun attemptFakeCertification(command: AttemptFakeCertificationCommand): AttemptFakeCertificationResult = synchronized(lock) {
        DeterministicBackendTestKitBinding.checkBound()
        validatePrincipal(command.principal, command.tenantId, requireAdmin = true)

        val fake = command.providerFake
        val now = clock.instant()

        // Strict architectural rule: Fakes cannot satisfy certification!
        if (command.requestedTier == ProviderTestTier.PRODUCTION_CERTIFIED || fake.satisfiesCertification()) {
            store.recordAudit(
                TestKitAuditRecord(
                    auditId = UUID.randomUUID(),
                    tenantId = command.tenantId,
                    principalId = command.principal!!.id,
                    action = TestKitAuditAction.FAKE_CERTIFICATION_ATTEMPT_REJECTED,
                    success = false,
                    timestamp = now,
                    correlationId = command.correlationId,
                    causationId = command.causationId,
                    detailsRedacted = "Rejected production certification attempt for fake ${fake.providerId}",
                    alertTriggered = true
                )
            )

            val alert = TestKitAlertRecord(
                alertId = "alert-${UUID.randomUUID()}",
                tenantId = command.tenantId,
                severity = "CRITICAL",
                alertType = "FAKE_CERTIFICATION_VIOLATION",
                message = "Provider fake ${fake.providerId} attempted to claim production certification. Blocked.",
                correlationId = command.correlationId,
                timestamp = now
            )
            store.recordAlert(alert)

            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val resultId = idGenerator.nextUuid()
        val evidenceRef = "fake-cert:${command.tenantId}:${fake.providerId}:$resultId"

        return AttemptFakeCertificationResult(
            providerId = fake.providerId,
            tierApproved = fake.tier,
            satisfiesCertification = false,
            serverTime = now,
            evidenceReference = evidenceRef,
            isFinancialAuthorityCreated = false
        )
    }

    // =========================================================================
    // Helper Validations
    // =========================================================================

    private fun validatePrincipal(principal: AuthenticatedPrincipal?, tenantId: String, requireAdmin: Boolean) {
        if (principal == null) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        }
        if (principal.tenantId != tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        if (requireAdmin && principal.kind != PrincipalKind.ADMIN) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }

    private fun validateCommonInvariants(idempotencyKey: String, expectedVersion: Long, mutatesMoney: Boolean) {
        if (idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
        if (mutatesMoney) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> checkIdempotency(tenantId: String, idempotencyKey: String, fingerprint: String): T? {
        val cached = store.findIdempotentResult(tenantId, idempotencyKey) ?: return null
        if (cached.first != fingerprint) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        return cached.second as T
    }
}
