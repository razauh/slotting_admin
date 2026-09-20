package com.slotting.admin.testkit

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Contract test suite for TEST-001-01: Create deterministic backend test kit.
 *
 * Source implementation-plan family: TEST-001
 * Semantic Contract: "Provider fakes emulate duplicate/late/reordered/bad signatures; no fake satisfies certification."
 * Expected RED failure: "nondeterministic retry/time tests"
 */
class DeterministicBackendTestKitTest {

    private val baseInstant = Instant.parse("2026-09-20T17:00:00Z")

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-testkit-01",
        tenantId = "tenant-test-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-testkit-01",
        tenantId = "tenant-test-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    @BeforeEach
    fun setUp() {
        DeterministicBackendTestKitBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        DeterministicBackendTestKitBinding.isBound = true
    }

    // =========================================================================
    // TEST-001-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `TEST-001-01-T001 Create deterministic backend test kit produces the required authoritative outcome`() {
        // Fail-closed gate check: triggers RED assertion failure when unbound
        DeterministicBackendTestKitBinding.checkBound()

        val clock = DeterministicTestClock(baseInstant, ZoneOffset.UTC)
        val idGenerator = DeterministicIdGenerator(prefix = "det-test", startValue = 1L)
        val store = InMemoryDeterministicTestKitStore()
        val service = DeterministicBackendTestKitService(store, clock, idGenerator)

        // 1. Verify deterministic clock and advance behavior
        assertEquals(baseInstant, clock.instant())
        clock.advance(Duration.ofMinutes(15))
        assertEquals(baseInstant.plus(Duration.ofMinutes(15)), clock.instant())

        // 2. Verify deterministic ID generation
        val id1 = idGenerator.nextId("order")
        val id2 = idGenerator.nextId("order")
        assertEquals("det-test-order-000001", id1)
        assertEquals("det-test-order-000002", id2)

        // 3. Provider fake emulates duplicate, late, reordered, and bad signatures
        val providerFake = AdversarialProviderFake(providerId = "provider-pragmatic-play-fake")

        // Clean callback
        val cleanCallback = providerFake.createCallback(
            eventId = "evt-clean-01",
            sequenceNumber = 101L,
            timestamp = clock.instant(),
            payloadData = "{\"action\":\"round_complete\",\"amount\":500}",
            anomaly = ProviderDeliveryAnomaly.NONE
        )
        val cleanResult = service.processProviderCallback(
            ProcessProviderCallbackCommand(
                principal = adminPrincipal,
                tenantId = "tenant-test-1",
                callback = cleanCallback,
                idempotencyKey = "idemp-clean-01",
                correlationId = idGenerator.nextCorrelationId(),
                causationId = idGenerator.nextCausationId(),
                expectedVersion = 1L,
                mutatesMoney = false
            )
        )
        assertTrue(cleanResult.accepted)
        assertEquals("ACCEPTED", cleanResult.reasonCode)
        assertFalse(cleanResult.isFinancialAuthorityCreated)

        // Duplicate delivery emulation
        val duplicateCallback = providerFake.createCallback(
            eventId = "evt-clean-01", // duplicate event ID
            sequenceNumber = 101L,
            timestamp = clock.instant(),
            payloadData = "{\"action\":\"round_complete\",\"amount\":500}",
            anomaly = ProviderDeliveryAnomaly.DUPLICATE
        )
        val duplicateResult = service.processProviderCallback(
            ProcessProviderCallbackCommand(
                principal = adminPrincipal,
                tenantId = "tenant-test-1",
                callback = duplicateCallback,
                idempotencyKey = "idemp-dup-01",
                correlationId = idGenerator.nextCorrelationId(),
                causationId = idGenerator.nextCausationId(),
                expectedVersion = 1L,
                mutatesMoney = false
            )
        )
        assertFalse(duplicateResult.accepted)
        assertEquals("DUPLICATE_DROPPED", duplicateResult.reasonCode)
        assertFalse(duplicateResult.isFinancialAuthorityCreated)

        // Late delivery emulation
        val lateCallback = providerFake.createCallback(
            eventId = "evt-late-01",
            sequenceNumber = 102L,
            timestamp = clock.instant().minus(Duration.ofHours(3)), // 3 hours old
            payloadData = "{\"action\":\"round_complete\",\"amount\":100}",
            anomaly = ProviderDeliveryAnomaly.LATE
        )
        val lateResult = service.processProviderCallback(
            ProcessProviderCallbackCommand(
                principal = adminPrincipal,
                tenantId = "tenant-test-1",
                callback = lateCallback,
                idempotencyKey = "idemp-late-01",
                correlationId = idGenerator.nextCorrelationId(),
                causationId = idGenerator.nextCausationId(),
                expectedVersion = 1L,
                mutatesMoney = false
            )
        )
        assertFalse(lateResult.accepted)
        assertEquals("LATE_REJECTED", lateResult.reasonCode)
        assertFalse(lateResult.isFinancialAuthorityCreated)

        // Reordered delivery emulation
        val reorderedCallback = providerFake.createCallback(
            eventId = "evt-reorder-01",
            sequenceNumber = 50L, // out of order sequence
            timestamp = clock.instant(),
            payloadData = "{\"action\":\"round_complete\",\"amount\":200}",
            anomaly = ProviderDeliveryAnomaly.REORDERED
        )
        val reorderResult = service.processProviderCallback(
            ProcessProviderCallbackCommand(
                principal = adminPrincipal,
                tenantId = "tenant-test-1",
                callback = reorderedCallback,
                idempotencyKey = "idemp-reorder-01",
                correlationId = idGenerator.nextCorrelationId(),
                causationId = idGenerator.nextCausationId(),
                expectedVersion = 1L,
                mutatesMoney = false
            )
        )
        assertFalse(reorderResult.accepted)
        assertEquals("REORDERED_HELD", reorderResult.reasonCode)
        assertFalse(reorderResult.isFinancialAuthorityCreated)

        // Bad signature emulation
        val badSigCallback = providerFake.createCallback(
            eventId = "evt-bad-sig-01",
            sequenceNumber = 103L,
            timestamp = clock.instant(),
            payloadData = "{\"action\":\"round_complete\",\"amount\":300}",
            anomaly = ProviderDeliveryAnomaly.BAD_SIGNATURE
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(
                ProcessProviderCallbackCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-test-1",
                    callback = badSigCallback,
                    idempotencyKey = "idemp-badsig-01",
                    correlationId = idGenerator.nextCorrelationId(),
                    causationId = idGenerator.nextCausationId(),
                    expectedVersion = 1L,
                    mutatesMoney = false
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Invariant: NO fake satisfies certification
        assertFalse(providerFake.satisfiesCertification())
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.attemptFakeCertification(
                AttemptFakeCertificationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-test-1",
                    providerFake = providerFake,
                    requestedTier = ProviderTestTier.PRODUCTION_CERTIFIED, // FORBIDDEN FOR FAKE!
                    idempotencyKey = "idemp-cert-attempt-01",
                    correlationId = idGenerator.nextCorrelationId(),
                    causationId = idGenerator.nextCausationId()
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Assert exact semantic contract
        assertEquals(
            "Provider fakes emulate duplicate/late/reordered/bad signatures; no fake satisfies certification.",
            DETERMINISTIC_BACKEND_TEST_KIT_CONTRACT
        )

        // 6. Verify audits exist and no secrets/passwords leaked
        val audits = store.getAudits("tenant-test-1")
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.any { it.action == TestKitAuditAction.PROVIDER_CALLBACK_PROCESSED })
        assertTrue(audits.any { it.action == TestKitAuditAction.DUPLICATE_CALLBACK_DROPPED })
        assertTrue(audits.any { it.action == TestKitAuditAction.LATE_CALLBACK_REJECTED })
        assertTrue(audits.any { it.action == TestKitAuditAction.REORDERED_CALLBACK_HELD })
        assertTrue(audits.any { it.action == TestKitAuditAction.BAD_SIGNATURE_REJECTED })
        assertTrue(audits.any { it.action == TestKitAuditAction.FAKE_CERTIFICATION_ATTEMPT_REJECTED })

        val auditDetails = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditDetails.contains("PASSWORD", ignoreCase = true))
        assertFalse(auditDetails.contains("SECRET", ignoreCase = true))

        // 7. Verify no financial mutation methods exist on service
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // TEST-001-01-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `TEST-001-01-T002 Create deterministic backend test kit rejects invalid boundary unauthorized and stale input`() {
        DeterministicBackendTestKitBinding.isBound = true

        val clock = DeterministicTestClock(baseInstant, ZoneOffset.UTC)
        val idGenerator = DeterministicIdGenerator()
        val store = InMemoryDeterministicTestKitStore()
        val service = DeterministicBackendTestKitService(store, clock, idGenerator)
        val providerFake = AdversarialProviderFake(providerId = "test-provider-t002")

        val validCallback = providerFake.createCallback(
            eventId = "evt-t002-01",
            sequenceNumber = 1L,
            timestamp = clock.instant(),
            payloadData = "{\"ping\":\"pong\"}",
            anomaly = ProviderDeliveryAnomaly.NONE
        )

        val validCommand = ProcessProviderCallbackCommand(
            principal = adminPrincipal,
            tenantId = "tenant-test-1",
            callback = validCallback,
            idempotencyKey = "idemp-t002-valid",
            correlationId = "corr-t002-01",
            causationId = "caus-t002-01",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(validCommand.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(validCommand.copy(tenantId = "other-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Stale expected version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(validCommand.copy(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Financial mutation attempt rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(validCommand.copy(mutatesMoney = true))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Blank eventId or providerId rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(validCommand.copy(callback = validCallback.copy(eventId = "  ")))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(validCommand.copy(callback = validCallback.copy(providerId = "")))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Blank idempotencyKey rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(validCommand.copy(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Non-admin attempting scenario execution rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeScenario(
                ExecuteDeterministicScenarioCommand(
                    principal = playerPrincipal,
                    tenantId = "tenant-test-1",
                    scenarioName = "admin_only_scenario",
                    simulatedEvents = emptyList(),
                    idempotencyKey = "idemp-t002-nonadmin",
                    correlationId = "corr-t002-02",
                    causationId = "caus-t002-02",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Blank scenario name rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeScenario(
                ExecuteDeterministicScenarioCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-test-1",
                    scenarioName = "   ",
                    simulatedEvents = emptyList(),
                    idempotencyKey = "idemp-t002-blank-scen",
                    correlationId = "corr-t002-03",
                    causationId = "caus-t002-03",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // TEST-001-01-T003: Concurrency, Replay, Conflict, and Dependency Failure
    // =========================================================================

    @Test
    fun `TEST-001-01-T003 Create deterministic backend test kit survives concurrency duplicate delivery and dependency failure`() {
        DeterministicBackendTestKitBinding.isBound = true

        val clock = DeterministicTestClock(baseInstant, ZoneOffset.UTC)
        val idGenerator = DeterministicIdGenerator(prefix = "conc-test")
        val store = InMemoryDeterministicTestKitStore()
        val service = DeterministicBackendTestKitService(store, clock, idGenerator)
        val providerFake = AdversarialProviderFake(providerId = "test-provider-t003")

        // 1. Concurrency: 10 concurrent threads running deterministic scenarios
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        try {
            val tasks = (1..threadCount).map { i ->
                Callable {
                    val events = listOf(
                        providerFake.createCallback(
                            eventId = "evt-conc-$i-1",
                            sequenceNumber = 1L,
                            timestamp = clock.instant(),
                            payloadData = "{\"data\":$i}",
                            anomaly = ProviderDeliveryAnomaly.NONE
                        ),
                        providerFake.createCallback(
                            eventId = "evt-conc-$i-1", // duplicate
                            sequenceNumber = 1L,
                            timestamp = clock.instant(),
                            payloadData = "{\"data\":$i}",
                            anomaly = ProviderDeliveryAnomaly.DUPLICATE
                        )
                    )
                    service.executeScenario(
                        ExecuteDeterministicScenarioCommand(
                            principal = adminPrincipal,
                            tenantId = "tenant-test-1",
                            scenarioName = "scenario-conc-$i",
                            simulatedEvents = events,
                            idempotencyKey = "idemp-conc-scen-$i",
                            correlationId = "corr-conc-$i",
                            causationId = "caus-conc-$i",
                            expectedVersion = 1L
                        )
                    )
                }
            }

            val futures = tasks.map { executor.submit(it) }
            val results = futures.map { it.get() }
            assertEquals(10, results.size)
            results.forEach {
                assertEquals(2, it.totalEvents)
                assertEquals(1, it.acceptedEvents)
                assertEquals(1, it.duplicateEvents)
                assertFalse(it.isFinancialAuthorityCreated)
            }
        } finally {
            executor.shutdown()
        }

        // 2. Idempotent replay: identical idempotencyKey + fingerprint returns cached result
        val sampleCallback = providerFake.createCallback(
            eventId = "evt-replay-01",
            sequenceNumber = 1L,
            timestamp = clock.instant(),
            payloadData = "{\"replay\":\"ok\"}",
            anomaly = ProviderDeliveryAnomaly.NONE
        )
        val replayCmd = ProcessProviderCallbackCommand(
            principal = adminPrincipal,
            tenantId = "tenant-test-1",
            callback = sampleCallback,
            idempotencyKey = "idemp-replay-key-01",
            correlationId = "corr-replay-01",
            causationId = "caus-replay-01",
            expectedVersion = 1L
        )
        val res1 = service.processProviderCallback(replayCmd)
        val res2 = service.processProviderCallback(replayCmd)
        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.evidenceReference, res2.evidenceReference)

        // 3. Conflict replay: identical idempotencyKey with modified payload throws CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processProviderCallback(
                replayCmd.copy(callback = sampleCallback.copy(payloadData = "{\"replay\":\"MODIFIED_PAYLOAD\"}"))
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // TEST-001-01-T004: Lifecycle, Fail-Closed Binding, Redaction, and Observability
    // =========================================================================

    @Test
    fun `TEST-001-01-T004 Create deterministic backend test kit remains compatible recoverable observable and lifecycle-safe`() {
        // 1. Verification gate test: when isBound = false, checkBound() throws AssertionError
        DeterministicBackendTestKitBinding.isBound = false
        val gateException = assertFailsWith<AssertionError> {
            DeterministicBackendTestKitBinding.checkBound()
        }
        assertEquals("nondeterministic retry/time tests", gateException.message)

        // Restore gate
        DeterministicBackendTestKitBinding.isBound = true

        val clock = DeterministicTestClock(baseInstant, ZoneOffset.UTC)
        val idGenerator = DeterministicIdGenerator(prefix = "life-test")
        val store = InMemoryDeterministicTestKitStore()
        val service = DeterministicBackendTestKitService(store, clock, idGenerator)
        val providerFake = AdversarialProviderFake(providerId = "provider-lifecycle")

        // 2. Execute scenario with diverse anomalies
        val simulatedEvents = listOf(
            providerFake.createCallback("evt-life-1", 1L, clock.instant(), "{\"step\":1}", ProviderDeliveryAnomaly.NONE),
            providerFake.createCallback("evt-life-1", 1L, clock.instant(), "{\"step\":1}", ProviderDeliveryAnomaly.DUPLICATE),
            providerFake.createCallback("evt-life-2", 2L, clock.instant().minus(Duration.ofHours(2)), "{\"step\":2}", ProviderDeliveryAnomaly.LATE),
            providerFake.createCallback("evt-life-3", 1L, clock.instant(), "{\"step\":3}", ProviderDeliveryAnomaly.REORDERED),
            providerFake.createCallback("evt-life-4", 4L, clock.instant(), "{\"step\":4}", ProviderDeliveryAnomaly.BAD_SIGNATURE)
        )

        val scenarioResult = service.executeScenario(
            ExecuteDeterministicScenarioCommand(
                principal = adminPrincipal,
                tenantId = "tenant-test-1",
                scenarioName = "lifecycle_adversarial_suite",
                simulatedEvents = simulatedEvents,
                idempotencyKey = "idemp-life-scen-01",
                correlationId = "corr-life-01",
                causationId = "caus-life-01",
                expectedVersion = 1L
            )
        )

        assertEquals(5, scenarioResult.totalEvents)
        assertEquals(1, scenarioResult.acceptedEvents)
        assertEquals(4, scenarioResult.rejectedEvents)
        assertEquals(1, scenarioResult.duplicateEvents)
        assertEquals(1, scenarioResult.lateEvents)
        assertEquals(1, scenarioResult.reorderedEvents)
        assertEquals(1, scenarioResult.badSignatureEvents)
        assertFalse(scenarioResult.isFinancialAuthorityCreated)

        // 3. Attempt fake certification and assert rejection + critical alert
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.attemptFakeCertification(
                AttemptFakeCertificationCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-test-1",
                    providerFake = providerFake,
                    requestedTier = ProviderTestTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-life-cert",
                    correlationId = "corr-life-02",
                    causationId = "caus-life-02"
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val alerts = store.getAlerts("tenant-test-1")
        assertTrue(alerts.any { it.severity == "CRITICAL" && it.alertType == "FAKE_CERTIFICATION_VIOLATION" })

        // 4. Observability and audit trail completeness
        val audits = store.getAudits("tenant-test-1")
        assertTrue(audits.any { it.action == TestKitAuditAction.SCENARIO_EXECUTED })
        assertTrue(audits.any { it.action == TestKitAuditAction.FAKE_CERTIFICATION_ATTEMPT_REJECTED })

        val auditDetails = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditDetails.contains("PASSWORD", ignoreCase = true))
        assertFalse(auditDetails.contains("SECRET", ignoreCase = true))
    }
}
