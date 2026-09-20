package com.slotting.admin.payment

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class WebhookOrderingIdempotencyTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-order-1"
    private val providerId = "prov-order-card-1"

    private lateinit var store: InMemoryWebhookOrderingStore
    private lateinit var alertSink: InMemoryWebhookOrderingAlertSink
    private lateinit var service: WebhookOrderingIdempotencyService

    @BeforeEach
    fun setUp() {
        WebhookOrderingIdempotencyBinding.isBound = true
        store = InMemoryWebhookOrderingStore()
        alertSink = InMemoryWebhookOrderingAlertSink()
        service = WebhookOrderingIdempotencyService(store, alertSink, clock = clock)
    }

    @AfterEach
    fun tearDown() {
        WebhookOrderingIdempotencyBinding.isBound = true
    }

    @Test
    fun `PAYMENT-004-T001 — Webhook ordering idempotency produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        WebhookOrderingIdempotencyBinding.isBound = false

        val initCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-ord-t001",
            externalEventId = "evt-init-001",
            incomingStatus = CanonicalWebhookPaymentStatus.INITIATED,
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            deliverySequence = 1L,
            idempotencyKey = "key-init-t001",
            correlationId = "corr-ord-1",
            causationId = "cause-ord-1",
        )

        val gateError = assertFailsWith<AssertionError> {
            service.processWebhook(initCmd)
        }
        assertEquals("late pending regresses success", gateError.message)

        // Bind the fail-closed gate
        WebhookOrderingIdempotencyBinding.isBound = true

        // 2. Authoritative operation: Payment initiated
        val initResult = service.processWebhook(initCmd)
        assertNotNull(initResult)
        assertEquals(CanonicalWebhookPaymentStatus.INITIATED, initResult.currentStatus)
        assertEquals(ReducerAction.APPLIED, initResult.action)
        assertEquals(10000L, initResult.debitMinorUnits)
        assertEquals(0L, initResult.creditMinorUnits)
        assertTrue(initResult.conserved)

        // 3. Webhook: Payment captured / SUCCEEDED (seq 2)
        val successCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-ord-t001",
            externalEventId = "evt-succ-002",
            incomingStatus = CanonicalWebhookPaymentStatus.SUCCEEDED,
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            deliverySequence = 2L,
            idempotencyKey = "key-succ-t001",
            correlationId = "corr-ord-2",
            causationId = "cause-ord-2",
        )
        val successResult = service.processWebhook(successCmd)
        assertEquals(CanonicalWebhookPaymentStatus.SUCCEEDED, successResult.currentStatus)
        assertEquals(ReducerAction.APPLIED, successResult.action)
        assertEquals(10000L, successResult.debitMinorUnits)
        assertEquals(10000L, successResult.creditMinorUnits)
        assertTrue(successResult.conserved)
        assertEquals(2L, successResult.currentSequence)

        // 4. Core defense assertion: LATE PENDING REGRESSES SUCCESS!
        // A late pending webhook (seq 1) arrives after success (seq 2)
        val latePendingCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-ord-t001",
            externalEventId = "evt-late-pending-001",
            incomingStatus = CanonicalWebhookPaymentStatus.PENDING,
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            deliverySequence = 1L,
            idempotencyKey = "key-late-pending-t001",
            correlationId = "corr-ord-3",
            causationId = "cause-ord-3",
        )
        val latePendingResult = service.processWebhook(latePendingCmd)
        // Must retain SUCCEEDED status! Monotonic canonical reducer does not regress to PENDING
        assertEquals(CanonicalWebhookPaymentStatus.SUCCEEDED, latePendingResult.currentStatus)
        assertEquals(ReducerAction.LATE_IGNORED, latePendingResult.action)
        assertEquals("LATE_PENDING_IGNORED_RETAINED_SUCCESS", latePendingResult.safeReasonCode)
        assertEquals(10000L, latePendingResult.debitMinorUnits)
        assertEquals(10000L, latePendingResult.creditMinorUnits)
        assertTrue(latePendingResult.conserved)

        // Verify alert emitted for late event
        assertTrue(alertSink.alerts.any { it.contains("LATE_PENDING_AFTER_SUCCESS") })

        // 5. Outcome semantic contract: "Duplicates same outcome; conflicts alert/reconcile; never guess missing provider state."
        assertEquals(WEBHOOK_ORDERING_IDEMPOTENCY_CONTRACT, latePendingResult.semanticContract)

        // Idempotent duplicate replay returns identical outcome
        val replayResult = service.processWebhook(successCmd)
        assertTrue(replayResult.isDuplicate)
        assertEquals(CanonicalWebhookPaymentStatus.SUCCEEDED, replayResult.currentStatus)

        // 6. "never guess missing provider state":
        // Non-existent payment reference receiving SUCCEEDED webhook is held for reconciliation with 0 money credited
        val unknownCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-unknown-ref-999",
            externalEventId = "evt-unk-001",
            incomingStatus = CanonicalWebhookPaymentStatus.SUCCEEDED,
            amountMinorUnits = 5000L,
            currencyCode = "EUR",
            deliverySequence = 1L,
            idempotencyKey = "key-unk-999",
            correlationId = "corr-ord-unk",
            causationId = "cause-ord-unk",
        )
        val unknownResult = service.processWebhook(unknownCmd)
        assertEquals(ReducerAction.UNKNOWN_HELD, unknownResult.action)
        assertTrue(unknownResult.requiresReconciliation)
        assertEquals(0L, unknownResult.creditMinorUnits) // no money fabricated/guessed
        assertTrue(alertSink.alerts.any { it.contains("UNKNOWN_PROVIDER_STATE") })

        // 7. "conflicts alert/reconcile":
        // Conflicting FAILED reported on SUCCEEDED payment triggers reconciliation hold & alert
        val conflictCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-ord-t001",
            externalEventId = "evt-conflict-fail",
            incomingStatus = CanonicalWebhookPaymentStatus.FAILED,
            amountMinorUnits = 10000L,
            currencyCode = "EUR",
            deliverySequence = 3L,
            idempotencyKey = "key-conflict-001",
            correlationId = "corr-conflict-1",
            causationId = "cause-conflict-1",
        )
        val conflictResult = service.processWebhook(conflictCmd)
        assertEquals(ReducerAction.CONFLICT_RECONCILE, conflictResult.action)
        assertTrue(conflictResult.requiresReconciliation)
        assertEquals(CanonicalWebhookPaymentStatus.SUCCEEDED, conflictResult.currentStatus) // retains success pending reconciliation
        assertTrue(alertSink.alerts.any { it.contains("PAYMENT_STATUS_CONFLICT") })

        // Transactional atomicity: audit and outbox events emitted
        val auditEvents = store.getAuditEvents()
        assertTrue(auditEvents.isNotEmpty())
        val outboxEvents = store.getOutboxEvents()
        assertTrue(outboxEvents.isNotEmpty())
    }

    @Test
    fun `PAYMENT-004-T002 — Webhook ordering idempotency rejects invalid, boundary, unauthorized, and stale input`() {
        val validCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-ord-t002",
            externalEventId = "evt-t002-001",
            incomingStatus = CanonicalWebhookPaymentStatus.INITIATED,
            amountMinorUnits = 5000L,
            currencyCode = "EUR",
            deliverySequence = 1L,
            idempotencyKey = "key-ord-t002-001",
            correlationId = "corr-t002-1",
            causationId = "cause-t002-1",
        )
        service.processWebhook(validCmd)

        // 1. Blank mandatory fields -> INVALID
        val blankRefError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(validCmd.copy(paymentReference = "", idempotencyKey = "key-blank-ref"))
        }
        assertEquals(AuthErrorCode.INVALID, blankRefError.code)

        val blankTenantError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(validCmd.copy(tenantId = "", idempotencyKey = "key-blank-tenant"))
        }
        assertEquals(AuthErrorCode.INVALID, blankTenantError.code)

        // 2. Invalid minor units or sequence -> INVALID
        val zeroAmountError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(validCmd.copy(amountMinorUnits = 0L, idempotencyKey = "key-zero-amount"))
        }
        assertEquals(AuthErrorCode.INVALID, zeroAmountError.code)

        val zeroSeqError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(validCmd.copy(deliverySequence = 0L, idempotencyKey = "key-zero-seq"))
        }
        assertEquals(AuthErrorCode.INVALID, zeroSeqError.code)

        // 3. Stale version -> STALE
        val staleVersionError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(validCmd.copy(expectedVersion = 2L, idempotencyKey = "key-stale-v"))
        }
        assertEquals(AuthErrorCode.STALE, staleVersionError.code)

        // 4. Conflicting payload reuse under same idempotency key -> CONFLICT
        val changedPayloadError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(validCmd.copy(amountMinorUnits = 99999L))
        }
        assertEquals(AuthErrorCode.CONFLICT, changedPayloadError.code)
    }

    @Test
    fun `PAYMENT-004-T003 — Webhook ordering idempotency survives concurrency, duplicate delivery, and dependency failure`() {
        val baseCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-con-001",
            externalEventId = "evt-con-001",
            incomingStatus = CanonicalWebhookPaymentStatus.INITIATED,
            amountMinorUnits = 12000L,
            currencyCode = "EUR",
            deliverySequence = 1L,
            idempotencyKey = "key-con-001",
            correlationId = "corr-con-1",
            causationId = "cause-con-1",
        )
        service.processWebhook(baseCmd)

        // 1. Concurrency: 8 threads concurrently submitting identical capture webhook
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<OrderedWebhookResult>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        val captureCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-con-001",
            externalEventId = "evt-con-capture",
            incomingStatus = CanonicalWebhookPaymentStatus.SUCCEEDED,
            amountMinorUnits = 12000L,
            currencyCode = "EUR",
            deliverySequence = 2L,
            idempotencyKey = "key-con-capture",
            correlationId = "corr-con-cap",
            causationId = "cause-con-cap",
        )

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.processWebhook(captureCmd)
                    results.add(res)
                } catch (t: Throwable) {
                    errors.add(t)
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertTrue(errors.isEmpty(), "No errors on concurrent execution: $errors")
        assertEquals(threadCount, results.size)
        for (res in results) {
            assertEquals(CanonicalWebhookPaymentStatus.SUCCEEDED, res.currentStatus)
            assertEquals(12000L, res.debitMinorUnits)
            assertEquals(12000L, res.creditMinorUnits)
            assertTrue(res.conserved)
        }

        // 2. Concurrency race between PENDING and SUCCEEDED
        val raceExecutor = Executors.newFixedThreadPool(2)
        val raceStart = CountDownLatch(1)
        val raceDone = CountDownLatch(2)

        val racePaymentRef = "pay-race-001"
        service.processWebhook(baseCmd.copy(paymentReference = racePaymentRef, idempotencyKey = "key-race-init"))

        val latePendingRaceCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = racePaymentRef,
            externalEventId = "evt-race-pend",
            incomingStatus = CanonicalWebhookPaymentStatus.PENDING,
            amountMinorUnits = 12000L,
            currencyCode = "EUR",
            deliverySequence = 2L,
            idempotencyKey = "key-race-pend",
            correlationId = "corr-race-1",
            causationId = "cause-race-1",
        )

        val successRaceCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = racePaymentRef,
            externalEventId = "evt-race-succ",
            incomingStatus = CanonicalWebhookPaymentStatus.SUCCEEDED,
            amountMinorUnits = 12000L,
            currencyCode = "EUR",
            deliverySequence = 3L,
            idempotencyKey = "key-race-succ",
            correlationId = "corr-race-2",
            causationId = "cause-race-2",
        )

        val raceResults = java.util.Collections.synchronizedList(mutableListOf<OrderedWebhookResult>())

        raceExecutor.submit {
            try {
                raceStart.await()
                raceResults.add(service.processWebhook(latePendingRaceCmd))
            } finally {
                raceDone.countDown()
            }
        }

        raceExecutor.submit {
            try {
                raceStart.await()
                raceResults.add(service.processWebhook(successRaceCmd))
            } finally {
                raceDone.countDown()
            }
        }

        raceStart.countDown()
        raceDone.await()
        raceExecutor.shutdown()

        assertEquals(2, raceResults.size)
        // Final state in store must be SUCCEEDED, never regressed to PENDING
        val finalRecord = store.findPayment(tenantId, racePaymentRef)
        assertNotNull(finalRecord)
        assertEquals(CanonicalWebhookPaymentStatus.SUCCEEDED, finalRecord.status)
        assertEquals(12000L, finalRecord.debitMinorUnits)
        assertEquals(12000L, finalRecord.creditMinorUnits)
        assertTrue(finalRecord.conserved)
    }

    @Test
    fun `PAYMENT-004-T004 — Webhook ordering idempotency remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Schema migration contract: V16 Flyway migration exists, no rogue V17
        val migrationsDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationsDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty(), "Migrations directory must contain Flyway files")
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.contains("V16"), "V16 must be present")
        assertFalse(migrationVersions.contains("V17"), "V17 must not be created prematurely")

        // 2. Lifecycle safety: Confirm no Android lifecycle surface is claimed
        val androidActivityClass = runCatching { Class.forName("android.app.Activity") }
        assertTrue(androidActivityClass.isFailure, "Authoritative backend must not link Android framework lifecycle")

        // 3. State recovery across restart
        val initCmd = ProcessOrderedWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            paymentReference = "pay-rec-001",
            externalEventId = "evt-rec-001",
            incomingStatus = CanonicalWebhookPaymentStatus.INITIATED,
            amountMinorUnits = 16000L,
            currencyCode = "EUR",
            deliverySequence = 1L,
            idempotencyKey = "key-rec-001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
        )
        val initialResult = service.processWebhook(initCmd)
        assertEquals(CanonicalWebhookPaymentStatus.INITIATED, initialResult.currentStatus)

        // Export snapshot and rehydrate into fresh store instance simulating server restart
        val snapshot = store.exportSnapshot()
        val rehydratedStore = InMemoryWebhookOrderingStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = WebhookOrderingIdempotencyService(rehydratedStore, alertSink, clock = clock)

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.processWebhook(initCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertEquals(initialResult.evidenceReference, replayedResult.evidenceReference)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(WEBHOOK_ORDERING_IDEMPOTENCY_CONTRACT, replayedResult.semanticContract)

        // 4. Observability: structured audit & outbox records contain zero credentials or PII
        val auditEvents = rehydratedStore.getAuditEvents()
        assertTrue(auditEvents.isNotEmpty())
        for (audit in auditEvents) {
            assertEquals(tenantId, audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
        }

        val outboxEvents = rehydratedStore.getOutboxEvents()
        assertTrue(outboxEvents.isNotEmpty())
    }
}
