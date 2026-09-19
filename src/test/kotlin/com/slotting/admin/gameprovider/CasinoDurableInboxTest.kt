package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CasinoDurableInboxTest {

    private val fixedInstant = Instant.parse("2026-09-19T02:00:00Z")
    private val clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)

    private val tenantId = "tenant-casino-alpha"
    private val providerId = "prv-pragmatic"

    private lateinit var store: InMemoryCasinoDurableInboxStore
    private lateinit var alertSink: InMemoryCasinoInboxAlertSink
    private lateinit var executionCounter: AtomicInteger
    private lateinit var service: CasinoDurableInboxService

    @BeforeEach
    fun setUp() {
        CasinoDurableInboxBinding.isBound = true
        store = InMemoryCasinoDurableInboxStore()
        alertSink = InMemoryCasinoInboxAlertSink()
        executionCounter = AtomicInteger(0)

        service = CasinoDurableInboxService(
            store = store,
            payloadHandler = { _, _, _ ->
                executionCounter.incrementAndGet()
                ProviderCallbackResponse(
                    httpStatusCode = 200,
                    responseBody = """{"error":0,"description":"Success"}""",
                    retryable = false,
                )
            },
            alertSink = alertSink,
            clock = clock,
        )
    }

    // =========================================================================
    // GAME-008-02-T001: Authoritative Durable Intake & Processing
    // =========================================================================

    @Test
    fun `GAME-008-02-T001 Deduplicate casino callbacks in a durable inbox produces the required authoritative outcome`() {
        CasinoDurableInboxBinding.checkBound()

        val command = ReceiveCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalMessageId = "msg-inbox-001",
            externalRoundId = "rnd-1001",
            externalTransactionId = "tx-1001",
            rawPayload = """{"roundId":"rnd-1001","win":500}""",
            idempotencyKey = "k-inbox-001",
            correlationId = "c-inbox-001",
            causationId = "cause-inbox-001",
        )

        val result = service.receiveAndProcessCallback(command)

        assertEquals(InboxMessageStatus.PROCESSED, result.status)
        assertFalse(result.isDuplicate)
        assertEquals(200, result.response.httpStatusCode)
        assertTrue(result.response.responseBody.contains(""""error":0"""))
        assertEquals(1, executionCounter.get())
        assertNotNull(result.evidenceReference)

        // Durable message persisted in inbox
        val stored = store.findMessageById(tenantId, result.messageId)
        assertNotNull(stored)
        assertEquals(InboxMessageStatus.PROCESSED, stored.status)
        assertEquals("msg-inbox-001", stored.externalMessageId)
        assertEquals(200, stored.httpStatusCode)

        // Structured intake and processing audit/outbox events
        val audits = store.auditEvents.filter { it.resultId == result.messageId }
        assertEquals(2, audits.size)
        assertEquals("CASINO_INBOX_MESSAGE_RECEIVED", audits[0].type)
        assertEquals("CASINO_INBOX_MESSAGE_PROCESSED", audits[1].type)
        assertEquals("c-inbox-001", audits[0].correlationId)
        assertEquals("cause-inbox-001", audits[0].causationId)
    }

    // =========================================================================
    // GAME-008-02-T002: Negative, Boundary, Conflicting Payload Rejection
    // =========================================================================

    @Test
    fun `GAME-008-02-T002 Deduplicate casino callbacks in a durable inbox rejects invalid, boundary, unauthorized, and stale input`() {
        CasinoDurableInboxBinding.checkBound()

        val command = ReceiveCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalMessageId = "msg-inbox-sec-01",
            externalRoundId = "rnd-sec-01",
            externalTransactionId = "tx-sec-01",
            rawPayload = """{"roundId":"rnd-sec-01","win":100}""",
            idempotencyKey = "k-sec-inbox-01",
            correlationId = "c-sec",
            causationId = "cause-sec",
        )

        // Process first legitimate message
        val firstResult = service.receiveAndProcessCallback(command)
        assertEquals(InboxMessageStatus.PROCESSED, firstResult.status)

        // 1. Conflicting Payload with SAME idempotency key -> CONFLICT and alert
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.receiveAndProcessCallback(
                command.copy(rawPayload = """{"roundId":"rnd-sec-01","win":9999}""") // Altered payload!
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_INBOX_IDEMPOTENCY_CONFLICT") })

        // 2. Conflicting Payload with SAME externalMessageId but different idempotency key -> CONFLICT and alert
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.receiveAndProcessCallback(
                command.copy(
                    idempotencyKey = "k-new-diff-key",
                    rawPayload = """{"roundId":"rnd-sec-01","win":5555}"""
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_INBOX_EXTERNAL_ID_CONFLICT") })

        // 3. Stale Expected Version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.receiveAndProcessCallback(command.copy(idempotencyKey = "k-stale-ver", externalMessageId = "msg-stale", expectedVersion = 2L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Blank input validation
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.receiveAndProcessCallback(command.copy(externalMessageId = "", idempotencyKey = "k-blank"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_INBOX_INVALID_INPUT") })

        // Ensure execution counter did not increment on invalid/conflicting attempts
        assertEquals(1, executionCounter.get())
    }

    // =========================================================================
    // GAME-008-02-T003: Concurrency, Duplicate Delivery, and Dependency Failure
    // =========================================================================

    @Test
    fun `GAME-008-02-T003 Deduplicate casino callbacks in a durable inbox survives concurrency, duplicate delivery, and dependency failure`() {
        CasinoDurableInboxBinding.checkBound()

        val command = ReceiveCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalMessageId = "msg-conc-001",
            externalRoundId = "rnd-conc-001",
            externalTransactionId = "tx-conc-001",
            rawPayload = """{"roundId":"rnd-conc-001","win":250}""",
            idempotencyKey = "k-conc-001",
            correlationId = "c-conc",
            causationId = "cause-conc",
        )

        // 1. Duplicate Delivery returns cached result without re-executing handler
        val res1 = service.receiveAndProcessCallback(command)
        val res2 = service.receiveAndProcessCallback(command)

        assertFalse(res1.isDuplicate)
        assertTrue(res2.isDuplicate)
        assertEquals(res1.messageId, res2.messageId)
        assertEquals(res1.response.responseBody, res2.response.responseBody)
        assertEquals(1, executionCounter.get()) // Handler executed exactly ONCE!

        // 2. Concurrent duplicate deliveries race
        val executor = Executors.newFixedThreadPool(8)
        val concCmd = ReceiveCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalMessageId = "msg-race-001",
            externalRoundId = "rnd-race-001",
            externalTransactionId = "tx-race-001",
            rawPayload = """{"roundId":"rnd-race-001","win":777}""",
            idempotencyKey = "k-race-001",
            correlationId = "c-race",
            causationId = "cause-race",
        )

        val tasks = (1..8).map {
            Callable {
                try {
                    service.receiveAndProcessCallback(concCmd)
                } catch (e: Exception) {
                    null
                }
            }
        }
        val results = executor.invokeAll(tasks).mapNotNull { it.get() }
        executor.shutdown()

        assertEquals(8, results.size)
        // All 8 returned identical messageId
        val distinctMessageIds = results.map { it.messageId }.distinct()
        assertEquals(1, distinctMessageIds.size)
        // Exactly 1 execution occurred for this batch (counter moved from 1 to 2)
        assertEquals(2, executionCounter.get())

        // 3. Handler dependency failure: records FAILED state in inbox, does not falsely mark PROCESSED
        val failingService = CasinoDurableInboxService(
            store = store,
            payloadHandler = { _, _, _ ->
                throw RuntimeException("Downstream ledger service unavailable")
            },
            alertSink = alertSink,
            clock = clock,
        )

        val failCmd = ReceiveCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalMessageId = "msg-fail-001",
            externalRoundId = "rnd-fail-001",
            externalTransactionId = "tx-fail-001",
            rawPayload = """{"roundId":"rnd-fail-001"}""",
            idempotencyKey = "k-fail-001",
            correlationId = "c-fail",
            causationId = "cause-fail",
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.receiveAndProcessCallback(failCmd)
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        val failedMsg = store.findMessageByIdempotency(tenantId, "k-fail-001")
        assertNotNull(failedMsg)
        assertEquals(InboxMessageStatus.FAILED, failedMsg.status)
        assertEquals(1, failedMsg.retryCount)
        assertTrue(failedMsg.lastError!!.contains("Downstream ledger service unavailable"))
    }

    // =========================================================================
    // GAME-008-02-T004: Lifecycle, Retry, Dead-Letter Queue & Observability
    // =========================================================================

    @Test
    fun `GAME-008-02-T004 Deduplicate casino callbacks in a durable inbox remains compatible, recoverable, observable, and lifecycle-safe`() {
        CasinoDurableInboxBinding.checkBound()

        // 1. Recovery & Reprocessing: Failed message retried and successfully transitions to PROCESSED
        var failFirstTime = true
        val retryableHandler = InboxPayloadHandler { _, _, _ ->
            if (failFirstTime) {
                failFirstTime = false
                throw RuntimeException("Temporary connection glitch")
            }
            ProviderCallbackResponse(httpStatusCode = 200, responseBody = """{"status":"RECOVERED"}""", retryable = false)
        }

        val retryService = CasinoDurableInboxService(
            store = store,
            payloadHandler = retryableHandler,
            alertSink = alertSink,
            clock = clock,
        )

        val recoverCmd = ReceiveCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.GENERIC_HMAC,
            externalMessageId = "msg-recover-01",
            externalRoundId = "rnd-rec-01",
            externalTransactionId = "tx-rec-01",
            rawPayload = """{"roundId":"rnd-rec-01"}""",
            idempotencyKey = "k-recover-01",
            correlationId = "c-rec",
            causationId = "cause-rec",
        )

        // First attempt fails
        assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.receiveAndProcessCallback(recoverCmd)
        }

        assertEquals(1, store.listPendingMessages(tenantId).size)

        // Administrator / worker triggers batch retry of pending messages
        val retryResults = retryService.retryFailedMessages(tenantId)
        assertEquals(1, retryResults.size)
        assertEquals(InboxMessageStatus.PROCESSED, retryResults[0].status)
        assertEquals(0, store.listPendingMessages(tenantId).size)

        // 2. Dead-lettering: Exhausting retries moves message to DEAD_LETTER and emits alert
        val alwaysFailingService = CasinoDurableInboxService(
            store = store,
            payloadHandler = { _, _, _ -> throw RuntimeException("Fatal schema bug") },
            alertSink = alertSink,
            clock = clock,
        )

        val dlqCmd = ReceiveCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.GENERIC_HMAC,
            externalMessageId = "msg-dlq-01",
            externalRoundId = "rnd-dlq-01",
            externalTransactionId = "tx-dlq-01",
            rawPayload = """{"roundId":"rnd-dlq-01"}""",
            idempotencyKey = "k-dlq-01",
            correlationId = "c-dlq",
            causationId = "cause-dlq",
        )

        // Exhaust retries: attempt 1 (receive), attempts 2 & 3 (retry)
        assertFailsWith<AuthenticationFailure.Rejected> {
            alwaysFailingService.receiveAndProcessCallback(dlqCmd)
        }
        alwaysFailingService.retryFailedMessages(tenantId)
        alwaysFailingService.retryFailedMessages(tenantId)

        val dlqList = store.listDeadLetterMessages(tenantId)
        assertEquals(1, dlqList.size)
        assertEquals(InboxMessageStatus.DEAD_LETTER, dlqList[0].status)
        assertTrue(alertSink.alerts.any { it.contains("CASINO_INBOX_DEAD_LETTER_THRESHOLD_EXCEEDED") })

        // 3. Observability & Redaction check
        val allAudits = store.auditEvents
        assertTrue(allAudits.isNotEmpty())
        for (a in allAudits) {
            assertFalse(a.type.contains("secret"))
            assertFalse(a.correlationId.contains("secret"))
        }
    }
}
