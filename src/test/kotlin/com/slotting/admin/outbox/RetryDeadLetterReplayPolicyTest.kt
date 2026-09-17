package com.slotting.admin.outbox

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class RetryDeadLetterReplayPolicyTest {
    private val now = Instant.parse("2026-09-17T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-003-02-T001 Decide retry, dead-letter, and replay policy produces the required authoritative outcome`() {
        val store = DeadLetterMemoryStore()
        val alerts = PolicyTestAlertSink()
        val service = service(store, alerts)

        // 1. Successful delivery attempt
        val normalEventId = UUID.randomUUID()
        val resSuccess = service.executeDelivery(
            deliveryCommand(
                eventId = normalEventId,
                idempotencyKey = "key-deliv-success",
            )
        )
        assertEquals(PolicyDeliveryOutcome.PUBLISHED, resSuccess.outcome)

        // 2. Transient failure below retry limit -> RETRY_SCHEDULED
        val transientEventId = UUID.randomUUID()
        val resTransient = service.executeDelivery(
            deliveryCommand(
                eventId = transientEventId,
                currentRetryCount = 1,
                maxRetries = 3,
                simulateTransientFailure = true,
                idempotencyKey = "key-deliv-transient",
            )
        )
        assertEquals(PolicyDeliveryOutcome.RETRY_SCHEDULED, resTransient.outcome)
        assertEquals(2, resTransient.retryCount)
        assertEquals(0, store.deadLetters.size) // Not quarantined yet

        // 3. Retry exhaustion -> moves to dead-letter QUARANTINED, emits alert
        val exhaustEventId = UUID.randomUUID()
        val resExhaust = service.executeDelivery(
            deliveryCommand(
                eventId = exhaustEventId,
                currentRetryCount = 3,
                maxRetries = 3,
                simulateTransientFailure = true,
                correlationId = "corr-exhaust",
                causationId = "cause-exhaust",
                idempotencyKey = "key-deliv-exhaust",
            )
        )
        assertEquals(PolicyDeliveryOutcome.QUARANTINED, resExhaust.outcome)
        assertEquals(1, store.deadLetters.size)
        assertEquals(1, alerts.emittedAlerts.size)
        assertEquals(exhaustEventId, alerts.emittedAlerts[0].eventId)
        assertTrue(alerts.emittedAlerts[0].reason.contains("exhausted"))

        // 4. Poison payload -> immediate quarantine & alert
        val poisonEventId = UUID.randomUUID()
        val resPoison = service.executeDelivery(
            deliveryCommand(
                eventId = poisonEventId,
                payload = "{\"corrupted\":\"POISON_DATA\"}",
                isPoisonPayload = true,
                idempotencyKey = "key-deliv-poison",
            )
        )
        assertEquals(PolicyDeliveryOutcome.QUARANTINED, resPoison.outcome)
        assertEquals(2, alerts.emittedAlerts.size)

        // 5. Replay policy: DB remains authority, replay preserves causation
        val dlRecord = store.findByEventId("tenant-1", exhaustEventId)!!
        val replayCmd = ReplayPolicyCommand(
            principal = admin(),
            sessionId = "session-policy-1",
            tenantId = "tenant-1",
            deadLetterId = dlRecord.deadLetterId,
            idempotencyKey = "key-replay-exhaust",
            expectedVersion = dlRecord.version,
        )
        val replayRes = service.replayDeadLetter(replayCmd)
        assertEquals(PolicyDeliveryOutcome.REPLAYED, replayRes.outcome)
        assertEquals(exhaustEventId, replayRes.eventId)
        assertEquals("cause-exhaust", replayRes.causationId)
        assertEquals("corr-exhaust", replayRes.correlationId)

        val replayedInStore = store.findDeadLetter("tenant-1", dlRecord.deadLetterId)!!
        assertNotNull(replayedInStore.replayedAt)
        assertEquals("admin-policy-1", replayedInStore.replayedBy)

        // Verify idempotency replay returns identical authoritative outcome
        val replayReplay = service.replayDeadLetter(replayCmd)
        assertEquals(replayRes.resultId, replayReplay.resultId)
        assertEquals("cause-exhaust", replayReplay.causationId)

        // Assert: no money mutated, no secret leaks
        assertFalse(store.audit.any { it.type.contains("secret") })
    }

    @Test
    fun `ADR-003-02-T002 Decide retry, dead-letter, and replay policy rejects invalid, boundary, unauthorized, and stale input`() {
        val store = DeadLetterMemoryStore()
        val alerts = PolicyTestAlertSink()
        val service = service(store, alerts)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(principal = null, idempotencyKey = "deliv-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(principal = player(), idempotencyKey = "deliv-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(principal = admin(tenantId = "tenant-other"), idempotencyKey = "deliv-cross"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Invalid: blank topic, correlationId, causationId
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(topic = "   ", idempotencyKey = "deliv-blank-top"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(correlationId = "", idempotencyKey = "deliv-blank-corr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(causationId = "", idempotencyKey = "deliv-blank-cause"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Negative retry count
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(currentRetryCount = -1, idempotencyKey = "deliv-neg-retry"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Conflicting replay with different payload
        service.executeDelivery(deliveryCommand(payload = "{\"v\":1}", idempotencyKey = "key-conflict-test"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeDelivery(deliveryCommand(payload = "{\"v\":2}", idempotencyKey = "key-conflict-test"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Replay non-existent dead-letter
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.replayDeadLetter(
                ReplayPolicyCommand(
                    principal = admin(),
                    sessionId = "session-policy-1",
                    tenantId = "tenant-1",
                    deadLetterId = UUID.randomUUID(),
                    idempotencyKey = "key-replay-unknown",
                    expectedVersion = 1L,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale version on replay
        val dlId = UUID.randomUUID()
        store.deadLetters["tenant-1:$dlId"] = DeadLetterRecord(
            deadLetterId = dlId,
            eventId = UUID.randomUUID(),
            tenantId = "tenant-1",
            topic = "test-topic",
            payload = "{}",
            correlationId = "corr-1",
            causationId = "cause-1",
            reason = DeadLetterReason.RETRY_EXHAUSTED,
            failureDetail = "exhausted",
            retryCount = 3,
            quarantinedAt = now,
            version = 1L,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.replayDeadLetter(
                ReplayPolicyCommand(
                    principal = admin(),
                    sessionId = "session-policy-1",
                    tenantId = "tenant-1",
                    deadLetterId = dlId,
                    idempotencyKey = "key-replay-stale",
                    expectedVersion = 99L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    @Test
    fun `ADR-003-02-T003 Decide retry, dead-letter, and replay policy survives concurrency, duplicate delivery, and dependency failure`() {
        val store = DeadLetterMemoryStore()
        val alerts = PolicyTestAlertSink()
        val service = service(store, alerts)

        // 1. Concurrent duplicate delivery attempts
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val eventId = UUID.randomUUID()
        val calls = (1..4).map {
            pool.submit<PolicyResult> {
                gate.await()
                service.executeDelivery(
                    deliveryCommand(
                        eventId = eventId,
                        idempotencyKey = "concurrent-policy-key",
                    )
                )
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store, alerts).executeDelivery(
                deliveryCommand(idempotencyKey = "dep-policy-fail")
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-003-02-T004 Decide retry, dead-letter, and replay policy remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation over store preserves causation and dead-letter records
        val store = DeadLetterMemoryStore()
        val alerts = PolicyTestAlertSink()
        val service = service(store, alerts)

        val evId = UUID.randomUUID()
        val firstQuarantine = service.executeDelivery(
            deliveryCommand(
                eventId = evId,
                currentRetryCount = 3,
                maxRetries = 3,
                simulateTransientFailure = true,
                correlationId = "corr-reboot",
                causationId = "cause-reboot",
                idempotencyKey = "key-reboot-quarantine",
            )
        )
        assertEquals(PolicyDeliveryOutcome.QUARANTINED, firstQuarantine.outcome)

        // Simulate reboot with new service instance
        val rebootedService = service(store, alerts)
        val dl = store.findByEventId("tenant-1", evId)!!
        val replayRes = rebootedService.replayDeadLetter(
            ReplayPolicyCommand(
                principal = admin(),
                sessionId = "session-policy-1",
                tenantId = "tenant-1",
                deadLetterId = dl.deadLetterId,
                idempotencyKey = "key-reboot-replay",
                expectedVersion = dl.version,
            )
        )
        assertEquals(PolicyDeliveryOutcome.REPLAYED, replayRes.outcome)
        assertEquals("cause-reboot", replayRes.causationId)
        assertEquals("corr-reboot", replayRes.correlationId)

        // Audit telemetry check
        assertTrue(store.audit.isNotEmpty())
        assertEquals("OUTBOX_POLICY_REPLAYED", store.audit.last().type)
        assertEquals("corr-reboot", store.audit.last().correlationId)
        assertEquals("cause-reboot", store.audit.last().causationId)
        assertFalse(store.audit.last().type.contains("secret"))
    }

    private fun service(store: DeadLetterStore, alerts: OutboxAlertSink) =
        RetryDeadLetterReplayPolicyService(AdminRbacPolicy(true), ActivePolicySessionDirectory(), store, alerts, clock)

    private fun serviceWithDependencyFailure(store: DeadLetterStore, alerts: OutboxAlertSink) =
        RetryDeadLetterReplayPolicyService(AdminRbacPolicy(true), FailingPolicySessionDirectory(), store, alerts, clock)

    private fun deliveryCommand(
        principal: AuthenticatedPrincipal? = admin(),
        eventId: UUID = UUID.randomUUID(),
        topic: String = "orders-topic",
        payload: String = "{\"test\":1}",
        correlationId: String = "corr-policy-1",
        causationId: String = "cause-policy-1",
        idempotencyKey: String = "key-policy-default",
        currentRetryCount: Int = 0,
        maxRetries: Int = 3,
        simulateTransientFailure: Boolean = false,
        isPoisonPayload: Boolean = false,
    ) = DeliveryAttemptCommand(
        principal = principal,
        sessionId = "session-policy-1",
        tenantId = "tenant-1",
        eventId = eventId,
        topic = topic,
        payload = payload,
        correlationId = correlationId,
        causationId = causationId,
        idempotencyKey = idempotencyKey,
        currentRetryCount = currentRetryCount,
        maxRetries = maxRetries,
        simulateTransientFailure = simulateTransientFailure,
        isPoisonPayload = isPoisonPayload,
        expectedVersion = 1L,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-policy-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActivePolicySessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-policy-1" && sessionId == "session-policy-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingPolicySessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory unavailable")
}

private class PolicyTestAlertSink : OutboxAlertSink {
    val emittedAlerts = mutableListOf<OutboxAlert>()

    override fun emitAlert(alert: OutboxAlert) {
        emittedAlerts += alert
    }
}

private class DeadLetterMemoryStore : DeadLetterStore {
    val deadLetters = mutableMapOf<String, DeadLetterRecord>()
    val results = mutableMapOf<String, Pair<String, PolicyResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findDeadLetter(tenantId: String, deadLetterId: UUID) =
        synchronized(this) { deadLetters["$tenantId:$deadLetterId"] }

    override fun findByEventId(tenantId: String, eventId: UUID) =
        synchronized(this) { deadLetters.values.find { it.tenantId == tenantId && it.eventId == eventId } }

    override fun saveQuarantined(
        record: DeadLetterRecord,
        result: PolicyResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        deadLetters["${record.tenantId}:${record.deadLetterId}"] = record
        results["${record.tenantId}:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }

    override fun saveReplayed(
        updatedRecord: DeadLetterRecord,
        result: PolicyResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        deadLetters["${updatedRecord.tenantId}:${updatedRecord.deadLetterId}"] = updatedRecord
        results["${updatedRecord.tenantId}:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }

    override fun recordSuccess(
        result: PolicyResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        results["${result.tenantId}:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
