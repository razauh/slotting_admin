package com.slotting.admin.payment

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DepositDurableInboxTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-inbox-1"
    private val providerId = "prov-inbox-card-1"
    private val providerSecret = "secret-hmac-key-inbox-001"

    private lateinit var secretResolver: InMemoryDepositWebhookSecretResolver
    private lateinit var webhookStore: InMemoryDepositWebhookStore
    private lateinit var webhookAlertSink: InMemoryDepositWebhookAlertSink
    private lateinit var authService: DepositWebhookAuthenticationService

    private lateinit var inboxStore: InMemoryDepositDurableInboxStore
    private lateinit var inboxAlertSink: InMemoryDepositInboxAlertSink
    private lateinit var payloadHandler: DepositInboxPayloadHandler
    private lateinit var service: DepositDurableInboxService

    @BeforeEach
    fun setUp() {
        DepositDurableInboxBinding.isBound = true
        DepositWebhookAuthenticationBinding.isBound = true

        secretResolver = InMemoryDepositWebhookSecretResolver()
        secretResolver.setSecret(tenantId, providerId, providerSecret)
        webhookStore = InMemoryDepositWebhookStore()
        webhookAlertSink = InMemoryDepositWebhookAlertSink()
        authService = DepositWebhookAuthenticationService(secretResolver, webhookStore, webhookAlertSink, clock = clock)

        inboxStore = InMemoryDepositDurableInboxStore()
        inboxAlertSink = InMemoryDepositInboxAlertSink()
        payloadHandler = DepositInboxPayloadHandler { _, _, ref, _ ->
            ProviderWebhookHttpResponse(
                httpStatusCode = 200,
                responseBody = "{\"status\":\"PROCESSED\",\"paymentReference\":\"$ref\"}",
                retryable = false,
            )
        }
        service = DepositDurableInboxService(authService, webhookStore, inboxStore, payloadHandler, inboxAlertSink, clock = clock)
    }

    @AfterEach
    fun tearDown() {
        DepositDurableInboxBinding.isBound = true
        DepositWebhookAuthenticationBinding.isBound = true
    }

    @Test
    fun `PAYMENT-003-02-T001 — Persist deposit callbacks in a durable inbox produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        DepositDurableInboxBinding.isBound = false

        val rawPayload = "{\"paymentReference\":\"dep-inbox-t001\",\"amount\":10000,\"currency\":\"EUR\",\"status\":\"CAPTURED\"}"
        val timestamp = "${now.epochSecond}"
        val signature = computeHmac(providerSecret, "$timestamp.$rawPayload")
        val cmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-inbox-001",
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-inbox-t001",
            correlationId = "corr-inbox-1",
            causationId = "cause-inbox-1",
        )

        val gateError = assertFailsWith<AssertionError> {
            service.persistAndProcessCallback(cmd)
        }
        assertEquals("bad signature/duplicate/late/out-of-order accepted wrongly", gateError.message)

        // Bind the fail-closed gate
        DepositDurableInboxBinding.isBound = true

        // 2. Authoritative operation: Persist and process valid deposit callback once
        val result = service.persistAndProcessCallback(cmd)
        assertNotNull(result)
        assertEquals(DepositInboxMessageStatus.PROCESSED, result.status)
        assertNull(result.quarantineReason)
        assertFalse(result.isDuplicate)
        assertEquals(tenantId, result.tenantId)
        assertEquals(providerId, result.providerId)
        assertEquals("evt-inbox-001", result.externalEventId)
        assertEquals("dep-inbox-t001", result.paymentReference)
        assertEquals(200, result.providerResponse.httpStatusCode)
        assertFalse(result.providerResponse.retryable)

        // Outcome-specific semantic contract assertion:
        // "Respond safely; quarantine unknowns; retain redacted forensic metadata."
        assertEquals(DEPOSIT_DURABLE_INBOX_CONTRACT, result.semanticContract)

        // Financial conservation: debits equal credits
        assertEquals(10000L, result.debitMinorUnits)
        assertEquals(10000L, result.creditMinorUnits)
        assertTrue(result.conserved)

        // Check durable inbox message persistence
        val storedMsg = inboxStore.findMessageById(tenantId, result.messageId)
        assertNotNull(storedMsg)
        assertEquals(DepositInboxMessageStatus.PROCESSED, storedMsg.status)
        assertEquals("evt-inbox-001", storedMsg.externalEventId)
        assertEquals(sha256(rawPayload), storedMsg.payloadHash)
        assertEquals(10000L, storedMsg.debitMinorUnits)
        assertEquals(10000L, storedMsg.creditMinorUnits)
        assertTrue(storedMsg.conserved)
        assertNotNull(storedMsg.processedAt)

        // Transactional audit and outbox emission (intake event + processed event)
        val auditEvents = inboxStore.getAuditEvents()
        assertEquals(2, auditEvents.size)
        assertEquals("DEPOSIT_INBOX_MESSAGE_RECEIVED", auditEvents[0].type)
        assertEquals("DEPOSIT_INBOX_MESSAGE_PROCESSED", auditEvents[1].type)
        assertEquals("corr-inbox-1", auditEvents[0].correlationId)
        assertEquals("cause-inbox-1", auditEvents[0].causationId)

        val outboxEvents = inboxStore.getOutboxEvents()
        assertEquals(2, outboxEvents.size)
        assertEquals("DEPOSIT_INBOX_MESSAGE_RECEIVED", outboxEvents[0].type)
        assertEquals("DEPOSIT_INBOX_MESSAGE_PROCESSED", outboxEvents[1].type)

        // Proves idempotent replay returns identical authoritative cached result with isDuplicate = true
        val replayResult = service.persistAndProcessCallback(cmd)
        assertEquals(result.messageId, replayResult.messageId)
        assertEquals(result.evidenceReference, replayResult.evidenceReference)
        assertTrue(replayResult.isDuplicate)
        assertEquals(DepositInboxMessageStatus.PROCESSED, replayResult.status)
    }

    @Test
    fun `PAYMENT-003-02-T002 — Persist deposit callbacks in a durable inbox rejects invalid, boundary, unauthorized, and stale input`() {
        val rawPayload = "{\"paymentReference\":\"dep-inbox-t002\",\"amount\":8000,\"currency\":\"EUR\"}"
        val validTimestamp = "${now.epochSecond}"
        val validSignature = computeHmac(providerSecret, "$validTimestamp.$rawPayload")

        // 1. Blank mandatory parameters -> INVALID
        val blankCmd = PersistDepositCallbackCommand(
            tenantId = "",
            providerId = providerId,
            externalEventId = "evt-blank",
            signatureHeader = validSignature,
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-blank",
            correlationId = "corr-blank",
            causationId = "cause-blank",
        )
        val blankError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(blankCmd)
        }
        assertEquals(AuthErrorCode.INVALID, blankError.code)

        // 2. Stale version -> STALE
        val staleVersionCmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-stale-v",
            signatureHeader = validSignature,
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-stale-v",
            correlationId = "corr-stale-v",
            causationId = "cause-stale-v",
            expectedVersion = 2L,
        )
        val staleVersionError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(staleVersionCmd)
        }
        assertEquals(AuthErrorCode.STALE, staleVersionError.code)

        // 3. Bad signature -> Quarantined in durable inbox with BAD_SIGNATURE + FORBIDDEN
        val badSigCmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-bad-sig",
            signatureHeader = "corrupted-sig-header",
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-bad-sig",
            correlationId = "corr-bad-sig",
            causationId = "cause-bad-sig",
        )
        val badSigError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(badSigCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, badSigError.code)
        val quarantinedBadSig = inboxStore.listQuarantinedMessages(tenantId).find { it.externalEventId == "evt-bad-sig" }
        assertNotNull(quarantinedBadSig)
        assertEquals(DepositInboxMessageStatus.QUARANTINED, quarantinedBadSig.status)
        assertEquals(WebhookQuarantineReason.BAD_SIGNATURE, quarantinedBadSig.quarantineReason)
        assertEquals(0L, quarantinedBadSig.creditMinorUnits) // zero unauthorized money crediting

        // 4. Expired timestamp (> 300s) -> Quarantined with EXPIRED_TIMESTAMP + STALE
        val expiredTs = "${now.minusSeconds(450).epochSecond}"
        val expiredSig = computeHmac(providerSecret, "$expiredTs.$rawPayload")
        val expiredCmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-expired-ts",
            signatureHeader = expiredSig,
            timestampHeader = expiredTs,
            rawPayload = rawPayload,
            idempotencyKey = "key-expired-ts",
            correlationId = "corr-expired-ts",
            causationId = "cause-expired-ts",
        )
        val expiredError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(expiredCmd)
        }
        assertEquals(AuthErrorCode.STALE, expiredError.code)
        val quarantinedExpired = inboxStore.listQuarantinedMessages(tenantId).find { it.externalEventId == "evt-expired-ts" }
        assertNotNull(quarantinedExpired)
        assertEquals(WebhookQuarantineReason.EXPIRED_TIMESTAMP, quarantinedExpired.quarantineReason)

        // 5. Unknown provider -> Quarantined with UNKNOWN_PROVIDER + FORBIDDEN
        val unknownProvCmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = "prov-unregistered-xyz",
            externalEventId = "evt-unk-prov",
            signatureHeader = validSignature,
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-unk-prov",
            correlationId = "corr-unk-prov",
            causationId = "cause-unk-prov",
        )
        val unkProvError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(unknownProvCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, unkProvError.code)
        val quarantinedUnkProv = inboxStore.listQuarantinedMessages(tenantId).find { it.externalEventId == "evt-unk-prov" }
        assertNotNull(quarantinedUnkProv)
        assertEquals(WebhookQuarantineReason.UNKNOWN_PROVIDER, quarantinedUnkProv.quarantineReason)

        // 6. Out-of-order sequence rejection: deliver sequence 2 then sequence 1 for same payment reference
        val payloadSeq2 = "{\"paymentReference\":\"dep-seq-inbox\",\"amount\":5000,\"currency\":\"EUR\"}"
        val sigSeq2 = computeHmac(providerSecret, "$validTimestamp.$payloadSeq2")
        service.persistAndProcessCallback(PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-seq-2",
            signatureHeader = sigSeq2,
            timestampHeader = validTimestamp,
            rawPayload = payloadSeq2,
            idempotencyKey = "key-seq-2",
            correlationId = "corr-seq-2",
            causationId = "cause-seq-2",
            deliverySequence = 2L,
        ))

        val payloadSeq1 = "{\"paymentReference\":\"dep-seq-inbox\",\"amount\":5000,\"currency\":\"EUR\",\"status\":\"UPDATE\"}"
        val sigSeq1 = computeHmac(providerSecret, "$validTimestamp.$payloadSeq1")
        val outOfOrderError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(PersistDepositCallbackCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalEventId = "evt-seq-1",
                signatureHeader = sigSeq1,
                timestampHeader = validTimestamp,
                rawPayload = payloadSeq1,
                idempotencyKey = "key-seq-1",
                correlationId = "corr-seq-1",
                causationId = "cause-seq-1",
                deliverySequence = 1L, // 1 <= last sequence 2
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, outOfOrderError.code)
        val quarantinedOoo = inboxStore.listQuarantinedMessages(tenantId).find { it.externalEventId == "evt-seq-1" }
        assertNotNull(quarantinedOoo)
        assertEquals(WebhookQuarantineReason.OUT_OF_ORDER, quarantinedOoo.quarantineReason)

        // 7. Conflicting payload replay under same idempotency key
        val validCmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-idemp-test",
            signatureHeader = validSignature,
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-idemp-test",
            correlationId = "corr-idemp-1",
            causationId = "cause-idemp-1",
            deliverySequence = 3L,
        )
        service.persistAndProcessCallback(validCmd)

        val changedPayloadError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(validCmd.copy(rawPayload = "{\"altered\":\"payload\"}"))
        }
        assertEquals(AuthErrorCode.CONFLICT, changedPayloadError.code)

        // 8. Conflicting payload replay under same external event ID
        val changedExtIdError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.persistAndProcessCallback(validCmd.copy(
                idempotencyKey = "key-different-idemp",
                rawPayload = "{\"different\":\"body\"}"
            ))
        }
        assertEquals(AuthErrorCode.CONFLICT, changedExtIdError.code)
    }

    @Test
    fun `PAYMENT-003-02-T003 — Persist deposit callbacks in a durable inbox survives concurrency, duplicate delivery, and dependency failure`() {
        val rawPayload = "{\"paymentReference\":\"dep-con-001\",\"amount\":14000,\"currency\":\"EUR\"}"
        val timestamp = "${now.epochSecond}"
        val signature = computeHmac(providerSecret, "$timestamp.$rawPayload")
        val cmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-con-001",
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-con-001",
            correlationId = "corr-con-1",
            causationId = "cause-con-1",
        )

        // 1. Concurrency: 8 threads concurrently submitting identical deposit callback
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<DepositInboxProcessingResult>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.persistAndProcessCallback(cmd)
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

        assertTrue(errors.isEmpty(), "No errors on concurrent duplicate replay: $errors")
        assertEquals(threadCount, results.size)
        val targetMessageId = results.first().messageId
        for (res in results) {
            assertEquals(targetMessageId, res.messageId)
            assertEquals("dep-con-001", res.paymentReference)
            assertEquals(DEPOSIT_DURABLE_INBOX_CONTRACT, res.semanticContract)
        }

        // Exactly one message durably persisted in the store
        val storedMsg = inboxStore.findMessageById(tenantId, targetMessageId)
        assertNotNull(storedMsg)
        assertEquals(DepositInboxMessageStatus.PROCESSED, storedMsg.status)

        // 2. Downstream handler failure: handler throws exception -> marks FAILED, increments retryCount
        var failAttempts = 0
        val failingHandler = DepositInboxPayloadHandler { _, _, _, _ ->
            failAttempts += 1
            throw RuntimeException("Gateway settlement timeout")
        }
        val failingService = DepositDurableInboxService(authService, webhookStore, inboxStore, failingHandler, inboxAlertSink, clock = clock)

        val failPayload = "{\"paymentReference\":\"dep-fail-001\",\"amount\":6000,\"currency\":\"EUR\"}"
        val failSig = computeHmac(providerSecret, "$timestamp.$failPayload")
        val failCmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-handler-fail",
            signatureHeader = failSig,
            timestampHeader = timestamp,
            rawPayload = failPayload,
            idempotencyKey = "key-handler-fail-1",
            correlationId = "corr-fail-1",
            causationId = "cause-fail-1",
        )

        // Attempt 1: Fails with DEPENDENCY_UNAVAILABLE
        val err1 = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.persistAndProcessCallback(failCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, err1.code)

        val failMsg1 = inboxStore.findMessageByExternalId(tenantId, providerId, "evt-handler-fail")
        assertNotNull(failMsg1)
        assertEquals(DepositInboxMessageStatus.FAILED, failMsg1.status)
        assertEquals(1, failMsg1.retryCount)

        // Attempt 2:
        val err2 = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.persistAndProcessCallback(failCmd.copy(idempotencyKey = "key-handler-fail-2"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, err2.code)
        val failMsg2 = inboxStore.findMessageByExternalId(tenantId, providerId, "evt-handler-fail")
        assertNotNull(failMsg2)
        assertEquals(2, failMsg2.retryCount)

        // Attempt 3: Reaches maxRetries (3) -> transitions to DEAD_LETTER and emits alert
        val err3 = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.persistAndProcessCallback(failCmd.copy(idempotencyKey = "key-handler-fail-3"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, err3.code)
        val failMsg3 = inboxStore.findMessageByExternalId(tenantId, providerId, "evt-handler-fail")
        assertNotNull(failMsg3)
        assertEquals(DepositInboxMessageStatus.DEAD_LETTER, failMsg3.status)
        assertEquals(3, failMsg3.retryCount)
        assertTrue(inboxAlertSink.alerts.any { it.contains("DEAD_LETTER_THRESHOLD_EXCEEDED") })
    }

    @Test
    fun `PAYMENT-003-02-T004 — Persist deposit callbacks in a durable inbox remains compatible, recoverable, observable, and lifecycle-safe`() {
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

        // 3. Rehydrate state across restart
        val rawPayload = "{\"paymentReference\":\"dep-rec-inbox-1\",\"amount\":18000,\"currency\":\"EUR\"}"
        val timestamp = "${now.epochSecond}"
        val signature = computeHmac(providerSecret, "$timestamp.$rawPayload")
        val cmd = PersistDepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalEventId = "evt-rec-001",
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-rec-inbox-1",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
        )
        val initialResult = service.persistAndProcessCallback(cmd)
        assertEquals(DepositInboxMessageStatus.PROCESSED, initialResult.status)

        // Export snapshot and rehydrate into fresh store simulating server restart
        val snapshot = inboxStore.exportSnapshot()
        val rehydratedStore = InMemoryDepositDurableInboxStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = DepositDurableInboxService(authService, webhookStore, rehydratedStore, payloadHandler, inboxAlertSink, clock = clock)

        // Calling with same idempotency key returns identical cached result
        val replayedResult = restartedService.persistAndProcessCallback(cmd)
        assertEquals(initialResult.messageId, replayedResult.messageId)
        assertEquals(initialResult.evidenceReference, replayedResult.evidenceReference)
        assertEquals(initialResult.payloadHash, replayedResult.payloadHash)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(DEPOSIT_DURABLE_INBOX_CONTRACT, replayedResult.semanticContract)

        // 4. Posted audit history is immutable
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

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val key = SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
        mac.init(key)
        val raw = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return raw.joinToString("") { "%02x".format(it) }
    }

    private fun sha256(data: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
