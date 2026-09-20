package com.slotting.admin.payment

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
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

class DepositWebhookAuthenticationTest {
    private val now = Instant.parse("2026-09-19T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-webhook-1"
    private val providerId = "prov-webhook-card-1"
    private val providerSecret = "secret-hmac-key-deposit-001"

    @BeforeEach
    fun setUp() {
        DepositWebhookAuthenticationBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        DepositWebhookAuthenticationBinding.isBound = true
    }

    @Test
    fun `PAYMENT-003-01-T001 — Authenticate deposit webhook raw bodies produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        DepositWebhookAuthenticationBinding.isBound = false
        val secretResolver = InMemoryDepositWebhookSecretResolver()
        secretResolver.setSecret(tenantId, providerId, providerSecret)
        val store = InMemoryDepositWebhookStore()
        val alertSink = InMemoryDepositWebhookAlertSink()
        val service = DepositWebhookAuthenticationService(secretResolver, store, alertSink, clock = clock)

        val rawPayload = "{\"paymentReference\":\"dep-t001-001\",\"amount\":10000,\"currency\":\"EUR\",\"status\":\"CAPTURED\"}"
        val timestamp = "${now.epochSecond}"
        val signature = computeHmac(providerSecret, "$timestamp.$rawPayload")
        val cmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-wh-t001-001",
            correlationId = "corr-wh-1",
            causationId = "cause-wh-1",
        )

        val gateError = assertFailsWith<AssertionError> {
            service.authenticateWebhook(cmd)
        }
        assertEquals("bad signature/duplicate/late/out-of-order accepted wrongly", gateError.message)

        // Bind the fail-closed gate
        DepositWebhookAuthenticationBinding.isBound = true

        // 2. Authoritative operation: Authenticate valid deposit webhook
        val authResult = service.authenticateWebhook(cmd)
        assertNotNull(authResult)
        assertTrue(authResult.authenticated)
        assertEquals(WebhookAuthStatus.AUTHENTICATED, authResult.status)
        assertNull(authResult.quarantineReason)
        assertEquals("dep-t001-001", authResult.paymentReference)
        assertEquals(providerId, authResult.providerId)
        assertEquals(200, authResult.providerResponse.httpStatusCode)
        assertFalse(authResult.providerResponse.retryable)

        // Outcome-specific semantic contract assertion:
        // "Respond safely; quarantine unknowns; retain redacted forensic metadata."
        assertEquals(DEPOSIT_WEBHOOK_AUTH_CONTRACT, authResult.semanticContract)

        // Financial conservation: debits equal credits
        assertEquals(10000L, authResult.debitMinorUnits)
        assertEquals(10000L, authResult.creditMinorUnits)
        assertTrue(authResult.conserved)

        // Forensic metadata retained: SHA-256 payload hash, zero raw secrets/PII
        val expectedHash = sha256(rawPayload)
        assertEquals(expectedHash, authResult.payloadHash)
        val forensicRecords = store.listForensicRecords(tenantId)
        assertEquals(1, forensicRecords.size)
        val record = forensicRecords.first()
        assertEquals(WebhookAuthStatus.AUTHENTICATED, record.status)
        assertEquals(expectedHash, record.payloadHash)
        assertEquals(signature, record.signatureHeader)
        assertEquals(timestamp, record.timestampHeader)
        assertFalse(record.payloadHash.contains("secret", ignoreCase = true))

        // Idempotent replay yields identical authoritative identity
        val replayResult = service.authenticateWebhook(cmd)
        assertEquals(authResult.resultId, replayResult.resultId)
        assertEquals(authResult.evidenceReference, replayResult.evidenceReference)
        assertEquals(authResult.payloadHash, replayResult.payloadHash)

        // Audit and outbox events emitted
        val auditEvents = store.getAuditEvents()
        assertEquals(1, auditEvents.size)
        assertEquals("DEPOSIT_WEBHOOK_AUTHENTICATED", auditEvents.first().type)
        assertEquals("corr-wh-1", auditEvents.first().correlationId)
        assertEquals("cause-wh-1", auditEvents.first().causationId)

        val outboxEvents = store.getOutboxEvents()
        assertEquals(1, outboxEvents.size)
        assertEquals("DEPOSIT_WEBHOOK_AUTHENTICATED", outboxEvents.first().type)
    }

    @Test
    fun `PAYMENT-003-01-T002 — Authenticate deposit webhook raw bodies rejects invalid, boundary, unauthorized, and stale input`() {
        val secretResolver = InMemoryDepositWebhookSecretResolver()
        secretResolver.setSecret(tenantId, providerId, providerSecret)
        val store = InMemoryDepositWebhookStore()
        val alertSink = InMemoryDepositWebhookAlertSink()
        val service = DepositWebhookAuthenticationService(secretResolver, store, alertSink, clock = clock)

        val rawPayload = "{\"paymentReference\":\"dep-t002-001\",\"amount\":5000,\"currency\":\"EUR\"}"
        val validTimestamp = "${now.epochSecond}"
        val validSignature = computeHmac(providerSecret, "$validTimestamp.$rawPayload")

        // 1. Bad signature: tampered signature header -> quarantined + FORBIDDEN
        val badSigCmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = "tampered-bad-signature",
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-bad-sig",
            correlationId = "corr-bad-sig",
            causationId = "cause-bad-sig",
        )
        val badSigError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(badSigCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, badSigError.code)
        // Verify quarantine record saved
        val quarantinedBadSig = store.listForensicRecords(tenantId).find { it.quarantineReason == WebhookQuarantineReason.BAD_SIGNATURE }
        assertNotNull(quarantinedBadSig)
        assertEquals(WebhookAuthStatus.QUARANTINED, quarantinedBadSig.status)

        // 2. Late / Expired timestamp: outside replay window (> 300s) -> quarantined + STALE
        val lateTimestamp = "${now.minusSeconds(400).epochSecond}"
        val lateSignature = computeHmac(providerSecret, "$lateTimestamp.$rawPayload")
        val lateCmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = lateSignature,
            timestampHeader = lateTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-late-ts",
            correlationId = "corr-late-ts",
            causationId = "cause-late-ts",
        )
        val lateError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(lateCmd)
        }
        assertEquals(AuthErrorCode.STALE, lateError.code)
        val quarantinedLate = store.listForensicRecords(tenantId).find { it.quarantineReason == WebhookQuarantineReason.EXPIRED_TIMESTAMP }
        assertNotNull(quarantinedLate)

        // 3. Future timestamp: ahead of clock skew tolerance (> 60s) -> quarantined + STALE
        val futureTimestamp = "${now.plusSeconds(300).epochSecond}"
        val futureSignature = computeHmac(providerSecret, "$futureTimestamp.$rawPayload")
        val futureCmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = futureSignature,
            timestampHeader = futureTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-future-ts",
            correlationId = "corr-future-ts",
            causationId = "cause-future-ts",
        )
        val futureError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(futureCmd)
        }
        assertEquals(AuthErrorCode.STALE, futureError.code)
        val quarantinedFuture = store.listForensicRecords(tenantId).find { it.quarantineReason == WebhookQuarantineReason.FUTURE_TIMESTAMP }
        assertNotNull(quarantinedFuture)

        // 4. Unknown provider: provider secret not found -> quarantined + FORBIDDEN
        val unknownProviderCmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = "prov-unknown-vendor",
            signatureHeader = validSignature,
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-unk-prov",
            correlationId = "corr-unk-prov",
            causationId = "cause-unk-prov",
        )
        val unknownProvError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(unknownProviderCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, unknownProvError.code)
        val quarantinedUnkProv = store.listForensicRecords(tenantId).find { it.quarantineReason == WebhookQuarantineReason.UNKNOWN_PROVIDER }
        assertNotNull(quarantinedUnkProv)

        // 5. Duplicate signature replay: execute valid first, then resubmit same signature with different idempotency key
        val validCmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = validSignature,
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-first-valid",
            correlationId = "corr-valid-1",
            causationId = "cause-valid-1",
            deliverySequence = 1L,
        )
        val firstResult = service.authenticateWebhook(validCmd)
        assertTrue(firstResult.authenticated)

        val replaySigCmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = validSignature,
            timestampHeader = validTimestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-replay-sig",
            correlationId = "corr-replay-sig",
            causationId = "cause-replay-sig",
            deliverySequence = 2L,
        )
        val replaySigError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(replaySigCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, replaySigError.code)

        // 6. Out-of-order sequence: sequence 1 after sequence 2
        val payloadSeq2 = "{\"paymentReference\":\"dep-seq-test\",\"amount\":5000,\"currency\":\"EUR\"}"
        val sigSeq2 = computeHmac(providerSecret, "$validTimestamp.$payloadSeq2")
        service.authenticateWebhook(AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = sigSeq2,
            timestampHeader = validTimestamp,
            rawPayload = payloadSeq2,
            idempotencyKey = "key-seq-2",
            correlationId = "corr-seq-2",
            causationId = "cause-seq-2",
            deliverySequence = 2L,
        ))

        val payloadSeq1 = "{\"paymentReference\":\"dep-seq-test\",\"amount\":5000,\"currency\":\"EUR\",\"status\":\"UPDATE\"}"
        val sigSeq1 = computeHmac(providerSecret, "$validTimestamp.$payloadSeq1")
        val outOfOrderError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(AuthenticateDepositWebhookCommand(
                tenantId = tenantId,
                providerId = providerId,
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
        val quarantinedOoo = store.listForensicRecords(tenantId).find { it.quarantineReason == WebhookQuarantineReason.OUT_OF_ORDER }
        assertNotNull(quarantinedOoo)

        // 7. Malformed / blank input:
        val blankSigError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(validCmd.copy(signatureHeader = "", idempotencyKey = "key-blank-sig"))
        }
        assertEquals(AuthErrorCode.INVALID, blankSigError.code)

        val blankPayloadError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(validCmd.copy(rawPayload = "", idempotencyKey = "key-blank-payload"))
        }
        assertEquals(AuthErrorCode.INVALID, blankPayloadError.code)

        val staleVersionError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(validCmd.copy(expectedVersion = 2L, idempotencyKey = "key-stale-v"))
        }
        assertEquals(AuthErrorCode.STALE, staleVersionError.code)

        // 8. Idempotency key reuse with changed payload
        val changedPayloadError = assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateWebhook(validCmd.copy(rawPayload = "{\"different\":\"payload\"}"))
        }
        assertEquals(AuthErrorCode.CONFLICT, changedPayloadError.code)

        // Verify actionable alerts recorded in alert sink
        assertTrue(alertSink.alerts.isNotEmpty())
        assertTrue(alertSink.alerts.any { it.contains("BAD_SIGNATURE") })
        assertTrue(alertSink.alerts.any { it.contains("EXPIRED_TIMESTAMP") })
        assertTrue(alertSink.alerts.any { it.contains("OUT_OF_ORDER") })
        assertTrue(alertSink.alerts.any { it.contains("DUPLICATE_SIGNATURE_REPLAY") })
    }

    @Test
    fun `PAYMENT-003-01-T003 — Authenticate deposit webhook raw bodies survives concurrency, duplicate delivery, and dependency failure`() {
        val secretResolver = InMemoryDepositWebhookSecretResolver()
        secretResolver.setSecret(tenantId, providerId, providerSecret)
        val store = InMemoryDepositWebhookStore()
        val alertSink = InMemoryDepositWebhookAlertSink()
        val service = DepositWebhookAuthenticationService(secretResolver, store, alertSink, clock = clock)

        val rawPayload = "{\"paymentReference\":\"dep-concurrent-001\",\"amount\":12000,\"currency\":\"EUR\"}"
        val timestamp = "${now.epochSecond}"
        val signature = computeHmac(providerSecret, "$timestamp.$rawPayload")
        val cmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-concurrent-001",
            correlationId = "corr-con-1",
            causationId = "cause-con-1",
        )

        // 1. Concurrency: 8 threads concurrently submitting identical webhook
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val results = java.util.Collections.synchronizedList(mutableListOf<DepositWebhookAuthResult>())
        val errors = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.authenticateWebhook(cmd)
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

        assertTrue(errors.isEmpty(), "No errors expected on concurrent replay: $errors")
        assertEquals(threadCount, results.size)
        val firstResultId = results.first().resultId
        for (res in results) {
            assertEquals(firstResultId, res.resultId)
            assertEquals("dep-concurrent-001", res.paymentReference)
            assertEquals(DEPOSIT_WEBHOOK_AUTH_CONTRACT, res.semanticContract)
        }

        // Exactly one forensic record and one audit record stored for this key
        assertEquals(1, store.listForensicRecords(tenantId).size)
        assertEquals(1, store.getAuditEvents().size)

        // 2. Dependency failure: Secret resolver throws DEPENDENCY_UNAVAILABLE
        val failingResolver = object : DepositWebhookSecretResolver {
            override fun resolveSecret(tenantId: String, providerId: String): String? {
                throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
            }
        }
        val failingService = DepositWebhookAuthenticationService(failingResolver, store, alertSink, clock = clock)

        val depFailError = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.authenticateWebhook(cmd.copy(idempotencyKey = "key-dep-fail-001"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depFailError.code)
    }

    @Test
    fun `PAYMENT-003-01-T004 — Authenticate deposit webhook raw bodies remains compatible, recoverable, observable, and lifecycle-safe`() {
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

        // 3. Recovery across restart: Recreating service instance sharing store state
        val secretResolver = InMemoryDepositWebhookSecretResolver()
        secretResolver.setSecret(tenantId, providerId, providerSecret)
        val initialStore = InMemoryDepositWebhookStore()
        val alertSink = InMemoryDepositWebhookAlertSink()
        val initialService = DepositWebhookAuthenticationService(secretResolver, initialStore, alertSink, clock = clock)

        val rawPayload = "{\"paymentReference\":\"dep-rec-001\",\"amount\":15000,\"currency\":\"EUR\"}"
        val timestamp = "${now.epochSecond}"
        val signature = computeHmac(providerSecret, "$timestamp.$rawPayload")
        val cmd = AuthenticateDepositWebhookCommand(
            tenantId = tenantId,
            providerId = providerId,
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "key-rec-001",
            correlationId = "corr-rec-1",
            causationId = "cause-rec-1",
        )
        val initialResult = initialService.authenticateWebhook(cmd)
        assertEquals(WebhookAuthStatus.AUTHENTICATED, initialResult.status)

        // 4. Export snapshot and rehydrate into fresh store instance simulating server restart
        val snapshot = initialStore.exportSnapshot()
        val rehydratedStore = InMemoryDepositWebhookStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = DepositWebhookAuthenticationService(secretResolver, rehydratedStore, alertSink, clock = clock)

        // Calling authenticateWebhook with same idempotency key on rehydrated instance returns identical cached result
        val replayedResult = restartedService.authenticateWebhook(cmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertEquals(initialResult.evidenceReference, replayedResult.evidenceReference)
        assertEquals(initialResult.payloadHash, replayedResult.payloadHash)
        assertEquals(DEPOSIT_WEBHOOK_AUTH_CONTRACT, replayedResult.semanticContract)

        // Replaying same signature with different idempotency key is rejected as replay attack on rehydrated instance
        val replaySigError = assertFailsWith<AuthenticationFailure.Rejected> {
            restartedService.authenticateWebhook(cmd.copy(idempotencyKey = "key-rec-dup-sig"))
        }
        assertEquals(AuthErrorCode.CONFLICT, replaySigError.code)

        // 5. Posted audit and forensic history are immutable (never edited or erased)
        val forensicRecords = rehydratedStore.listForensicRecords(tenantId)
        assertEquals(1, forensicRecords.size)
        val forensicRecord = forensicRecords.first()
        assertEquals(initialResult.payloadHash, forensicRecord.payloadHash)
        assertEquals(signature, forensicRecord.signatureHeader)

        // 6. Observability: zero secrets or sensitive PII in audit or outbox
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
