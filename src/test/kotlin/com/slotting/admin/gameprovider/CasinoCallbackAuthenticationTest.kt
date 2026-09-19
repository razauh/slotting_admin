package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CasinoCallbackAuthenticationTest {

    private val fixedInstant = Instant.parse("2026-09-19T02:00:00Z")
    private val clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)

    private val tenantId = "tenant-casino-alpha"
    private val providerId = "prv-pragmatic"
    private val providerSecret = "secret-pragmatic-test-key-2026"

    private lateinit var secretResolver: InMemoryCasinoCallbackSecretResolver
    private lateinit var store: InMemoryCasinoCallbackStore
    private lateinit var alertSink: InMemoryCasinoCallbackAlertSink
    private lateinit var service: CasinoCallbackAuthenticationService

    @BeforeEach
    fun setUp() {
        CasinoCallbackAuthenticationBinding.isBound = true
        secretResolver = InMemoryCasinoCallbackSecretResolver()
        secretResolver.setSecret(tenantId, providerId, providerSecret)
        secretResolver.setSecret(tenantId, "prv-evolution", "secret-evolution-key")

        store = InMemoryCasinoCallbackStore()
        alertSink = InMemoryCasinoCallbackAlertSink()

        service = CasinoCallbackAuthenticationService(
            secretResolver = secretResolver,
            store = store,
            alertSink = alertSink,
            clock = clock,
            maxTimestampSkewSeconds = 300L,
        )
    }

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    // =========================================================================
    // GAME-008-01-T001: Primary Authoritative Outcome & Provider-Specific Response
    // =========================================================================

    @Test
    fun `GAME-008-01-T001 Authenticate casino callbacks produces the required authoritative outcome`() {
        CasinoCallbackAuthenticationBinding.checkBound()

        val timestamp = fixedInstant.epochSecond.toString()
        val payload = """{"roundId":"rnd-1001","transactionId":"tx-cb-01","amount":500,"currency":"USD"}"""
        val signature = computeHmac(providerSecret, "$timestamp.$payload")

        val request = AuthenticatedCallbackRequest(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalRoundId = "rnd-1001",
            externalTransactionId = "tx-cb-01",
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = payload,
            idempotencyKey = "k-cb-001",
            correlationId = "c-cb-001",
            causationId = "cause-cb-001",
        )

        // 1. Authenticate valid callback
        val result = service.authenticateCallback(request)

        assertTrue(result.authenticated)
        assertEquals(tenantId, result.tenantId)
        assertEquals(providerId, result.providerId)
        assertEquals("rnd-1001", result.externalRoundId)
        assertEquals("tx-cb-01", result.externalTransactionId)
        assertNotNull(result.evidenceReference)

        // Verify provider-specific response contract (Pragmatic Play error: 0 success)
        assertEquals(200, result.providerResponse.httpStatusCode)
        assertTrue(result.providerResponse.responseBody.contains(""""error":0"""))
        assertTrue(result.providerResponse.responseBody.contains(""""description":"Success""""))
        assertFalse(result.providerResponse.retryable)

        // 2. Verify audit record and outbox event persistence
        val auditRecords = store.listAuditRecords(tenantId)
        assertEquals(1, auditRecords.size)
        assertEquals("VERIFIED_AUTHENTIC", auditRecords[0].outcome)
        assertEquals(signature, auditRecords[0].signature)

        assertEquals(1, store.auditEvents.size)
        assertEquals("CASINO_CALLBACK_AUTHENTICATED", store.auditEvents[0].type)
        assertEquals("c-cb-001", store.auditEvents[0].correlationId)

        assertEquals(1, store.outboxEvents.size)
        assertEquals("CASINO_CALLBACK_AUTHENTICATED", store.outboxEvents[0].type)

        // 3. Test Evolution protocol provider response
        val evoSecret = "secret-evolution-key"
        val evoPayload = """{"roundId":"rnd-evo-01","transactionId":"tx-evo-01","bet":200}"""
        val evoSig = computeHmac(evoSecret, "$timestamp.$evoPayload")
        val evoResult = service.authenticateCallback(
            request.copy(
                providerId = "prv-evolution",
                protocol = CallbackProviderProtocol.EVOLUTION,
                externalRoundId = "rnd-evo-01",
                externalTransactionId = "tx-evo-01",
                signatureHeader = evoSig,
                rawPayload = evoPayload,
                idempotencyKey = "k-evo-001",
            )
        )
        assertEquals(200, evoResult.providerResponse.httpStatusCode)
        assertTrue(evoResult.providerResponse.responseBody.contains(""""status":"OK""""))
    }

    // =========================================================================
    // GAME-008-01-T002: Negative, Boundary, Unauthorized, Spoof & Stale Payload
    // =========================================================================

    @Test
    fun `GAME-008-01-T002 Authenticate casino callbacks rejects invalid, boundary, unauthorized, and stale input`() {
        CasinoCallbackAuthenticationBinding.checkBound()

        val timestamp = fixedInstant.epochSecond.toString()
        val payload = """{"roundId":"rnd-sec-01","txId":"tx-sec-01"}"""
        val validSig = computeHmac(providerSecret, "$timestamp.$payload")

        val baseReq = AuthenticatedCallbackRequest(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalRoundId = "rnd-sec-01",
            externalTransactionId = "tx-sec-01",
            signatureHeader = validSig,
            timestampHeader = timestamp,
            rawPayload = payload,
            idempotencyKey = "k-sec-01",
            correlationId = "c-sec-01",
            causationId = "cause-sec-01",
        )

        // 1. Spoofed Signature: Tampered signature rejected with FORBIDDEN and alert emitted!
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(baseReq.copy(signatureHeader = "spoofed-bad-signature", idempotencyKey = "k-spoof-sig"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_CALLBACK_SPOOF_ATTEMPT") })
        // Zero mutation in store
        assertEquals(0, store.listAuditRecords(tenantId).size)

        // 2. Tampered Payload (valid signature for different payload) -> FORBIDDEN and alert
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(baseReq.copy(rawPayload = """{"roundId":"rnd-sec-01","tampered":true}""", idempotencyKey = "k-tampered"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Stale Payload: Timestamp older than max skew tolerance (e.g. 600 seconds old) -> INVALID and alert
        val oldTimestamp = (fixedInstant.epochSecond - 600).toString()
        val oldSig = computeHmac(providerSecret, "$oldTimestamp.$payload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(baseReq.copy(timestampHeader = oldTimestamp, signatureHeader = oldSig, idempotencyKey = "k-stale-old"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_CALLBACK_STALE_PAYLOAD") })

        // 4. Future Timestamp: Timestamp too far in future -> INVALID and alert
        val futureTimestamp = (fixedInstant.epochSecond + 600).toString()
        val futureSig = computeHmac(providerSecret, "$futureTimestamp.$payload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(baseReq.copy(timestampHeader = futureTimestamp, signatureHeader = futureSig, idempotencyKey = "k-stale-future"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Unknown Provider Secret -> FORBIDDEN and alert
        val unknownProviderSig = computeHmac("any-key", "$timestamp.$payload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(baseReq.copy(providerId = "prv-unknown", signatureHeader = unknownProviderSig, idempotencyKey = "k-unknown-prv"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_CALLBACK_UNKNOWN_PROVIDER") })

        // 6. Stale Expected Version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(baseReq.copy(expectedVersion = 2L, idempotencyKey = "k-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 7. Blank required parameters -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(baseReq.copy(signatureHeader = "", idempotencyKey = "k-blank-sig"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Authoritative store remains completely empty (zero unauthorized mutation)
        assertEquals(0, store.listAuditRecords(tenantId).size)
    }

    // =========================================================================
    // GAME-008-01-T003: Concurrency, Duplicate Delivery, and Dependency Failure
    // =========================================================================

    @Test
    fun `GAME-008-01-T003 Authenticate casino callbacks survives concurrency, duplicate delivery, and dependency failure`() {
        CasinoCallbackAuthenticationBinding.checkBound()

        val timestamp = fixedInstant.epochSecond.toString()
        val payload = """{"roundId":"rnd-conc-01","txId":"tx-conc-01","win":1000}"""
        val signature = computeHmac(providerSecret, "$timestamp.$payload")

        val request = AuthenticatedCallbackRequest(
            tenantId = tenantId,
            providerId = providerId,
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            externalRoundId = "rnd-conc-01",
            externalTransactionId = "tx-conc-01",
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = payload,
            idempotencyKey = "k-conc-idemp",
            correlationId = "c-conc",
            causationId = "cause-conc",
        )

        // 1. Idempotent replay: exact same payload returns identical cached result
        val res1 = service.authenticateCallback(request)
        val res2 = service.authenticateCallback(request)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.evidenceReference, res2.evidenceReference)
        assertEquals(1, store.listAuditRecords(tenantId).size) // Exactly one persisted record!

        // 2. Changed payload under existing idempotency key throws CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.authenticateCallback(request.copy(rawPayload = """{"roundId":"rnd-conc-01","txId":"tx-conc-01","win":9999}"""))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_CALLBACK_IDEMPOTENCY_CONFLICT") })

        // 3. Concurrent duplicate deliveries race condition
        val executor = Executors.newFixedThreadPool(8)
        val concPayload = """{"roundId":"rnd-race","txId":"tx-race"}"""
        val concSig = computeHmac(providerSecret, "$timestamp.$concPayload")
        val concReq = request.copy(
            externalRoundId = "rnd-race",
            externalTransactionId = "tx-race",
            signatureHeader = concSig,
            rawPayload = concPayload,
            idempotencyKey = "k-race-idemp",
        )

        val tasks = (1..8).map {
            Callable {
                try {
                    service.authenticateCallback(concReq)
                } catch (e: Exception) {
                    null
                }
            }
        }
        val results = executor.invokeAll(tasks).mapNotNull { it.get() }
        executor.shutdown()

        assertEquals(8, results.size)
        // All 8 returned the exact same resultId
        val distinctResultIds = results.map { it.resultId }.distinct()
        assertEquals(1, distinctResultIds.size)

        // 4. Dependency failure: secret resolution throws exception -> fails closed with DEPENDENCY_UNAVAILABLE
        val failingResolver = object : CasinoCallbackSecretResolver {
            override fun resolveSecret(tenantId: String, providerId: String): String {
                throw RuntimeException("Vault connection timed out")
            }
        }
        val serviceWithFailingResolver = CasinoCallbackAuthenticationService(
            secretResolver = failingResolver,
            store = store,
            alertSink = alertSink,
            clock = clock,
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithFailingResolver.authenticateCallback(request.copy(idempotencyKey = "k-vault-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        assertTrue(alertSink.alerts.any { it.contains("CASINO_CALLBACK_VAULT_FAILURE") })
    }

    // =========================================================================
    // GAME-008-01-T004: Observability, Provider Retry Contract, and Lifecycle
    // =========================================================================

    @Test
    fun `GAME-008-01-T004 Authenticate casino callbacks remains compatible, recoverable, observable, and lifecycle-safe`() {
        CasinoCallbackAuthenticationBinding.checkBound()

        // 1. Provider-specific failure responses and retry guidance
        val pragmaticRetryResponse = service.getFailureResponse(
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            errorCode = AuthErrorCode.DEPENDENCY_UNAVAILABLE,
            reason = "Service temporarily unavailable",
        )
        assertEquals(503, pragmaticRetryResponse.httpStatusCode)
        assertTrue(pragmaticRetryResponse.retryable)
        assertEquals(5L, pragmaticRetryResponse.retryAfterSeconds)
        assertTrue(pragmaticRetryResponse.responseBody.contains(""""error":120"""))

        val pragmaticNonRetryResponse = service.getFailureResponse(
            protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
            errorCode = AuthErrorCode.FORBIDDEN,
            reason = "Invalid hash",
        )
        assertEquals(400, pragmaticNonRetryResponse.httpStatusCode)
        assertFalse(pragmaticNonRetryResponse.retryable)
        assertTrue(pragmaticNonRetryResponse.responseBody.contains(""""error":5"""))

        // Evolution failure response format
        val evoFailureResponse = service.getFailureResponse(
            protocol = CallbackProviderProtocol.EVOLUTION,
            errorCode = AuthErrorCode.FORBIDDEN,
            reason = "Invalid signature",
        )
        assertEquals(400, evoFailureResponse.httpStatusCode)
        assertTrue(evoFailureResponse.responseBody.contains(""""status":"INVALID_SIGNATURE""""))

        // 2. Observability & Redaction: Zero secret or credential disclosure in audit or alerts
        val timestamp = fixedInstant.epochSecond.toString()
        val payload = """{"roundId":"rnd-obs-01","txId":"tx-obs-01"}"""
        val sig = computeHmac(providerSecret, "$timestamp.$payload")

        service.authenticateCallback(
            AuthenticatedCallbackRequest(
                tenantId = tenantId,
                providerId = providerId,
                protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
                externalRoundId = "rnd-obs-01",
                externalTransactionId = "tx-obs-01",
                signatureHeader = sig,
                timestampHeader = timestamp,
                rawPayload = payload,
                idempotencyKey = "k-obs-01",
                correlationId = "c-obs-01",
                causationId = "cause-obs-01",
            )
        )

        val audits = store.auditEvents
        assertTrue(audits.isNotEmpty())
        for (a in audits) {
            assertFalse(a.type.contains(providerSecret))
            assertFalse(a.correlationId.contains(providerSecret))
        }

        val alerts = alertSink.alerts
        for (alert in alerts) {
            assertFalse(alert.contains(providerSecret))
        }

        // 3. Lifecycle & Recovery: Restart preserves idempotency without re-verifying
        val restartedService = CasinoCallbackAuthenticationService(
            secretResolver = secretResolver,
            store = store,
            alertSink = alertSink,
            clock = clock,
        )

        val replayAfterRestart = restartedService.authenticateCallback(
            AuthenticatedCallbackRequest(
                tenantId = tenantId,
                providerId = providerId,
                protocol = CallbackProviderProtocol.PRAGMATIC_PLAY,
                externalRoundId = "rnd-obs-01",
                externalTransactionId = "tx-obs-01",
                signatureHeader = sig,
                timestampHeader = timestamp,
                rawPayload = payload,
                idempotencyKey = "k-obs-01",
                correlationId = "c-obs-01",
                causationId = "cause-obs-01",
            )
        )
        assertTrue(replayAfterRestart.authenticated)
        assertEquals(audits[0].resultId, replayAfterRestart.resultId)
    }
}
