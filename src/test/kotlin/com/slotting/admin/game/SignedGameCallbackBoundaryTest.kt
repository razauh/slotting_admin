package com.slotting.admin.game

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.*
import org.junit.jupiter.api.Test

class SignedGameCallbackBoundaryTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val providerSecret = "test-aviator-secret-key"

    @Test
    fun `ADR-005-02-T001 Define signed game-callback boundary produces the required authoritative outcome`() {
        val store = SignedCallbackMemoryStore()
        val resolver = FakeSecretResolver(mapOf("tenant-1:prov-aviator" to providerSecret))
        val service = service(store, resolver)

        val timestamp = now.epochSecond.toString()
        val payload = "{\"roundId\":\"round-av-101\",\"crashPoint\":3.42,\"cashOut\":2.50}"
        val signature = computeHmac(providerSecret, "$timestamp.$payload")

        val req = SignedCallbackRequest(
            tenantId = "tenant-1",
            providerId = "prov-aviator",
            roundReference = "round-av-101",
            signatureHeader = signature,
            timestampHeader = timestamp,
            rawPayload = payload,
            idempotencyKey = "key-signed-cb-001",
            correlationId = "corr-signed-1",
            causationId = "cause-signed-1",
        )

        // 1. Process validly signed Aviator callback
        val res = service.verifyAndProcessCallback(req)
        assertTrue(res.verified)
        assertFalse(res.directSettlementPermitted) // Callbacks CANNOT settle directly!
        assertEquals("round-av-101", res.roundReference)
        assertEquals(2.50, res.extractedMultiplier)

        // 2. Replay with identical idempotency key returns identical authoritative outcome
        val replay = service.verifyAndProcessCallback(req)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.evidenceReference, replay.evidenceReference)

        // Assert: Preserve existing Aviator contracts as compatibility input, not authority
        assertEquals(1, store.audit.size)
        assertEquals("GAME_CALLBACK_SIGNATURE_VERIFIED", store.audit[0].type)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-signed-1", store.audit[0].correlationId)
        assertEquals("cause-signed-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-005-02-T002 Define signed game-callback boundary rejects invalid, boundary, unauthorized, and stale input`() {
        val store = SignedCallbackMemoryStore()
        val resolver = FakeSecretResolver(mapOf("tenant-1:prov-aviator" to providerSecret))
        val service = service(store, resolver)

        val timestamp = now.epochSecond.toString()
        val payload = "{\"roundId\":\"round-101\",\"crashPoint\":1.5}"
        val validSig = computeHmac(providerSecret, "$timestamp.$payload")

        // Tampered signature
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessCallback(
                callbackRequest(signature = "tampered-bad-signature", timestamp = timestamp, payload = payload, idempotencyKey = "key-bad-sig")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Tampered payload with valid signature for different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessCallback(
                callbackRequest(signature = validSig, timestamp = timestamp, payload = "{\"tampered\":true}", idempotencyKey = "key-tampered-payload")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Timestamp skew: too old (> 300 seconds in past)
        val oldTimestamp = (now.epochSecond - 600).toString()
        val oldSig = computeHmac(providerSecret, "$oldTimestamp.$payload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessCallback(
                callbackRequest(signature = oldSig, timestamp = oldTimestamp, payload = payload, idempotencyKey = "key-skewed-old")
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Timestamp skew: in future (> 300 seconds)
        val futureTimestamp = (now.epochSecond + 600).toString()
        val futureSig = computeHmac(providerSecret, "$futureTimestamp.$payload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessCallback(
                callbackRequest(signature = futureSig, timestamp = futureTimestamp, payload = payload, idempotencyKey = "key-skewed-future")
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unknown provider / missing secret
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessCallback(
                callbackRequest(providerId = "prov-unknown", signature = validSig, timestamp = timestamp, payload = payload, idempotencyKey = "key-unknown-prov")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessCallback(
                callbackRequest(signature = validSig, timestamp = timestamp, payload = payload, expectedVersion = 999L, idempotencyKey = "key-stale-ver")
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different payload
        service.verifyAndProcessCallback(
            callbackRequest(signature = validSig, timestamp = timestamp, payload = payload, idempotencyKey = "key-conflict-cb")
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyAndProcessCallback(
                callbackRequest(signature = validSig, timestamp = timestamp, payload = "{\"other\":true}", idempotencyKey = "key-conflict-cb")
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-005-02-T003 Define signed game-callback boundary survives concurrency, duplicate delivery, and dependency failure`() {
        val store = SignedCallbackMemoryStore()
        val resolver = FakeSecretResolver(mapOf("tenant-1:prov-aviator" to providerSecret))
        val service = service(store, resolver)

        val timestamp = now.epochSecond.toString()
        val payload = "{\"roundId\":\"round-concurrent\",\"crashPoint\":2.0}"
        val signature = computeHmac(providerSecret, "$timestamp.$payload")

        // 1. Benchmark concurrent duplicate calls with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val calls = (1..4).map {
            pool.submit<SignedCallbackVerificationResult> {
                gate.await()
                service.verifyAndProcessCallback(
                    callbackRequest(
                        signature = signature,
                        timestamp = timestamp,
                        payload = payload,
                        idempotencyKey = "key-concurrent-signed-cb",
                    )
                )
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on secret resolver
        val failingResolver = FailingSecretResolver()
        val failingService = service(store, failingResolver)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.verifyAndProcessCallback(
                callbackRequest(signature = signature, timestamp = timestamp, payload = payload, idempotencyKey = "key-dep-fail-cb")
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-005-02-T004 Define signed game-callback boundary remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = SignedCallbackMemoryStore()
        val resolver = FakeSecretResolver(mapOf("tenant-1:prov-aviator" to providerSecret))
        val service = service(store, resolver)

        val timestamp = now.epochSecond.toString()
        val payload = "{\"roundId\":\"round-reboot\",\"crashPoint\":1.85}"
        val signature = computeHmac(providerSecret, "$timestamp.$payload")

        val req = callbackRequest(
            roundReference = "round-reboot",
            signature = signature,
            timestamp = timestamp,
            payload = payload,
            idempotencyKey = "key-reboot-signed-cb",
            correlationId = "corr-reboot-cb-1",
            causationId = "cause-reboot-cb-1",
        )
        val first = service.verifyAndProcessCallback(req)

        val restartedService = service(store, resolver)
        val second = restartedService.verifyAndProcessCallback(req)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("GAME_CALLBACK_SIGNATURE_VERIFIED", store.audit[0].type)
        assertEquals("corr-reboot-cb-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-cb-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: SignedGameCallbackBoundaryStore, resolver: ProviderSecretResolver) =
        SignedGameCallbackBoundaryService(AdminRbacPolicy(true), resolver, store, clock)

    private fun callbackRequest(
        providerId: String = "prov-aviator",
        roundReference: String = "round-101",
        signature: String,
        timestamp: String,
        payload: String,
        idempotencyKey: String,
        correlationId: String = "corr-signed-default",
        causationId: String = "cause-signed-default",
        expectedVersion: Long = 1L,
    ) = SignedCallbackRequest(
        tenantId = "tenant-1",
        providerId = providerId,
        roundReference = roundReference,
        signatureHeader = signature,
        timestampHeader = timestamp,
        rawPayload = payload,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

private class FakeSecretResolver(private val secrets: Map<String, String>) : ProviderSecretResolver {
    override fun resolveSecret(tenantId: String, providerId: String): String? =
        secrets["$tenantId:$providerId"]
}

private class FailingSecretResolver : ProviderSecretResolver {
    override fun resolveSecret(tenantId: String, providerId: String): String =
        error("secret vault unavailable")
}

private class SignedCallbackMemoryStore : SignedGameCallbackBoundaryStore {
    val results = mutableMapOf<String, Pair<String, SignedCallbackVerificationResult>>()
    val processedSignatures = mutableSetOf<String>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun isSignatureReplayed(tenantId: String, signature: String) =
        synchronized(this) { processedSignatures.contains("$tenantId:$signature") }

    override fun save(
        result: SignedCallbackVerificationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        signature: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        processedSignatures.add("$tenantId:$signature")
        this.audit += audit
        this.outbox += outbox
    }
}
