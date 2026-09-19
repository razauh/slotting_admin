package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.io.File
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

class CanonicalCasinoProviderContractTest {
    private val now = Instant.parse("2026-09-19T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-casino-1"
    private val providerId = "prov-evolution-slots"
    private val activeKeyId = "key-v1"
    private val activeKeySecret = "raw-secret-v1-abcdef123456"
    private val nextKeyId = "key-v2"
    private val nextKeySecret = "raw-secret-v2-789012uvwxyz"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPPORT),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "admin-support-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val unauthorizedPrincipal = AuthenticatedPrincipal(
        id = "admin-viewer-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-1",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SECURITY),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-other-tenant",
        tenantId = "tenant-casino-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    @BeforeEach
    fun setUp() {
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @Test
    fun `GAME-001-01-T001 Define canonical casino provider contract produces the required authoritative outcome`() {
        // 1. Verify fail-closed gate throws expected RED assertion error when unbound
        CanonicalCasinoProviderContractBinding.isBound = false
        val store = InMemoryCasinoProviderContractStore()
        val resolver = MapProviderSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
            "$tenantId:$providerId:$nextKeyId" to nextKeySecret,
        ))
        val sessions = TestCasinoActiveSessionDirectory()
        val service = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, store, clock)

        val regCmd = createRegisterCommand()
        val gateError = assertFailsWith<AssertionError> {
            service.registerSchema(regCmd)
        }
        assertEquals("bad creds/signature/replay", gateError.message)

        // Bind the gate
        CanonicalCasinoProviderContractBinding.isBound = true

        // 2. Register canonical casino provider schema
        val regResult = service.registerSchema(regCmd)
        assertNotNull(regResult)
        assertEquals(tenantId, regResult.tenantId)
        assertEquals(providerId, regResult.providerId)
        assertTrue(regResult.rotationObservable)
        assertTrue(regResult.outageObservable)
        assertEquals(1L, regResult.schema.version)
        assertEquals(CasinoProviderType.SLOTS, regResult.schema.providerType)
        assertEquals(activeKeyId, regResult.schema.activeKey.keyId)
        assertEquals(ProviderKeyRotationState.ACTIVE, regResult.schema.activeKey.rotationState)
        assertNull(regResult.schema.nextKey)
        assertEquals(ProviderHealthState.HEALTHY, regResult.schema.healthState)

        // Idempotent replay of registration returns identical authoritative result
        val regReplay = service.registerSchema(regCmd)
        assertEquals(regResult.resultId, regReplay.resultId)
        assertEquals(regResult.evidenceReference, regReplay.evidenceReference)
        assertEquals(1, store.auditLogs.count { it.type == "CASINO_PROVIDER_SCHEMA_REGISTERED" })
        assertEquals(1, store.outboxLogs.count { it.type == "CASINO_PROVIDER_SCHEMA_REGISTERED" })

        // 3. Rotate provider key: updates schema and emits rotation observable event
        val rotateCmd = RotateCasinoProviderKeyCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            nextKeyId = nextKeyId,
            nextKeySecret = nextKeySecret,
            idempotencyKey = "idemp-rotate-001",
            correlationId = "corr-rotate-1",
            causationId = "cause-rotate-1",
            expectedVersion = 2L,
        )
        val rotateResult = service.rotateKey(rotateCmd)
        assertEquals(2L, rotateResult.schema.version)
        assertNotNull(rotateResult.schema.nextKey)
        assertEquals(nextKeyId, rotateResult.schema.nextKey?.keyId)
        assertEquals(ProviderKeyRotationState.ROTATING, rotateResult.schema.nextKey?.rotationState)
        assertTrue(rotateResult.rotationObservable)

        // Idempotent replay of rotation
        val rotateReplay = service.rotateKey(rotateCmd)
        assertEquals(rotateResult.resultId, rotateReplay.resultId)
        assertEquals(1, store.auditLogs.count { it.type == "CASINO_PROVIDER_KEY_ROTATED" })

        // 4. Record outage / health state: emits outage observable event
        val outageCmd = RecordProviderHealthCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            healthState = ProviderHealthState.OUTAGE_TRIPPED,
            consecutiveFailures = 5,
            outageReason = "Upstream provider gateway 503 circuit broken",
            idempotencyKey = "idemp-health-001",
            correlationId = "corr-health-1",
            causationId = "cause-health-1",
            expectedVersion = 3L,
        )
        val outageResult = service.recordHealth(outageCmd)
        assertEquals(3L, outageResult.schema.version)
        assertEquals(ProviderHealthState.OUTAGE_TRIPPED, outageResult.schema.healthState)
        assertEquals(5, outageResult.schema.consecutiveFailures)
        assertTrue(outageResult.outageObservable)
        assertEquals(1, store.auditLogs.count { it.type == "CASINO_PROVIDER_OUTAGE_OBSERVED_OUTAGE_TRIPPED" })

        // 5. Verify valid signed callback
        val rawPayload = "{\"roundId\":\"round-slots-999\",\"debit\":1000,\"credit\":2500,\"currency\":\"USD\"}"
        val timestamp = now.epochSecond
        val signature = computeHmac(activeKeySecret, "$timestamp.$rawPayload")

        val callbackCmd = VerifyCasinoCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            keyId = activeKeyId,
            signature = signature,
            timestamp = timestamp,
            roundReference = "round-slots-999",
            rawPayload = rawPayload,
            debitMinorUnits = 1000L,
            creditMinorUnits = 2500L,
            currencyCode = "USD",
            idempotencyKey = "idemp-callback-001",
            correlationId = "corr-cb-1",
            causationId = "cause-cb-1",
            expectedVersion = 1L,
        )

        val verifyResult = service.verifyCallback(callbackCmd)
        assertTrue(verifyResult.verified)
        assertTrue(verifyResult.signatureValid)
        assertTrue(verifyResult.credentialValid)
        assertFalse(verifyResult.replayDetected)
        assertTrue(verifyResult.conservationVerified)
        assertTrue(verifyResult.rotationObservable)
        assertTrue(verifyResult.outageObservable)

        // Idempotent callback replay
        val verifyReplay = service.verifyCallback(callbackCmd)
        assertEquals(verifyResult.resultId, verifyReplay.resultId)
        assertEquals(1, store.auditLogs.count { it.type == "CASINO_CALLBACK_VERIFIED" })
    }

    @Test
    fun `GAME-001-01-T002 Define canonical casino provider contract rejects invalid, boundary, unauthorized, and stale input`() {
        val store = InMemoryCasinoProviderContractStore()
        val resolver = MapProviderSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
            "$tenantId:$providerId:$nextKeyId" to nextKeySecret,
        ))
        val sessions = TestCasinoActiveSessionDirectory()
        val service = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, store, clock)

        // Register schema first
        service.registerSchema(createRegisterCommand())

        val rawPayload = "{\"roundId\":\"round-test-101\",\"debit\":500,\"credit\":1200}"
        val timestamp = now.epochSecond
        val validSig = computeHmac(activeKeySecret, "$timestamp.$rawPayload")

        // 1. Rejects bad credentials: keyId unknown/invalid -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = "key-unknown-foreign",
                    signature = validSig,
                    timestamp = timestamp,
                    rawPayload = rawPayload,
                    idempotencyKey = "idemp-bad-cred",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Rejects bad / forged signature -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = "bad-forged-signature-hex-12345678",
                    timestamp = timestamp,
                    rawPayload = rawPayload,
                    idempotencyKey = "idemp-bad-sig",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Rejects replayed signature across separate attempts -> FORBIDDEN
        service.verifyCallback(
            callbackCommand(
                keyId = activeKeyId,
                signature = validSig,
                timestamp = timestamp,
                rawPayload = rawPayload,
                idempotencyKey = "idemp-first-valid",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = validSig, // Replaying the exact same signature
                    timestamp = timestamp,
                    rawPayload = rawPayload,
                    idempotencyKey = "idemp-replay-attempt",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Rejects timestamp skew: expired / future timestamp -> INVALID
        val oldTimestamp = timestamp - 301L
        val oldSig = computeHmac(activeKeySecret, "$oldTimestamp.$rawPayload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = oldSig,
                    timestamp = oldTimestamp,
                    rawPayload = rawPayload,
                    idempotencyKey = "idemp-old-timestamp",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val futureTimestamp = timestamp + 301L
        val futureSig = computeHmac(activeKeySecret, "$futureTimestamp.$rawPayload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = futureSig,
                    timestamp = futureTimestamp,
                    rawPayload = rawPayload,
                    idempotencyKey = "idemp-future-timestamp",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Financial sanity: rejects negative minor units -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = validSig,
                    timestamp = timestamp,
                    rawPayload = rawPayload,
                    debitMinorUnits = -100L,
                    idempotencyKey = "idemp-neg-debit",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = validSig,
                    timestamp = timestamp,
                    rawPayload = rawPayload,
                    creditMinorUnits = -50L,
                    idempotencyKey = "idemp-neg-credit",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Currency code validation: rejects invalid format -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = validSig,
                    timestamp = timestamp,
                    rawPayload = rawPayload,
                    currencyCode = "US",
                    idempotencyKey = "idemp-bad-curr",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Rejects unauthenticated principal -> UNAUTHENTICATED
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerSchema(createRegisterCommand().copy(principal = null, idempotencyKey = "idemp-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 8. Rejects non-admin player kind -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerSchema(createRegisterCommand().copy(principal = playerPrincipal, idempotencyKey = "idemp-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 9. Rejects cross-tenant principal -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerSchema(createRegisterCommand().copy(principal = crossTenantPrincipal, idempotencyKey = "idemp-cross"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 10. Rejects expired session -> FORBIDDEN
        val expiredSessions = TestCasinoExpiredSessionDirectory()
        val expiredService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), expiredSessions, resolver, store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredService.registerSchema(createRegisterCommand().copy(idempotencyKey = "idemp-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 11. Rejects unauthorized permissions -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerSchema(createRegisterCommand().copy(principal = unauthorizedPrincipal, idempotencyKey = "idemp-noperm"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 12. Rejects stale expected version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerSchema(createRegisterCommand().copy(expectedVersion = 99L, idempotencyKey = "idemp-stale-reg"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.rotateKey(
                RotateCasinoProviderKeyCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    nextKeyId = nextKeyId,
                    nextKeySecret = nextKeySecret,
                    idempotencyKey = "idemp-stale-rotate",
                    correlationId = "corr-stale-1",
                    causationId = "cause-stale-1",
                    expectedVersion = 99L, // Current version is 1, expected must be 2
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 13. Rejects idempotency conflict -> CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerSchema(
                createRegisterCommand().copy(
                    idempotencyKey = "idemp-reg-001", // Reused with different endpoint
                    callbackEndpoint = "https://different-endpoint.com/callback",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `GAME-001-01-T003 Define canonical casino provider contract survives concurrency, duplicate delivery, and dependency failure`() {
        val store = InMemoryCasinoProviderContractStore()
        val resolver = MapProviderSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
        ))
        val sessions = TestCasinoActiveSessionDirectory()
        val service = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, store, clock)

        // 1. Race 8 threads concurrently executing registerSchema with identical idempotency key
        val threadCount = 8
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threadCount)
        val regCmd = createRegisterCommand().copy(idempotencyKey = "idemp-concurrent-reg")

        val regFutures = (1..threadCount).map {
            pool.submit<ProviderSchemaResult> {
                gate.await()
                service.registerSchema(regCmd)
            }
        }
        gate.countDown()
        val regResults = regFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, regResults.count { it.isSuccess })
        val distinctResultIds = regResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)
        assertEquals(1, store.auditLogs.count { it.type == "CASINO_PROVIDER_SCHEMA_REGISTERED" })
        assertEquals(1, store.outboxLogs.count { it.type == "CASINO_PROVIDER_SCHEMA_REGISTERED" })

        // 2. Race 8 threads concurrently executing callback verification with identical idempotency key
        val rawPayload = "{\"roundId\":\"round-conc-1\",\"debit\":100,\"credit\":200}"
        val timestamp = now.epochSecond
        val signature = computeHmac(activeKeySecret, "$timestamp.$rawPayload")

        val callbackGate = CountDownLatch(1)
        val cbCmd = callbackCommand(
            keyId = activeKeyId,
            signature = signature,
            timestamp = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "idemp-concurrent-cb",
        )

        val cbFutures = (1..threadCount).map {
            pool.submit<ProviderCallbackVerificationResult> {
                callbackGate.await()
                service.verifyCallback(cbCmd)
            }
        }
        callbackGate.countDown()
        val cbResults = cbFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, cbResults.count { it.isSuccess })
        val distinctCbResultIds = cbResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctCbResultIds.size)
        assertEquals(1, store.auditLogs.count { it.type == "CASINO_CALLBACK_VERIFIED" })
        assertEquals(1, store.outboxLogs.count { it.type == "CASINO_CALLBACK_VERIFIED" })

        pool.shutdown()

        // 3. Dependency failure on session directory -> DEPENDENCY_UNAVAILABLE
        val failingSessions = TestCasinoFailingSessionDirectory()
        val failingSessionService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), failingSessions, resolver, store, clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.registerSchema(createRegisterCommand().copy(idempotencyKey = "idemp-dep-fail-sess"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 4. Dependency failure on secret resolver -> DEPENDENCY_UNAVAILABLE
        val failingResolver = FailingProviderSecretResolver()
        val failingResolverService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, failingResolver, store, clock)
        val payloadForResolverFail = "{\"roundId\":\"round-fail\",\"debit\":100,\"credit\":200}"
        val sigForResolverFail = computeHmac(activeKeySecret, "$timestamp.$payloadForResolverFail")
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingResolverService.verifyCallback(
                callbackCommand(
                    keyId = activeKeyId,
                    signature = sigForResolverFail,
                    timestamp = timestamp,
                    rawPayload = payloadForResolverFail,
                    idempotencyKey = "idemp-dep-fail-resolver",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `GAME-001-01-T004 Define canonical casino provider contract remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Flyway migration guardrail: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertFalse(migrationVersions.contains("V17"))

        // 2. Recovery across reboot / recreation
        val store = InMemoryCasinoProviderContractStore()
        val resolver = MapProviderSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
        ))
        val sessions = TestCasinoActiveSessionDirectory()
        val initialService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, store, clock)

        val regCmd = createRegisterCommand().copy(idempotencyKey = "idemp-reboot-reg")
        val initialReg = initialService.registerSchema(regCmd)

        // Instantiate restarted service with same durable store
        val restartedService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, store, clock)
        val replayedReg = restartedService.registerSchema(regCmd)
        assertEquals(initialReg.resultId, replayedReg.resultId)
        assertEquals(initialReg.evidenceReference, replayedReg.evidenceReference)

        // Callback verification across reboot
        val rawPayload = "{\"roundId\":\"round-reboot-1\",\"debit\":300,\"credit\":450}"
        val timestamp = now.epochSecond
        val signature = computeHmac(activeKeySecret, "$timestamp.$rawPayload")
        val cbCmd = callbackCommand(
            keyId = activeKeyId,
            signature = signature,
            timestamp = timestamp,
            rawPayload = rawPayload,
            idempotencyKey = "idemp-reboot-cb",
        )

        val initialCb = initialService.verifyCallback(cbCmd)
        val replayedCb = restartedService.verifyCallback(cbCmd)
        assertEquals(initialCb.resultId, replayedCb.resultId)
        assertEquals(initialCb.evidenceReference, replayedCb.evidenceReference)

        // 3. Observability & Zero Secret Exposure
        assertTrue(store.auditLogs.isNotEmpty())
        for (audit in store.auditLogs) {
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertNotNull(audit.occurredAt)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("keySecret", ignoreCase = true))
        }
    }

    private fun createRegisterCommand() = RegisterCasinoProviderSchemaCommand(
        principal = adminPrincipal,
        sessionId = "session-1",
        tenantId = tenantId,
        providerId = providerId,
        providerName = "Evolution Slots Provider",
        providerType = CasinoProviderType.SLOTS,
        schemaVersion = "1.0.0",
        supportedCurrencies = setOf("USD", "EUR", "GBP"),
        signatureAlgorithm = ProviderSignatureAlgorithm.HMAC_SHA256,
        callbackEndpoint = "https://api.evolution.com/callback",
        maxRoundDurationSeconds = 120L,
        activeKeyId = activeKeyId,
        activeKeySecret = activeKeySecret,
        idempotencyKey = "idemp-reg-001",
        correlationId = "corr-reg-1",
        causationId = "cause-reg-1",
        expectedVersion = 1L,
    )

    private fun callbackCommand(
        keyId: String,
        signature: String,
        timestamp: Long,
        rawPayload: String,
        idempotencyKey: String,
        debitMinorUnits: Long = 1000L,
        creditMinorUnits: Long = 2000L,
        currencyCode: String = "USD",
        correlationId: String = "corr-cb-default",
        causationId: String = "cause-cb-default",
    ) = VerifyCasinoCallbackCommand(
        tenantId = tenantId,
        providerId = providerId,
        keyId = keyId,
        signature = signature,
        timestamp = timestamp,
        roundReference = "round-ref-100",
        rawPayload = rawPayload,
        debitMinorUnits = debitMinorUnits,
        creditMinorUnits = creditMinorUnits,
        currencyCode = currencyCode,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = 1L,
    )

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

private class MapProviderSecretResolver(private val secrets: Map<String, String>) : ProviderSecretResolver {
    override fun resolveRawSecret(tenantId: String, providerId: String, keyId: String): String? =
        secrets["$tenantId:$providerId:$keyId"]
}

private class FailingProviderSecretResolver : ProviderSecretResolver {
    override fun resolveRawSecret(tenantId: String, providerId: String, keyId: String): String =
        error("secret vault unavailable")
}

private class TestCasinoActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T12:00:00Z"),
        )
}

private class TestCasinoExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-18T02:00:00Z"), // Expired
        )
}

private class TestCasinoFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        error("database connection pool exhausted")
}

private class InMemoryCasinoProviderContractStore : CanonicalCasinoProviderContractStore {
    private val schemas = mutableMapOf<String, CanonicalCasinoProviderSchema>()
    private val idempotencyMap = mutableMapOf<String, Pair<String, Any>>()
    private val seenSignatures = mutableSetOf<String>()
    val auditLogs = mutableListOf<AuditEvent>()
    val outboxLogs = mutableListOf<OutboxEvent>()

    override fun findSchema(tenantId: String, providerId: String): CanonicalCasinoProviderSchema? =
        synchronized(this) { schemas["$tenantId:$providerId"] }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, Any>? =
        synchronized(this) { idempotencyMap["$tenantId:$idempotencyKey"] }

    override fun isSignatureSeen(tenantId: String, signature: String): Boolean =
        synchronized(this) { seenSignatures.contains("$tenantId:$signature") }

    override fun saveSchema(
        schema: CanonicalCasinoProviderSchema,
        result: ProviderSchemaResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        schemas["$tenantId:${schema.providerId}"] = schema
        idempotencyMap["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }

    override fun recordVerification(
        result: ProviderCallbackVerificationResult,
        tenantId: String,
        signature: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        seenSignatures.add("$tenantId:$signature")
        idempotencyMap["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }
}
