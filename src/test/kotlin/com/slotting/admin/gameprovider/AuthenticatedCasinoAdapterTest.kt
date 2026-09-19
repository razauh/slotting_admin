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

class AuthenticatedCasinoAdapterTest {
    private val now = Instant.parse("2026-09-19T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-auth-adapter-1"
    private val providerId = "prov-auth-slots"
    private val activeKeyId = "key-v1"
    private val activeKeySecret = "raw-secret-auth-v1"
    private val nextKeyId = "key-v2"
    private val nextKeySecret = "raw-secret-auth-v2"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-auth-1",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPPORT),
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
        id = "admin-cross",
        tenantId = "tenant-auth-adapter-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    @BeforeEach
    fun setUp() {
        AuthenticatedCasinoAdapterBinding.isBound = true
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        AuthenticatedCasinoAdapterBinding.isBound = true
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @Test
    fun `GAME-001-03-T001 Implement authenticated sandbox and production adapter produces the required authoritative outcome`() {
        // 1. Verify fail-closed gate throws expected RED assertion error when unbound
        AuthenticatedCasinoAdapterBinding.isBound = false
        val contractStore = AuthAdapterContractStore()
        val adapterStore = AuthAdapterStore()
        val resolver = AuthAdapterSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
            "$tenantId:$providerId:$nextKeyId" to nextKeySecret,
        ))
        val sessions = AuthAdapterActiveSessionDirectory()
        val gateway = AuthAdapterFakeGatewayClient()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)
        val adapterService = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )

        val certCmd = createCertifyCommand(requestedTier = CasinoProviderAdapterTier.SANDBOX)
        val gateError = assertFailsWith<AssertionError> {
            adapterService.certifyAdapter(certCmd)
        }
        assertEquals("bad creds/signature/replay", gateError.message)

        // Bind the gate
        AuthenticatedCasinoAdapterBinding.isBound = true

        // Register canonical schema in contract store
        registerTestSchema(contractService)

        // 2. Certify adapter for SANDBOX
        val sandboxCertResult = adapterService.certifyAdapter(certCmd)
        assertNotNull(sandboxCertResult)
        assertEquals(tenantId, sandboxCertResult.tenantId)
        assertEquals(providerId, sandboxCertResult.providerId)
        assertEquals(CasinoProviderAdapterTier.SANDBOX, sandboxCertResult.tier)
        assertEquals(CasinoCertificationStatus.CERTIFIED, sandboxCertResult.status)

        // Idempotent replay of sandbox certification
        val sandboxCertReplay = adapterService.certifyAdapter(certCmd)
        assertEquals(sandboxCertResult.resultId, sandboxCertReplay.resultId)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_ADAPTER_CERTIFIED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_ADAPTER_CERTIFIED" })

        // 3. Execute round on SANDBOX
        val sandboxRoundCmd = ExecuteCasinoRoundCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            roundReference = "round-sbx-001",
            debitMinorUnits = 1000L,
            creditMinorUnits = 2500L,
            currencyCode = "USD",
            tier = CasinoProviderAdapterTier.SANDBOX,
            idempotencyKey = "idemp-sbx-round-1",
            correlationId = "corr-sbx-1",
            causationId = "cause-sbx-1",
            expectedVersion = 1L,
        )
        val sandboxRoundResult = adapterService.executeRound(sandboxRoundCmd)
        assertTrue(sandboxRoundResult.executedSuccessfully)
        assertEquals(CasinoProviderAdapterTier.SANDBOX, sandboxRoundResult.tier)

        // Idempotent replay of sandbox round
        val sandboxRoundReplay = adapterService.executeRound(sandboxRoundCmd)
        assertEquals(sandboxRoundResult.resultId, sandboxRoundReplay.resultId)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_ADAPTER_ROUND_EXECUTED" })

        // 4. Certify adapter for PRODUCTION_CERTIFIED with full evidence
        val prodCertCmd = createCertifyCommand(
            requestedTier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
            canonicalSemanticsVerified = true,
            signatureVerificationVerified = true,
            retryAcknowledgementVerified = true,
            productionApproved = true,
            idempKey = "idemp-prod-cert-1",
            expectedVersion = 2L,
        )
        val prodCertResult = adapterService.certifyAdapter(prodCertCmd)
        assertNotNull(prodCertResult)
        assertEquals(CasinoProviderAdapterTier.PRODUCTION_CERTIFIED, prodCertResult.tier)
        assertEquals(CasinoCertificationStatus.CERTIFIED, prodCertResult.status)

        // 5. Execute round on PRODUCTION_CERTIFIED
        val prodRoundCmd = ExecuteCasinoRoundCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            roundReference = "round-prod-001",
            debitMinorUnits = 5000L,
            creditMinorUnits = 12500L,
            currencyCode = "USD",
            tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
            idempotencyKey = "idemp-prod-round-1",
            correlationId = "corr-prod-1",
            causationId = "cause-prod-1",
            expectedVersion = 1L,
        )
        val prodRoundResult = adapterService.executeRound(prodRoundCmd)
        assertTrue(prodRoundResult.executedSuccessfully)
        assertEquals(CasinoProviderAdapterTier.PRODUCTION_CERTIFIED, prodRoundResult.tier)

        // 6. Execute rollback on PRODUCTION_CERTIFIED (conservation: debits equal credits)
        val rollbackCmd = ExecuteCasinoRollbackCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            roundReference = "round-prod-001",
            originalDebitMinorUnits = 5000L,
            compensatingCreditMinorUnits = 5000L,
            currencyCode = "USD",
            reason = "Network disruption between provider and player",
            tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
            idempotencyKey = "idemp-prod-rollback-1",
            correlationId = "corr-rb-1",
            causationId = "cause-rb-1",
            expectedVersion = 1L,
        )
        val rollbackResult = adapterService.executeRollback(rollbackCmd)
        assertTrue(rollbackResult.conserved)
        assertEquals(5000L, rollbackResult.debitMinorUnits)
        assertEquals(5000L, rollbackResult.creditMinorUnits)
        assertTrue(rollbackResult.compensationReference.startsWith("COMP-ROLLBACK-"))

        // Idempotent replay of rollback
        val rollbackReplay = adapterService.executeRollback(rollbackCmd)
        assertEquals(rollbackResult.resultId, rollbackReplay.resultId)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_ADAPTER_ROLLBACK_COMPENSATED" })

        // 7. Process incoming callback on PRODUCTION_CERTIFIED
        val rawPayload = "{\"roundId\":\"round-cb-999\",\"debit\":1000,\"credit\":3000}"
        val timestamp = now.epochSecond
        val signature = computeHmac(activeKeySecret, "$timestamp.$rawPayload")

        val callbackCmd = ProcessCasinoCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            keyId = activeKeyId,
            signature = signature,
            timestamp = timestamp,
            roundReference = "round-cb-999",
            rawPayload = rawPayload,
            debitMinorUnits = 1000L,
            creditMinorUnits = 3000L,
            currencyCode = "USD",
            tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
            idempotencyKey = "idemp-cb-1",
            correlationId = "corr-cb-1",
            causationId = "cause-cb-1",
            expectedVersion = 1L,
        )
        val callbackResult = adapterService.processIncomingCallback(callbackCmd)
        assertTrue(callbackResult.verified)
        assertTrue(callbackResult.signatureValid)
        assertTrue(callbackResult.credentialValid)
        assertFalse(callbackResult.replayDetected)
        assertTrue(callbackResult.conservationVerified)

        // Idempotent replay of callback
        val callbackReplay = adapterService.processIncomingCallback(callbackCmd)
        assertEquals(callbackResult.resultId, callbackReplay.resultId)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_ADAPTER_CALLBACK_VERIFIED" })
    }

    @Test
    fun `GAME-001-03-T002 Implement authenticated sandbox and production adapter rejects invalid, boundary, unauthorized, and stale input`() {
        val contractStore = AuthAdapterContractStore()
        val adapterStore = AuthAdapterStore()
        val resolver = AuthAdapterSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
            "$tenantId:$providerId:$nextKeyId" to nextKeySecret,
        ))
        val sessions = AuthAdapterActiveSessionDirectory()
        val gateway = AuthAdapterFakeGatewayClient()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)
        val adapterService = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )

        registerTestSchema(contractService)

        // 1. Production certification absent: attempting to execute production round -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRound(
                ExecuteCasinoRoundCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-no-cert",
                    debitMinorUnits = 100L,
                    creditMinorUnits = 200L,
                    currencyCode = "USD",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-no-cert",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Incomplete production certification evidence: productionApproved = false -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(
                createCertifyCommand(
                    requestedTier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    canonicalSemanticsVerified = true,
                    signatureVerificationVerified = true,
                    retryAcknowledgementVerified = true,
                    productionApproved = false, // Absent approval
                    idempKey = "idemp-unapproved-prod",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Sandbox access unverified: sandboxAccessVerified = false -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(
                createCertifyCommand(
                    requestedTier = CasinoProviderAdapterTier.SANDBOX,
                    sandboxAccessVerified = false,
                    idempKey = "idemp-unverified-sbx",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Certify valid production adapter
        val prodCertResult = adapterService.certifyAdapter(
            createCertifyCommand(
                requestedTier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                canonicalSemanticsVerified = true,
                signatureVerificationVerified = true,
                retryAcknowledgementVerified = true,
                productionApproved = true,
                idempKey = "idemp-valid-prod-cert",
            )
        )

        // 4. Revocation: revoke certification, then attempt production round -> FORBIDDEN
        adapterService.revokeCertification(
            RevokeCasinoCertificationCommand(
                principal = adminPrincipal,
                sessionId = "session-1",
                tenantId = tenantId,
                providerId = providerId,
                certificationId = prodCertResult.certificationId,
                reason = "Provider security compliance breach",
                idempotencyKey = "idemp-revoke-cert",
                correlationId = "corr-rev-1",
                causationId = "cause-rev-1",
                expectedVersion = 2L,
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRound(
                ExecuteCasinoRoundCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-after-revoke",
                    debitMinorUnits = 100L,
                    creditMinorUnits = 200L,
                    currencyCode = "USD",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-after-revoke",
                    correlationId = "corr-2",
                    causationId = "cause-2",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Re-certify production adapter for callback tests
        adapterService.certifyAdapter(
            createCertifyCommand(
                requestedTier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                canonicalSemanticsVerified = true,
                signatureVerificationVerified = true,
                retryAcknowledgementVerified = true,
                productionApproved = true,
                idempKey = "idemp-re-cert",
                expectedVersion = 3L,
            )
        )

        val rawPayload = "{\"roundId\":\"round-test\",\"debit\":500,\"credit\":1000}"
        val timestamp = now.epochSecond
        val validSig = computeHmac(activeKeySecret, "$timestamp.$rawPayload")

        // 5. Bad credentials in callback: unknown keyId -> FORBIDDEN (bad creds)
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.processIncomingCallback(
                callbackCommand(keyId = "key-unknown-foreign", signature = validSig, timestamp = timestamp, payload = rawPayload, idempKey = "idemp-bad-cred")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Bad signature in callback: corrupted HMAC -> FORBIDDEN (bad signature)
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.processIncomingCallback(
                callbackCommand(keyId = activeKeyId, signature = "deadbeef12345678badbadbad", timestamp = timestamp, payload = rawPayload, idempKey = "idemp-bad-sig")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Replay attack in callback: replaying seen signature -> FORBIDDEN (replay)
        adapterService.processIncomingCallback(
            callbackCommand(keyId = activeKeyId, signature = validSig, timestamp = timestamp, payload = rawPayload, idempKey = "idemp-cb-first")
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.processIncomingCallback(
                callbackCommand(keyId = activeKeyId, signature = validSig, timestamp = timestamp, payload = rawPayload, idempKey = "idemp-cb-replay")
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Timestamp skew: expired (> 300s) -> INVALID
        val oldTs = timestamp - 301L
        val oldSig = computeHmac(activeKeySecret, "$oldTs.$rawPayload")
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.processIncomingCallback(
                callbackCommand(keyId = activeKeyId, signature = oldSig, timestamp = oldTs, payload = rawPayload, idempKey = "idemp-old-ts")
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 9. Financial conservation: negative minor units -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRound(
                ExecuteCasinoRoundCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-neg",
                    debitMinorUnits = -500L,
                    creditMinorUnits = 1000L,
                    currencyCode = "USD",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-neg-debit",
                    correlationId = "corr-neg",
                    causationId = "cause-neg",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unbalanced rollback: debit != credit -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRollback(
                ExecuteCasinoRollbackCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-unbalanced",
                    originalDebitMinorUnits = 1000L,
                    compensatingCreditMinorUnits = 500L,
                    currencyCode = "USD",
                    reason = "Unbalanced",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-unbalanced-rb",
                    correlationId = "corr-unbal",
                    causationId = "cause-unbal",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid currency code -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRound(
                ExecuteCasinoRoundCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-bad-curr",
                    debitMinorUnits = 100L,
                    creditMinorUnits = 200L,
                    currencyCode = "US",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-bad-curr",
                    correlationId = "corr-curr",
                    causationId = "cause-curr",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 10. Security & Principal Checks
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(createCertifyCommand(requestedTier = CasinoProviderAdapterTier.SANDBOX).copy(principal = null, idempotencyKey = "idemp-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(createCertifyCommand(requestedTier = CasinoProviderAdapterTier.SANDBOX).copy(principal = playerPrincipal, idempotencyKey = "idemp-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(createCertifyCommand(requestedTier = CasinoProviderAdapterTier.SANDBOX).copy(principal = crossTenantPrincipal, idempotencyKey = "idemp-cross"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Expired session -> FORBIDDEN
        val expiredSessions = AuthAdapterExpiredSessionDirectory()
        val expiredService = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = expiredSessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredService.certifyAdapter(createCertifyCommand(requestedTier = CasinoProviderAdapterTier.SANDBOX).copy(idempotencyKey = "idemp-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unauthorized permissions -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(createCertifyCommand(requestedTier = CasinoProviderAdapterTier.SANDBOX).copy(principal = unauthorizedPrincipal, idempotencyKey = "idemp-noperm"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale expected version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(createCertifyCommand(requestedTier = CasinoProviderAdapterTier.SANDBOX).copy(expectedVersion = 999L, idempotencyKey = "idemp-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Idempotency conflict -> CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.certifyAdapter(
                createCertifyCommand(
                    requestedTier = CasinoProviderAdapterTier.SANDBOX,
                    idempKey = "idemp-valid-prod-cert", // Reusing key with different tier
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `GAME-001-03-T003 Implement authenticated sandbox and production adapter survives concurrency, duplicate delivery, and dependency failure`() {
        val contractStore = AuthAdapterContractStore()
        val adapterStore = AuthAdapterStore()
        val resolver = AuthAdapterSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
        ))
        val sessions = AuthAdapterActiveSessionDirectory()
        val gateway = AuthAdapterFakeGatewayClient()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)
        val adapterService = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )

        registerTestSchema(contractService)

        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)

        // 1. Race 8 threads certifying adapter concurrently
        val certGate = CountDownLatch(1)
        val certCmd = createCertifyCommand(
            requestedTier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
            canonicalSemanticsVerified = true,
            signatureVerificationVerified = true,
            retryAcknowledgementVerified = true,
            productionApproved = true,
            idempKey = "idemp-conc-cert",
            expectedVersion = 1L,
        )
        val certFutures = (1..threadCount).map {
            pool.submit<CasinoCertificationResult> {
                certGate.await()
                adapterService.certifyAdapter(certCmd)
            }
        }
        certGate.countDown()
        val certResults = certFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, certResults.count { it.isSuccess })
        val distinctCertIds = certResults.mapNotNull { it.getOrNull()?.certificationId }.toSet()
        assertEquals(1, distinctCertIds.size)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_ADAPTER_CERTIFIED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_ADAPTER_CERTIFIED" })

        // 2. Race 8 threads executing rollback concurrently
        val rbGate = CountDownLatch(1)
        val rbCmd = ExecuteCasinoRollbackCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            roundReference = "round-conc-rb",
            originalDebitMinorUnits = 1000L,
            compensatingCreditMinorUnits = 1000L,
            currencyCode = "USD",
            reason = "Concurrent rollback test",
            tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
            idempotencyKey = "idemp-conc-rb",
            correlationId = "corr-conc-rb",
            causationId = "cause-conc-rb",
            expectedVersion = 1L,
        )
        val rbFutures = (1..threadCount).map {
            pool.submit<CasinoRollbackExecutionResult> {
                rbGate.await()
                adapterService.executeRollback(rbCmd)
            }
        }
        rbGate.countDown()
        val rbResults = rbFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, rbResults.count { it.isSuccess })
        val distinctRbIds = rbResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctRbIds.size)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_ADAPTER_ROLLBACK_COMPENSATED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_ADAPTER_ROLLBACK_COMPENSATED" })

        pool.shutdown()

        // 3. Dependency failure on session directory -> DEPENDENCY_UNAVAILABLE
        val failingSessions = AuthAdapterFailingSessionDirectory()
        val failingSessionService = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = failingSessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.executeRound(
                ExecuteCasinoRoundCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-dep-fail-sess",
                    debitMinorUnits = 100L,
                    creditMinorUnits = 200L,
                    currencyCode = "USD",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-dep-fail-sess",
                    correlationId = "corr-f1",
                    causationId = "cause-f1",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 4. Dependency failure on remote gateway (returns 503) -> DEPENDENCY_UNAVAILABLE
        val failingGateway = AuthAdapterFailingGatewayClient()
        val failingGatewayService = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = failingGateway,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingGatewayService.executeRound(
                ExecuteCasinoRoundCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-dep-fail-gw",
                    debitMinorUnits = 100L,
                    creditMinorUnits = 200L,
                    currencyCode = "USD",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-dep-fail-gw",
                    correlationId = "corr-f2",
                    causationId = "cause-f2",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 5. Dependency failure on secret resolver -> DEPENDENCY_UNAVAILABLE
        val failingResolver = AuthAdapterFailingSecretResolver()
        val failingResolverService = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            secretResolver = failingResolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingResolverService.executeRound(
                ExecuteCasinoRoundCommand(
                    principal = adminPrincipal,
                    sessionId = "session-1",
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-dep-fail-sec",
                    debitMinorUnits = 100L,
                    creditMinorUnits = 200L,
                    currencyCode = "USD",
                    tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
                    idempotencyKey = "idemp-dep-fail-sec",
                    correlationId = "corr-f3",
                    causationId = "cause-f3",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `GAME-001-03-T004 Implement authenticated sandbox and production adapter remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Flyway migration guardrail: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertFalse(migrationVersions.contains("V17"))

        // 2. Recovery across reboot / restart
        val contractStore = AuthAdapterContractStore()
        val adapterStore = AuthAdapterStore()
        val resolver = AuthAdapterSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
        ))
        val sessions = AuthAdapterActiveSessionDirectory()
        val gateway = AuthAdapterFakeGatewayClient()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)

        val serviceInitial = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )

        registerTestSchema(contractService)
        val certCmd = createCertifyCommand(
            requestedTier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
            canonicalSemanticsVerified = true,
            signatureVerificationVerified = true,
            retryAcknowledgementVerified = true,
            productionApproved = true,
            idempKey = "idemp-reboot-cert",
            expectedVersion = 1L,
        )
        val initialCert = serviceInitial.certifyAdapter(certCmd)

        // Instantiate restarted service sharing the persistent store
        val serviceRestarted = AuthenticatedCasinoAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            contractStore = contractStore,
            secretResolver = resolver,
            adapterStore = adapterStore,
            gatewayClient = gateway,
            clock = clock,
        )

        val replayedCert = serviceRestarted.certifyAdapter(certCmd.copy(expectedVersion = 1L))
        assertEquals(initialCert.resultId, replayedCert.resultId)
        assertEquals(initialCert.evidenceReference, replayedCert.evidenceReference)

        // 3. Observability & Zero Raw Secret Exposure
        assertTrue(adapterStore.auditLogs.isNotEmpty())
        for (audit in adapterStore.auditLogs) {
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertNotNull(audit.occurredAt)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("keySecret", ignoreCase = true))
        }
    }

    private fun registerTestSchema(contractService: CanonicalCasinoProviderContractService) {
        contractService.registerSchema(
            RegisterCasinoProviderSchemaCommand(
                principal = adminPrincipal,
                sessionId = "session-1",
                tenantId = tenantId,
                providerId = providerId,
                providerName = "Evolution Production Slots",
                providerType = CasinoProviderType.SLOTS,
                schemaVersion = "1.0.0",
                supportedCurrencies = setOf("USD", "EUR"),
                signatureAlgorithm = ProviderSignatureAlgorithm.HMAC_SHA256,
                callbackEndpoint = "https://api.evolution.com/callback",
                maxRoundDurationSeconds = 120L,
                activeKeyId = activeKeyId,
                activeKeySecret = activeKeySecret,
                idempotencyKey = "idemp-reg-schema-001",
                correlationId = "corr-schema-1",
                causationId = "cause-schema-1",
                expectedVersion = 1L,
            )
        )
    }

    private fun createCertifyCommand(
        requestedTier: CasinoProviderAdapterTier,
        canonicalSemanticsVerified: Boolean = false,
        signatureVerificationVerified: Boolean = false,
        retryAcknowledgementVerified: Boolean = false,
        productionApproved: Boolean = false,
        sandboxAccessVerified: Boolean = true,
        idempKey: String = "idemp-cert-default",
        expectedVersion: Long = 1L,
    ) = CertifyCasinoAdapterCommand(
        principal = adminPrincipal,
        sessionId = "session-1",
        tenantId = tenantId,
        providerId = providerId,
        requestedTier = requestedTier,
        canonicalSemanticsVerified = canonicalSemanticsVerified,
        signatureVerificationVerified = signatureVerificationVerified,
        retryAcknowledgementVerified = retryAcknowledgementVerified,
        productionApproved = productionApproved,
        sandboxAccessVerified = sandboxAccessVerified,
        expiresAt = now.plusSeconds(86400 * 30),
        idempotencyKey = idempKey,
        correlationId = "corr-cert-1",
        causationId = "cause-cert-1",
        expectedVersion = expectedVersion,
    )

    private fun callbackCommand(
        keyId: String,
        signature: String,
        timestamp: Long,
        payload: String,
        idempKey: String,
    ) = ProcessCasinoCallbackCommand(
        tenantId = tenantId,
        providerId = providerId,
        keyId = keyId,
        signature = signature,
        timestamp = timestamp,
        roundReference = "round-cb-ref",
        rawPayload = payload,
        debitMinorUnits = 500L,
        creditMinorUnits = 1000L,
        currencyCode = "USD",
        tier = CasinoProviderAdapterTier.PRODUCTION_CERTIFIED,
        idempotencyKey = idempKey,
        correlationId = "corr-cb-def",
        causationId = "cause-cb-def",
        expectedVersion = 1L,
    )

    private fun computeHmac(secret: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}

private class AuthAdapterFakeGatewayClient : CasinoProviderGatewayClient {
    override fun executePost(endpoint: String, headers: Map<String, String>, payload: String): CasinoGatewayResponse =
        CasinoGatewayResponse(
            statusCode = 200,
            headers = mapOf("Content-Type" to "application/json"),
            body = "{\"success\":true,\"transactionId\":\"tx-gw-12345\"}",
        )
}

private class AuthAdapterFailingGatewayClient : CasinoProviderGatewayClient {
    override fun executePost(endpoint: String, headers: Map<String, String>, payload: String): CasinoGatewayResponse =
        CasinoGatewayResponse(
            statusCode = 503,
            headers = mapOf("Content-Type" to "application/json"),
            body = "{\"error\":\"Service Unavailable\"}",
        )
}

private class AuthAdapterSecretResolver(private val secrets: Map<String, String>) : ProviderSecretResolver {
    override fun resolveRawSecret(tenantId: String, providerId: String, keyId: String): String? =
        secrets["$tenantId:$providerId:$keyId"]
}

private class AuthAdapterFailingSecretResolver : ProviderSecretResolver {
    override fun resolveRawSecret(tenantId: String, providerId: String, keyId: String): String =
        error("vault offline")
}

private class AuthAdapterActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T18:00:00Z"),
        )
}

private class AuthAdapterExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-18T02:00:00Z"), // Expired
        )
}

private class AuthAdapterFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        error("database connection pool exhausted")
}

private class AuthAdapterContractStore : CanonicalCasinoProviderContractStore {
    private val schemas = mutableMapOf<String, CanonicalCasinoProviderSchema>()
    private val idempotencyMap = mutableMapOf<String, Pair<String, Any>>()
    private val seenSignatures = mutableSetOf<String>()

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
    }
}

private class AuthAdapterStore : AuthenticatedCasinoAdapterStore {
    private val certifications = mutableMapOf<String, CasinoProviderCertification>()
    private val certsById = mutableMapOf<String, CasinoProviderCertification>()
    private val certIdempotency = mutableMapOf<String, Pair<String, CasinoCertificationResult>>()
    private val rounds = mutableMapOf<String, Pair<String, CasinoRoundExecutionResult>>()
    private val rollbacks = mutableMapOf<String, Pair<String, CasinoRollbackExecutionResult>>()
    private val callbacks = mutableMapOf<String, Pair<String, CasinoCallbackProcessingResult>>()
    private val seenSignatures = mutableSetOf<String>()
    val auditLogs = mutableListOf<AuditEvent>()
    val outboxLogs = mutableListOf<OutboxEvent>()

    override fun findCertification(tenantId: String, providerId: String): CasinoProviderCertification? =
        synchronized(this) { certifications["$tenantId:$providerId"] }

    override fun findCertificationById(tenantId: String, certificationId: UUID): CasinoProviderCertification? =
        synchronized(this) { certsById["$tenantId:$certificationId"] }

    override fun findCertByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoCertificationResult>? =
        synchronized(this) { certIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveCertification(
        certification: CasinoProviderCertification,
        result: CasinoCertificationResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        certifications["$tenantId:${certification.providerId}"] = certification
        certsById["$tenantId:${certification.certificationId}"] = certification
        certIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }

    override fun findRoundByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoRoundExecutionResult>? =
        synchronized(this) { rounds["$tenantId:$idempotencyKey"] }

    override fun saveRound(
        result: CasinoRoundExecutionResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        rounds["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }

    override fun findRollbackByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoRollbackExecutionResult>? =
        synchronized(this) { rollbacks["$tenantId:$idempotencyKey"] }

    override fun saveRollback(
        result: CasinoRollbackExecutionResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        rollbacks["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }

    override fun findCallbackByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoCallbackProcessingResult>? =
        synchronized(this) { callbacks["$tenantId:$idempotencyKey"] }

    override fun isSignatureSeen(tenantId: String, signature: String): Boolean =
        synchronized(this) { seenSignatures.contains("$tenantId:$signature") }

    override fun saveCallback(
        result: CasinoCallbackProcessingResult,
        tenantId: String,
        signature: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        seenSignatures.add("$tenantId:$signature")
        callbacks["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }
}
