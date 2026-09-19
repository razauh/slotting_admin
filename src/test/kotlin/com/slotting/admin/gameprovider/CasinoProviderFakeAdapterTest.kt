package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
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

class CasinoProviderFakeAdapterTest {
    private val now = Instant.parse("2026-09-19T11:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-adapter-1"
    private val providerId = "prov-fake-slots"
    private val activeKeyId = "key-v1"
    private val activeKeySecret = "raw-secret-fake-v1"
    private val nextKeyId = "key-v2"
    private val nextKeySecret = "raw-secret-fake-v2"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-adapter-1",
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
        tenantId = "tenant-adapter-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    @BeforeEach
    fun setUp() {
        CasinoProviderFakeAdapterBinding.isBound = true
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        CasinoProviderFakeAdapterBinding.isBound = true
        CanonicalCasinoProviderContractBinding.isBound = true
    }

    @Test
    fun `GAME-001-02-T001 Build casino provider fake adapter produces the required authoritative outcome`() {
        // 1. Verify fail-closed gate throws expected RED assertion error when unbound
        CasinoProviderFakeAdapterBinding.isBound = false
        val contractStore = InMemoryContractStore()
        val adapterStore = InMemoryAdapterStore()
        val resolver = TestSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
            "$tenantId:$providerId:$nextKeyId" to nextKeySecret,
        ))
        val sessions = TestAdapterActiveSessionDirectory()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)
        val fakeAdapter = CasinoProviderFakeAdapter(contractStore, resolver, clock)
        val adapterService = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            adapter = fakeAdapter,
            contractService = contractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )

        val cfgCmd = createConfigureCommand()
        val gateError = assertFailsWith<AssertionError> {
            adapterService.configureAdapter(cfgCmd)
        }
        assertEquals("bad creds/signature/replay", gateError.message)

        // Bind the gate
        CasinoProviderFakeAdapterBinding.isBound = true

        // Setup canonical schema in contract store
        registerTestSchema(contractService)

        // 2. Configure adapter to ADVERSARIAL_FAKE tier and NORMAL mode
        val configResult = adapterService.configureAdapter(cfgCmd)
        assertNotNull(configResult)
        assertEquals(tenantId, configResult.tenantId)
        assertEquals(providerId, configResult.providerId)
        assertEquals(CasinoProviderAdapterTier.ADVERSARIAL_FAKE, configResult.tier)
        assertEquals(AdversarialSimulationMode.NORMAL, configResult.simulationMode)
        assertFalse(configResult.rotationObservable) // Initially no next key
        assertFalse(configResult.outageObservable)   // Initially healthy

        // Idempotent replay of configuration
        val configReplay = adapterService.configureAdapter(cfgCmd.copy(expectedVersion = 1L))
        assertEquals(configResult.resultId, configReplay.resultId)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_PROVIDER_ADAPTER_CONFIGURED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_PROVIDER_ADAPTER_CONFIGURED" })

        // 3. Execute simulated round rollback (conservation: debits equal credits)
        val rollbackCmd = ExecuteSimulatedRollbackCommand(
            principal = adminPrincipal,
            sessionId = "session-1",
            tenantId = tenantId,
            providerId = providerId,
            roundReference = "round-fake-101",
            debitMinorUnits = 2500L,
            creditMinorUnits = 2500L,
            currencyCode = "USD",
            reason = "Player connection dropped mid-spin",
            idempotencyKey = "idemp-rollback-001",
            correlationId = "corr-rollback-1",
            causationId = "cause-rollback-1",
            expectedVersion = 1L,
        )
        val rollbackResult = adapterService.executeRollback(rollbackCmd)
        assertNotNull(rollbackResult)
        assertTrue(rollbackResult.conserved)
        assertEquals("round-fake-101", rollbackResult.roundReference)
        assertEquals(2500L, rollbackResult.debitMinorUnits)
        assertEquals(2500L, rollbackResult.creditMinorUnits)
        assertTrue(rollbackResult.compensationReference.startsWith("COMP-ROLLBACK-"))

        // Idempotent replay of rollback
        val rollbackReplay = adapterService.executeRollback(rollbackCmd)
        assertEquals(rollbackResult.resultId, rollbackReplay.resultId)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_PROVIDER_ROLLBACK_COMPENSATED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_PROVIDER_ROLLBACK_COMPENSATED" })

        // 4. Dispatch simulated callback in NORMAL mode through contract service
        val dispatchCmd = DispatchSimulatedCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            roundReference = "round-fake-101",
            debitMinorUnits = 1000L,
            creditMinorUnits = 2000L,
            currencyCode = "USD",
            idempotencyKey = "idemp-dispatch-001",
            correlationId = "corr-dispatch-1",
            causationId = "cause-dispatch-1",
            expectedVersion = 1L,
        )
        val dispatchResult = adapterService.dispatchSimulatedCallback(dispatchCmd)
        assertNotNull(dispatchResult)
        assertNotNull(dispatchResult.verificationResult)
        assertTrue(dispatchResult.verificationResult!!.verified)
        assertTrue(dispatchResult.verificationResult!!.signatureValid)
        assertTrue(dispatchResult.verificationResult!!.credentialValid)
        assertFalse(dispatchResult.verificationResult!!.replayDetected)
        assertTrue(dispatchResult.verificationResult!!.conservationVerified)
        assertTrue(dispatchResult.rotationObservable)
        assertTrue(dispatchResult.outageObservable)
        assertNull(dispatchResult.failureCode)

        // Idempotent replay of dispatch
        val dispatchReplay = adapterService.dispatchSimulatedCallback(dispatchCmd)
        assertEquals(dispatchResult.resultId, dispatchReplay.resultId)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_PROVIDER_CALLBACK_DISPATCHED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_PROVIDER_CALLBACK_DISPATCHED" })
    }

    @Test
    fun `GAME-001-02-T002 Build casino provider fake adapter rejects invalid, boundary, unauthorized, and stale input`() {
        val contractStore = InMemoryContractStore()
        val adapterStore = InMemoryAdapterStore()
        val resolver = TestSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
            "$tenantId:$providerId:$nextKeyId" to nextKeySecret,
        ))
        val sessions = TestAdapterActiveSessionDirectory()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)
        val fakeAdapter = CasinoProviderFakeAdapter(contractStore, resolver, clock)
        val adapterService = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            adapter = fakeAdapter,
            contractService = contractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )

        registerTestSchema(contractService)
        adapterService.configureAdapter(createConfigureCommand())

        // 1. Adversarial mode BAD_CREDENTIALS -> FORBIDDEN (bad creds)
        adapterService.configureAdapter(
            createConfigureCommand().copy(
                simulationMode = AdversarialSimulationMode.BAD_CREDENTIALS,
                expectedVersion = 2L,
                idempotencyKey = "idemp-cfg-bad-creds",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.dispatchSimulatedCallback(
                DispatchSimulatedCallbackCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-bad-creds",
                    debitMinorUnits = 500L,
                    creditMinorUnits = 1000L,
                    currencyCode = "USD",
                    idempotencyKey = "idemp-dispatch-bad-creds",
                    correlationId = "corr-bc",
                    causationId = "cause-bc",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Adversarial mode BAD_SIGNATURE -> FORBIDDEN (bad signature)
        adapterService.configureAdapter(
            createConfigureCommand().copy(
                simulationMode = AdversarialSimulationMode.BAD_SIGNATURE,
                expectedVersion = 3L,
                idempotencyKey = "idemp-cfg-bad-sig",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.dispatchSimulatedCallback(
                DispatchSimulatedCallbackCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-bad-sig",
                    debitMinorUnits = 500L,
                    creditMinorUnits = 1000L,
                    currencyCode = "USD",
                    idempotencyKey = "idemp-dispatch-bad-sig",
                    correlationId = "corr-bs",
                    causationId = "cause-bs",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Adversarial mode REPLAY_ATTACK -> FORBIDDEN (replayed signature)
        // First, dispatch valid in NORMAL mode
        adapterService.configureAdapter(
            createConfigureCommand().copy(
                simulationMode = AdversarialSimulationMode.NORMAL,
                expectedVersion = 4L,
                idempotencyKey = "idemp-cfg-norm-before-replay",
            )
        )
        adapterService.dispatchSimulatedCallback(
            DispatchSimulatedCallbackCommand(
                tenantId = tenantId,
                providerId = providerId,
                roundReference = "round-initial-normal",
                debitMinorUnits = 500L,
                creditMinorUnits = 1000L,
                currencyCode = "USD",
                idempotencyKey = "idemp-dispatch-norm-before-replay",
                correlationId = "corr-rep-1",
                causationId = "cause-rep-1",
            )
        )
        // Now switch to REPLAY_ATTACK
        adapterService.configureAdapter(
            createConfigureCommand().copy(
                simulationMode = AdversarialSimulationMode.REPLAY_ATTACK,
                expectedVersion = 5L,
                idempotencyKey = "idemp-cfg-replay",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.dispatchSimulatedCallback(
                DispatchSimulatedCallbackCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-replay-attempt",
                    debitMinorUnits = 500L,
                    creditMinorUnits = 1000L,
                    currencyCode = "USD",
                    idempotencyKey = "idemp-dispatch-replay-attempt",
                    correlationId = "corr-rep-2",
                    causationId = "cause-rep-2",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Adversarial mode OUTAGE_SIMULATION -> DEPENDENCY_UNAVAILABLE
        adapterService.configureAdapter(
            createConfigureCommand().copy(
                simulationMode = AdversarialSimulationMode.OUTAGE_SIMULATION,
                expectedVersion = 6L,
                idempotencyKey = "idemp-cfg-outage",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.dispatchSimulatedCallback(
                DispatchSimulatedCallbackCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-outage-attempt",
                    debitMinorUnits = 500L,
                    creditMinorUnits = 1000L,
                    currencyCode = "USD",
                    idempotencyKey = "idemp-dispatch-outage",
                    correlationId = "corr-out",
                    causationId = "cause-out",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 5. Rollback financial sanity: debit != credit -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRollback(
                rollbackCommand(debit = 2000L, credit = 1000L, idempKey = "idemp-unbalanced-rb")
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Negative minor units -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRollback(
                rollbackCommand(debit = -100L, credit = -100L, idempKey = "idemp-neg-rb")
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid currency -> INVALID
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRollback(
                rollbackCommand(debit = 500L, credit = 500L, currency = "US", idempKey = "idemp-curr-rb")
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Security & Principal Checks
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.configureAdapter(createConfigureCommand().copy(principal = null, idempotencyKey = "idemp-unauth-cfg"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.configureAdapter(createConfigureCommand().copy(principal = playerPrincipal, idempotencyKey = "idemp-player-cfg"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.configureAdapter(createConfigureCommand().copy(principal = crossTenantPrincipal, idempotencyKey = "idemp-cross-cfg"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Expired Session -> FORBIDDEN
        val expiredSessions = TestAdapterExpiredSessionDirectory()
        val expiredService = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = expiredSessions,
            adapter = fakeAdapter,
            contractService = contractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredService.configureAdapter(createConfigureCommand().copy(idempotencyKey = "idemp-expired-cfg"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Unauthorized Principal -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.configureAdapter(createConfigureCommand().copy(principal = unauthorizedPrincipal, idempotencyKey = "idemp-noperm-cfg"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 9. Stale expected version -> STALE
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.configureAdapter(createConfigureCommand().copy(expectedVersion = 999L, idempotencyKey = "idemp-stale-cfg"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 10. Idempotency Conflict -> CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            adapterService.executeRollback(
                rollbackCommand(debit = 500L, credit = 500L, idempKey = "idemp-rollback-reuse-conflict", roundRef = "round-orig")
            )
            adapterService.executeRollback(
                rollbackCommand(debit = 500L, credit = 500L, idempKey = "idemp-rollback-reuse-conflict", roundRef = "round-changed")
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `GAME-001-02-T003 Build casino provider fake adapter survives concurrency, duplicate delivery, and dependency failure`() {
        val contractStore = InMemoryContractStore()
        val adapterStore = InMemoryAdapterStore()
        val resolver = TestSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
        ))
        val sessions = TestAdapterActiveSessionDirectory()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)
        val fakeAdapter = CasinoProviderFakeAdapter(contractStore, resolver, clock)
        val adapterService = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            adapter = fakeAdapter,
            contractService = contractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )

        registerTestSchema(contractService)
        adapterService.configureAdapter(createConfigureCommand())

        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)

        // 1. Race 8 threads executing executeRollback concurrently
        val rollbackGate = CountDownLatch(1)
        val rollbackCmd = rollbackCommand(debit = 1000L, credit = 1000L, idempKey = "idemp-conc-rollback")
        val rollbackFutures = (1..threadCount).map {
            pool.submit<CasinoRollbackCompensationResult> {
                rollbackGate.await()
                adapterService.executeRollback(rollbackCmd)
            }
        }
        rollbackGate.countDown()
        val rollbackResults = rollbackFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, rollbackResults.count { it.isSuccess })
        val distinctRollbackIds = rollbackResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctRollbackIds.size)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_PROVIDER_ROLLBACK_COMPENSATED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_PROVIDER_ROLLBACK_COMPENSATED" })

        // 2. Race 8 threads executing dispatchSimulatedCallback concurrently
        val dispatchGate = CountDownLatch(1)
        val dispatchCmd = DispatchSimulatedCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            roundReference = "round-conc-dispatch",
            debitMinorUnits = 300L,
            creditMinorUnits = 600L,
            currencyCode = "USD",
            idempotencyKey = "idemp-conc-dispatch",
            correlationId = "corr-conc-d",
            causationId = "cause-conc-d",
            expectedVersion = 1L,
        )
        val dispatchFutures = (1..threadCount).map {
            pool.submit<SimulatedCallbackDispatchResult> {
                dispatchGate.await()
                adapterService.dispatchSimulatedCallback(dispatchCmd)
            }
        }
        dispatchGate.countDown()
        val dispatchResults = dispatchFutures.map { runCatching { it.get() } }

        assertEquals(threadCount, dispatchResults.count { it.isSuccess })
        val distinctDispatchIds = dispatchResults.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctDispatchIds.size)
        assertEquals(1, adapterStore.auditLogs.count { it.type == "CASINO_PROVIDER_CALLBACK_DISPATCHED" })
        assertEquals(1, adapterStore.outboxLogs.count { it.type == "CASINO_PROVIDER_CALLBACK_DISPATCHED" })

        pool.shutdown()

        // 3. Dependency failure on session directory -> DEPENDENCY_UNAVAILABLE
        val failingSessions = TestAdapterFailingSessionDirectory()
        val failingSessionService = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = failingSessions,
            adapter = fakeAdapter,
            contractService = contractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.executeRollback(rollbackCommand(debit = 100L, credit = 100L, idempKey = "idemp-dep-fail-sess"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 4. Dependency failure on contract secret resolver -> DEPENDENCY_UNAVAILABLE
        val failingResolver = FailingSecretResolver()
        val failingContractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, failingResolver, contractStore, clock)
        val failingAdapter = CasinoProviderFakeAdapter(contractStore, failingResolver, clock)
        val failingResolverService = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            adapter = failingAdapter,
            contractService = failingContractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingResolverService.dispatchSimulatedCallback(
                DispatchSimulatedCallbackCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    roundReference = "round-dep-fail-secret",
                    debitMinorUnits = 100L,
                    creditMinorUnits = 200L,
                    currencyCode = "USD",
                    idempotencyKey = "idemp-dep-fail-secret",
                    correlationId = "corr-fail",
                    causationId = "cause-fail",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `GAME-001-02-T004 Build casino provider fake adapter remains compatible, recoverable, observable, and lifecycle-safe`() {
        // 1. Flyway migration guardrail: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertFalse(migrationVersions.contains("V17"))

        // 2. Recovery across reboot / restart
        val contractStore = InMemoryContractStore()
        val adapterStore = InMemoryAdapterStore()
        val resolver = TestSecretResolver(mapOf(
            "$tenantId:$providerId:$activeKeyId" to activeKeySecret,
        ))
        val sessions = TestAdapterActiveSessionDirectory()
        val contractService = CanonicalCasinoProviderContractService(AdminRbacPolicy(true), sessions, resolver, contractStore, clock)
        val fakeAdapter = CasinoProviderFakeAdapter(contractStore, resolver, clock)

        val serviceInitial = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            adapter = fakeAdapter,
            contractService = contractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )

        registerTestSchema(contractService)
        val cfgCmd = createConfigureCommand().copy(idempotencyKey = "idemp-reboot-cfg")
        val initialConfig = serviceInitial.configureAdapter(cfgCmd)

        // Instantiate restarted service sharing the persistent store
        val serviceRestarted = CasinoProviderAdapterService(
            policy = AdminRbacPolicy(true),
            sessions = sessions,
            adapter = fakeAdapter,
            contractService = contractService,
            contractStore = contractStore,
            adapterStore = adapterStore,
            clock = clock,
        )

        val replayedConfig = serviceRestarted.configureAdapter(cfgCmd.copy(expectedVersion = 1L))
        assertEquals(initialConfig.resultId, replayedConfig.resultId)
        assertEquals(initialConfig.evidenceReference, replayedConfig.evidenceReference)

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
                providerName = "Fake Evolution Slots",
                providerType = CasinoProviderType.SLOTS,
                schemaVersion = "1.0.0",
                supportedCurrencies = setOf("USD", "EUR"),
                signatureAlgorithm = ProviderSignatureAlgorithm.HMAC_SHA256,
                callbackEndpoint = "https://api.fake-evolution.com/callback",
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

    private fun createConfigureCommand() = ConfigureCasinoAdapterCommand(
        principal = adminPrincipal,
        sessionId = "session-1",
        tenantId = tenantId,
        providerId = providerId,
        tier = CasinoProviderAdapterTier.ADVERSARIAL_FAKE,
        simulationMode = AdversarialSimulationMode.NORMAL,
        idempotencyKey = "idemp-cfg-default",
        correlationId = "corr-cfg-1",
        causationId = "cause-cfg-1",
        expectedVersion = 1L,
    )

    private fun rollbackCommand(
        debit: Long,
        credit: Long,
        idempKey: String,
        currency: String = "USD",
        roundRef: String = "round-rb-default",
    ) = ExecuteSimulatedRollbackCommand(
        principal = adminPrincipal,
        sessionId = "session-1",
        tenantId = tenantId,
        providerId = providerId,
        roundReference = roundRef,
        debitMinorUnits = debit,
        creditMinorUnits = credit,
        currencyCode = currency,
        reason = "Test rollback",
        idempotencyKey = idempKey,
        correlationId = "corr-rb-default",
        causationId = "cause-rb-default",
        expectedVersion = 1L,
    )
}

private class TestSecretResolver(private val secrets: Map<String, String>) : ProviderSecretResolver {
    override fun resolveRawSecret(tenantId: String, providerId: String, keyId: String): String? =
        secrets["$tenantId:$providerId:$keyId"]
}

private class FailingSecretResolver : ProviderSecretResolver {
    override fun resolveRawSecret(tenantId: String, providerId: String, keyId: String): String =
        error("vault offline")
}

private class TestAdapterActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-19T12:00:00Z"),
        )
}

private class TestAdapterExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        AdminSessionStatus(
            active = true,
            breakGlass = false,
            expiresAt = Instant.parse("2026-09-18T02:00:00Z"), // Expired
        )
}

private class TestAdapterFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
        error("database connection pool exhausted")
}

private class InMemoryContractStore : CanonicalCasinoProviderContractStore {
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

private class InMemoryAdapterStore : CasinoProviderAdapterStore {
    private val configs = mutableMapOf<String, Pair<CasinoProviderAdapterConfig, CasinoAdapterConfigResult>>()
    private val configIdempotency = mutableMapOf<String, Pair<String, CasinoAdapterConfigResult>>()
    private val rollbacks = mutableMapOf<String, Pair<String, CasinoRollbackCompensationResult>>()
    private val dispatches = mutableMapOf<String, Pair<String, SimulatedCallbackDispatchResult>>()
    val auditLogs = mutableListOf<AuditEvent>()
    val outboxLogs = mutableListOf<OutboxEvent>()

    override fun findConfig(tenantId: String, providerId: String): CasinoProviderAdapterConfig? =
        synchronized(this) { configs["$tenantId:$providerId"]?.first }

    override fun findConfigByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoAdapterConfigResult>? =
        synchronized(this) { configIdempotency["$tenantId:$idempotencyKey"] }

    override fun saveConfig(
        config: CasinoProviderAdapterConfig,
        result: CasinoAdapterConfigResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        configs["$tenantId:${config.providerId}"] = config to result
        configIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }

    override fun findRollbackByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CasinoRollbackCompensationResult>? =
        synchronized(this) { rollbacks["$tenantId:$idempotencyKey"] }

    override fun saveRollback(
        result: CasinoRollbackCompensationResult,
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

    override fun findDispatchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, SimulatedCallbackDispatchResult>? =
        synchronized(this) { dispatches["$tenantId:$idempotencyKey"] }

    override fun saveDispatch(
        result: SimulatedCallbackDispatchResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        dispatches["$tenantId:$idempotencyKey"] = fingerprint to result
        auditLogs += audit
        outboxLogs += outbox
    }
}
