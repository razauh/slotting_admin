package com.slotting.admin.validation.chaos

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class LoadSoakChaosFailoverTest {

    private lateinit var service: LoadSoakChaosFailoverService
    private lateinit var evidenceStore: InMemoryChaosEvidenceStore
    private lateinit var alertSink: InMemoryChaosAlertSink
    private lateinit var observability: InMemoryChaosObservability

    private val tenantId = "tenant-chaos-validation"
    private val adminPrincipal = AuthenticatedPrincipal(
        id = "superadmin-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
        tenantId = tenantId
    )
    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
        tenantId = tenantId
    )

    private val now = Instant.now()
    private val validManifest = ChaosArtifactManifest(
        commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
        artifactDigest = "sha256:load-soak-chaos-failover-v1",
        configurationVersion = "1.0.0",
        environment = "staging-production-mirror",
        owner = "security-reliability-council",
        reviewer = "principal-sre-auditor",
        signedAt = now.minus(1, ChronoUnit.HOURS),
        expiry = now.plus(24, ChronoUnit.HOURS)
    )

    @BeforeEach
    fun setUp() {
        evidenceStore = InMemoryChaosEvidenceStore()
        alertSink = InMemoryChaosAlertSink()
        observability = InMemoryChaosObservability()
        service = LoadSoakChaosFailoverService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability
        )
    }

    private fun createValidCommand(
        idempotencyKey: String = UUID.randomUUID().toString(),
        scenarios: Set<ChaosScenarioType> = ChaosScenarioType.values().toSet(),
        injectedFaults: Set<ChaosFaultType> = emptySet(),
        thresholdConfig: ChaosThresholdConfig = ChaosThresholdConfig()
    ): RunChaosValidationCommand {
        return RunChaosValidationCommand(
            principal = adminPrincipal,
            tenantId = tenantId,
            scenarios = scenarios,
            thresholdConfig = thresholdConfig,
            manifest = validManifest,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-${UUID.randomUUID()}",
            causationId = "caus-${UUID.randomUUID()}",
            injectedFaults = injectedFaults
        )
    }

    @Test
    @DisplayName("SYS-004-T001 — Load/soak/chaos/failover produces the required authoritative outcome")
    fun testSYS004T001PrimaryAuthoritativeOutcome() {
        val cmd = createValidCommand()
        val report = service.runChaosValidation(cmd)

        // Outcome contract assertion
        assertEquals(
            "Includes hot wallet, callback burst, socket soak, DB failover, Redis loss, worker restart.",
            report.semanticContract
        )
        assertEquals(ChaosExecutionStatus.COMPLETED_HEALTHY, report.status)

        // All 6 scenarios must be present and PASSED
        assertEquals(6, report.scenarioResults.size)
        assertTrue(report.scenarioResults.containsKey(ChaosScenarioType.HOT_WALLET))
        assertTrue(report.scenarioResults.containsKey(ChaosScenarioType.CALLBACK_BURST))
        assertTrue(report.scenarioResults.containsKey(ChaosScenarioType.SOCKET_SOAK))
        assertTrue(report.scenarioResults.containsKey(ChaosScenarioType.DB_FAILOVER))
        assertTrue(report.scenarioResults.containsKey(ChaosScenarioType.REDIS_LOSS))
        assertTrue(report.scenarioResults.containsKey(ChaosScenarioType.WORKER_RESTART))

        for ((_, result) in report.scenarioResults) {
            assertEquals(ChaosScenarioStatus.PASSED, result.status)
        }

        // Hot wallet latency and operations
        val hotWalletResult = report.scenarioResults[ChaosScenarioType.HOT_WALLET]!!
        assertEquals(5_000L, hotWalletResult.totalOperations)
        assertTrue(hotWalletResult.p99LatencyMs <= 200L)

        // Callback burst deduplication
        val callbackResult = report.scenarioResults[ChaosScenarioType.CALLBACK_BURST]!!
        assertEquals(10_000L, callbackResult.totalOperations)
        assertEquals(100.0, callbackResult.deduplicationRatePercent)

        // Socket soak stability
        val socketResult = report.scenarioResults[ChaosScenarioType.SOCKET_SOAK]!!
        assertEquals(20_000L, socketResult.totalOperations)
        assertTrue(socketResult.socketStabilityPercent!! >= 99.9)

        // DB failover recovery time
        val dbResult = report.scenarioResults[ChaosScenarioType.DB_FAILOVER]!!
        assertTrue(dbResult.recoveryTimeMs!! <= 5_000L)

        // Redis loss fallback success
        val redisResult = report.scenarioResults[ChaosScenarioType.REDIS_LOSS]!!
        assertEquals(10_000L, redisResult.totalOperations)
        assertEquals(100.0, redisResult.fallbackSuccessRatePercent)

        // Worker restart recovery time
        val workerResult = report.scenarioResults[ChaosScenarioType.WORKER_RESTART]!!
        assertTrue(workerResult.recoveryTimeMs!! <= 2_000L)
        assertEquals(0L, workerResult.duplicateExecutions)

        // Financial conservation: debits equal credits at all times
        assertEquals(hotWalletResult.ledgerDebitsMinor, report.totalLedgerDebitsMinor)
        assertEquals(hotWalletResult.ledgerCreditsMinor, report.totalLedgerCreditsMinor)
        assertEquals(0L, report.netLedgerImbalanceMinor)
        assertTrue(report.isZeroLedgerImbalance)

        // Strict Android boundary: untrusted presentation layer only
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Correlated evidence reference
        assertNotNull(report.evidenceReference)
        assertEquals(cmd.correlationId, report.correlationId)
        assertEquals(cmd.causationId, report.causationId)

        // Stored in evidence repository
        val stored = evidenceStore.getReport(report.executionId)
        assertNotNull(stored)
        assertEquals(report.executionId, stored!!.executionId)
    }

    @Test
    @DisplayName("SYS-004-T002 — Load/soak/chaos/failover rejects invalid, boundary, unauthorized, and stale input")
    fun testSYS004T002RejectsInvalidBoundaryUnauthorizedInput() {
        val validCmd = createValidCommand()

        // 1. Unauthenticated principal
        val unauthCmd = validCmd.copy(principal = null)
        assertThrows<UnauthorizedChaosException> {
            service.runChaosValidation(unauthCmd)
        }

        // 2. Insufficient permissions (AUDITOR cannot execute chaos)
        val auditorCmd = validCmd.copy(principal = auditorPrincipal)
        assertThrows<UnauthorizedChaosException> {
            service.runChaosValidation(auditorCmd)
        }

        // 3. Cross-tenant execution
        val crossTenantCmd = validCmd.copy(tenantId = "other-tenant")
        assertThrows<UnauthorizedChaosException> {
            service.runChaosValidation(crossTenantCmd)
        }

        // 4. Blank required input fields
        assertThrows<InvalidChaosInputException> {
            service.runChaosValidation(validCmd.copy(idempotencyKey = "   "))
        }
        assertThrows<InvalidChaosInputException> {
            service.runChaosValidation(validCmd.copy(correlationId = "   "))
        }
        assertThrows<InvalidChaosInputException> {
            service.runChaosValidation(validCmd.copy(causationId = "   "))
        }
        assertThrows<InvalidChaosInputException> {
            service.runChaosValidation(validCmd.copy(scenarios = emptySet()))
        }

        // 5. Invalid threshold boundaries
        assertThrows<InvalidChaosInputException> {
            service.runChaosValidation(validCmd.copy(thresholdConfig = ChaosThresholdConfig(maxAllowedLatencyMs = 0)))
        }
        assertThrows<InvalidChaosInputException> {
            service.runChaosValidation(validCmd.copy(thresholdConfig = ChaosThresholdConfig(minSocketStabilityPercent = 105.0)))
        }

        // 6. Expired manifest
        val expiredManifest = validManifest.copy(expiry = now.minus(1, ChronoUnit.HOURS))
        assertThrows<InvalidChaosManifestException> {
            service.runChaosValidation(validCmd.copy(manifest = expiredManifest))
        }

        // 7. Threshold breaches (e.g. latency spike beyond threshold)
        val latencyFaultCmd = createValidCommand(injectedFaults = setOf(ChaosFaultType.LATENCY_SPIKE))
        val exLatency = assertThrows<ChaosThresholdBreachedException> {
            service.runChaosValidation(latencyFaultCmd)
        }
        assertTrue(exLatency.message!!.contains("establish failure thresholds"))

        // Injected failover timeout threshold breach
        val timeoutFaultCmd = createValidCommand(injectedFaults = setOf(ChaosFaultType.FAILOVER_TIMEOUT))
        val exTimeout = assertThrows<ChaosThresholdBreachedException> {
            service.runChaosValidation(timeoutFaultCmd)
        }
        assertTrue(exTimeout.message!!.contains("establish failure thresholds"))

        // Verify alert emitted on threshold breach
        assertTrue(alertSink.getAlerts().any { it.message.contains("Threshold breach") })
    }

    @Test
    @DisplayName("SYS-004-T003 — Load/soak/chaos/failover survives concurrency, duplicate delivery, and dependency failure")
    fun testSYS004T003ConcurrencyIdempotencyDependencyFailure() {
        val idempotencyKey = "chaos-idem-${UUID.randomUUID()}"
        val cmd1 = createValidCommand(idempotencyKey = idempotencyKey)

        // 1. First execution succeeds
        val report1 = service.runChaosValidation(cmd1)
        assertEquals(ChaosExecutionStatus.COMPLETED_HEALTHY, report1.status)

        // 2. Duplicate delivery with identical payload returns exact same report
        val report2 = service.runChaosValidation(cmd1)
        assertEquals(report1.executionId, report2.executionId)
        assertEquals(report1.executedAt, report2.executedAt)

        // 3. Changed-payload key reuse throws IdempotencyConflictException
        val conflictingCmd = cmd1.copy(
            scenarios = setOf(ChaosScenarioType.HOT_WALLET)
        )
        assertThrows<IdempotencyConflictException> {
            service.runChaosValidation(conflictingCmd)
        }

        // 4. Dependency failure handling
        service.scenarioFaults["DEPENDENCY_FAILURE"] = "Simulated PostgreSQL replica synchronization timeout"
        val depFailCmd = createValidCommand()
        val depEx = assertThrows<ChaosValidationException> {
            service.runChaosValidation(depFailCmd)
        }
        assertTrue(depEx.message!!.contains("Dependency failure"))
        assertTrue(alertSink.getAlerts().any { it.message.contains("Dependency failure") })
        service.scenarioFaults.remove("DEPENDENCY_FAILURE")

        // 5. Concurrency: multiple parallel requests handle cleanly
        val executor = Executors.newFixedThreadPool(4)
        val callables = (1..8).map { i ->
            Callable {
                val threadCmd = createValidCommand(idempotencyKey = "thread-idem-$i")
                service.runChaosValidation(threadCmd)
            }
        }
        val futures = executor.invokeAll(callables)
        for (f in futures) {
            val r = f.get()
            assertEquals(ChaosExecutionStatus.COMPLETED_HEALTHY, r.status)
            assertTrue(r.isZeroLedgerImbalance)
        }
        executor.shutdown()
    }

    @Test
    @DisplayName("SYS-004-T004 — Load/soak/chaos/failover remains compatible, recoverable, observable, and lifecycle-safe")
    fun testSYS004T004LifecycleRecoveryObservability() {
        val cmd = createValidCommand()
        val report = service.runChaosValidation(cmd)

        // Recovery assertion: DB failover recovered, Redis loss fell back, worker restarted
        val dbResult = report.scenarioResults[ChaosScenarioType.DB_FAILOVER]!!
        val redisResult = report.scenarioResults[ChaosScenarioType.REDIS_LOSS]!!
        val workerResult = report.scenarioResults[ChaosScenarioType.WORKER_RESTART]!!

        assertNotNull(dbResult.recoveryTimeMs)
        assertNotNull(redisResult.fallbackSuccessRatePercent)
        assertNotNull(workerResult.recoveryTimeMs)

        // Zero Android lifecycle surface
        assertFalse(report.hasAndroidLifecycleClaim)
        assertFalse(report.hasAndroidDbImpact)

        // Observability metrics recorded
        assertTrue(observability.getExecutionsCount() > 0)
        assertTrue(observability.getScenariosCompletedCount() >= 6)

        // Immutable evidence binding
        assertEquals(validManifest.commitHash, report.manifest.commitHash)
        assertEquals(validManifest.artifactDigest, report.manifest.artifactDigest)
        assertEquals(validManifest.environment, report.manifest.environment)
        assertEquals(validManifest.owner, report.manifest.owner)
        assertEquals(validManifest.reviewer, report.manifest.reviewer)
        assertTrue(report.evidenceReference.startsWith("ev-chaos-"))
    }
}
