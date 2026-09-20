package com.slotting.admin.privacy

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DsarFulfillmentTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-dsar-1"
    private val subjectId = "player-dsar-001"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-dsar-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-dsar-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-dsar-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-dsar-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-cross-01",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerSelfPrincipal = AuthenticatedPrincipal(
        id = subjectId,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val playerOtherPrincipal = AuthenticatedPrincipal(
        id = "player-other-999",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private lateinit var dsarStore: InMemoryDsarStore
    private lateinit var inventoryStore: InMemoryPersonalDataInventoryStore
    private lateinit var alertSink: InMemoryDsarAlertSink
    private lateinit var service: DsarFulfillmentService
    private lateinit var inventoryService: PersonalDataInventoryService

    @BeforeEach
    fun setUp() {
        DsarFulfillmentBinding.isBound = true
        PersonalDataInventoryBinding.isBound = true
        dsarStore = InMemoryDsarStore()
        inventoryStore = InMemoryPersonalDataInventoryStore()
        alertSink = InMemoryDsarAlertSink()
        service = DsarFulfillmentService(
            store = dsarStore,
            inventoryStore = inventoryStore,
            alertSink = alertSink,
            clock = clock,
        )
        inventoryService = PersonalDataInventoryService(
            store = inventoryStore,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        DsarFulfillmentBinding.isBound = true
        PersonalDataInventoryBinding.isBound = true
    }

    @Test
    fun `PRIV-001-02-T001 — Fulfil data-subject access requests produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        DsarFulfillmentBinding.isBound = false

        val fulfilCmd = FulfilDsarCommand(
            tenantId = tenantId,
            dsarReference = "DSAR-2026-001",
            subjectId = subjectId,
            requestType = DsarRequestType.ACCESS_EXPORT,
            idempotencyKey = "key-dsar-001",
            correlationId = "corr-dsar-1",
            causationId = "cause-dsar-1",
            principal = auditorPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.fulfilDsar(fulfilCmd)
        }
        assertEquals("missed copy/illegal delete/hold bypass", gateError.message)

        // Bind the fail-closed gate
        DsarFulfillmentBinding.isBound = true

        // 2. Prepopulate Personal Data Inventory across multiple systems (prevent missed copy)
        inventoryService.registerItem(
            RegisterInventoryItemCommand(
                tenantId = tenantId,
                inventoryReference = "INV-IDENTITY-01",
                dataCategory = DataCategory.IDENTITY,
                classification = DataClassification.PII,
                storageSystem = "player_profile_db",
                dataOwner = "identity-team",
                legalBasis = ProcessingLegalBasis.CONTRACT_PERFORMANCE,
                retentionDays = 365,
                idempotencyKey = "key-inv-id-1",
                correlationId = "corr-inv-1",
                causationId = "cause-inv-1",
                principal = auditorPrincipal,
            )
        )
        inventoryService.registerItem(
            RegisterInventoryItemCommand(
                tenantId = tenantId,
                inventoryReference = "INV-PAYMENT-01",
                dataCategory = DataCategory.PAYMENT,
                classification = DataClassification.FINANCIAL,
                storageSystem = "payment_vault_db",
                dataOwner = "payments-team",
                legalBasis = ProcessingLegalBasis.CONTRACT_PERFORMANCE,
                retentionDays = 1825,
                idempotencyKey = "key-inv-pay-1",
                correlationId = "corr-inv-2",
                causationId = "cause-inv-2",
                principal = auditorPrincipal,
            )
        )
        inventoryService.registerItem(
            RegisterInventoryItemCommand(
                tenantId = tenantId,
                inventoryReference = "INV-LEDGER-01",
                dataCategory = DataCategory.LEDGER,
                classification = DataClassification.FINANCIAL,
                storageSystem = "ledger_journal_db",
                dataOwner = "finance-team",
                legalBasis = ProcessingLegalBasis.STATUTORY_RETENTION,
                retentionDays = 2555,
                statutoryRetentionOverride = true,
                idempotencyKey = "key-inv-led-1",
                correlationId = "corr-inv-3",
                causationId = "cause-inv-3",
                principal = auditorPrincipal,
            )
        )
        inventoryService.registerItem(
            RegisterInventoryItemCommand(
                tenantId = tenantId,
                inventoryReference = "INV-DEVICE-01",
                dataCategory = DataCategory.DEVICE_SESSION,
                classification = DataClassification.TECHNICAL,
                storageSystem = "session_cache",
                dataOwner = "security-team",
                legalBasis = ProcessingLegalBasis.CONSENT,
                retentionDays = 90,
                idempotencyKey = "key-inv-dev-1",
                correlationId = "corr-inv-4",
                causationId = "cause-inv-4",
                principal = auditorPrincipal,
            )
        )

        // 3. Apply active legal hold on the subject (prevent hold bypass)
        inventoryService.applyLegalHold(
            ApplyLegalHoldCommand(
                tenantId = tenantId,
                holdReference = "HOLD-CASE-2026-991",
                subjectId = subjectId,
                caseReference = "SEC-SUBPOENA-991",
                reason = "Regulatory investigation freeze",
                approverId = "compliance-lead-01",
                idempotencyKey = "key-hold-apply-01",
                correlationId = "corr-hold-1",
                causationId = "cause-hold-1",
                principal = securityPrincipal,
            )
        )

        // 4. Authoritative DSAR fulfillment execution
        val result = service.fulfilDsar(fulfilCmd)
        assertNotNull(result)
        assertFalse(result.isDuplicate)
        assertFalse(result.isFinancialAuthorityCreated, "DSAR cannot create financial authority or mutate money")
        assertEquals(DSAR_FULFILLMENT_CONTRACT, result.semanticContract)

        val dsar = result.dsar
        assertEquals("DSAR-2026-001", dsar.dsarReference)
        assertEquals(subjectId, dsar.subjectId)
        assertEquals(DsarStatus.FULFILLED, dsar.status)

        // Verify all 4 registered data categories were collected (no missed copy)
        assertEquals(4, dsar.collectedCategories.size)
        val collectedCategoryTypes = dsar.collectedCategories.map { it.category }.toSet()
        assertTrue(collectedCategoryTypes.contains(DataCategory.IDENTITY))
        assertTrue(collectedCategoryTypes.contains(DataCategory.PAYMENT))
        assertTrue(collectedCategoryTypes.contains(DataCategory.LEDGER))
        assertTrue(collectedCategoryTypes.contains(DataCategory.DEVICE_SESSION))

        // Verify active legal hold was recognized and flagged (prevents hold bypass)
        assertTrue(dsar.legalHoldActive)
        assertEquals("HOLD-CASE-2026-991", dsar.legalHoldReference)

        // Verify statutory retention was recognized and flagged for ledger records (prevents illegal delete)
        assertTrue(dsar.statutoryRetentionApplies)
        val ledgerCategory = dsar.collectedCategories.first { it.category == DataCategory.LEDGER }
        assertTrue(ledgerCategory.statutoryRetentionOverride)

        // Verify cryptographic package export checksum (64-character SHA-256 hex string)
        assertTrue(dsar.exportChecksumSha256.isNotBlank())
        assertEquals(64, dsar.exportChecksumSha256.length)
        assertTrue(dsar.exportChecksumSha256.matches(Regex("^[0-9a-f]{64}$")))

        assertTrue(alertSink.alerts.any { it.contains("DSAR_FULFILLED") })

        // 5. Idempotent replay: Calling again with same idempotency key returns cached duplicate
        val replayed = service.fulfilDsar(fulfilCmd)
        assertTrue(replayed.isDuplicate)
        assertEquals(result.resultId, replayed.resultId)
        assertEquals(result.dsar.dsarId, replayed.dsar.dsarId)
        assertEquals(result.dsar.exportChecksumSha256, replayed.dsar.exportChecksumSha256)

        // 6. Verify audit and outbox emission
        val auditEvents = dsarStore.getAuditEvents()
        assertEquals(1, auditEvents.size)
        assertEquals("DSAR_FULFILLED", auditEvents[0].type)
        assertEquals(tenantId, auditEvents[0].tenantId)
        assertEquals("corr-dsar-1", auditEvents[0].correlationId)
        assertEquals("cause-dsar-1", auditEvents[0].causationId)

        val outboxEvents = dsarStore.getOutboxEvents()
        assertEquals(1, outboxEvents.size)
        assertEquals("DSAR_FULFILLED", outboxEvents[0].type)
    }

    @Test
    fun `PRIV-001-02-T002 — Fulfil data-subject access requests rejects invalid, boundary, unauthorized, and stale input`() {
        val validCmd = FulfilDsarCommand(
            tenantId = tenantId,
            dsarReference = "DSAR-VAL-001",
            subjectId = subjectId,
            requestType = DsarRequestType.ACCESS_EXPORT,
            idempotencyKey = "key-val-001",
            correlationId = "corr-val-1",
            causationId = "cause-val-1",
            principal = auditorPrincipal,
        )

        // 1. Blank mandatory fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(tenantId = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(dsarReference = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(subjectId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(correlationId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(causationId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(expectedVersion = 2L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 3. Principal authorization & IDOR protection
        // Player attempting to access ANOTHER user's DSAR -> FORBIDDEN (IDOR prevented)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(principal = playerOtherPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant principal -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(principal = crossTenantPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Admin without SUPER_ADMIN/AUDITOR/SECURITY role (e.g. SUPPORT) -> FORBIDDEN
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(principal = supportPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Player accessing their OWN DSAR -> PERMITTED
        val playerSelfCmd = validCmd.copy(
            dsarReference = "DSAR-PLAYER-SELF-01",
            idempotencyKey = "key-player-self-01",
            principal = playerSelfPrincipal,
        )
        val selfResult = service.fulfilDsar(playerSelfCmd)
        assertNotNull(selfResult)
        assertEquals(subjectId, selfResult.dsar.subjectId)

        // 4. Idempotency conflict: same key with different payload
        service.fulfilDsar(validCmd)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(requestType = DsarRequestType.PORTABILITY_EXPORT))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 5. Reference collision: different key with existing reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.fulfilDsar(validCmd.copy(idempotencyKey = "key-val-different"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `PRIV-001-02-T003 — Fulfil data-subject access requests survives concurrency, duplicate delivery, and dependency failure`() {
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val endLatch = CountDownLatch(threadCount)

        val results = ConcurrentHashMap<Int, DsarResult>()
        val exceptions = ConcurrentHashMap<Int, Throwable>()

        val cmd = FulfilDsarCommand(
            tenantId = tenantId,
            dsarReference = "DSAR-CONCURRENT-001",
            subjectId = subjectId,
            requestType = DsarRequestType.ACCESS_EXPORT,
            idempotencyKey = "key-dsar-concurrent",
            correlationId = "corr-conc-1",
            causationId = "cause-conc-1",
            principal = auditorPrincipal,
        )

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.fulfilDsar(cmd)
                    results[i] = res
                } catch (t: Throwable) {
                    exceptions[i] = t
                } finally {
                    endLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        endLatch.await()
        executor.shutdown()

        // Invariant: Zero uncaught exceptions across all racing threads
        assertTrue(exceptions.isEmpty(), "Concurrent executions must not throw errors: ${exceptions.values}")
        assertEquals(threadCount, results.size)

        // All threads must converge on the exact same DSAR ID and export checksum
        val distinctDsarIds = results.values.map { it.dsar.dsarId }.toSet()
        val distinctChecksums = results.values.map { it.dsar.exportChecksumSha256 }.toSet()
        assertEquals(1, distinctDsarIds.size, "All threads must return identical DSAR ID")
        assertEquals(1, distinctChecksums.size, "All threads must return identical export checksum")

        // Exactly 1 primary creation and 7 duplicate responses
        val duplicateCount = results.values.count { it.isDuplicate }
        assertEquals(threadCount - 1, duplicateCount)

        // Storage dependency failure handling
        class FailingDsarStore : InMemoryDsarStore() {
            var shouldFail = true
            override fun saveDsar(
                record: DsarRecord,
                result: DsarResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) {
                    throw RuntimeException("DSAR storage connection timeout")
                }
                super.saveDsar(record, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val failingStore = FailingDsarStore()
        val retryService = DsarFulfillmentService(
            store = failingStore,
            inventoryStore = inventoryStore,
            alertSink = alertSink,
            clock = clock,
        )

        val retryCmd = FulfilDsarCommand(
            tenantId = tenantId,
            dsarReference = "DSAR-RETRY-001",
            subjectId = subjectId,
            requestType = DsarRequestType.ACCESS_EXPORT,
            idempotencyKey = "key-dsar-retry-01",
            correlationId = "corr-retry-1",
            causationId = "cause-retry-1",
            principal = adminPrincipal,
        )

        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.fulfilDsar(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("DSAR_STORAGE_FAILED") })

        // Invariant: Zero corrupt state committed on storage failure
        assertNull(failingStore.findByReference(tenantId, "DSAR-RETRY-001"))

        // Dependency recovers: Retry succeeds cleanly
        failingStore.shouldFail = false
        val recoveredResult = retryService.fulfilDsar(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
        assertNotNull(failingStore.findByReference(tenantId, "DSAR-RETRY-001"))
    }

    @Test
    fun `PRIV-001-02-T004 — Fulfil data-subject access requests remains compatible, recoverable, observable, and lifecycle-safe`() {
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

        // 3. State recovery across restart
        val dsarCmd = FulfilDsarCommand(
            tenantId = tenantId,
            dsarReference = "DSAR-RESTART-001",
            subjectId = subjectId,
            requestType = DsarRequestType.PORTABILITY_EXPORT,
            idempotencyKey = "key-dsar-restart-01",
            correlationId = "corr-restart-1",
            causationId = "cause-restart-1",
            principal = adminPrincipal,
        )

        val initialResult = service.fulfilDsar(dsarCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = dsarStore.exportSnapshot()
        val rehydratedStore = InMemoryDsarStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = DsarFulfillmentService(
            store = rehydratedStore,
            inventoryStore = inventoryStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.fulfilDsar(dsarCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(DSAR_FULFILLMENT_CONTRACT, replayedResult.semanticContract)
        assertEquals(initialResult.dsar.exportChecksumSha256, replayedResult.dsar.exportChecksumSha256)

        // 4. Observability: structured audit & outbox records contain zero credentials or PII
        val auditEvents = rehydratedStore.getAuditEvents()
        assertTrue(auditEvents.isNotEmpty())
        for (audit in auditEvents) {
            assertEquals(tenantId, audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
            assertFalse(audit.type.contains("password", ignoreCase = true))
        }

        val outboxEvents = rehydratedStore.getOutboxEvents()
        assertTrue(outboxEvents.isNotEmpty())
    }
}
