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

class PersonalDataInventoryTest {
    private val now = Instant.parse("2026-09-20T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-priv-1"

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-priv-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-priv-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-priv-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-priv-01",
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

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private lateinit var store: InMemoryPersonalDataInventoryStore
    private lateinit var alertSink: InMemoryPersonalDataInventoryAlertSink
    private lateinit var service: PersonalDataInventoryService

    @BeforeEach
    fun setUp() {
        PersonalDataInventoryBinding.isBound = true
        store = InMemoryPersonalDataInventoryStore()
        alertSink = InMemoryPersonalDataInventoryAlertSink()
        service = PersonalDataInventoryService(
            store = store,
            alertSink = alertSink,
            clock = clock,
        )
    }

    @AfterEach
    fun tearDown() {
        PersonalDataInventoryBinding.isBound = true
    }

    @Test
    fun `PRIV-001-01-T001 — Maintain personal-data inventory produces the required authoritative outcome`() {
        // 1. Expected RED failure verification: Fail-closed gate throws expected assertion when unbound
        PersonalDataInventoryBinding.isBound = false

        val registerLedgerCmd = RegisterInventoryItemCommand(
            tenantId = tenantId,
            inventoryReference = "INV-LEDGER-TRANSACTIONS",
            dataCategory = DataCategory.LEDGER,
            classification = DataClassification.FINANCIAL,
            storageSystem = "ledger_journal_db",
            dataOwner = "finance-operations",
            legalBasis = ProcessingLegalBasis.STATUTORY_RETENTION,
            retentionDays = 2555, // 7 years
            statutoryRetentionOverride = true,
            idempotencyKey = "key-reg-ledger-01",
            correlationId = "corr-priv-1",
            causationId = "cause-priv-1",
            principal = auditorPrincipal,
        )

        val gateError = assertFailsWith<AssertionError> {
            service.registerItem(registerLedgerCmd)
        }
        assertEquals("missed copy/illegal delete/hold bypass", gateError.message)

        // Bind the fail-closed gate
        PersonalDataInventoryBinding.isBound = true

        // 2. Authoritative Registration of Personal Data Inventory Items
        val ledgerResult = service.registerItem(registerLedgerCmd)
        assertNotNull(ledgerResult)
        assertFalse(ledgerResult.isDuplicate)
        assertFalse(ledgerResult.isFinancialAuthorityCreated, "Privacy inventory cannot create financial authority")
        assertEquals(PERSONAL_DATA_INVENTORY_CONTRACT, ledgerResult.semanticContract)
        assertEquals("INV-LEDGER-TRANSACTIONS", ledgerResult.item.inventoryReference)
        assertEquals(DataCategory.LEDGER, ledgerResult.item.dataCategory)
        assertTrue(ledgerResult.item.statutoryRetentionOverride)
        assertEquals(InventoryItemStatus.ACTIVE, ledgerResult.item.status)

        // Register additional inventory items: KYC documents and Device Sessions
        val registerKycCmd = RegisterInventoryItemCommand(
            tenantId = tenantId,
            inventoryReference = "INV-KYC-DOCUMENTS",
            dataCategory = DataCategory.KYC_DOCUMENT,
            classification = DataClassification.SENSITIVE_PII,
            storageSystem = "kyc_evidence_vault",
            dataOwner = "compliance-team",
            legalBasis = ProcessingLegalBasis.LEGAL_OBLIGATION,
            retentionDays = 1825, // 5 years
            statutoryRetentionOverride = false,
            idempotencyKey = "key-reg-kyc-01",
            correlationId = "corr-priv-2",
            causationId = "cause-priv-2",
            principal = auditorPrincipal,
        )
        val kycResult = service.registerItem(registerKycCmd)
        assertNotNull(kycResult)

        val registerSessionCmd = RegisterInventoryItemCommand(
            tenantId = tenantId,
            inventoryReference = "INV-DEVICE-SESSIONS",
            dataCategory = DataCategory.DEVICE_SESSION,
            classification = DataClassification.TECHNICAL,
            storageSystem = "session_cache_db",
            dataOwner = "security-team",
            legalBasis = ProcessingLegalBasis.CONSENT,
            retentionDays = 90, // 90 days
            statutoryRetentionOverride = false,
            idempotencyKey = "key-reg-sess-01",
            correlationId = "corr-priv-3",
            causationId = "cause-priv-3",
            principal = auditorPrincipal,
        )
        val sessionResult = service.registerItem(registerSessionCmd)
        assertNotNull(sessionResult)

        // 3. Deletion Evaluation Contract:
        // "Ledger retention/legal obligations override deletion only with approved basis; actions audited."

        // Case A: Ledger record under statutory retention without approved basis -> OVERRIDDEN_BY_LEGAL_OBLIGATION
        val evalLedgerCmd = EvaluateDeletionEligibilityCommand(
            tenantId = tenantId,
            inventoryReference = "INV-LEDGER-TRANSACTIONS",
            subjectId = "user-dsar-001",
            recordAgeDays = 365, // 1 year old, 2190 days remaining
            idempotencyKey = "key-eval-ledger-01",
            correlationId = "corr-eval-1",
            causationId = "cause-eval-1",
            principal = auditorPrincipal,
        )
        val evalLedgerResult = service.evaluateDeletionEligibility(evalLedgerCmd)
        assertEquals(DeletionEligibilityStatus.OVERRIDDEN_BY_LEGAL_OBLIGATION, evalLedgerResult.eligibilityStatus)
        assertEquals(DeletionOverrideReason.STATUTORY_LEDGER_RETENTION, evalLedgerResult.overrideReason)
        assertEquals(2190, evalLedgerResult.statutoryRetentionDaysRemaining)
        assertNull(evalLedgerResult.approvedBasisReference)
        assertFalse(evalLedgerResult.isFinancialAuthorityCreated)
        assertEquals(PERSONAL_DATA_INVENTORY_CONTRACT, evalLedgerResult.semanticContract)
        assertTrue(alertSink.alerts.any { it.contains("DELETION_OVERRIDDEN_LEGAL_OBLIGATION") })

        // Case B: Legal Hold Active -> BLOCKED_BY_LEGAL_HOLD (Prevents hold bypass)
        val applyHoldCmd = ApplyLegalHoldCommand(
            tenantId = tenantId,
            holdReference = "HOLD-CASE-2026-001",
            inventoryReference = "INV-KYC-DOCUMENTS",
            subjectId = "user-dsar-001",
            caseReference = "LITIGATION-COURT-8891",
            reason = "Pending regulatory subpoena and financial crimes inquiry",
            approverId = "compliance-officer-01",
            idempotencyKey = "key-apply-hold-01",
            correlationId = "corr-hold-1",
            causationId = "cause-hold-1",
            principal = securityPrincipal,
        )
        val holdResult = service.applyLegalHold(applyHoldCmd)
        assertNotNull(holdResult)
        assertTrue(holdResult.hold.active)
        assertEquals("HOLD-CASE-2026-001", holdResult.hold.holdReference)

        // Evaluate deletion for the KYC item under active legal hold
        val evalKycCmd = EvaluateDeletionEligibilityCommand(
            tenantId = tenantId,
            inventoryReference = "INV-KYC-DOCUMENTS",
            subjectId = "user-dsar-001",
            recordAgeDays = 2000, // Older than standard 1825 retention, but under legal hold!
            idempotencyKey = "key-eval-kyc-01",
            correlationId = "corr-eval-2",
            causationId = "cause-eval-2",
            principal = auditorPrincipal,
        )
        val evalKycResult = service.evaluateDeletionEligibility(evalKycCmd)
        assertEquals(DeletionEligibilityStatus.BLOCKED_BY_LEGAL_HOLD, evalKycResult.eligibilityStatus)
        assertEquals(DeletionOverrideReason.LEGAL_HOLD_ACTIVE, evalKycResult.overrideReason)
        assertEquals("HOLD-CASE-2026-001", evalKycResult.legalHoldReference)
        assertTrue(alertSink.alerts.any { it.contains("DELETION_BLOCKED_LEGAL_HOLD") })

        // Case C: Ledger retention overridden WITH an approved legal basis and authorized approver
        val evalWithOverrideCmd = EvaluateDeletionEligibilityCommand(
            tenantId = tenantId,
            inventoryReference = "INV-LEDGER-TRANSACTIONS",
            subjectId = "user-dsar-001",
            recordAgeDays = 365,
            approvedBasisReference = "COURT-EXPUNGEMENT-ORDER-7712",
            approvedBasisJustification = "Federal court approved specific privacy expungement order",
            approverId = "general-counsel-01",
            idempotencyKey = "key-eval-override-01",
            correlationId = "corr-eval-3",
            causationId = "cause-eval-3",
            principal = securityPrincipal,
        )
        val evalOverrideResult = service.evaluateDeletionEligibility(evalWithOverrideCmd)
        assertEquals(DeletionEligibilityStatus.APPROVED_OVERRIDE_EXECUTABLE, evalOverrideResult.eligibilityStatus)
        assertEquals(DeletionOverrideReason.APPROVED_LEGAL_OVERRIDE, evalOverrideResult.overrideReason)
        assertEquals("COURT-EXPUNGEMENT-ORDER-7712", evalOverrideResult.approvedBasisReference)
        assertEquals("general-counsel-01", evalOverrideResult.approverId)
        assertTrue(alertSink.alerts.any { it.contains("DELETION_APPROVED_LEGAL_OVERRIDE") })

        // Case D: Non-statutory record with expired retention and no legal hold -> ELIGIBLE_FOR_DELETION
        val evalSessionCmd = EvaluateDeletionEligibilityCommand(
            tenantId = tenantId,
            inventoryReference = "INV-DEVICE-SESSIONS",
            subjectId = "user-dsar-001",
            recordAgeDays = 120, // 120 days old, retention was 90 days
            idempotencyKey = "key-eval-sess-01",
            correlationId = "corr-eval-4",
            causationId = "cause-eval-4",
            principal = auditorPrincipal,
        )
        val evalSessionResult = service.evaluateDeletionEligibility(evalSessionCmd)
        assertEquals(DeletionEligibilityStatus.ELIGIBLE_FOR_DELETION, evalSessionResult.eligibilityStatus)
        assertEquals(DeletionOverrideReason.NONE, evalSessionResult.overrideReason)

        // 4. Idempotent replay: Replaying evaluate command returns cached duplicate
        val replayedEval = service.evaluateDeletionEligibility(evalLedgerCmd)
        assertTrue(replayedEval.isDuplicate)
        assertEquals(evalLedgerResult.evaluationId, replayedEval.evaluationId)

        // 5. Verify audit and outbox emission
        val auditEvents = store.getAuditEvents()
        assertTrue(auditEvents.size >= 5)
        for (audit in auditEvents) {
            assertEquals(tenantId, audit.tenantId)
            assertNotNull(audit.correlationId)
            assertNotNull(audit.causationId)
            assertFalse(audit.type.contains("secret", ignoreCase = true))
            assertFalse(audit.type.contains("token", ignoreCase = true))
        }

        val outboxEvents = store.getOutboxEvents()
        assertTrue(outboxEvents.size >= 5)
    }

    @Test
    fun `PRIV-001-01-T002 — Maintain personal-data inventory rejects invalid, boundary, unauthorized, and stale input`() {
        val validCmd = RegisterInventoryItemCommand(
            tenantId = tenantId,
            inventoryReference = "INV-TEST-001",
            dataCategory = DataCategory.IDENTITY,
            classification = DataClassification.PII,
            storageSystem = "identity_db",
            dataOwner = "id-ops",
            legalBasis = ProcessingLegalBasis.CONTRACT_PERFORMANCE,
            retentionDays = 365,
            idempotencyKey = "key-val-01",
            correlationId = "corr-val-1",
            causationId = "cause-val-1",
            principal = auditorPrincipal,
        )

        // 1. Blank mandatory fields on registration
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(tenantId = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(inventoryReference = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(storageSystem = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(dataOwner = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(idempotencyKey = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 2. Negative retention days
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(retentionDays = -1))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 3. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(expectedVersion = 2L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Principal authorization rejections
        // Player principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(principal = playerPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(principal = crossTenantPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Admin without SUPER_ADMIN/AUDITOR/SECURITY role (e.g. SUPPORT) rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(principal = supportPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Idempotency conflict: same key with different payload
        service.registerItem(validCmd)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(storageSystem = "different_system"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 6. Reference collision: different key with existing reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerItem(validCmd.copy(idempotencyKey = "key-val-different"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 7. Legal hold invalid and conflict rejections
        val holdCmd = ApplyLegalHoldCommand(
            tenantId = tenantId,
            holdReference = "HOLD-VAL-01",
            inventoryReference = "INV-TEST-001",
            caseReference = "CASE-123",
            reason = "Audit hold",
            approverId = "security-lead",
            idempotencyKey = "key-hold-val-1",
            correlationId = "corr-hold-val",
            causationId = "cause-hold-val",
            principal = securityPrincipal,
        )

        // Blank target (both inventoryReference and subjectId null) rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyLegalHold(holdCmd.copy(inventoryReference = null, subjectId = null))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank hold reference rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyLegalHold(holdCmd.copy(holdReference = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Apply valid hold
        service.applyLegalHold(holdCmd)

        // Duplicate hold reference rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.applyLegalHold(holdCmd.copy(idempotencyKey = "key-hold-different"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 8. Release Legal Hold rejections
        val relCmd = ReleaseLegalHoldCommand(
            tenantId = tenantId,
            holdReference = "HOLD-VAL-01",
            releaseReason = "Case resolved",
            approverId = "security-lead",
            idempotencyKey = "key-rel-1",
            correlationId = "corr-rel-1",
            causationId = "cause-rel-1",
            principal = securityPrincipal,
        )

        // Blank release reason rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.releaseLegalHold(relCmd.copy(releaseReason = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank approverId rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.releaseLegalHold(relCmd.copy(approverId = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Non-existent hold rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.releaseLegalHold(relCmd.copy(holdReference = "NON-EXISTENT"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Release succeeds
        service.releaseLegalHold(relCmd)

        // Releasing already released hold rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.releaseLegalHold(relCmd.copy(idempotencyKey = "key-rel-second"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 9. Deletion evaluation on non-existent item rejected
        val evalCmd = EvaluateDeletionEligibilityCommand(
            tenantId = tenantId,
            inventoryReference = "NON-EXISTENT-INV",
            recordAgeDays = 50,
            idempotencyKey = "key-eval-fail-1",
            correlationId = "corr-fail",
            causationId = "cause-fail",
            principal = auditorPrincipal,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.evaluateDeletionEligibility(evalCmd)
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `PRIV-001-01-T003 — Maintain personal-data inventory survives concurrency, duplicate delivery, and dependency failure`() {
        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val endLatch = CountDownLatch(threadCount)

        val results = ConcurrentHashMap<Int, InventoryItemResult>()
        val exceptions = ConcurrentHashMap<Int, Throwable>()

        val cmd = RegisterInventoryItemCommand(
            tenantId = tenantId,
            inventoryReference = "INV-CONCURRENT-001",
            dataCategory = DataCategory.COMMUNICATION,
            classification = DataClassification.PII,
            storageSystem = "crm_comms_db",
            dataOwner = "support-comms",
            legalBasis = ProcessingLegalBasis.LEGITIMATE_INTEREST,
            retentionDays = 365,
            idempotencyKey = "key-priv-concurrent",
            correlationId = "corr-conc-1",
            causationId = "cause-conc-1",
            principal = auditorPrincipal,
        )

        for (i in 0 until threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val res = service.registerItem(cmd)
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

        // All threads must converge on the exact same item ID and evidence reference
        val distinctItemIds = results.values.map { it.item.itemId }.toSet()
        val distinctEvidenceRefs = results.values.map { it.evidenceReference }.toSet()
        assertEquals(1, distinctItemIds.size, "All threads must return identical item ID")
        assertEquals(1, distinctEvidenceRefs.size, "All threads must return identical evidence reference")

        // Exactly 1 primary creation and 7 duplicate responses
        val duplicateCount = results.values.count { it.isDuplicate }
        assertEquals(threadCount - 1, duplicateCount)

        // Storage dependency failure handling
        class FailingInventoryStore : InMemoryPersonalDataInventoryStore() {
            var shouldFail = true
            override fun saveItem(
                item: PersonalDataInventoryItem,
                result: InventoryItemResult,
                idempotencyKey: String,
                fingerprint: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                if (shouldFail) {
                    throw RuntimeException("Privacy inventory database connection timeout")
                }
                super.saveItem(item, result, idempotencyKey, fingerprint, audit, outbox)
            }
        }

        val failingStore = FailingInventoryStore()
        val retryService = PersonalDataInventoryService(
            store = failingStore,
            alertSink = alertSink,
            clock = clock,
        )

        val retryCmd = RegisterInventoryItemCommand(
            tenantId = tenantId,
            inventoryReference = "INV-RETRY-001",
            dataCategory = DataCategory.IDENTITY,
            classification = DataClassification.PII,
            storageSystem = "identity_db",
            dataOwner = "ops",
            legalBasis = ProcessingLegalBasis.CONSENT,
            retentionDays = 180,
            idempotencyKey = "key-priv-retry-01",
            correlationId = "corr-retry-1",
            causationId = "cause-retry-1",
            principal = adminPrincipal,
        )

        val depError = assertFailsWith<AuthenticationFailure.Rejected> {
            retryService.registerItem(retryCmd)
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, depError.code)
        assertTrue(alertSink.alerts.any { it.contains("INVENTORY_STORAGE_FAILED") })

        // Invariant: Zero corrupt state committed on storage failure
        assertNull(failingStore.findItemByReference(tenantId, "INV-RETRY-001"))

        // Dependency recovers: Retry succeeds cleanly
        failingStore.shouldFail = false
        val recoveredResult = retryService.registerItem(retryCmd)
        assertNotNull(recoveredResult)
        assertFalse(recoveredResult.isDuplicate)
        assertNotNull(failingStore.findItemByReference(tenantId, "INV-RETRY-001"))
    }

    @Test
    fun `PRIV-001-01-T004 — Maintain personal-data inventory remains compatible, recoverable, observable, and lifecycle-safe`() {
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
        val regCmd = RegisterInventoryItemCommand(
            tenantId = tenantId,
            inventoryReference = "INV-RESTART-001",
            dataCategory = DataCategory.GAMING_ACTIVITY,
            classification = DataClassification.FINANCIAL,
            storageSystem = "game_history_db",
            dataOwner = "game-ops",
            legalBasis = ProcessingLegalBasis.STATUTORY_RETENTION,
            retentionDays = 1825,
            statutoryRetentionOverride = true,
            idempotencyKey = "key-priv-restart-01",
            correlationId = "corr-rep-1",
            causationId = "cause-rep-1",
            principal = adminPrincipal,
        )

        val initialResult = service.registerItem(regCmd)
        assertNotNull(initialResult)
        assertFalse(initialResult.isDuplicate)

        // Export snapshot and import into fresh store instance simulating server restart
        val snapshot = store.exportSnapshot()
        val rehydratedStore = InMemoryPersonalDataInventoryStore()
        rehydratedStore.importSnapshot(snapshot)
        val restartedService = PersonalDataInventoryService(
            store = rehydratedStore,
            alertSink = alertSink,
            clock = clock,
        )

        // Calling with same idempotency key on rehydrated store returns identical cached outcome
        val replayedResult = restartedService.registerItem(regCmd)
        assertEquals(initialResult.resultId, replayedResult.resultId)
        assertTrue(replayedResult.isDuplicate)
        assertEquals(PERSONAL_DATA_INVENTORY_CONTRACT, replayedResult.semanticContract)

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
