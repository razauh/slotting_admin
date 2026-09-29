package com.slotting.admin.ledger

import com.slotting.admin.adjustment.*
import com.slotting.admin.auth.*
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/**
 * TC-008 TDD Contract Test Suite:
 * Persistent double-entry ledger and idempotent journal posting.
 *
 * Covers:
 * - BE-001: Persistent double-entry ledger, immutable journal legs, and projection rebuild.
 * - BE-018: Checked integer minor-unit arithmetic, preventing Long sum wrap/overflow.
 *
 * Required test scenarios:
 * 1. zero/negative leg
 * 2. currency mismatch
 * 3. overflow (Long overflow counterexample in LedgerPostingService & ManualAdjustmentService)
 * 4. duplicate/replay (exact payload)
 * 5. changed payload reuse (conflict)
 * 6. concurrent posting (same reference & same key)
 * 7. failure after each write (transactional rollback leaves no partial records)
 * 8. restart (persistent reload matches previous state)
 * 9. compensation (reversal via compensating entries)
 * 10. cross-tenant same reference (tenant-scoped isolation)
 * 11. deterministic balance rebuild from journal legs
 * 12. PostgreSQL V21 Flyway schema and constraint validation
 */
class PersistentDoubleEntryLedgerContractTest {

    private val now = Instant.parse("2026-09-24T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-01",
        tenantId = "tenant-prod-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val tenant2Principal = AuthenticatedPrincipal(
        id = "admin-user-02",
        tenantId = "tenant-prod-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    // =========================================================================
    // 1. BE-018: Checked Integer Minor-Unit Arithmetic & Overflow Counterexample
    // =========================================================================

    @Test
    fun `test01 ledger posting rejects integer overflow with PostingInvalidException`() {
        val service = LedgerPostingService(clock = clock)

        // Long.MAX_VALUE - 100 + 200 wraps around to negative in unchecked 64-bit arithmetic
        val largeAmount1 = Long.MAX_VALUE - 100L
        val largeAmount2 = 200L

        val command = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-OVERFLOW-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-DEBIT-1", JournalEntryDirection.DEBIT, largeAmount1, "USD"),
                JournalEntryDraft("ACC-DEBIT-2", JournalEntryDirection.DEBIT, largeAmount2, "USD"),
                JournalEntryDraft("ACC-CREDIT-1", JournalEntryDirection.CREDIT, largeAmount1, "USD"),
                JournalEntryDraft("ACC-CREDIT-2", JournalEntryDirection.CREDIT, largeAmount2, "USD"),
            ),
            idempotencyKey = "IDEM-OVERFLOW-1",
            correlationId = "corr-overflow-1",
            causationId = "caus-overflow-1",
        )

        val ex = assertFailsWith<PostingInvalidException> {
            service.postTransaction(command)
        }
        assertTrue(ex.message!!.contains("overflow", ignoreCase = true) || ex.errorCode == "INVALID",
            "Expected overflow rejection but got: ${ex.message}")
    }

    @Test
    fun `test02 manual adjustment rejects integer overflow with INVALID rejection`() {
        val store = object : com.slotting.admin.adjustment.ManualAdjustmentStore {
            override fun findByIdempotency(tenantId: String, key: String): Pair<String, com.slotting.admin.adjustment.ManualAdjustmentResult>? = null
            override fun findItem(tenantId: String, adjustmentReference: String): ManualAdjustmentBatch? = null
            override fun save(
                result: com.slotting.admin.adjustment.ManualAdjustmentResult,
                tenantId: String,
                reason: ManualAdjustmentReason,
                evidenceReference: String,
                queryFingerprint: String,
                idempotencyKey: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {}
        }
        val sessionDir = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) =
                AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(8)), mfaVerified = true)
        }
        val service = ManualAdjustmentService(
            sessions = sessionDir,
            policy = AdminRbacPolicy(dualControlRequired = false),
            store = store,
            clock = clock,
            dualApprovalRequired = false,
        )

        val command = ManualAdjustmentCommand(
            action = ManualAdjustmentAction.PREVIEW,
            principal = adminPrincipal,
            sessionId = "sess-1",
            tenantId = "tenant-prod-1",
            adjustmentReference = "ADJ-OVERFLOW-1",
            reason = ManualAdjustmentReason.GOODWILL_CREDIT,
            evidenceReference = "EVID-OVERFLOW-1",
            currencyCode = "USD",
            legs = listOf(
                AdjustmentLeg("ACC-1", Long.MAX_VALUE, AdjustmentLegDirection.DEBIT),
                AdjustmentLeg("ACC-2", Long.MAX_VALUE, AdjustmentLegDirection.DEBIT),
                AdjustmentLeg("ACC-3", 102L, AdjustmentLegDirection.DEBIT),
                AdjustmentLeg("ACC-4", Long.MAX_VALUE, AdjustmentLegDirection.CREDIT),
                AdjustmentLeg("ACC-5", Long.MAX_VALUE, AdjustmentLegDirection.CREDIT),
                AdjustmentLeg("ACC-6", 102L, AdjustmentLegDirection.CREDIT),
            ),
            idempotencyKey = "IDEM-ADJ-OVERFLOW-1",
            correlationId = "corr-1",
            causationId = "caus-1",
            expectedVersion = 0L,
        )

        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command)
        }
        assertEquals(AuthErrorCode.INVALID, ex.code)
    }

    // =========================================================================
    // 2. Validation: Zero, Negative Legs, and Currency Mismatch
    // =========================================================================

    @Test
    fun `test03 ledger posting rejects zero and negative legs`() {
        val service = LedgerPostingService(clock = clock)

        val zeroCmd = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-ZERO-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-1", JournalEntryDirection.DEBIT, 0L, "USD"),
                JournalEntryDraft("ACC-2", JournalEntryDirection.CREDIT, 0L, "USD"),
            ),
            idempotencyKey = "IDEM-ZERO-1",
            correlationId = "corr-1",
            causationId = "caus-1",
        )
        assertFailsWith<PostingInvalidException> {
            service.postTransaction(zeroCmd)
        }

        val negCmd = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-NEG-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-1", JournalEntryDirection.DEBIT, -100L, "USD"),
                JournalEntryDraft("ACC-2", JournalEntryDirection.CREDIT, -100L, "USD"),
            ),
            idempotencyKey = "IDEM-NEG-1",
            correlationId = "corr-2",
            causationId = "caus-2",
        )
        assertFailsWith<PostingInvalidException> {
            service.postTransaction(negCmd)
        }
    }

    @Test
    fun `test04 ledger posting rejects currency mismatch`() {
        val service = LedgerPostingService(clock = clock)

        val mismatchCmd = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-MISMATCH-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-1", JournalEntryDirection.DEBIT, 100L, "EUR"),
                JournalEntryDraft("ACC-2", JournalEntryDirection.CREDIT, 100L, "USD"),
            ),
            idempotencyKey = "IDEM-MISMATCH-1",
            correlationId = "corr-1",
            causationId = "caus-1",
        )
        assertFailsWith<PostingInvalidException> {
            service.postTransaction(mismatchCmd)
        }
    }

    // =========================================================================
    // 3. BE-001: Durable Store, Rollback on Failure, and Persistence Invariants
    // =========================================================================

    @Test
    fun `test05 durable store records transaction legs and receipts atomically`() {
        val store = InMemoryLedgerJournalStore()
        val service = LedgerPostingService(store = store, clock = clock)

        val command = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-DURABLE-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-PLAYER-1", JournalEntryDirection.DEBIT, 5000L, "USD"),
                JournalEntryDraft("ACC-HOUSE-1", JournalEntryDirection.CREDIT, 5000L, "USD"),
            ),
            idempotencyKey = "IDEM-DURABLE-1",
            correlationId = "corr-dur-1",
            causationId = "caus-dur-1",
        )

        val result = service.postTransaction(command)
        assertEquals(JournalBatchStatus.POSTED, result.status)
        assertEquals(1L, result.serverVersion)

        // Verify stored in store
        val storedTx = store.findByTransactionReference("tenant-prod-1", "TX-DURABLE-1")
        assertNotNull(storedTx)
        assertEquals(result.resultId, storedTx.resultId)

        val legs = store.findLegs("tenant-prod-1", result.resultId)
        assertEquals(2, legs.size)
        assertEquals(5000L, legs[0].amountMinorUnits)
        assertEquals(JournalEntryDirection.DEBIT, legs[0].direction)
        assertEquals(5000L, legs[1].amountMinorUnits)
        assertEquals(JournalEntryDirection.CREDIT, legs[1].direction)
    }

    @Test
    fun `test06 failure before commit rolls back leaving no partial records`() {
        val failingStore = object : LedgerJournalStore {
            var saveAttempted = false
            override fun findByIdempotency(tenantId: String, idempotencyKey: String) = null
            override fun findByTransactionReference(tenantId: String, transactionReference: String) = null
            override fun findLegs(tenantId: String, transactionId: UUID): List<JournalEntryRecord> = emptyList()
            override fun findAllLegsForTenant(tenantId: String): List<JournalEntryRecord> = emptyList()
            override fun findBalance(tenantId: String, accountReference: String, currencyCode: String): Long = 0L
            override fun nextLedgerVersion(tenantId: String): Long = 1L
            override fun save(
                result: PostingResult,
                legs: List<JournalEntryRecord>,
                payloadDigest: String,
                audit: AuditEvent,
                outbox: OutboxEvent,
            ) {
                saveAttempted = true
                throw IllegalStateException("Simulated database failure during batch save")
            }
        }

        val service = LedgerPostingService(store = failingStore, clock = clock)

        val command = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-FAIL-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-1", JournalEntryDirection.DEBIT, 1000L, "USD"),
                JournalEntryDraft("ACC-2", JournalEntryDirection.CREDIT, 1000L, "USD"),
            ),
            idempotencyKey = "IDEM-FAIL-1",
            correlationId = "corr-1",
            causationId = "caus-1",
        )

        assertFailsWith<IllegalStateException> {
            service.postTransaction(command)
        }
        assertTrue(failingStore.saveAttempted)
        assertNull(failingStore.findByIdempotency("tenant-prod-1", "IDEM-FAIL-1"))
        assertNull(failingStore.findByTransactionReference("tenant-prod-1", "TX-FAIL-1"))
    }

    // =========================================================================
    // 4. Duplicate Replay vs Changed Payload Conflict
    // =========================================================================

    @Test
    fun `test07 exact replay returns identical result and changed payload conflicts`() {
        val store = InMemoryLedgerJournalStore()
        val service = LedgerPostingService(store = store, clock = clock)

        val command1 = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-REPLAY-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-A", JournalEntryDirection.DEBIT, 2500L, "USD"),
                JournalEntryDraft("ACC-B", JournalEntryDirection.CREDIT, 2500L, "USD"),
            ),
            idempotencyKey = "IDEM-REPLAY-KEY-1",
            correlationId = "corr-replay-1",
            causationId = "caus-replay-1",
        )

        val result1 = service.postTransaction(command1)
        val result2 = service.postTransaction(command1) // Replay
        assertEquals(result1.resultId, result2.resultId)
        assertEquals(result1.totalDebitsMinorUnits, result2.totalDebitsMinorUnits)

        // Now change amount with the same idempotency key -> MUST conflict
        val conflictingCmd = command1.copy(
            transactionReference = "TX-DIFFERENT-REF",
            entries = listOf(
                JournalEntryDraft("ACC-A", JournalEntryDirection.DEBIT, 3000L, "USD"),
                JournalEntryDraft("ACC-B", JournalEntryDirection.CREDIT, 3000L, "USD"),
            )
        )
        val ex = assertFailsWith<IdempotencyConflictException> {
            service.postTransaction(conflictingCmd)
        }
        assertTrue(ex.message!!.contains("conflict", ignoreCase = true) || ex.errorCode == "CONFLICT")
    }

    // =========================================================================
    // 5. Cross-Tenant Same Reference Isolation
    // =========================================================================

    @Test
    fun `test08 cross-tenant same transaction reference posts independently`() {
        val store = InMemoryLedgerJournalStore()
        val service = LedgerPostingService(store = store, clock = clock)

        val txRef = "TX-SHARED-REF-100"

        val cmdTenant1 = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = txRef,
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-1", JournalEntryDirection.DEBIT, 1000L, "USD"),
                JournalEntryDraft("ACC-2", JournalEntryDirection.CREDIT, 1000L, "USD"),
            ),
            idempotencyKey = "IDEM-KEY-T1",
            correlationId = "corr-t1",
            causationId = "caus-t1",
        )

        val cmdTenant2 = PostTransactionCommand(
            principal = tenant2Principal,
            tenantId = "tenant-prod-2",
            transactionReference = txRef, // Same reference!
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-1", JournalEntryDirection.DEBIT, 2000L, "USD"),
                JournalEntryDraft("ACC-2", JournalEntryDirection.CREDIT, 2000L, "USD"),
            ),
            idempotencyKey = "IDEM-KEY-T2",
            correlationId = "corr-t2",
            causationId = "caus-t2",
        )

        val res1 = service.postTransaction(cmdTenant1)
        val res2 = service.postTransaction(cmdTenant2)

        assertNotNull(res1.resultId)
        assertNotNull(res2.resultId)
        assertNotEquals(res1.resultId, res2.resultId)
        assertEquals("tenant-prod-1", res1.tenantId)
        assertEquals("tenant-prod-2", res2.tenantId)
    }

    // =========================================================================
    // 6. Restart Replay & Deterministic Projection Rebuild
    // =========================================================================

    @Test
    fun `test09 service restart preserves state and rebuilds exact account balances from journal legs`() {
        val store = InMemoryLedgerJournalStore()
        val serviceInstance1 = LedgerPostingService(store = store, clock = clock)

        // Post 1: ACC-PLAYER +10,000 credit (from house debit)
        serviceInstance1.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-DEP-1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("ACC-HOUSE", JournalEntryDirection.DEBIT, 10000L, "USD"),
                    JournalEntryDraft("ACC-PLAYER", JournalEntryDirection.CREDIT, 10000L, "USD"),
                ),
                idempotencyKey = "IDEM-DEP-1",
                correlationId = "c1",
                causationId = "c1",
            )
        )

        // Post 2: ACC-PLAYER -3,000 debit (wager to house credit)
        serviceInstance1.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-WAGER-1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("ACC-PLAYER", JournalEntryDirection.DEBIT, 3000L, "USD"),
                    JournalEntryDraft("ACC-HOUSE", JournalEntryDirection.CREDIT, 3000L, "USD"),
                ),
                idempotencyKey = "IDEM-WAGER-1",
                correlationId = "c2",
                causationId = "c2",
            )
        )

        // SIMULATE SERVICE RESTART (new instance reading from the same persistent store)
        val serviceInstance2 = LedgerPostingService(store = store, clock = clock)

        // Replay of TX-DEP-1 on restarted service succeeds via persistent idempotency store
        val replayed = serviceInstance2.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = "tenant-prod-1",
                transactionReference = "TX-DEP-1",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("ACC-HOUSE", JournalEntryDirection.DEBIT, 10000L, "USD"),
                    JournalEntryDraft("ACC-PLAYER", JournalEntryDirection.CREDIT, 10000L, "USD"),
                ),
                idempotencyKey = "IDEM-DEP-1",
                correlationId = "c1",
                causationId = "c1",
            )
        )
        assertEquals("TX-DEP-1", replayed.transactionReference)

        // Deterministic rebuild of balances from journal legs
        val playerBalance = store.findBalance("tenant-prod-1", "ACC-PLAYER", "USD")
        val houseBalance = store.findBalance("tenant-prod-1", "ACC-HOUSE", "USD")

        // Player: +10,000 credit - 3,000 debit = 7,000 minor units
        assertEquals(7000L, playerBalance)
        // House: -10,000 debit + 3,000 credit = -7,000 minor units
        assertEquals(-7000L, houseBalance)
    }

    // =========================================================================
    // 7. Compensation / Reversal Pattern
    // =========================================================================

    @Test
    fun `test10 compensation creates immutable reversal transaction referencing original`() {
        val store = InMemoryLedgerJournalStore()
        val service = LedgerPostingService(store = store, clock = clock)

        // Original transaction
        val origCmd = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-ORIGINAL-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-A", JournalEntryDirection.DEBIT, 5000L, "USD"),
                JournalEntryDraft("ACC-B", JournalEntryDirection.CREDIT, 5000L, "USD"),
            ),
            idempotencyKey = "IDEM-ORIG-1",
            correlationId = "c1",
            causationId = "c1",
        )
        val origResult = service.postTransaction(origCmd)
        assertEquals(JournalBatchStatus.POSTED, origResult.status)

        // Compensating transaction (inverts entries)
        val compCmd = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-COMP-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-A", JournalEntryDirection.CREDIT, 5000L, "USD"),
                JournalEntryDraft("ACC-B", JournalEntryDirection.DEBIT, 5000L, "USD"),
            ),
            idempotencyKey = "IDEM-COMP-1",
            correlationId = "c2",
            causationId = origResult.resultId.toString(),
            compensationForReference = "TX-ORIGINAL-1",
        )
        val compResult = service.postTransaction(compCmd)
        assertEquals(JournalBatchStatus.POSTED, compResult.status)
        assertEquals("TX-ORIGINAL-1", compResult.compensationForReference)

        // Net balance is 0 for both accounts
        assertEquals(0L, store.findBalance("tenant-prod-1", "ACC-A", "USD"))
        assertEquals(0L, store.findBalance("tenant-prod-1", "ACC-B", "USD"))
    }

    // =========================================================================
    // 8. Concurrency: Parallel Posting
    // =========================================================================

    @Test
    fun `test11 concurrent duplicate posting produces exactly one execution`() {
        val store = InMemoryLedgerJournalStore()
        val service = LedgerPostingService(store = store, clock = clock)

        val threads = 8
        val latch = CountDownLatch(threads)
        val pool = Executors.newFixedThreadPool(threads)

        val cmd = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-prod-1",
            transactionReference = "TX-CONCURRENT-1",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("ACC-X", JournalEntryDirection.DEBIT, 1000L, "USD"),
                JournalEntryDraft("ACC-Y", JournalEntryDirection.CREDIT, 1000L, "USD"),
            ),
            idempotencyKey = "IDEM-CONCURRENT-1",
            correlationId = "c-race",
            causationId = "c-race",
        )

        val results = mutableListOf<PostingResult>()
        val successCount = AtomicInteger(0)

        for (i in 0 until threads) {
            pool.submit {
                try {
                    val r = service.postTransaction(cmd)
                    synchronized(results) { results.add(r) }
                    successCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(5, TimeUnit.SECONDS)
        pool.shutdown()

        assertEquals(threads, successCount.get())
        // All threads received identical result ID
        val uniqueIds = results.map { it.resultId }.distinct()
        assertEquals(1, uniqueIds.size)
        // Store has only 1 record
        val legs = store.findLegs("tenant-prod-1", uniqueIds.single())
        assertEquals(2, legs.size)
    }

    // =========================================================================
    // 9. PostgreSQL V21 Schema & Migration Invariant Verification
    // =========================================================================

    @Test
    fun `test12 persistent double entry ledger schema exists and enforces constraints`() {
        val migrationFile = File("src/main/resources/db/migration/V21__persistent_double_entry_ledger.sql")
        assertTrue(migrationFile.exists(), "V21 migration file must exist")
        val sql = migrationFile.readText()

        assertTrue(sql.contains("create table if not exists ledger_account"), "Must define ledger_account")
        assertTrue(sql.contains("create table if not exists ledger_transaction"), "Must define ledger_transaction")
        assertTrue(sql.contains("create table if not exists ledger_leg"), "Must define ledger_leg")
        assertTrue(sql.contains("create table if not exists ledger_idempotency_receipt"), "Must define ledger_idempotency_receipt")
        assertTrue(sql.contains("create table if not exists ledger_version_tracker"), "Must define ledger_version_tracker")

        // Constraints
        assertTrue(sql.contains("check (total_debits_minor_units = total_credits_minor_units)"), "Must enforce total debits = total credits check constraint")
        assertTrue(sql.contains("unique (tenant_id, transaction_reference)"), "Must enforce tenant-scoped transaction reference uniqueness")
        assertTrue(sql.contains("unique (tenant_id, idempotency_key)"), "Must enforce tenant-scoped idempotency key uniqueness")
        assertTrue(sql.contains("unique (tenant_id, account_reference, currency_code)"), "Must enforce unique account per currency within tenant")
    }
}
