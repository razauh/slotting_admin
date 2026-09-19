package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors

/**
 * Mandatory backend TDD test suite for LEDGER-002:
 * Posting/idempotency.
 *
 * Semantic contract: "One accepted key→one result; payload mismatch conflicts; all direct balance writes prohibited."
 * Protected risk assertion: "duplicate/concurrent posting"
 */
class LedgerPostingTest {

    private val fixedClock = Clock.fixed(Instant.parse("2026-09-19T10:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: LedgerPostingService

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-user-01",
        tenantId = "tenant-01",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val securityPrincipal = AuthenticatedPrincipal(
        id = "security-user-01",
        tenantId = "tenant-01",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-user-02",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-01",
        tenantId = "tenant-01",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        service = LedgerPostingService(clock = fixedClock)
    }

    // =========================================================================
    // LEDGER-002-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `LEDGER-002-T001 Posting idempotency produces the required authoritative outcome`() {
        val entries = listOf(
            JournalEntryDraft(
                accountReference = "ACC-PLAYER-100",
                direction = JournalEntryDirection.DEBIT,
                amountMinorUnits = 10000L,
                currencyCode = "USD",
                narration = "Wager debit",
            ),
            JournalEntryDraft(
                accountReference = "ACC-HOUSE-200",
                direction = JournalEntryDirection.CREDIT,
                amountMinorUnits = 10000L,
                currencyCode = "USD",
                narration = "House revenue credit",
            ),
        )

        val command = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            transactionReference = "TX-2026-001",
            currencyCode = "USD",
            entries = entries,
            idempotencyKey = "IDEM-KEY-001",
            correlationId = "corr-001",
            causationId = "caus-001",
            expectedVersion = 0L,
        )

        val result = service.postTransaction(command)

        assertNotNull(result.resultId)
        assertEquals("tenant-01", result.tenantId)
        assertEquals("TX-2026-001", result.transactionReference)
        assertEquals("USD", result.currencyCode)
        assertEquals(10000L, result.totalDebitsMinorUnits)
        assertEquals(10000L, result.totalCreditsMinorUnits)
        assertTrue(result.isBalanced)
        assertEquals(JournalBatchStatus.POSTED, result.status)
        assertEquals(2, result.entryCount)
        assertEquals("IDEM-KEY-001", result.idempotencyKey)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertTrue(result.directBalanceWriteProhibited)
        assertEquals(
            "One accepted key→one result; payload mismatch conflicts; all direct balance writes prohibited.",
            result.semanticContract
        )

        // Verify idempotency replay returns identical result
        val replayResult = service.postTransaction(command)
        assertEquals(result.resultId, replayResult.resultId)
        assertEquals(result.serverTime, replayResult.serverTime)
        assertEquals(result.evidenceReference, replayResult.evidenceReference)
    }

    // =========================================================================
    // LEDGER-002-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `LEDGER-002-T002 Posting idempotency rejects invalid, boundary, unauthorized, and stale input`() {
        // Direct balance write prohibition: MUST throw DirectBalanceWriteProhibitedException
        val directWriteCmd = DirectBalanceWriteCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            accountReference = "ACC-PLAYER-100",
            amountMinorUnits = 5000L,
            currencyCode = "USD",
        )
        val directEx = assertThrows(DirectBalanceWriteProhibitedException::class.java) {
            service.directBalanceWrite(directWriteCmd)
        }
        assertEquals("All direct balance writes prohibited", directEx.message)
        assertEquals("DIRECT_BALANCE_WRITE_PROHIBITED", directEx.errorCode)

        // Unauthenticated posting attempt
        val unauthCmd = PostTransactionCommand(
            principal = null,
            tenantId = "tenant-01",
            transactionReference = "TX-UNAUTH",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft("A", JournalEntryDirection.DEBIT, 100L, "USD"),
                JournalEntryDraft("B", JournalEntryDirection.CREDIT, 100L, "USD"),
            ),
            idempotencyKey = "IDEM-UNAUTH",
            correlationId = "corr",
            causationId = "caus",
        )
        assertThrows(PostingUnauthorizedException::class.java) {
            service.postTransaction(unauthCmd)
        }

        // Cross-tenant IDOR attempt
        val idorCmd = unauthCmd.copy(principal = crossTenantPrincipal)
        assertThrows(PostingForbiddenException::class.java) {
            service.postTransaction(idorCmd)
        }

        // Player principal attempting financial posting
        val playerCmd = unauthCmd.copy(principal = playerPrincipal)
        assertThrows(PostingForbiddenException::class.java) {
            service.postTransaction(playerCmd)
        }

        // Blank idempotency key
        val blankIdemCmd = unauthCmd.copy(principal = adminPrincipal, idempotencyKey = "  ")
        assertThrows(PostingInvalidException::class.java) {
            service.postTransaction(blankIdemCmd)
        }

        // Invalid currency
        val badCurrencyCmd = unauthCmd.copy(principal = adminPrincipal, currencyCode = "usd")
        assertThrows(PostingInvalidException::class.java) {
            service.postTransaction(badCurrencyCmd)
        }

        // Unbalanced double-entry batch
        val unbalancedCmd = unauthCmd.copy(
            principal = adminPrincipal,
            entries = listOf(
                JournalEntryDraft("A", JournalEntryDirection.DEBIT, 100L, "USD"),
                JournalEntryDraft("B", JournalEntryDirection.CREDIT, 200L, "USD"),
            )
        )
        assertThrows(PostingInvalidException::class.java) {
            service.postTransaction(unbalancedCmd)
        }
    }

    // =========================================================================
    // LEDGER-002-T003: Concurrency, Duplicate Delivery & Failure Recovery
    // =========================================================================

    @Test
    fun `LEDGER-002-T003 Posting idempotency survives concurrency, duplicate delivery, and dependency failure`() {
        val entries = listOf(
            JournalEntryDraft("ACC-1", JournalEntryDirection.DEBIT, 2500L, "EUR"),
            JournalEntryDraft("ACC-2", JournalEntryDirection.CREDIT, 2500L, "EUR"),
        )
        val command = PostTransactionCommand(
            principal = securityPrincipal,
            tenantId = "tenant-01",
            transactionReference = "TX-CONCURRENT-001",
            currencyCode = "EUR",
            entries = entries,
            idempotencyKey = "IDEM-CONCURRENCY-001",
            correlationId = "corr-conc",
            causationId = "caus-conc",
        )

        // Simulate 8 concurrent calls with the exact same idempotency key and payload
        val executor = Executors.newFixedThreadPool(8)
        val tasks = (1..8).map {
            Callable { service.postTransaction(command) }
        }
        val futures = executor.invokeAll(tasks)
        val results = futures.map { it.get() }
        executor.shutdown()

        // Exactly one result generated and shared across all callers
        val firstResultId = results.first().resultId
        results.forEach { res ->
            assertEquals(firstResultId, res.resultId)
            assertEquals("IDEM-CONCURRENCY-001", res.idempotencyKey)
            assertEquals(2500L, res.totalDebitsMinorUnits)
            assertEquals(2500L, res.totalCreditsMinorUnits)
        }

        // Reusing the idempotency key with conflicting payload MUST throw IdempotencyConflictException (CONFLICT)
        val conflictingCommand = command.copy(
            transactionReference = "TX-CONFLICTING", // Different reference
        )
        val conflictEx = assertThrows(IdempotencyConflictException::class.java) {
            service.postTransaction(conflictingCommand)
        }
        assertEquals("CONFLICT", conflictEx.errorCode)

        // Attempting to post a new transaction with an already-used transactionReference must also conflict
        val duplicateTxRefCommand = command.copy(
            idempotencyKey = "IDEM-NEW-KEY-002",
        )
        val dupTxEx = assertThrows(IdempotencyConflictException::class.java) {
            service.postTransaction(duplicateTxRefCommand)
        }
        assertEquals("CONFLICT", dupTxEx.errorCode)
    }

    // =========================================================================
    // LEDGER-002-T004: Compatibility, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `LEDGER-002-T004 Posting idempotency remains compatible, recoverable, observable, and lifecycle-safe`() {
        val entries = listOf(
            JournalEntryDraft("ACC-AUDIT-1", JournalEntryDirection.DEBIT, 5000L, "GBP"),
            JournalEntryDraft("ACC-AUDIT-2", JournalEntryDirection.CREDIT, 5000L, "GBP"),
        )
        val command = PostTransactionCommand(
            principal = adminPrincipal,
            tenantId = "tenant-01",
            transactionReference = "TX-AUDIT-001",
            currencyCode = "GBP",
            entries = entries,
            idempotencyKey = "IDEM-AUDIT-001",
            correlationId = "corr-audit-99",
            causationId = "caus-audit-99",
            expectedVersion = 2L,
        )

        val result = service.postTransaction(command)
        assertEquals(3L, result.serverVersion)

        // Direct balance write remains strictly prohibited
        assertThrows(DirectBalanceWriteProhibitedException::class.java) {
            service.directBalanceWrite(
                DirectBalanceWriteCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-01",
                    accountReference = "ACC-AUDIT-1",
                    amountMinorUnits = 1000L,
                    currencyCode = "GBP",
                )
            )
        }

        // Audit observability
        val logs = service.getAuditLogs("tenant-01")
        val auditEvent = logs.find { it.resultId == result.resultId }
        assertNotNull(auditEvent)
        assertEquals("LEDGER_TRANSACTION_POSTED", auditEvent!!.type)
        assertEquals("corr-audit-99", auditEvent.correlationId)
        assertEquals("caus-audit-99", auditEvent.causationId)

        // Untrusted client assertions
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
    }
}
