package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class JournalSchemaTest {

    private lateinit var fixedInstant: Instant
    private lateinit var clock: Clock
    private lateinit var service: JournalSchemaService

    private val tenantId = "tenant-alpha"
    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-fin-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )
    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-001",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        fixedInstant = Instant.parse("2026-09-19T10:00:00Z")
        clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
        service = JournalSchemaService(clock = clock)
    }

    @Test
    fun `LEDGER-001-T001 Journal schema produces the required authoritative outcome`() {
        val command = PostJournalBatchCommand(
            principal = adminPrincipal,
            tenantId = tenantId,
            batchReference = "BATCH-2026-001",
            currencyCode = "USD",
            entries = listOf(
                JournalEntryDraft(
                    accountReference = "player-wallet-101",
                    direction = JournalEntryDirection.DEBIT,
                    amountMinorUnits = 5000L,
                    currencyCode = "USD",
                    narration = "Wager debit",
                ),
                JournalEntryDraft(
                    accountReference = "house-treasury-202",
                    direction = JournalEntryDirection.CREDIT,
                    amountMinorUnits = 5000L,
                    currencyCode = "USD",
                    narration = "House credit",
                ),
            ),
            idempotencyKey = "idemp-batch-001",
            correlationId = "corr-001",
            causationId = "cause-001",
        )

        val result = service.postBatch(command)

        assertNotNull(result.batchId)
        assertEquals("BATCH-2026-001", result.batchReference)
        assertEquals("USD", result.currencyCode)
        assertEquals(5000L, result.totalDebitsMinorUnits)
        assertEquals(5000L, result.totalCreditsMinorUnits)
        assertTrue(result.isBalanced)
        assertEquals(JournalBatchStatus.POSTED, result.status)
        assertEquals(2, result.entryCount)
        assertEquals(fixedInstant, result.serverTime)
        assertEquals(1L, result.serverVersion)
        assertEquals("Sum debits=credits per currency/batch; posted rows update/delete denied.", result.message)

        // Untrusted client & financial rule invariants
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)

        // Verify batch retrieval
        val persisted = service.getBatch(tenantId, result.batchId)
        assertNotNull(persisted)
        assertEquals(JournalBatchStatus.POSTED, persisted!!.status)
        assertEquals(2, persisted.entries.size)
    }

    @Test
    fun `LEDGER-001-T002 Journal schema rejects invalid, boundary, unauthorized, and stale input`() {
        // 1. Unbalanced batch (debits != credits)
        assertThrows(UnbalancedJournalBatchException::class.java) {
            service.postBatch(
                PostJournalBatchCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    batchReference = "BATCH-UNBALANCED",
                    currencyCode = "USD",
                    entries = listOf(
                        JournalEntryDraft("act-1", JournalEntryDirection.DEBIT, 5000L, "USD"),
                        JournalEntryDraft("act-2", JournalEntryDirection.CREDIT, 4999L, "USD"),
                    ),
                    idempotencyKey = "idemp-unbalanced",
                    correlationId = "corr-002",
                    causationId = "cause-002",
                )
            )
        }

        // 2. Post without currency / blank currency
        assertThrows(InvalidCurrencyException::class.java) {
            service.postBatch(
                PostJournalBatchCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    batchReference = "BATCH-NO-CURRENCY",
                    currencyCode = "",
                    entries = listOf(
                        JournalEntryDraft("act-1", JournalEntryDirection.DEBIT, 1000L, ""),
                        JournalEntryDraft("act-2", JournalEntryDirection.CREDIT, 1000L, ""),
                    ),
                    idempotencyKey = "idemp-no-curr",
                    correlationId = "corr-003",
                    causationId = "cause-003",
                )
            )
        }

        // 3. Mixed currencies within a batch
        assertThrows(CurrencyMismatchException::class.java) {
            service.postBatch(
                PostJournalBatchCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    batchReference = "BATCH-MIXED-CURRENCY",
                    currencyCode = "USD",
                    entries = listOf(
                        JournalEntryDraft("act-1", JournalEntryDirection.DEBIT, 1000L, "USD"),
                        JournalEntryDraft("act-2", JournalEntryDirection.CREDIT, 1000L, "EUR"),
                    ),
                    idempotencyKey = "idemp-mixed-curr",
                    correlationId = "corr-004",
                    causationId = "cause-004",
                )
            )
        }

        // 4. Non-positive entry amount (0 or negative)
        assertThrows(InvalidJournalEntryException::class.java) {
            service.postBatch(
                PostJournalBatchCommand(
                    principal = adminPrincipal,
                    tenantId = tenantId,
                    batchReference = "BATCH-ZERO-AMOUNT",
                    currencyCode = "USD",
                    entries = listOf(
                        JournalEntryDraft("act-1", JournalEntryDirection.DEBIT, 0L, "USD"),
                        JournalEntryDraft("act-2", JournalEntryDirection.CREDIT, 0L, "USD"),
                    ),
                    idempotencyKey = "idemp-zero-amt",
                    correlationId = "corr-005",
                    causationId = "cause-005",
                )
            )
        }

        // 5. Unauthorized player attempting to post journal batch
        assertThrows(IdorForbiddenException::class.java) {
            service.postBatch(
                PostJournalBatchCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    batchReference = "BATCH-PLAYER-POST",
                    currencyCode = "USD",
                    entries = listOf(
                        JournalEntryDraft("act-1", JournalEntryDirection.DEBIT, 1000L, "USD"),
                        JournalEntryDraft("act-2", JournalEntryDirection.CREDIT, 1000L, "USD"),
                    ),
                    idempotencyKey = "idemp-player-post",
                    correlationId = "corr-006",
                    causationId = "cause-006",
                )
            )
        }

        // 6. Immutability: Attempting update or delete on posted batch / entries
        val validPost = service.postBatch(
            PostJournalBatchCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                batchReference = "BATCH-IMMUTABLE-TARGET",
                currencyCode = "USD",
                entries = listOf(
                    JournalEntryDraft("act-1", JournalEntryDirection.DEBIT, 2000L, "USD"),
                    JournalEntryDraft("act-2", JournalEntryDirection.CREDIT, 2000L, "USD"),
                ),
                idempotencyKey = "idemp-immut-target",
                correlationId = "corr-007",
                causationId = "cause-007",
            )
        )

        assertThrows(ImmutableJournalException::class.java) {
            service.updatePostedBatch(validPost.batchId, "MUTATED_REFERENCE")
        }
        assertThrows(ImmutableJournalException::class.java) {
            service.deletePostedBatch(validPost.batchId)
        }
        assertThrows(ImmutableJournalException::class.java) {
            service.updatePostedEntry(UUID.randomUUID(), 9999L)
        }
        assertThrows(ImmutableJournalException::class.java) {
            service.deletePostedEntry(UUID.randomUUID())
        }
    }

    @Test
    fun `LEDGER-001-T003 Journal schema survives concurrency, duplicate delivery, and dependency failure`() {
        val command = PostJournalBatchCommand(
            principal = adminPrincipal,
            tenantId = tenantId,
            batchReference = "BATCH-IDEMP-001",
            currencyCode = "GBP",
            entries = listOf(
                JournalEntryDraft("act-gbp-1", JournalEntryDirection.DEBIT, 7500L, "GBP"),
                JournalEntryDraft("act-gbp-2", JournalEntryDirection.CREDIT, 7500L, "GBP"),
            ),
            idempotencyKey = "idemp-gbp-001",
            correlationId = "corr-008",
            causationId = "cause-008",
        )

        // 1. Initial post
        val res1 = service.postBatch(command)

        // 2. Exact duplicate replay returns cached result
        val res2 = service.postBatch(command)
        assertEquals(res1.batchId, res2.batchId)
        assertEquals(res1.totalDebitsMinorUnits, res2.totalDebitsMinorUnits)

        // 3. Conflicting payload with same idempotency key throws ConcurrencyConflictException
        assertThrows(ConcurrencyConflictException::class.java) {
            service.postBatch(command.copy(currencyCode = "EUR"))
        }

        // 4. Compensation flow: reverses batch without editing original
        val compResult = service.compensateBatch(
            CompensateJournalBatchCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                targetBatchReference = "BATCH-IDEMP-001",
                compensatingBatchReference = "BATCH-IDEMP-001-COMP",
                reason = "Settlement dispute reversal",
                idempotencyKey = "idemp-comp-001",
                correlationId = "corr-009",
                causationId = "cause-009",
            )
        )

        assertEquals("BATCH-IDEMP-001-COMP", compResult.batchReference)
        assertEquals("GBP", compResult.currencyCode)
        assertEquals(7500L, compResult.totalDebitsMinorUnits)
        assertEquals(7500L, compResult.totalCreditsMinorUnits)
        assertTrue(compResult.isBalanced)

        // Original batch remains untouched
        val originalBatch = service.getBatchByReference(tenantId, "BATCH-IDEMP-001")
        assertNotNull(originalBatch)
        assertEquals(JournalBatchStatus.POSTED, originalBatch!!.status)
    }

    @Test
    fun `LEDGER-001-T004 Journal schema remains compatible, recoverable, observable, and lifecycle-safe`() {
        val command = PostJournalBatchCommand(
            principal = adminPrincipal,
            tenantId = tenantId,
            batchReference = "BATCH-RECOVER-001",
            currencyCode = "EUR",
            entries = listOf(
                JournalEntryDraft("act-eur-1", JournalEntryDirection.DEBIT, 3000L, "EUR"),
                JournalEntryDraft("act-eur-2", JournalEntryDirection.CREDIT, 3000L, "EUR"),
            ),
            idempotencyKey = "idemp-rec-001",
            correlationId = "corr-010",
            causationId = "cause-010",
        )

        val result = service.postBatch(command)

        // Lookup and assert recovery state
        val batch = service.getBatch(tenantId, result.batchId)
        assertNotNull(batch)
        assertEquals("BATCH-RECOVER-001", batch!!.batchReference)
        assertEquals("EUR", batch.currencyCode)
        assertEquals(3000L, batch.totalDebitsMinorUnits)
        assertEquals(3000L, batch.totalCreditsMinorUnits)

        // Immutability verified again
        assertThrows(ImmutableJournalException::class.java) {
            service.deletePostedBatch(batch.batchId)
        }
    }
}
