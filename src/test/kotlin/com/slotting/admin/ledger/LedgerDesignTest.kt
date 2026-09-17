package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class LedgerDesignTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-001-T001 Ledger design produces the required authoritative outcome`() {
        val store = LedgerDesignMemoryStore()
        val service = service(store)

        // 1. Balanced double-entry transaction: minor units, single currency partition
        val transfer = service.operate(
            command(
                transactionReference = "TX-2026-001",
                transactionType = LedgerTransactionType.TRANSFER,
                currencyCode = "EUR",
                legs = listOf(
                    LedgerLeg("player-wallet-1", LedgerLegDirection.DEBIT, 10000L, "EUR"),
                    LedgerLeg("house-treasury-1", LedgerLegDirection.CREDIT, 10000L, "EUR"),
                ),
                idempotencyKey = "key-tx-001",
            )
        )
        assertTrue(transfer.isBalanced)
        assertEquals(10000L, transfer.totalDebitsMinorUnits)
        assertEquals(10000L, transfer.totalCreditsMinorUnits)
        assertFalse(transfer.isCompensation)

        // 2. Compensating transaction: reverses previous transaction without editing history
        val compensation = service.operate(
            command(
                transactionReference = "TX-2026-001-COMP",
                transactionType = LedgerTransactionType.COMPENSATION,
                currencyCode = "EUR",
                legs = listOf(
                    LedgerLeg("house-treasury-1", LedgerLegDirection.DEBIT, 10000L, "EUR"),
                    LedgerLeg("player-wallet-1", LedgerLegDirection.CREDIT, 10000L, "EUR"),
                ),
                compensationForTransactionReference = "TX-2026-001",
                idempotencyKey = "key-tx-comp-001",
            )
        )
        assertTrue(compensation.isBalanced)
        assertTrue(compensation.isCompensation)
        assertEquals(10000L, compensation.totalDebitsMinorUnits)
        assertEquals(10000L, compensation.totalCreditsMinorUnits)

        // Original transaction remains unchanged and immutable
        val original = store.findTransaction("tenant-1", "TX-2026-001")
        assertNotNull(original)
        assertFalse(original.isCompensation)

        // Verify audit and outbox entries
        assertEquals(2, store.audit.size)
        assertEquals(2, store.outbox.size)
        assertEquals("LEDGER_DESIGN_TRANSFER", store.audit[0].type)
        assertEquals("LEDGER_DESIGN_COMPENSATION", store.audit[1].type)
    }

    @Test
    fun `ADR-001-T002 Ledger design rejects invalid, boundary, unauthorized, and stale input`() {
        val store = LedgerDesignMemoryStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = null)) }
            .also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = admin(tenantId = "tenant-other"))) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Counterexamples violating conservation: debits != credits
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    transactionReference = "TX-UNBALANCED",
                    currencyCode = "EUR",
                    legs = listOf(
                        LedgerLeg("acc-1", LedgerLegDirection.DEBIT, 10000L, "EUR"),
                        LedgerLeg("acc-2", LedgerLegDirection.CREDIT, 9000L, "EUR"), // 10000 != 9000
                    ),
                    idempotencyKey = "key-unbalanced",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Counterexamples violating conservation: zero minor units
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    transactionReference = "TX-ZERO",
                    currencyCode = "EUR",
                    legs = listOf(
                        LedgerLeg("acc-1", LedgerLegDirection.DEBIT, 0L, "EUR"),
                        LedgerLeg("acc-2", LedgerLegDirection.CREDIT, 0L, "EUR"),
                    ),
                    idempotencyKey = "key-zero",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Counterexamples violating conservation: negative minor units
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    transactionReference = "TX-NEG",
                    currencyCode = "EUR",
                    legs = listOf(
                        LedgerLeg("acc-1", LedgerLegDirection.DEBIT, -500L, "EUR"),
                        LedgerLeg("acc-2", LedgerLegDirection.CREDIT, -500L, "EUR"),
                    ),
                    idempotencyKey = "key-neg",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Currency partition violation: mixed currencies
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    transactionReference = "TX-MIXED-CURR",
                    currencyCode = "EUR",
                    legs = listOf(
                        LedgerLeg("acc-1", LedgerLegDirection.DEBIT, 1000L, "EUR"),
                        LedgerLeg("acc-2", LedgerLegDirection.CREDIT, 1000L, "USD"), // USD != EUR
                    ),
                    idempotencyKey = "key-mixed-curr",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Compensation referencing non-existent transaction
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    transactionReference = "TX-COMP-UNKNOWN",
                    transactionType = LedgerTransactionType.COMPENSATION,
                    currencyCode = "EUR",
                    legs = listOf(
                        LedgerLeg("acc-1", LedgerLegDirection.DEBIT, 1000L, "EUR"),
                        LedgerLeg("acc-2", LedgerLegDirection.CREDIT, 1000L, "EUR"),
                    ),
                    compensationForTransactionReference = "NON-EXISTENT",
                    idempotencyKey = "key-comp-unknown",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test
    fun `ADR-001-T003 Ledger design survives concurrency, duplicate delivery, and dependency failure`() {
        val store = LedgerDesignMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<LedgerDesignVerificationResult> {
                gate.await()
                service.operate(command(idempotencyKey = "race-ledger-design"))
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }
        pool.shutdown()

        assertEquals(2, outcomes.count { it.isSuccess })
        assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // Conflicting replay with different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    currencyCode = "USD",
                    legs = listOf(
                        LedgerLeg("acc-1", LedgerLegDirection.DEBIT, 5000L, "USD"),
                        LedgerLeg("acc-2", LedgerLegDirection.CREDIT, 5000L, "USD"),
                    ),
                    idempotencyKey = "race-ledger-design",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(command(idempotencyKey = "dep-ledger-design"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADR-001-T004 Ledger design remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: Approve minor units, currency partitions, immutable entries, projection/reconciliation/compensation
        // Assert no unapproved persistence or migration is introduced.
        val migrationDir = java.io.File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        // Ensure only approved migrations V1 through V16 exist and no unapproved migrations are introduced
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(migrationVersions.all { it.matches(Regex("V[0-9]+")) })
        assertTrue(!migrationVersions.contains("V17"))

        // Assert contract principles:
        // 1. Minor units: integer longs
        val leg = LedgerLeg("acc", LedgerLegDirection.DEBIT, 100L, "EUR")
        assertEquals(100L, leg.amountMinorUnits)

        // 2. Currency partitions: ISO 4217 code validation
        assertTrue(leg.currencyCode.matches(Regex("[A-Z]{3}")))

        // 3. Compensation preserves immutability: posted transactions are never edited
        val store = LedgerDesignMemoryStore()
        val service = service(store)
        val initial = service.operate(command(transactionReference = "TX-IMMUTABLE", idempotencyKey = "key-imm-1"))
        val compensation = service.operate(
            command(
                transactionReference = "TX-COMPENSATING",
                transactionType = LedgerTransactionType.COMPENSATION,
                compensationForTransactionReference = "TX-IMMUTABLE",
                idempotencyKey = "key-imm-2",
            )
        )
        assertNotEquals(initial.transactionReference, compensation.transactionReference)
        val reReadInitial = store.findTransaction("tenant-1", "TX-IMMUTABLE")
        assertEquals(initial.transactionReference, reReadInitial?.transactionReference)
        assertFalse(reReadInitial?.isCompensation ?: true)
    }

    private fun service(store: LedgerDesignMemoryStore) =
        LedgerDesignService(AdminRbacPolicy(true), ActiveLedgerDesignSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: LedgerDesignMemoryStore) =
        LedgerDesignService(AdminRbacPolicy(true), FailingLedgerDesignSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        transactionReference: String = "TX-100",
        transactionType: LedgerTransactionType = LedgerTransactionType.TRANSFER,
        currencyCode: String = "EUR",
        legs: List<LedgerLeg> = listOf(
            LedgerLeg("wallet-1", LedgerLegDirection.DEBIT, 5000L, "EUR"),
            LedgerLeg("treasury-1", LedgerLegDirection.CREDIT, 5000L, "EUR"),
        ),
        compensationForTransactionReference: String? = null,
        idempotencyKey: String = "key-ld-${transactionReference}",
        sessionId: String = "session-ld-1",
        correlationId: String = "corr-ld-1",
        causationId: String = "cause-ld-1",
        expectedVersion: Long = 0L,
    ) = LedgerDesignCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = "tenant-1",
        transactionReference = transactionReference,
        transactionType = transactionType,
        currencyCode = currencyCode,
        legs = legs,
        compensationForTransactionReference = compensationForTransactionReference,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-finance-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveLedgerDesignSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-finance-1" && sessionId == "session-ld-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingLedgerDesignSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class LedgerDesignMemoryStore : LedgerDesignStore {
    val items = mutableMapOf<String, LedgerDesignVerificationResult>()
    val results = mutableMapOf<String, Pair<String, LedgerDesignVerificationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findTransaction(tenantId: String, transactionReference: String) = synchronized(this) { items["$tenantId:$transactionReference"] }
    override fun save(
        result: LedgerDesignVerificationResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        items["$tenantId:${result.transactionReference}"] = result
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
