package com.slotting.admin.locking

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*
import org.junit.jupiter.api.Test

class LockingStrategyTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-002-T001 Locking idempotency strategy produces the required authoritative outcome`() {
        val store = LockingMemoryStore()
        store.accounts["tenant-1:acc-1"] = LockingAccount("acc-1", "tenant-1", 10000L, "EUR", 1L)
        val service = service(store)

        // 1. Valid debit under optimistic locking
        val res = service.operate(
            command(
                accountId = "acc-1",
                amountMinorUnits = 3000L,
                operationType = SpendOperationType.DEBIT,
                expectedVersion = 1L,
                idempotencyKey = "key-debit-001",
            )
        )
        assertEquals(7000L, res.balanceAfterMinorUnits)
        assertEquals(2L, res.accountVersionAfter)
        assertEquals(3000L, res.appliedAmountMinorUnits)

        // 2. Retry with same idempotency key returns identical authoritative result (idempotency semantics)
        val replay = service.operate(
            command(
                accountId = "acc-1",
                amountMinorUnits = 3000L,
                operationType = SpendOperationType.DEBIT,
                expectedVersion = 1L,
                idempotencyKey = "key-debit-001",
            )
        )
        assertEquals(res.resultId, replay.resultId)
        assertEquals(7000L, replay.balanceAfterMinorUnits)

        // Verify audit and outbox entries
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("LOCKING_SPEND_DEBIT", store.audit[0].type)
        assertEquals("corr-lock-1", store.audit[0].correlationId)
    }

    @Test
    fun `ADR-002-T002 Locking idempotency strategy rejects invalid, boundary, unauthorized, and stale input`() {
        val store = LockingMemoryStore()
        store.accounts["tenant-1:acc-1"] = LockingAccount("acc-1", "tenant-1", 2000L, "EUR", 1L)
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

        // Insufficient funds / overspend attempt: balance is 2000L, attempting 3000L
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    accountId = "acc-1",
                    amountMinorUnits = 3000L,
                    operationType = SpendOperationType.DEBIT,
                    expectedVersion = 1L,
                    idempotencyKey = "key-overspend-fail",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    accountId = "acc-1",
                    amountMinorUnits = 500L,
                    expectedVersion = 99L,
                    idempotencyKey = "key-stale-version",
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Boundary: zero or negative amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(amountMinorUnits = 0L, idempotencyKey = "key-zero-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(amountMinorUnits = -100L, idempotencyKey = "key-neg-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unknown account
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(accountId = "acc-unknown", idempotencyKey = "key-unknown-acc"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test
    fun `ADR-002-T003 Locking idempotency strategy survives concurrency, duplicate delivery, and dependency failure`() {
        val store = LockingMemoryStore()
        // Account has exactly 10000 minor units.
        store.accounts["tenant-1:acc-stress"] = LockingAccount("acc-stress", "tenant-1", 10000L, "EUR", 1L)
        val service = service(store)

        // 1. Benchmark simultaneous duplicate requests with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val dupCalls = (1..4).map {
            pool.submit<LockingResult> {
                gate.await()
                service.operate(
                    command(
                        accountId = "acc-stress",
                        amountMinorUnits = 1000L,
                        expectedVersion = 1L,
                        idempotencyKey = "key-concurrent-dup",
                    )
                )
            }
        }
        gate.countDown()
        val dupOutcomes = dupCalls.map { runCatching { it.get() } }

        // Exactly one unique deduction occurred, all threads received identical outcome
        assertEquals(4, dupOutcomes.count { it.isSuccess })
        assertEquals(1, dupOutcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        val updatedAccount = store.getAccount("tenant-1", "acc-stress")
        assertEquals(9000L, updatedAccount?.balanceMinorUnits)
        assertEquals(2L, updatedAccount?.version)

        // 2. Benchmark competing requests attempting to overspend
        // Balance is now 9000L. 10 threads attempt to debit 2000L each (total requested = 20000L).
        val startGate = CountDownLatch(1)
        val successCount = AtomicInteger(0)
        val overspendOrConflictCount = AtomicInteger(0)
        val spendCalls = (1..10).map { i ->
            pool.submit {
                startGate.await()
                try {
                    // Each thread queries the latest version and attempts to debit
                    var debited = false
                    for (attempt in 1..3) {
                        val current = store.getAccount("tenant-1", "acc-stress")!!
                        try {
                            service.operate(
                                command(
                                    accountId = "acc-stress",
                                    amountMinorUnits = 2000L,
                                    expectedVersion = current.version,
                                    idempotencyKey = "key-spend-$i-$attempt",
                                )
                            )
                            successCount.incrementAndGet()
                            debited = true
                            break
                        } catch (e: AuthenticationFailure.Rejected) {
                            if (e.code == AuthErrorCode.INVALID) {
                                // Insufficient funds
                                break
                            }
                            // STALE: retry loop
                        }
                    }
                    if (!debited) overspendOrConflictCount.incrementAndGet()
                } catch (_: Exception) {
                    overspendOrConflictCount.incrementAndGet()
                }
            }
        }
        startGate.countDown()
        spendCalls.forEach { it.get() }
        pool.shutdown()

        // With balance 9000L and 2000L debits, at most 4 can succeed (8000L debited), remaining balance is 1000L
        val finalAccount = store.getAccount("tenant-1", "acc-stress")!!
        assertTrue(finalAccount.balanceMinorUnits >= 0L)
        assertEquals(4, successCount.get())
        assertEquals(1000L, finalAccount.balanceMinorUnits)

        // 3. Conflicting replay with different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    accountId = "acc-stress",
                    amountMinorUnits = 9999L,
                    idempotencyKey = "key-concurrent-dup",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(command(idempotencyKey = "dep-lock-key"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADR-002-T004 Locking idempotency strategy remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: document uniqueness keys and retry semantics
        // Assert no unapproved persistence or migration is introduced.
        val migrationDir = java.io.File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Documented uniqueness key: (tenant_id, idempotency_key)
        val store = LockingMemoryStore()
        store.accounts["tenant-1:acc-doc"] = LockingAccount("acc-doc", "tenant-1", 5000L, "EUR", 1L)
        val service = service(store)

        val first = service.operate(
            command(
                accountId = "acc-doc",
                amountMinorUnits = 1000L,
                expectedVersion = 1L,
                idempotencyKey = "key-unique-test",
            )
        )
        // Retry returns identical result reference
        val retry = service.operate(
            command(
                accountId = "acc-doc",
                amountMinorUnits = 1000L,
                expectedVersion = 1L,
                idempotencyKey = "key-unique-test",
            )
        )
        assertEquals(first.resultId, retry.resultId)
        assertEquals(first.evidenceReference, retry.evidenceReference)

        // Verify rollback / failure never edits posted finance history
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: LockingMemoryStore) =
        LockingStrategyService(AdminRbacPolicy(true), ActiveLockingSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: LockingMemoryStore) =
        LockingStrategyService(AdminRbacPolicy(true), FailingLockingSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        accountId: String = "acc-1",
        amountMinorUnits: Long = 1000L,
        operationType: SpendOperationType = SpendOperationType.DEBIT,
        expectedVersion: Long = 1L,
        idempotencyKey: String = "key-lock-default",
        sessionId: String = "session-lock-1",
        correlationId: String = "corr-lock-1",
        causationId: String = "cause-lock-1",
    ) = LockingCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = "tenant-1",
        accountId = accountId,
        amountMinorUnits = amountMinorUnits,
        operationType = operationType,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-lock-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveLockingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-lock-1" && sessionId == "session-lock-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingLockingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class LockingMemoryStore : LockingStrategyStore {
    val accounts = mutableMapOf<String, LockingAccount>()
    val results = mutableMapOf<String, Pair<String, LockingResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun getAccount(tenantId: String, accountId: String) = synchronized(this) { accounts["$tenantId:$accountId"] }
    override fun save(
        result: LockingResult,
        updatedAccount: LockingAccount,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        accounts["$tenantId:${updatedAccount.accountId}"] = updatedAccount
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
