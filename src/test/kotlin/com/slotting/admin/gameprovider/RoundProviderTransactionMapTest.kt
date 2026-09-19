package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class RoundProviderTransactionMapTest {

    private val now = Instant.parse("2026-09-19T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-casino-round"
    private val providerId = "prov-evolution"
    private val gameId = "game-roulette-live"
    private val currencyUsd = "USD"
    private val currencyEur = "EUR"

    private lateinit var store: InMemoryRoundProviderTransactionStore
    private lateinit var service: RoundProviderTransactionMapService

    @BeforeEach
    fun setUp() {
        RoundProviderTransactionBinding.isBound = true
        store = InMemoryRoundProviderTransactionStore()
        service = RoundProviderTransactionMapService(store = store, clock = clock)
    }

    @AfterEach
    fun tearDown() {
        RoundProviderTransactionBinding.isBound = true
    }

    // =========================================================================
    // GAME-005-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `GAME-005-T001 Round provider transaction map produces the required authoritative outcome`() {
        // 1. Prove fail-closed gate throws expected RED assertion error when unbound
        RoundProviderTransactionBinding.isBound = false
        val playerId = UUID.randomUUID()
        val betCmd = MapProviderTransactionCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-evo-001",
            externalTransactionId = "tx-evo-bet-001",
            playerId = playerId,
            gameId = gameId,
            transactionType = ProviderTransactionType.BET,
            amountMinorUnits = 500L,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-bet-001",
            correlationId = "corr-bet-001",
            causationId = "cause-bet-001",
        )

        val redError = assertFailsWith<AssertionError> {
            service.mapTransaction(betCmd)
        }
        assertEquals("ID collision/currency mismatch", redError.message)

        // Bind the gate
        RoundProviderTransactionBinding.isBound = true

        // 2. Map primary BET transaction
        val betResult = service.mapTransaction(betCmd)

        // Assert: Unique provider+tenant+transaction; immutable lineage.
        assertNotNull(betResult)
        assertEquals(tenantId, betResult.tenantId)
        assertEquals(providerId, betResult.providerId)
        assertEquals("rnd-evo-001", betResult.externalRoundId)
        assertEquals("tx-evo-bet-001", betResult.externalTransactionId)
        assertEquals(ProviderTransactionType.BET, betResult.transactionType)
        assertEquals(500L, betResult.amountMinorUnits)
        assertEquals(currencyUsd, betResult.currencyCode)
        assertEquals(CanonicalRoundStatus.OPEN, betResult.roundStatus)
        assertEquals(500L, betResult.roundTotalDebitMinorUnits)
        assertEquals(0L, betResult.roundTotalCreditMinorUnits)
        assertEquals(-500L, betResult.roundNetOutcomeMinorUnits)

        // 3. Map subsequent WIN transaction settling the round
        val winCmd = MapProviderTransactionCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-evo-001",
            externalTransactionId = "tx-evo-win-001",
            playerId = playerId,
            gameId = gameId,
            transactionType = ProviderTransactionType.WIN,
            amountMinorUnits = 1500L,
            currencyCode = currencyUsd,
            settleRound = true,
            idempotencyKey = "idemp-win-001",
            correlationId = "corr-win-001",
            causationId = "cause-win-001",
        )
        val winResult = service.mapTransaction(winCmd)

        assertNotNull(winResult)
        assertEquals(betResult.canonicalRoundId, winResult.canonicalRoundId)
        assertEquals(CanonicalRoundStatus.SETTLED, winResult.roundStatus)
        assertEquals(500L, winResult.roundTotalDebitMinorUnits)
        assertEquals(1500L, winResult.roundTotalCreditMinorUnits)
        assertEquals(1000L, winResult.roundNetOutcomeMinorUnits)

        // Verify immutable lineage in store
        val roundTxs = store.findRoundTransactions(tenantId, betResult.canonicalRoundId)
        assertEquals(2, roundTxs.size)
        assertEquals(1L, roundTxs[0].sequenceNumber)
        assertEquals(ProviderTransactionType.BET, roundTxs[0].transactionType)
        assertEquals(2L, roundTxs[1].sequenceNumber)
        assertEquals(ProviderTransactionType.WIN, roundTxs[1].transactionType)

        // Verify audit and outbox events
        assertEquals(2, store.auditEvents.size)
        assertEquals(2, store.outboxEvents.size)
        assertTrue(store.auditEvents.all { it.type == "PROVIDER_TRANSACTION_MAPPED" })
        assertEquals("corr-bet-001", store.auditEvents[0].correlationId)
        assertEquals("corr-win-001", store.auditEvents[1].correlationId)
    }

    // =========================================================================
    // GAME-005-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `GAME-005-T002 Round provider transaction map rejects invalid, boundary, unauthorized, and stale input`() {
        val playerId = UUID.randomUUID()

        // 1. Invalid / blank input fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = "",
                    providerId = providerId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.BET,
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c1",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.BET,
                    amountMinorUnits = 100L,
                    currencyCode = "INVALID_CURRENCY",
                    idempotencyKey = "k2",
                    correlationId = "c2",
                    causationId = "c2",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.BET,
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k3",
                    correlationId = "c3",
                    causationId = "c3",
                    expectedVersion = 2L,
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Cross-tenant principal
        val crossTenantPrincipal = AuthenticatedPrincipal(
            id = "admin-cross",
            tenantId = "other-tenant",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    principal = crossTenantPrincipal,
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-1",
                    externalTransactionId = "tx-1",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.BET,
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "k4",
                    correlationId = "c4",
                    causationId = "c4",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Map an initial BET transaction to set up round state
        val betResult = service.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = "rnd-neg-001",
                externalTransactionId = "tx-neg-bet-001",
                playerId = playerId,
                gameId = gameId,
                transactionType = ProviderTransactionType.BET,
                amountMinorUnits = 200L,
                currencyCode = currencyUsd,
                idempotencyKey = "idemp-neg-bet-001",
                correlationId = "c-neg-1",
                causationId = "cause-neg-1",
            )
        )

        // 2. ID Collision (Protected Risk: ID collision)
        // Submitting another transaction with the SAME externalTransactionId must fail with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-neg-001",
                    externalTransactionId = "tx-neg-bet-001", // Reusing ID
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.WIN,
                    amountMinorUnits = 300L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "idemp-neg-collision",
                    correlationId = "c-col",
                    causationId = "cause-col",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Currency Mismatch (Protected Risk: currency mismatch)
        // Submitting a transaction in the same round with a mismatched currency
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-neg-001",
                    externalTransactionId = "tx-neg-mismatch-curr",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.WIN,
                    amountMinorUnits = 200L,
                    currencyCode = currencyEur, // Mismatched currency (round is in USD)!
                    idempotencyKey = "idemp-neg-curr-mismatch",
                    correlationId = "c-curr",
                    causationId = "cause-curr",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Player Mismatch in Round
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-neg-001",
                    externalTransactionId = "tx-neg-diff-player",
                    playerId = UUID.randomUUID(), // Different player in same round
                    gameId = gameId,
                    transactionType = ProviderTransactionType.WIN,
                    amountMinorUnits = 200L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "idemp-neg-diff-player",
                    correlationId = "c-dp",
                    causationId = "cause-dp",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 5. Rollback with non-existent parent transaction ID
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-neg-001",
                    externalTransactionId = "tx-neg-bad-rollback",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.ROLLBACK,
                    amountMinorUnits = 200L,
                    currencyCode = currencyUsd,
                    parentTransactionId = UUID.randomUUID(), // Unknown parent
                    idempotencyKey = "idemp-neg-bad-parent",
                    correlationId = "c-bp",
                    causationId = "cause-bp",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Settle round and reject further non-rollback transactions
        service.mapTransaction(
            MapProviderTransactionCommand(
                tenantId = tenantId,
                providerId = providerId,
                externalRoundId = "rnd-neg-001",
                externalTransactionId = "tx-neg-settle",
                playerId = playerId,
                gameId = gameId,
                transactionType = ProviderTransactionType.WIN,
                amountMinorUnits = 400L,
                currencyCode = currencyUsd,
                settleRound = true,
                idempotencyKey = "idemp-neg-settle",
                correlationId = "c-set",
                causationId = "cause-set",
            )
        )

        // Attempting to append BET to settled round must fail with CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-neg-001",
                    externalTransactionId = "tx-neg-after-settle",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.BET,
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "idemp-neg-after-settle",
                    correlationId = "c-as",
                    causationId = "cause-as",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // GAME-005-T003: Concurrency, Duplicate Delivery, and Dependency Failure
    // =========================================================================

    @Test
    fun `GAME-005-T003 Round provider transaction map survives concurrency, duplicate delivery, and dependency failure`() {
        val playerId = UUID.randomUUID()

        // 1. Idempotent request replay (identical payload) returns identical result
        val cmd = MapProviderTransactionCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-conc-001",
            externalTransactionId = "tx-conc-001",
            playerId = playerId,
            gameId = gameId,
            transactionType = ProviderTransactionType.BET,
            amountMinorUnits = 300L,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-conc-repeat",
            correlationId = "c-cr",
            causationId = "cause-cr",
        )
        val initial = service.mapTransaction(cmd)
        val replay = service.mapTransaction(cmd)
        assertEquals(initial.canonicalTransactionId, replay.canonicalTransactionId)
        assertEquals(initial.canonicalRoundId, replay.canonicalRoundId)
        assertEquals(initial.amountMinorUnits, replay.amountMinorUnits)

        // 2. Changed payload with same idempotency key fails with CONFLICT
        val conflictCmd = cmd.copy(amountMinorUnits = 999L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.mapTransaction(conflictCmd)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 3. Concurrent transaction execution across threads
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val successCount = AtomicInteger(0)

        for (i in 1..threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val threadPlayer = UUID.randomUUID()
                    val res = service.mapTransaction(
                        MapProviderTransactionCommand(
                            tenantId = tenantId,
                            providerId = providerId,
                            externalRoundId = "rnd-parallel-$i",
                            externalTransactionId = "tx-parallel-$i",
                            playerId = threadPlayer,
                            gameId = gameId,
                            transactionType = ProviderTransactionType.BET,
                            amountMinorUnits = 100L * i,
                            currencyCode = currencyUsd,
                            idempotencyKey = "idemp-parallel-$i",
                            correlationId = "corr-par-$i",
                            causationId = "cause-par-$i",
                        )
                    )
                    if (res.canonicalTransactionId != null) {
                        successCount.incrementAndGet()
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        doneLatch.await()
        executor.shutdown()

        assertEquals(threadCount, successCount.get(), "All parallel unique round mappings must succeed")

        // 4. Dependency failure fails closed
        val failingStore = RoundTestFailingStore()
        val failingService = RoundProviderTransactionMapService(store = failingStore, clock = clock)

        assertFailsWith<RuntimeException> {
            failingService.mapTransaction(
                MapProviderTransactionCommand(
                    tenantId = tenantId,
                    providerId = providerId,
                    externalRoundId = "rnd-fail-001",
                    externalTransactionId = "tx-fail-001",
                    playerId = playerId,
                    gameId = gameId,
                    transactionType = ProviderTransactionType.BET,
                    amountMinorUnits = 100L,
                    currencyCode = currencyUsd,
                    idempotencyKey = "idemp-fail",
                    correlationId = "c-f",
                    causationId = "cause-f",
                )
            )
        }
    }

    // =========================================================================
    // GAME-005-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `GAME-005-T004 Round provider transaction map remains compatible, recoverable, observable, and lifecycle-safe`() {
        val playerId = UUID.randomUUID()

        // 1. Initial BET transaction
        val betCmd = MapProviderTransactionCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-life-001",
            externalTransactionId = "tx-life-bet-001",
            playerId = playerId,
            gameId = gameId,
            transactionType = ProviderTransactionType.BET,
            amountMinorUnits = 1000L,
            currencyCode = currencyUsd,
            idempotencyKey = "idemp-life-bet",
            correlationId = "corr-life-bet",
            causationId = "cause-life-bet",
        )
        val betResult = service.mapTransaction(betCmd)

        // 2. Re-instantiate service (simulating application restart / migration)
        val restartedService = RoundProviderTransactionMapService(store = store, clock = clock)

        // State recovered accurately from store
        val recoveredRound = store.findRoundByExternalId(tenantId, providerId, "rnd-life-001")
        assertNotNull(recoveredRound)
        assertEquals(betResult.canonicalRoundId, recoveredRound.canonicalRoundId)
        assertEquals(1000L, recoveredRound.totalDebitMinorUnits)
        assertEquals(CanonicalRoundStatus.OPEN, recoveredRound.status)

        // 3. Perform compensating ROLLBACK referencing the parent BET transaction
        val rollbackCmd = MapProviderTransactionCommand(
            tenantId = tenantId,
            providerId = providerId,
            externalRoundId = "rnd-life-001",
            externalTransactionId = "tx-life-rollback-001",
            playerId = playerId,
            gameId = gameId,
            transactionType = ProviderTransactionType.ROLLBACK,
            amountMinorUnits = 1000L,
            currencyCode = currencyUsd,
            parentTransactionId = betResult.canonicalTransactionId, // Strict lineage to parent
            settleRound = true,
            idempotencyKey = "idemp-life-rollback",
            correlationId = "corr-life-rollback",
            causationId = "cause-life-rollback",
        )
        val rollbackResult = restartedService.mapTransaction(rollbackCmd)

        assertNotNull(rollbackResult)
        assertEquals(CanonicalRoundStatus.SETTLED, rollbackResult.roundStatus)
        assertEquals(1000L, rollbackResult.roundTotalDebitMinorUnits)
        assertEquals(1000L, rollbackResult.roundTotalCreditMinorUnits)
        assertEquals(0L, rollbackResult.roundNetOutcomeMinorUnits) // Compensated to 0 net

        // 4. Verify immutable lineage is completely preserved in sequence
        val transactions = store.findRoundTransactions(tenantId, betResult.canonicalRoundId)
        assertEquals(2, transactions.size)
        assertEquals(1L, transactions[0].sequenceNumber)
        assertEquals(ProviderTransactionType.BET, transactions[0].transactionType)
        assertNull(transactions[0].parentTransactionId)

        assertEquals(2L, transactions[1].sequenceNumber)
        assertEquals(ProviderTransactionType.ROLLBACK, transactions[1].transactionType)
        assertEquals(betResult.canonicalTransactionId, transactions[1].parentTransactionId)

        // 5. Observability checks
        val auditEvents = store.auditEvents
        val outboxEvents = store.outboxEvents
        assertEquals(2, auditEvents.size)
        assertEquals(2, outboxEvents.size)

        for (event in auditEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.occurredAt)
            assertNotNull(event.correlationId)
            assertNotNull(event.causationId)
        }

        for (event in outboxEvents) {
            assertNotNull(event.eventId)
            assertNotNull(event.tenantId)
            assertNotNull(event.type)
            assertNotNull(event.createdAt)
        }
    }
}

// =============================================================================
// Test Fakes & In-Memory Helpers
// =============================================================================

class RoundTestFailingStore : RoundProviderTransactionStore {
    override fun findTransactionByExternalId(tenantId: String, providerId: String, externalTransactionId: String): ProviderTransactionRecord? {
        throw RuntimeException("Database connection failure")
    }

    override fun findRoundByExternalId(tenantId: String, providerId: String, externalRoundId: String): CanonicalRoundRecord? {
        throw RuntimeException("Database connection failure")
    }

    override fun findRoundTransactions(tenantId: String, canonicalRoundId: UUID): List<ProviderTransactionRecord> {
        throw RuntimeException("Database connection failure")
    }

    override fun saveTransactionAndRound(
        transaction: ProviderTransactionRecord,
        round: CanonicalRoundRecord,
        result: ProviderTransactionMapResult,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        throw RuntimeException("Database connection failure")
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, ProviderTransactionMapResult>? {
        throw RuntimeException("Database connection failure")
    }
}
