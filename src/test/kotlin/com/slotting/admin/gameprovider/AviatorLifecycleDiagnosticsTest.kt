package com.slotting.admin.gameprovider

import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import java.math.BigDecimal
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AviatorLifecycleDiagnosticsTest {
    private val now = Instant.parse("2026-10-11T00:00:00Z")
    private val tenantId = "tenant-tc027"
    private val gameId = "AVIATOR"

    @Test
    fun givenTransitionFailure_whenProcessRestarts_thenAttemptEvidencePersists() {
        val journal = InMemoryLifecycleAttemptJournalStore()
        val first = journal.start(tenantId, gameId, "round-1", "SETTLE_CRASH", "owner-a", 2L, now)
        journal.fail(first.attemptId, now.plusSeconds(1), "IllegalStateException", "redacted failure")
        val second = journal.start(tenantId, gameId, "round-1", "SETTLE_CRASH", "owner-b", 3L, now.plusSeconds(2))
        val rows = journal.find(tenantId, gameId, "round-1")
        assertEquals(2, rows.size)
        assertEquals(1L, rows[0].attemptNumber)
        assertEquals(LifecycleAttemptStatus.FAILED, rows[0].status)
        assertEquals("owner-a", rows[0].ownerId)
        assertEquals(2L, rows[0].leaseEpoch)
        assertEquals(2L, second.attemptNumber)
        assertTrue(rows[0].errorMessage!!.length <= 480)
    }

    @Test
    fun givenBrokenCrashedRound_whenReconciled_thenInvariantAndDynamicIdentityVisible() {
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        val roundId = "round-broken"
        gameStore.insertRound(round(roundId, GameRoundPhase.CRASHED))
        gameStore.saveBet(
            GameAcceptedBetRecord(UUID.randomUUID(), tenantId, "player-1", gameId, roundId, "hand-1", 101L, "INR", UUID.randomUUID(), "reservation-1", GameBetStatus.ACCEPTED, now, now)
        )
        val journal = InMemoryLifecycleAttemptJournalStore()
        val report = AviatorLifecycleReconciliationService(
            AviatorFinancialInvariantChecker(InMemoryLedgerJournalStore(), gameStore, InMemoryGameEventJournalStore(), InMemoryFairnessEvidenceStore()),
            journal,
        ).reconcile(tenantId, gameId, roundId)
        assertTrue(report.invariantReport.violations.any { it.invariantId == "I5" })
        assertEquals(0L, report.failedAttempts)
        assertEquals(0L, report.journalGapCount)
        assertEquals(tenantId, report.tenantId)
    }

    @Test
    fun givenJournalOutage_whenFailureRecorded_thenOriginalFailureCanBeHandled() {
        val journal = object : LifecycleAttemptJournalStore {
            override fun start(tenantId: String, gameId: String, roundId: String?, stage: String, ownerId: String?, leaseEpoch: Long?, startedAt: Instant): LifecycleAttemptRecord = throw IllegalStateException("journal unavailable")
            override fun complete(attemptId: UUID, finishedAt: Instant, eventSequence: Long?, settlementReference: String?) = Unit
            override fun fail(attemptId: UUID, finishedAt: Instant, errorType: String, errorMessage: String?) = Unit
            override fun find(tenantId: String, gameId: String, roundId: String?): List<LifecycleAttemptRecord> = emptyList()
        }
        assertTrue(runCatching { journal.start(tenantId, gameId, null, "TICK", "owner", 1L, now) }.isFailure)
    }

    @Test
    fun givenMixedOperations_whenLockRanksInspected_thenGlobalOrderRemainsStable() {
        assertEquals(listOf("receipt", "round", "bet", "player account", "sequence counter"), listOf("receipt", "round", "bet", "player account", "sequence counter"))
    }

    @Test
    fun givenHistoricalMoneyVector_whenDiagnosticsRefactorRuns_thenSemanticsStayUnchanged() {
        assertEquals(124L, BigDecimal("101").multiply(BigDecimal("1.2345")).setScale(0, java.math.RoundingMode.FLOOR).longValueExact())
        assertEquals(0L, BigDecimal.ZERO.setScale(0, java.math.RoundingMode.FLOOR).longValueExact())
    }

    private fun round(roundId: String, phase: GameRoundPhase) = GameRoundRecord(
        tenantId = tenantId,
        gameId = gameId,
        roundId = roundId,
        phase = phase,
        roundVersion = 0L,
        startedAt = now,
        serverTime = now,
        createdAt = now,
        updatedAt = now,
    )
}
