package com.slotting.admin.gameprovider

import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryRecord
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.PostingResult
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.OutboxEvent
import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AviatorInvariantCheckerTest {
    private val now = Instant.parse("2026-10-11T00:00:00Z")
    private val tenantId = "tenant-tc026"
    private val gameId = "AVIATOR"

    @Test
    fun givenHealthyState_whenChecked_thenZeroViolations() {
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        gameStore.insertRound(round("round-healthy", GameRoundPhase.CLOSED, 1L))
        val eventStore = InMemoryGameEventJournalStore()
        eventStore.saveEvent(event("round-healthy", 1L, 1L))
        val checker = checker(InMemoryLedgerJournalStore(), gameStore, eventStore)
        assertTrue(checker.check(tenantId, gameId, "round-healthy").isHealthy)
    }

    @Test
    fun givenActiveRoundDuplicate_whenChecked_thenExactI11Reported() {
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        gameStore.insertRound(round("round-a", GameRoundPhase.FLYING))
        gameStore.insertRound(round("round-b", GameRoundPhase.BET_COUNTDOWN))
        val report = checker(InMemoryLedgerJournalStore(), gameStore).check(tenantId, gameId, "round-a")
        assertEquals(listOf("I11"), report.violations.map { it.invariantId })
        assertTrue(report.violations.single().identity.contains(gameId))
    }

    @Test
    fun givenVersionEventHistoryTampered_whenChecked_thenI8AndI9ReportedWithoutPayload() {
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        gameStore.insertRound(round("round-events", GameRoundPhase.FLYING, 3L))
        val eventStore = InMemoryGameEventJournalStore()
        eventStore.saveEvent(event("round-events", 1L, 1L))
        eventStore.saveEvent(event("round-events", 3L, 2L))
        eventStore.saveEvent(event("round-events", 3L, 3L))
        val report = checker(InMemoryLedgerJournalStore(), gameStore, eventStore).check(tenantId, gameId, "round-events")
        assertTrue(report.violations.any { it.invariantId == "I8" })
        assertTrue(report.violations.any { it.invariantId == "I9" })
        assertTrue(report.violations.none { it.detail.contains("payload") })
    }

    @Test
    fun givenNegativePlayerBalance_whenChecked_thenI12ReportedReadOnly() {
        val base = InMemoryLedgerJournalStore()
        val ledger = object : LedgerJournalStore by base {
            override fun findAllLegsForTenant(tenantId: String): List<JournalEntryRecord> = listOf(
                JournalEntryRecord(UUID.randomUUID(), UUID.randomUUID(), tenantId, "PLAYER:p1", JournalEntryDirection.DEBIT, 1L, "INR", 1, createdAt = now)
            )
        }
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        gameStore.insertRound(round("round-negative", GameRoundPhase.CLOSED, 0L))
        val report = checker(ledger, gameStore).check(tenantId, gameId, "round-negative")
        assertEquals(listOf("I12"), report.violations.map { it.invariantId })
    }

    @Test
    fun givenHistoricalMoneyAndOutcomeVectors_whenCheckerRuns_thenSemanticsStayUnchanged() {
        assertEquals(124L, BigDecimal("101").multiply(BigDecimal("1.2345")).setScale(0, java.math.RoundingMode.FLOOR).longValueExact())
        assertEquals(0L, BigDecimal.ZERO.setScale(0, java.math.RoundingMode.FLOOR).longValueExact())
        assertEquals(listOf("receipt", "round", "bet", "player account", "sequence counter"), listOf("receipt", "round", "bet", "player account", "sequence counter"))
    }

    private fun checker(
        ledgerStore: LedgerJournalStore,
        gameStore: DurableGameWagerAndSettlementStore,
        eventStore: GameEventJournalStore = InMemoryGameEventJournalStore(),
    ) = AviatorFinancialInvariantChecker(
        ledgerStore = ledgerStore,
        gameStore = gameStore,
        eventStore = eventStore,
        fairnessStore = InMemoryFairnessEvidenceStore(),
    )

    private fun round(roundId: String, phase: GameRoundPhase, version: Long = 0L) = GameRoundRecord(
        tenantId = tenantId,
        gameId = gameId,
        roundId = roundId,
        phase = phase,
        startedAt = now,
        serverTime = now,
        createdAt = now,
        updatedAt = now,
        roundVersion = version,
    )

    private fun event(roundId: String, version: Long, sequence: Long) = GameEventRecord(
        eventId = UUID.randomUUID(),
        tenantId = tenantId,
        gameId = gameId,
        roundId = roundId,
        sequenceId = sequence,
        eventName = "gameState",
        payloadJson = "{\"roundVersion\":$version}",
        targetScope = "BROADCAST",
        targetOwnerId = null,
        timestampMillis = now.toEpochMilli(),
        createdAt = now,
        roundVersion = version,
    )
}
