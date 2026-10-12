package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID
import kotlin.test.assertTrue

class AviatorFinancialFailpointMatrixTest {
    @Test
    fun givenLedgerPostWithoutBet_whenInvariantMatrixRuns_thenOrphanFinancialEffectIsReported() {
        val tenantId = "tenant-tc033-control"
        val gameId = "AVIATOR"
        val roundId = "round-unsafe-ordering"
        val now = Instant.parse("2026-10-11T00:00:00Z")
        val ledgerStore = InMemoryLedgerJournalStore()
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        gameStore.insertRound(
            GameRoundRecord(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                startedAt = now,
                serverTime = now,
                createdAt = now,
                updatedAt = now,
            ),
        )
        val principal = AuthenticatedPrincipal(
            id = "admin-tc033-control",
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN),
        )
        val commandKey = AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, "player-tc033", "hand-1")
        LedgerPostingService(ledgerStore).postTransaction(
            PostTransactionCommand(
                principal = principal,
                tenantId = tenantId,
                transactionReference = AviatorCommandKeys.ledgerTransactionReference("WAGER", commandKey),
                currencyCode = "INR",
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, 101L, "INR"),
                    JournalEntryDraft("PLAYER:player-tc033", JournalEntryDirection.CREDIT, 101L, "INR"),
                ),
                idempotencyKey = commandKey,
                correlationId = "corr-tc033-control",
                causationId = "caus-tc033-control",
            ),
        )
        val checker = AviatorFinancialInvariantChecker(
            ledgerStore = ledgerStore,
            gameStore = gameStore,
            eventStore = InMemoryGameEventJournalStore(),
            fairnessStore = InMemoryFairnessEvidenceStore(),
        )

        val report = checker.check(tenantId, gameId, roundId)

        assertTrue(
            report.violations.any { it.invariantId in setOf("I2", "I3", "I6") },
            "unsafe ledger-before-bet ordering must report the exact financial boundary",
        )
    }
}
