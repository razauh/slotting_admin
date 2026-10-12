package com.slotting.admin.gameprovider

import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.LedgerJournalStore
import org.springframework.stereotype.Service
import java.math.BigDecimal

data class FinancialInvariantViolation(
    val invariantId: String,
    val identity: String,
    val detail: String,
)

data class FinancialInvariantReport(
    val tenantId: String,
    val gameId: String,
    val roundId: String,
    val violations: List<FinancialInvariantViolation>,
) {
    val isHealthy: Boolean get() = violations.isEmpty()
}

@Service
class AviatorFinancialInvariantChecker(
    private val ledgerStore: LedgerJournalStore,
    private val gameStore: DurableGameWagerAndSettlementStore,
    private val eventStore: GameEventJournalStore,
    private val fairnessStore: FairnessEvidenceStore,
) {
    fun check(tenantId: String, gameId: String, roundId: String): FinancialInvariantReport {
        val violations = mutableListOf<FinancialInvariantViolation>()
        val round = gameStore.findRound(tenantId, gameId, roundId)
        val bets = gameStore.findBetsForRound(tenantId, gameId, roundId)
        val settlements = bets.mapNotNull { gameStore.findSettlement(tenantId, it.betId) }
        val transactions = ledgerStore.findAllTransactionsForTenant(tenantId)
        val legsByTransaction = transactions.associateWith { ledgerStore.findLegs(tenantId, it.resultId) }

        legsByTransaction.forEach { (transaction, legs) ->
            val debits = legs.filter { it.direction == JournalEntryDirection.DEBIT }.sumOf { it.amountMinorUnits }
            val credits = legs.filter { it.direction == JournalEntryDirection.CREDIT }.sumOf { it.amountMinorUnits }
            if (!transaction.isBalanced || debits != credits || transaction.totalDebitsMinorUnits != debits || transaction.totalCreditsMinorUnits != credits) {
                add(violations, "I1", "transaction:${transaction.resultId}", "ledger transaction is not balanced")
            }
        }

        val tenantNet = legsByTransaction.values.flatten().groupBy { it.currencyCode }
            .mapValues { (_, legs) -> legs.sumOf { if (it.direction == JournalEntryDirection.CREDIT) it.amountMinorUnits else -it.amountMinorUnits } }
        tenantNet.filterValues { it != 0L }.forEach { (currency, amount) ->
            add(violations, "I2", "tenant:$tenantId/currency:$currency", "ledger conservation differs by $amount")
        }

        bets.forEach { bet ->
            val settlement = gameStore.findSettlement(tenantId, bet.betId)
            val terminal = bet.status in setOf(GameBetStatus.CANCELLED, GameBetStatus.CASHED_OUT, GameBetStatus.LOST)
            if (terminal != (settlement != null)) {
                add(violations, "I4", "bet:${bet.betId}", "bet status and settlement presence disagree")
            }
            if (round?.phase == GameRoundPhase.CRASHED && bet.status == GameBetStatus.ACCEPTED) {
                add(violations, "I5", "round:$roundId/bet:${bet.betId}", "crashed round retains an accepted bet")
            }
            if (settlement != null) {
                val expected = when (bet.status) {
                    GameBetStatus.CANCELLED -> GameSettlementOutcome.REFUND_CANCEL
                    GameBetStatus.CASHED_OUT -> GameSettlementOutcome.PAYOUT_CASH_OUT
                    GameBetStatus.LOST -> GameSettlementOutcome.LOSS_CRASH
                    GameBetStatus.ACCEPTED -> null
                }
                if (expected != settlement.outcome || settlement.ledgerSettlementRef == null || ledgerStore.findByTransactionReference(tenantId, settlement.ledgerSettlementRef) == null) {
                    add(violations, "I3", "bet:${bet.betId}", "terminal settlement and ledger transaction are not bijective")
                }
            }
            if (bet.status == GameBetStatus.ACCEPTED && ledgerStore.findByTransactionReference(tenantId, bet.ledgerReservationRef) == null) {
                add(violations, "I6", "bet:${bet.betId}", "accepted bet has no reservation transaction")
            }
        }

        val reservationReferences = bets.map { it.ledgerReservationRef }.toSet()
        transactions.filter {
            it.idempotencyKey.startsWith("bet:$tenantId:$gameId:$roundId:") &&
                it.transactionReference !in reservationReferences
        }.forEach { transaction ->
            add(
                violations,
                "I6",
                "ledger:${transaction.transactionReference}",
                "wager reservation ledger effect has no accepted bet",
            )
        }

        val receipts = gameStore.findAllReceiptsForTenant(tenantId)
        receipts.groupBy { it.serverSequenceId }.filter { it.key > 0L && it.value.size > 1 }.forEach { (sequence, rows) ->
            add(violations, "I7", "sequence:$sequence", "command sequence is not unique")
        }
        receipts.filter { it.roundId == roundId && it.status.equals("ACCEPTED", true) && isPlaceBetAction(it.action) }
            .forEach { receipt ->
                if (bets.none { it.ownerId == receipt.ownerId && it.handId == receipt.handId }) {
                    add(violations, "I6", "command:${receipt.commandId}", "accepted command has no bet effect")
                }
            }
        receipts.filter { it.roundId == roundId && it.status.equals("REJECTED", true) && isPlaceBetAction(it.action) }
            .forEach { receipt ->
                val matchingBet = bets.any { it.ownerId == receipt.ownerId && it.handId == receipt.handId }
                val reservationReference = AviatorCommandKeys.ledgerTransactionReference(
                    "WAGER",
                    AviatorCommandKeys.placeBetKey(tenantId, gameId, roundId, receipt.ownerId, receipt.handId),
                )
                if (matchingBet || ledgerStore.findByTransactionReference(tenantId, reservationReference) != null) {
                    add(violations, "I6", "command:${receipt.commandId}", "rejected command has a financial effect")
                }
            }

        val events = eventStore.findEventsForRound(tenantId, gameId, roundId)
        val versions = events.map { it.roundVersion }.distinct().sorted()
        if (versions.isNotEmpty() && versions != (versions.first()..versions.last()).toList()) {
            add(violations, "I8", "round:$roundId", "event version history is not monotonic")
        }
        val committedVersion = round?.roundVersion ?: 0L
        if (committedVersion > 0L && (versions.isEmpty() || versions.last() < committedVersion)) {
            add(violations, "I9", "round:$roundId/version:$committedVersion", "latest committed lifecycle version has no journal event")
        }
        events.groupBy { it.roundVersion }.filterValues { rows -> rows.count { it.eventName == "gameState" } != 1 }.keys.forEach { version ->
            add(violations, "I9", "round:$roundId/version:$version", "committed lifecycle version does not have exactly one event")
        }

        val commitment = fairnessStore.findCommitment(tenantId, gameId, roundId)
        if (commitment != null) {
            val requiresPostCommit = bets.any { it.status != GameBetStatus.ACCEPTED } || round?.phase in setOf(GameRoundPhase.CRASHED, GameRoundPhase.CLOSED)
            if (requiresPostCommit && commitment.status !in setOf(RoundCommitmentStatus.LOCKED, RoundCommitmentStatus.REVEALED)) {
                add(violations, "I10", "commitment:${commitment.commitmentId}", "fairness status disagrees with terminal round state")
            }
        }

        val activeRounds = gameStore.findActiveRounds(tenantId, gameId)
        if (activeRounds.size > 1) {
            add(violations, "I11", "game:$gameId", "multiple active rounds exist")
        }

        ledgerStore.findAllLegsForTenant(tenantId)
            .filter { it.accountReference.startsWith("PLAYER:") }
            .groupBy { it.accountReference to it.currencyCode }
            .mapValues { (_, legs) -> legs.sumOf { if (it.direction == JournalEntryDirection.CREDIT) it.amountMinorUnits else -it.amountMinorUnits } }
            .filterValues { it < 0L }
            .forEach { (account, balance) -> add(violations, "I12", "${account.first}/${account.second}", "player balance is negative: $balance") }

        return FinancialInvariantReport(tenantId, gameId, roundId, violations.distinct())
    }

    private fun add(
        violations: MutableList<FinancialInvariantViolation>,
        invariantId: String,
        identity: String,
        detail: String,
    ) {
        violations += FinancialInvariantViolation(invariantId, identity, detail)
    }

    private fun isPlaceBetAction(action: String): Boolean =
        action.equals(AviatorCommandAction.PLACE_BET.name, true) || action.equals("PLACE_BET", true)
}
