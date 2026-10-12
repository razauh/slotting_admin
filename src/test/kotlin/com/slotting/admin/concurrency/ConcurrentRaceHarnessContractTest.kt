package com.slotting.admin.concurrency

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.gameprovider.AuthoritativeGameSnapshotAndEventService
import com.slotting.admin.gameprovider.CommandReceiptClaimResult
import com.slotting.admin.gameprovider.GameCommandReceiptClaim
import com.slotting.admin.gameprovider.JdbcDurableGameWagerAndSettlementStore
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class ConcurrentRaceHarnessContractTest {
    @MockBean
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            PostgresIntegrationSupport.configureProperties(registry)
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var txManager: PlatformTransactionManager

    private val now = Instant.parse("2026-10-12T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val currency = "INR"
    private val gameId = "AVIATOR"

    private fun adminFor(tenantId: String) = AuthenticatedPrincipal(
        id = "admin-sys-tc01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private fun clearTenant(tenantId: String) {
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
    }

    private fun claimOnce(
        store: JdbcDurableGameWagerAndSettlementStore,
        tx: TransactionTemplate,
        tenantId: String,
        commandId: String,
        roundId: String,
        index: Int,
    ): RaceOutcome {
        val claim = GameCommandReceiptClaim(
            receiptId = UUID.randomUUID(),
            tenantId = tenantId,
            ownerId = "owner-tc01",
            gameId = gameId,
            commandId = commandId,
            roundId = roundId,
            handId = "hand-primary",
            action = "PLACE_BET",
            fingerprint = "fp-tc01-single-claim",
            causationId = "caus-tc01-" + index,
            correlationId = "corr-tc01-single-claim",
            roundVersion = 1L,
            createdAt = now,
        )
        val result = tx.execute<CommandReceiptClaimResult> {
            val claimed = store.claimReceipt(claim)
            if (claimed is CommandReceiptClaimResult.Claimed) {
                store.completeReceipt(tenantId, commandId, "ACCEPTED", "{\"winner\":true}", 1L, 1L)
            }
            claimed
        }!!
        return when (result) {
            is CommandReceiptClaimResult.Claimed -> RaceOutcome.Succeeded(index.toLong())
            is CommandReceiptClaimResult.AlreadyClaimed -> RaceOutcome.Rejected("already-claimed")
        }
    }

    private fun receiptCount(tenantId: String, commandId: String): Int =
        jdbc.queryForObject(
            "select count(*) from game_command_receipt where tenant_id = ? and command_id = ?",
            Int::class.java,
            tenantId,
            commandId,
        ) ?: 0

    @Test
    fun concurrentWorkersEnforceExactlyOneWinnerOnSingleClaim() {
        for (workers in listOf(8, 16, 32)) {
            val tenantId = RaceTenantFactory.newTenant("tenant-tc01-claim")
            clearTenant(tenantId)
            val store = JdbcDurableGameWagerAndSettlementStore(jdbc)
            val tx = TransactionTemplate(txManager)
            val suffix = UUID.randomUUID().toString().take(8)
            val commandId = "cmd-tc01-claim-" + suffix
            val roundId = "rnd-tc01-claim-" + suffix
            val report = ConcurrentRaceHarness.runRace(workers, RaceTimeouts.secondsFor(workers)) { index ->
                claimOnce(store, tx, tenantId, commandId, roundId, index)
            }
            RaceInvariants.requireExactlyOneWinner(report)
            assertEquals(
                1,
                receiptCount(tenantId, commandId),
                "workers=" + workers + " must leave exactly one receipt",
            )
        }
    }

    @Test
    fun concurrentDepositsConserveLedgerSumAcrossEightSixteenAndThirtyTwoWorkers() {
        for (workers in listOf(8, 16, 32)) {
            val tenantId = RaceTenantFactory.newTenant("tenant-tc01-ledger")
            clearTenant(tenantId)
            val admin = adminFor(tenantId)
            val ledgerStore = JdbcLedgerJournalStore(jdbc)
            val ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
            val tx = TransactionTemplate(txManager)
            val amountMinor = 100L
            val account = "PLAYER:tc01-conservation"
            val report = ConcurrentRaceHarness.runRace(workers, RaceTimeouts.secondsFor(workers)) { index ->
                tx.execute<Unit> {
                    ledgerService.postTransaction(
                        PostTransactionCommand(
                            principal = admin,
                            tenantId = tenantId,
                            transactionReference = "TX-TC01-" + tenantId + "-" + index,
                            currencyCode = currency,
                            entries = listOf(
                                JournalEntryDraft("HOUSE:TC01", JournalEntryDirection.DEBIT, amountMinor, currency),
                                JournalEntryDraft(account, JournalEntryDirection.CREDIT, amountMinor, currency),
                            ),
                            idempotencyKey = "IDEM-TC01-" + tenantId + "-" + index,
                            correlationId = "corr-tc01-" + index,
                            causationId = "caus-tc01-" + index,
                        ),
                    )
                }
                RaceOutcome.Succeeded(amountMinor)
            }
            assertEquals(workers, RaceInvariants.winnerCount(report))
            val debits = jdbc.queryForObject(
                "select coalesce(sum(total_debits_minor_units), 0) from ledger_transaction where tenant_id = ?",
                Long::class.java,
                tenantId,
            ) ?: 0L
            val credits = jdbc.queryForObject(
                "select coalesce(sum(total_credits_minor_units), 0) from ledger_transaction where tenant_id = ?",
                Long::class.java,
                tenantId,
            ) ?: 0L
            RaceInvariants.requireLedgerConserved(debits, credits, workers * amountMinor)
            RaceInvariants.requireNoOverdraft(ledgerStore.findBalance(tenantId, account, currency), account)
            assertEquals(workers * amountMinor, ledgerStore.findBalance(tenantId, account, currency))
        }
    }

    @Test
    fun perTestTenantIsolationPreventsCrossTestInterference() {
        val firstTenant = RaceTenantFactory.newTenant("tenant-tc01-isolation")
        val secondTenant = RaceTenantFactory.newTenant("tenant-tc01-isolation")
        assertNotEquals(firstTenant, secondTenant)
        val store = JdbcDurableGameWagerAndSettlementStore(jdbc)
        val tx = TransactionTemplate(txManager)
        val commandIds = ConcurrentHashMap<String, String>()
        for (tenantId in listOf(firstTenant, secondTenant)) {
            clearTenant(tenantId)
            val suffix = UUID.randomUUID().toString().take(8)
            val commandId = "cmd-tc01-isolation-" + suffix
            commandIds[tenantId] = commandId
            val report = ConcurrentRaceHarness.runRace(8, RaceTimeouts.secondsFor(8)) { index ->
                claimOnce(store, tx, tenantId, commandId, "rnd-tc01-isolation-" + suffix, index)
            }
            RaceInvariants.requireExactlyOneWinner(report)
        }
        assertEquals(1, receiptCount(firstTenant, commandIds[firstTenant]!!))
        assertEquals(1, receiptCount(secondTenant, commandIds[secondTenant]!!))
        val distinct = (1..64).map { RaceTenantFactory.newTenant("tenant-tc01-unique") }.toSet()
        assertEquals(64, distinct.size)
    }

}
