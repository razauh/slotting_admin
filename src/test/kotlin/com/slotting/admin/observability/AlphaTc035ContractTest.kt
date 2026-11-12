package com.slotting.admin.observability

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.deposit.DepositIntentStatus
import com.slotting.admin.deposit.DurableDepositWorkflowService
import com.slotting.admin.deposit.JdbcDepositWorkflowStore
import com.slotting.admin.gameprovider.AviatorCommandAckResult
import com.slotting.admin.gameprovider.AviatorCommandAckStatus
import com.slotting.admin.gameprovider.AviatorRestCommand
import com.slotting.admin.gameprovider.CreateOrUpdateRoundCommand
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementService
import com.slotting.admin.gameprovider.FairnessSeedEnvelope
import com.slotting.admin.gameprovider.GameRoundPhase
import com.slotting.admin.gameprovider.DurableGameWagerAndSettlementStore
import com.slotting.admin.gameprovider.JdbcDurableGameWagerAndSettlementStore
import com.slotting.admin.gameprovider.JdbcFairnessEvidenceStore
import com.slotting.admin.gameprovider.ProvablyFairOutcomeAuthority
import com.slotting.admin.gameprovider.PublishCommitmentCommand
import com.slotting.admin.gameprovider.SettleRoundCrashCommand
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.JdbcPlayerRegistrationStore
import java.math.BigDecimal
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AlphaTc035ContractTest {
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

    private val now = Instant.parse("2026-10-31T17:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-tc035"
    private val gameId = "AVIATOR"

    private lateinit var ledgerService: LedgerPostingService
    private lateinit var fairnessAuthority: ProvablyFairOutcomeAuthority
    private lateinit var gameService: DurableGameWagerAndSettlementService
    private lateinit var depositService: DurableDepositWorkflowService

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc035",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val eligibilityStore = InMemoryServerEligibilityStore()
    private val financialAudit by lazy { JdbcFinancialAuditProjector(JdbcDiagnosticEventStore(jdbc, clock), clock) }

    @BeforeEach
    fun setUp() {
        clearTenantState()
        ledgerService = LedgerPostingService(store = JdbcLedgerJournalStore(jdbc), clock = clock)
        fairnessAuthority = ProvablyFairOutcomeAuthority(
            store = JdbcFairnessEvidenceStore(jdbc),
            clock = clock,
            envelope = FairnessSeedEnvelope.devDefault(),
        )
        gameService = DurableGameWagerAndSettlementService(
            store = JdbcDurableGameWagerAndSettlementStore(jdbc),
            ledgerService = ledgerService,
            registrationStore = JdbcPlayerRegistrationStore(jdbc),
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            fairnessAuthority = fairnessAuthority,
            txManager = txManager,
        )
        depositService = DurableDepositWorkflowService(
            workflowStore = JdbcDepositWorkflowStore(jdbc),
            paymentMethodStore = com.slotting.admin.provider.InMemoryPaymentMethodStore(),
            sessions = object : com.slotting.admin.auth.AdminSessionDirectory {
                override fun find(tenantId: String, principalId: String, sessionId: String) =
                    com.slotting.admin.auth.AdminSessionStatus(true, false, now.plusSeconds(3600), true)
            },
            ledgerPostingService = ledgerService,
            providerPorts = mapOf(
                "SAFEPAY_RAAST" to com.slotting.admin.provider.port.adapters.SafepayRaastAdapter(),
            ),
            credentialsResolver = { _, _ ->
                com.slotting.admin.provider.port.ProviderCredentials(
                    merchantId = "MERCHANT-01",
                    apiKey = "api-key-test",
                    signingSecretOrKey = "signing-secret-tc035",
                )
            },
            configResolver = { _, _ ->
                com.slotting.admin.provider.port.ProviderConfiguration(
                    providerId = "SAFEPAY_RAAST",
                    environment = com.slotting.admin.provider.port.ProviderEnvironment.SANDBOX,
                    baseUrl = "https://sandbox.api.test/v1",
                )
            },
            clock = clock,
            financialAudit = financialAudit,
        )
    }

    @Test
    fun `TC-035-R1 two independent instances race two 7000 wagers at a shared barrier and admit at most one`() {
        val playerId = UUID.randomUUID()
        seedPlayer(playerId)
        seedFunds(playerId, "PKR", 10_000L)
        seedFunds(playerId, "USD", 77_777L)
        val roundId = "round-tc035-r1"
        createRound(roundId)

        val raceStart = java.util.concurrent.CyclicBarrier(2)
        val storeOne = JdbcDurableGameWagerAndSettlementStore(jdbc)
        val storeTwo = JdbcDurableGameWagerAndSettlementStore(jdbc)
        val ledgerOne = BarrierLedgerStore(JdbcLedgerJournalStore(jdbc))
        val ledgerTwo = BarrierLedgerStore(JdbcLedgerJournalStore(jdbc))
        val instanceOne = buildGameInstance(storeOne, ledgerOne)
        val instanceTwo = buildGameInstance(storeTwo, ledgerTwo)

        val pool = Executors.newFixedThreadPool(2)
        val outcomes = java.util.Collections.synchronizedList(mutableListOf<AviatorCommandAckStatus>())
        val rejectionReasons = mutableListOf<String>()
        try {
            val futures = listOf(instanceOne to "cmd-tc035-r1-a", instanceTwo to "cmd-tc035-r1-b").map { (instance, commandId) ->
                pool.submit(Callable {
                    raceStart.await(30, TimeUnit.SECONDS)
                    TransactionTemplate(txManager).execute {
                        instance.processCommand(
                            AviatorRestCommand(
                                tenantId = tenantId,
                                principal = playerPrincipal(playerId),
                                commandId = commandId,
                                roundId = roundId,
                                handId = "hand_primary",
                                action = "PLACE_BET",
                                wagerMinor = 7_000L,
                                currency = "PKR",
                                correlationId = "corr-$commandId",
                            )
                        )
                    }!!
                })
            }
            futures.forEach { ack ->
                val result = ack.get(60, TimeUnit.SECONDS)
                outcomes.add(result.status)
                if (result.rejection != null) rejectionReasons.add(result.rejection.code.name)
            }
        } finally {
            pool.shutdownNow()
        }

        assertEquals(1, outcomes.count { it == AviatorCommandAckStatus.ACCEPTED })
        assertEquals(1, outcomes.count { it == AviatorCommandAckStatus.REJECTED })
        assertEquals(1, rejectionReasons.size)
        assertTrue(rejectionReasons.single() in setOf("INSUFFICIENT_BALANCE", "LOCK_TIMEOUT"))
        assertEquals(3_000L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerId", "PKR"))
        assertEquals(77_777L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerId", "USD"))
        assertTrue(ledgerService.store.findBalance(tenantId, "PLAYER:$playerId", "PKR") >= 0L)

        val admittedCommandId = if (outcomes[0] == AviatorCommandAckStatus.ACCEPTED) "cmd-tc035-r1-a" else "cmd-tc035-r1-b"
        val escrowLegs = jdbc.queryForObject(
            "select count(*) from ledger_leg where tenant_id = ? and account_reference = ? and amount_minor_units = 7000 and direction = 'CREDIT'",
            Int::class.java,
            tenantId,
            "ESCROW:GAME:$gameId",
        )
        assertEquals(1, escrowLegs, "the admitted wager must complete its escrow reservation and the loser none")

        val receipts = jdbc.queryForObject(
            "select count(*) from game_command_receipt where tenant_id = ? and status = 'ACCEPTED'",
            Int::class.java,
            tenantId,
        )
        assertEquals(1, receipts)
        assertJournalBalanced("PKR")
        assertJournalBalanced("USD")
    }

    @Test
    fun `TC-035-R2 cash-out and crash race has one terminal outcome and restart replay returns the same receipt`() {
        val playerId = UUID.randomUUID()
        seedPlayer(playerId)
        seedFunds(playerId, "PKR", 10_000L)
        val roundId = "round-tc035-r2"
        createRound(roundId)
        val placeAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = playerPrincipal(playerId),
                commandId = "cmd-tc035-r2-place",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 2_000L,
                currency = "PKR",
                correlationId = "corr-tc035-r2-place",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, placeAck.status)
        flyRound(roundId)

        val cashOutCommand = AviatorRestCommand(
            tenantId = tenantId,
            principal = playerPrincipal(playerId),
            commandId = "cmd-tc035-r2-cashout",
            roundId = roundId,
            handId = "hand_primary",
            action = "CASH_OUT",
            currency = "PKR",
            correlationId = "corr-tc035-r2-cashout",
        )
        val raceStart = java.util.concurrent.CyclicBarrier(2)
        val storeForCashOut = BarrierGameStore(JdbcDurableGameWagerAndSettlementStore(jdbc))
        val storeForCrash = BarrierGameStore(JdbcDurableGameWagerAndSettlementStore(jdbc))
        val cashOutInstance = buildGameInstance(storeForCashOut, JdbcLedgerJournalStore(jdbc))
        val crashInstance = buildGameInstance(storeForCrash, JdbcLedgerJournalStore(jdbc))

        val pool = Executors.newFixedThreadPool(2)
        val results = mutableListOf<Pair<String, String>>()
        var racingCashOutAck: AviatorCommandAckResult? = null
        try {
            val cashOutFuture = pool.submit(Callable {
                raceStart.await(30, TimeUnit.SECONDS)
                TransactionTemplate(txManager).execute { cashOutInstance.processCommand(cashOutCommand) }
            })
            val crashFuture = pool.submit(Callable {
                raceStart.await(30, TimeUnit.SECONDS)
                TransactionTemplate(txManager).execute {
                    crashInstance.settleRoundCrash(
                        SettleRoundCrashCommand(tenantId, gameId, roundId, BigDecimal("2.5000"))
                    )
                }
            })

            val cashOutAck = cashOutFuture.get(60, TimeUnit.SECONDS)
            val crashResult = crashFuture.get(60, TimeUnit.SECONDS)
            racingCashOutAck = cashOutAck
            results.add("cashout" to (cashOutAck?.status?.name ?: "NULL"))
            results.add("crash" to "settled:${crashResult?.settledBetsCount}")
        } finally {
            pool.shutdownNow()
        }

        val bet = jdbc.queryForObject(
            "select status from game_accepted_bet where tenant_id = ? and round_id = ?",
            String::class.java,
            tenantId,
            roundId,
        )
        assertTrue(bet == "CASHED_OUT" || bet == "LOST", "bet must reach exactly one terminal state, was $bet")
        assertEquals(
            1,
            jdbc.queryForObject(
                "select count(*) from game_bet_settlement where tenant_id = ? and round_id = ?",
                Int::class.java,
                tenantId,
                roundId,
            ),
        )
        assertJournalBalanced("PKR")

        val restartedService = buildGameInstance(
            JdbcDurableGameWagerAndSettlementStore(jdbc),
            JdbcLedgerJournalStore(jdbc),
        )
        val replay = TransactionTemplate(txManager).execute { restartedService.processCommand(cashOutCommand) }!!
        val persistedReceipt = jdbc.queryForObject(
            "select response_json from game_command_receipt where tenant_id = ? and command_id = ?",
            String::class.java,
            tenantId,
            "cmd-tc035-r2-cashout",
        )
        if (bet == "CASHED_OUT") {
            assertEquals(AviatorCommandAckStatus.ACCEPTED, replay.status)
            assertEquals("cmd-tc035-r2-cashout", replay.commandId)
            val racingAck = checkNotNull(racingCashOutAck) { "the racing cash-out acknowledgment must be captured" }
            assertEquals(AviatorCommandAckStatus.ACCEPTED, racingAck.status)
            assertEquals(racingAck.evidenceReference, replay.evidenceReference)
            assertEquals(racingAck.sequenceId, replay.sequenceId)
            assertEquals(racingAck.revision, replay.revision)
            assertEquals(racingAck.timestampMillis, replay.timestampMillis)
            assertTrue(persistedReceipt.contains(racingAck.evidenceReference))
        } else {
            assertEquals(AviatorCommandAckStatus.REJECTED, replay.status)
        }
        assertEquals(
            1,
            jdbc.queryForObject(
                "select count(*) from game_bet_settlement where tenant_id = ? and round_id = ?",
                Int::class.java,
                tenantId,
                roundId,
            ),
        )
    }

    @Test
    fun `TC-035-R3 crash after credit recovers with one final credit balanced journals and agreeing diagnostics`() {
        val playerId = UUID.randomUUID()
        seedPlayer(playerId)
        val tracker = "track-tc035-r3"
        val intent = JdbcDepositWorkflowStore(jdbc).saveIntent(
            com.slotting.admin.deposit.DepositIntentRecord(
                intentId = UUID.randomUUID(),
                tenantId = tenantId,
                playerId = playerId,
                methodId = "SAFEPAY",
                providerId = "SAFEPAY_RAAST",
                amountMinorUnits = 50_000L,
                currencyCode = "PKR",
                status = DepositIntentStatus.PROVIDER_PENDING,
                idempotencyKey = "idem-tc035-r3",
                requestFingerprint = "fp-tc035-r3",
                providerReference = tracker,
                providerCredentialVersion = null,
                expiresAt = now.plusSeconds(900),
                createdAt = now,
                updatedAt = now,
            )
        )
        val body = """{"data":{"token":"token_123","amount":50000,"currency":"PKR","status":"paid","tracker":"$tracker"}}"""
        val command = com.slotting.admin.deposit.DepositCallbackCommand(
            tenantId = tenantId,
            providerId = "SAFEPAY_RAAST",
            providerEventId = "evt-tc035-r3",
            rawBody = body,
            headers = mapOf(
                "x-sfpy-signature" to com.slotting.admin.provider.port.adapters.SafepayRaastAdapter()
                    .calculateHmacSha256(body, "signing-secret-tc035"),
            ),
        )

        val credited = TransactionTemplate(txManager).execute { depositService.processCallback(command) }!!
        assertEquals(DepositIntentStatus.SETTLED, credited.status)
        val ledgerRefAfterCredit = credited.ledgerTransactionReference
        assertEquals(1, ledgerTransactionCount("LEDGER-DEP-${intent.intentId}"))

        val restartedDeposit = DurableDepositWorkflowService(
            workflowStore = JdbcDepositWorkflowStore(jdbc),
            paymentMethodStore = com.slotting.admin.provider.InMemoryPaymentMethodStore(),
            sessions = object : com.slotting.admin.auth.AdminSessionDirectory {
                override fun find(tenantId: String, principalId: String, sessionId: String) =
                    com.slotting.admin.auth.AdminSessionStatus(true, false, now.plusSeconds(3600), true)
            },
            ledgerPostingService = ledgerService,
            providerPorts = mapOf("SAFEPAY_RAAST" to com.slotting.admin.provider.port.adapters.SafepayRaastAdapter()),
            credentialsResolver = { _, _ ->
                com.slotting.admin.provider.port.ProviderCredentials(
                    merchantId = "MERCHANT-01",
                    apiKey = "api-key-test",
                    signingSecretOrKey = "signing-secret-tc035",
                )
            },
            configResolver = { _, _ ->
                com.slotting.admin.provider.port.ProviderConfiguration(
                    providerId = "SAFEPAY_RAAST",
                    environment = com.slotting.admin.provider.port.ProviderEnvironment.SANDBOX,
                    baseUrl = "https://sandbox.api.test/v1",
                )
            },
            clock = clock,
            financialAudit = financialAudit,
        )
        val replay = TransactionTemplate(txManager).execute { restartedDeposit.processCallback(command) }!!
        assertTrue(replay.alreadyProcessed)
        assertEquals(ledgerRefAfterCredit, replay.ledgerTransactionReference)
        assertEquals(1, ledgerTransactionCount("LEDGER-DEP-${intent.intentId}"))
        assertJournalBalanced("PKR")

        val events = jdbc.query(
            "select event_type, payload_json->>'ledgerId' as ledger_ref, payload_json->>'paymentId' as payment_id, payload_json->>'currency' as currency from diagnostic_event where tenant_id = ? and correlation_id = ?",
            { rs, _ -> listOf(rs.getString("event_type"), rs.getString("ledger_ref"), rs.getString("payment_id"), rs.getString("currency")) },
            tenantId,
            "corr-${intent.intentId}",
        )
        val creditedEvent = events.single { it[0] == "DEPOSIT_CREDITED" }
        assertEquals(ledgerRefAfterCredit, creditedEvent[1])
        assertEquals(intent.intentId.toString(), creditedEvent[2])
        assertEquals("PKR", creditedEvent[3])

        assertEquals(50_000L, ledgerService.store.findBalance(tenantId, "PLAYER:$playerId", "PKR"))
        val (debits, credits) = journalTotals("PKR")
        assertEquals(debits, credits)
    }

    private fun buildGameInstance(
        store: DurableGameWagerAndSettlementStore,
        ledgerStore: com.slotting.admin.ledger.LedgerJournalStore,
    ): DurableGameWagerAndSettlementService = DurableGameWagerAndSettlementService(
        store = store,
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock),
        registrationStore = JdbcPlayerRegistrationStore(jdbc),
        eligibilityStore = eligibilityStore,
        adminPrincipal = adminPrincipal,
        clock = clock,
        fairnessAuthority = fairnessAuthority,
        txManager = txManager,
    )

    private class BarrierGameStore(
        private val delegate: JdbcDurableGameWagerAndSettlementStore,
    ) : DurableGameWagerAndSettlementStore by delegate {
        val contestedWriteCount = java.util.concurrent.atomic.AtomicInteger(0)

        override fun transitionBetStatus(
            betId: UUID,
            tenantId: String,
            from: com.slotting.admin.gameprovider.GameBetStatus,
            to: com.slotting.admin.gameprovider.GameBetStatus,
            updatedAt: Instant,
        ): Boolean {
            contestedWriteCount.incrementAndGet()
            return delegate.transitionBetStatus(betId, tenantId, from, to, updatedAt)
        }
    }

    private class BarrierLedgerStore(
        private val delegate: com.slotting.admin.ledger.LedgerJournalStore,
    ) : com.slotting.admin.ledger.LedgerJournalStore by delegate {
        val contestedReadCount = java.util.concurrent.atomic.AtomicInteger(0)

        override fun findBalance(tenantId: String, accountReference: String, currencyCode: String): Long {
            if (accountReference.startsWith("PLAYER:")) contestedReadCount.incrementAndGet()
            return delegate.findBalance(tenantId, accountReference, currencyCode)
        }
    }

    private fun assertJournalBalanced(currency: String) {
        val (debits, credits) = journalTotals(currency)
        assertEquals(debits, credits, "journal must be balanced for $currency")
    }

    private fun journalTotals(currency: String): Pair<Long, Long> {
        var debits = 0L
        var credits = 0L
        jdbc.query(
            "select direction, amount_minor_units from ledger_leg where tenant_id = ? and currency_code = ?",
            { rs, _ ->
                if (rs.getString("direction") == "DEBIT") debits += rs.getLong("amount_minor_units") else credits += rs.getLong("amount_minor_units")
            },
            tenantId,
            currency,
        )
        return Pair(debits, credits)
    }

    private fun ledgerTransactionCount(idempotencyKey: String): Int = jdbc.queryForObject(
        "select count(*) from ledger_transaction where idempotency_key = ?",
        Int::class.java,
        idempotencyKey,
    ) ?: 0

    private fun clearTenantState() {
        jdbc.update("delete from game_fairness_audit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_reveal where tenant_id = ?", tenantId)
        jdbc.update("delete from game_fairness_commitment where tenant_id = ?", tenantId)
        jdbc.update("delete from diagnostic_event where tenant_id = ?", tenantId)
        jdbc.update("delete from game_bet_settlement where tenant_id = ?", tenantId)
        jdbc.update("delete from game_accepted_bet where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from game_cumulative_player_limit where tenant_id = ?", tenantId)
        jdbc.update("delete from game_authoritative_round where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_deposit_inbox where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_deposit_reconciliation where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_deposit_intent where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_leg where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_idempotency_receipt where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_transaction where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_outbox_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_audit_event where tenant_id = ?", tenantId)
        jdbc.update("delete from admin_operation where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_account where tenant_id = ?", tenantId)
        jdbc.update("delete from game_command_sequence where tenant_id = ?", tenantId)
        jdbc.update("delete from ledger_version_tracker where tenant_id = ?", tenantId)
        jdbc.update("delete from wallet_projection where tenant_id = ?", tenantId)
    }

    private fun playerPrincipal(uuid: UUID) = AuthenticatedPrincipal(
        id = uuid.toString(),
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT),
    )

    private fun seedPlayer(uuid: UUID) {
        jdbc.update(
            """
            insert into player_credential (
                player_id, tenant_id, identifier, password_hash, password_algo,
                password_salt, iterations, status, version, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, identifier) do nothing
            """.trimIndent(),
            uuid, tenantId, uuid.toString(), "pbkdf2_sha256_hash", "pbkdf2_sha256", "salt", 10000, "ACTIVE", 1L,
            Timestamp.from(now.minusSeconds(86400)), Timestamp.from(now.minusSeconds(86400)),
        )
        eligibilityStore.saveComplianceProfile(
            com.slotting.admin.identity.PlayerComplianceProfile(
                playerId = uuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 5, 5),
                kycStatus = com.slotting.admin.identity.KycComplianceStatus.VERIFIED,
                amlStatus = com.slotting.admin.identity.AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = com.slotting.admin.identity.ResponsiblePlayProfile(
                    playerId = uuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 500_000L,
                    dailyWagerLimitMinor = 2_000_000L,
                    currentDailyWagerMinor = 0L,
                ),
            )
        )
    }

    private fun seedFunds(uuid: UUID, currency: String, amount: Long) {
        ledgerService.postTransaction(
            com.slotting.admin.ledger.PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC035-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    com.slotting.admin.ledger.JournalEntryDraft("HOUSE:SEED", com.slotting.admin.ledger.JournalEntryDirection.DEBIT, amount, currency),
                    com.slotting.admin.ledger.JournalEntryDraft("PLAYER:$uuid", com.slotting.admin.ledger.JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC035-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc035-seed",
                causationId = "caus-tc035-seed",
            )
        )
    }

    private fun createRound(roundId: String) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
                roundVersion = 1L,
                currentMultiplier = BigDecimal("1.0000"),
            )
        )
        fairnessAuthority.publishPreBetCommitment(
            PublishCommitmentCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                publicSalt = "salt-$roundId",
            )
        )
    }

    private fun flyRound(roundId: String) {
        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                currentMultiplier = BigDecimal("1.2345"),
                crashMultiplier = BigDecimal("10.0000"),
            )
        )
    }
}
