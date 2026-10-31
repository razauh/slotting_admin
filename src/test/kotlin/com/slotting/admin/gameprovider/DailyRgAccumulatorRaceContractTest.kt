package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.ContactVerificationChannel
import com.slotting.admin.identity.ContactVerificationStatus
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.RegisterPlayerCommand
import com.slotting.admin.identity.RegisterPlayerResult
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.identity.VerificationCodeRecord
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.JournalEntryDraft
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DailyRgAccumulatorRaceContractTest {

    private val now = Instant.parse("2026-10-15T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val todayStr = "2026-10-15"
    private val tenantId = "tenant-tc45"
    private val gameId = "AVIATOR"
    private val currency = "PKR"
    private val playerUuid = UUID.randomUUID()
    private val playerIdStr = playerUuid.toString()

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-sys-tc45",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = playerIdStr,
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = setOf(AdminRole.SUPPORT),
    )

    private lateinit var gameStore: InMemoryDurableGameWagerAndSettlementStore
    private lateinit var ledgerStore: InMemoryLedgerJournalStore
    private lateinit var registrationStore: InMemoryPlayerRegistrationStore
    private lateinit var eligibilityStore: InMemoryServerEligibilityStore
    private lateinit var ledgerService: LedgerPostingService
    private lateinit var meterRegistry: SimpleMeterRegistry
    private lateinit var gameService: DurableGameWagerAndSettlementService

    @BeforeEach
    fun setUp() {
        gameStore = InMemoryDurableGameWagerAndSettlementStore()
        ledgerStore = InMemoryLedgerJournalStore()
        registrationStore = InMemoryPlayerRegistrationStore()
        eligibilityStore = InMemoryServerEligibilityStore()
        ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        meterRegistry = SimpleMeterRegistry()
        gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = adminPrincipal,
            clock = clock,
            meterRegistry = meterRegistry,
        )

        val regRecord = PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "email-hash",
            phoneHash = "phone-hash",
            maskedEmail = "p***@example.com",
            maskedPhone = "+91******1234",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            status = PlayerAccountStatus.ACTIVE,
            mfaRequired = false,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )
        registrationStore.players[playerUuid] = regRecord
    }

    private fun seedFunds(amount: Long) {
        ledgerService.postTransaction(
            PostTransactionCommand(
                principal = adminPrincipal,
                tenantId = tenantId,
                transactionReference = "TX-TC45-SEED-${UUID.randomUUID()}",
                currencyCode = currency,
                entries = listOf(
                    JournalEntryDraft("HOUSE:SEED", JournalEntryDirection.DEBIT, amount, currency),
                    JournalEntryDraft("PLAYER:$playerIdStr", JournalEntryDirection.CREDIT, amount, currency),
                ),
                idempotencyKey = "IDEM-TC45-SEED-${UUID.randomUUID()}",
                correlationId = "corr-tc45-seed",
                causationId = "caus-tc45-seed",
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
    }

    private fun setDailyLimit(dailyLimitMinor: Long, singleLimitMinor: Long = Long.MAX_VALUE) {
        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerUuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 5, 5),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = singleLimitMinor,
                    dailyWagerLimitMinor = dailyLimitMinor,
                    currentDailyWagerMinor = 0L,
                )
            )
        )
    }

    @Test
    fun concurrentWagersNeverExceedDailyLimit() {
        val dailyLimit = 100_00L
        setDailyLimit(dailyLimit)
        seedFunds(2000_00L)

        val roundId = "round-${UUID.randomUUID()}"
        createRound(roundId)

        val workers = 16
        val wagerAmount = 60_00L
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(workers)
        val executor = Executors.newFixedThreadPool(workers)
        val results = Collections.synchronizedList(mutableListOf<AviatorCommandAckResult>())

        for (i in 0 until workers) {
            val handId = "hand-$i"
            val cmdId = "cmd-$i-${UUID.randomUUID()}"
            executor.submit {
                try {
                    startLatch.await()
                    val ack = gameService.processCommand(
                        AviatorRestCommand(
                            commandId = cmdId,
                            tenantId = tenantId,
                            roundId = roundId,
                            handId = handId,
                            action = AviatorCommandAction.PLACE_BET.name,
                            wagerMinor = wagerAmount,
                            currency = currency,
                            principal = playerPrincipal,
                            expectedRoundVersion = 1L,
                            correlationId = "corr-$cmdId",
                        )
                    )
                    results.add(ack)
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS))
        executor.shutdown()

        val finalAccumulated = gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr)
        val accepted = results.filter { it.status == AviatorCommandAckStatus.ACCEPTED }
        val rejected = results.filter { it.status == AviatorCommandAckStatus.REJECTED }

        assertEquals(workers, results.size)
        assertTrue(finalAccumulated <= dailyLimit)
        assertEquals(accepted.size * wagerAmount, finalAccumulated)
        for (rej in rejected) {
            assertEquals(AviatorCommandRejectionCode.OUT_OF_LIMITS, rej.rejection?.code)
        }
    }

    @Test
    fun fittingWagerIsAcceptedAndAccumulatorAdvancesExactly() {
        val dailyLimit = 100_00L
        setDailyLimit(dailyLimit)
        seedFunds(500_00L)

        val roundId = "round-${UUID.randomUUID()}"
        createRound(roundId)

        val ack1 = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-fit-1",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-1",
                action = AviatorCommandAction.PLACE_BET.name,
                wagerMinor = 40_00L,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 1L,
                correlationId = "corr-cmd-fit-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack1.status)
        assertEquals(40_00L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr))

        val ack2 = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-fit-2",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-2",
                action = AviatorCommandAction.PLACE_BET.name,
                wagerMinor = 30_00L,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 1L,
                correlationId = "corr-cmd-fit-2",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack2.status)
        assertEquals(70_00L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr))
    }

    @Test
    fun rejectedOverLimitWagerLeavesAccumulatorUnchanged() {
        val dailyLimit = 50_00L
        setDailyLimit(dailyLimit)
        seedFunds(500_00L)

        val roundId = "round-${UUID.randomUUID()}"
        createRound(roundId)

        val ack1 = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-over-1",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-1",
                action = AviatorCommandAction.PLACE_BET.name,
                wagerMinor = 40_00L,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 1L,
                correlationId = "corr-cmd-over-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.ACCEPTED, ack1.status)
        assertEquals(40_00L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr))

        val ack2 = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-over-2",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-2",
                action = AviatorCommandAction.PLACE_BET.name,
                wagerMinor = 20_00L,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 1L,
                correlationId = "corr-cmd-over-2",
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, ack2.status)
        assertEquals(AviatorCommandRejectionCode.OUT_OF_LIMITS, ack2.rejection?.code)
        assertEquals(40_00L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr))
    }

    @Test
    fun accumulatorOverflowFailsClosed() {
        val dailyLimit = Long.MAX_VALUE
        setDailyLimit(dailyLimit, Long.MAX_VALUE)
        seedFunds(1000_00L)

        gameStore.addDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr, Long.MAX_VALUE - 1000L)
        assertEquals(Long.MAX_VALUE - 1000L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr))

        val roundId = "round-${UUID.randomUUID()}"
        createRound(roundId)

        val ack = gameService.processCommand(
            AviatorRestCommand(
                commandId = "cmd-overflow-1",
                tenantId = tenantId,
                roundId = roundId,
                handId = "hand-overflow",
                action = AviatorCommandAction.PLACE_BET.name,
                wagerMinor = 2000L,
                currency = currency,
                principal = playerPrincipal,
                expectedRoundVersion = 1L,
                correlationId = "corr-cmd-overflow-1",
            )
        )
        assertEquals(AviatorCommandAckStatus.REJECTED, ack.status)
        assertEquals(AviatorCommandRejectionCode.OUT_OF_LIMITS, ack.rejection?.code)
        assertEquals(Long.MAX_VALUE - 1000L, gameStore.findDailyAccumulatedWager(tenantId, playerIdStr, currency, todayStr))
    }
}
