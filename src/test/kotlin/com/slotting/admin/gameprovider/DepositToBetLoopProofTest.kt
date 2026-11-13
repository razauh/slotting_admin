package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.identity.AmlComplianceStatus
import com.slotting.admin.identity.InMemoryPlayerRegistrationStore
import com.slotting.admin.identity.InMemoryServerEligibilityStore
import com.slotting.admin.identity.KycComplianceStatus
import com.slotting.admin.identity.PlayerAccountStatus
import com.slotting.admin.identity.PlayerComplianceProfile
import com.slotting.admin.identity.PlayerRegistrationRecord
import com.slotting.admin.identity.ResponsiblePlayProfile
import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.rails.ApprovalOutcome
import com.slotting.admin.rails.DepositGate
import com.slotting.admin.rails.DepositSubmission
import com.slotting.admin.rails.DepositSubmissionRepository
import com.slotting.admin.rails.GateDecision
import com.slotting.admin.rails.LedgerDepositCreditPoster
import com.slotting.admin.rails.ManualRailsApprovalFlow
import com.slotting.admin.rails.ManualRailsService
import com.slotting.admin.rails.SubmissionStatus
import com.slotting.admin.realtime.RealtimeHint
import com.slotting.admin.realtime.RealtimeHintTransport
import com.slotting.admin.realtime.RealtimePublishService
import com.slotting.admin.realtime.RoundHintPublisher
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.InMemoryAuthoritativeWalletStore
import org.junit.jupiter.api.Test
import java.math.BigDecimal
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DepositToBetLoopProofTest {
    private class RecordingHintTransport : RealtimeHintTransport {
        val batches = mutableListOf<Pair<String, List<RealtimeHint>>>()
        override fun send(channel: String, hints: List<RealtimeHint>) {
            batches.add(channel to hints)
        }
    }

    private val now = Instant.parse("2026-11-12T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-loop"
    private val gameId = "AVIATOR"
    private val playerUuid = UUID.randomUUID()
    private val playerId = playerUuid.toString()
    private val roundId = "round-loop-1"
    private val submissionId = "sub-loop-1"
    private val admin = AuthenticatedPrincipal("admin-loop", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private val player = AuthenticatedPrincipal(playerId, tenantId, PrincipalKind.PLAYER, emptySet())

    private class InMemoryDepositRepository : DepositSubmissionRepository {
        val submissions = linkedMapOf<String, DepositSubmission>()

        override fun find(id: String) = submissions[id]

        override fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String): Boolean {
            val current = submissions[id] ?: return false
            if (current.status != SubmissionStatus.SUBMITTED) return false
            submissions[id] = current.copy(status = SubmissionStatus.APPROVED, rateApplied = rate, amountUsd = usd)
            return true
        }

        override fun markRejected(id: String, reason: String, by: String): Boolean {
            val current = submissions[id] ?: return false
            if (current.status != SubmissionStatus.SUBMITTED) return false
            submissions[id] = current.copy(status = SubmissionStatus.REJECTED, rejectReason = reason)
            return true
        }

        override fun hasApprovedDeposit(playerId: String) =
            submissions.values.any { it.playerId == playerId && it.status == SubmissionStatus.APPROVED }

        override fun insert(
            submission: DepositSubmission,
            fundingAccountId: String,
            transferReference: String,
            transferredUtc: Instant,
            receiptObject: String,
        ) {
            submissions[submission.id] = submission
        }

        override fun listByStatus(tenantId: String, status: SubmissionStatus) =
            submissions.values.filter { it.tenantId == tenantId && it.status == status }

        override fun listMine(tenantId: String, playerId: String) =
            submissions.values.filter { it.tenantId == tenantId && it.playerId == playerId }

        override fun revertApproval(id: String): Boolean {
            val current = submissions[id] ?: return false
            submissions[id] = current.copy(status = SubmissionStatus.SUBMITTED, rateApplied = null, amountUsd = null)
            return true
        }
    }

    @Test
    fun `deposit approval credits the canonical account and funds a real bet`() {
        val repository = InMemoryDepositRepository()
        repository.submissions[submissionId] = DepositSubmission(
            id = submissionId,
            tenantId = tenantId,
            playerId = playerId,
            amountPkr = BigDecimal("2800.00"),
            status = SubmissionStatus.SUBMITTED,
        )
        val ledgerStore = InMemoryLedgerJournalStore()
        val ledgerService = LedgerPostingService(store = ledgerStore, clock = clock)
        val poster = LedgerDepositCreditPoster(ledgerService)
        val railsService = ManualRailsService(repository, { BigDecimal("280") }) { creditedPlayer, usd ->
            poster.post(tenantId, creditedPlayer, usd, submissionId)
        }
        val approvalFlow = ManualRailsApprovalFlow(repository, railsService, poster)

        assertEquals(GateDecision.DENIED, DepositGate(repository).check(playerId).decision)
        val approval = approvalFlow.approve(submissionId, "admin-loop")
        assertEquals(ApprovalOutcome.APPROVED, approval.outcome)
        assertEquals(BigDecimal("10.00"), approval.amountUsd)

        val depositLegs = ledgerStore.findAllLegsForTenant(tenantId).filter { it.accountReference.contains(playerId) }
        assertEquals(1, depositLegs.size)
        assertEquals("PLAYER:$playerId", depositLegs.single().accountReference)
        assertEquals(1000L, depositLegs.single().amountMinorUnits)
        assertEquals(1000L, ledgerStore.findBalance(tenantId, "PLAYER:$playerId", "USD"))
        assertEquals(GateDecision.ALLOWED, DepositGate(repository).check(playerId).decision)

        val walletService = AuthoritativeWalletService(
            store = InMemoryAuthoritativeWalletStore(ledgerStore = ledgerStore, clock = clock),
            clock = clock,
        )
        val gameStore = InMemoryDurableGameWagerAndSettlementStore()
        val registrationStore = InMemoryPlayerRegistrationStore()
        registrationStore.players[playerUuid] = PlayerRegistrationRecord(
            playerId = playerUuid,
            tenantId = tenantId,
            emailHash = "email-loop",
            phoneHash = "phone-loop",
            maskedEmail = "loop@test.internal",
            maskedPhone = "+1***0001",
            jurisdiction = "DEFAULT",
            riskScore = 0.0,
            mfaRequired = false,
            status = PlayerAccountStatus.ACTIVE,
            createdAt = now.minusSeconds(86400),
            updatedAt = now.minusSeconds(86400),
        )
        val eligibilityStore = InMemoryServerEligibilityStore()
        eligibilityStore.saveComplianceProfile(
            PlayerComplianceProfile(
                playerId = playerUuid,
                tenantId = tenantId,
                dateOfBirth = LocalDate.of(1995, 1, 1),
                kycStatus = KycComplianceStatus.VERIFIED,
                amlStatus = AmlComplianceStatus.CLEARED,
                jurisdiction = "DEFAULT",
                responsiblePlay = ResponsiblePlayProfile(
                    playerId = playerUuid,
                    selfExcluded = false,
                    singleWagerLimitMinor = 50000L,
                    dailyWagerLimitMinor = 200000L,
                    currentDailyWagerMinor = 0L,
                ),
            ),
        )
        val hintTransport = RecordingHintTransport()
        val hintPublisher = RoundHintPublisher(RealtimePublishService(hintTransport), enabled = true)
        val gameService = DurableGameWagerAndSettlementService(
            store = gameStore,
            ledgerService = ledgerService,
            registrationStore = registrationStore,
            eligibilityStore = eligibilityStore,
            adminPrincipal = admin,
            clock = clock,
            roundHintPublisher = hintPublisher,
            depositGate = DepositGate(repository),
        )
        val fairnessStore = InMemoryFairnessEvidenceStore()
        val eventJournalStore = InMemoryGameEventJournalStore()
        val snapshotService = AuthoritativeGameSnapshotAndEventService(
            gameStore = gameStore,
            gameService = gameService,
            walletService = walletService,
            ledgerStore = ledgerStore,
            fairnessStore = fairnessStore,
            eventJournalStore = eventJournalStore,
            registrationStore = registrationStore,
            clock = clock,
        )

        val myInfo = snapshotService.getMyInfo(tenantId, player, "USD")
        assertEquals(1000L, myInfo.balanceMinor)
        assertEquals("USD", myInfo.currency)

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.BET_COUNTDOWN,
            ),
        )
        val betAck = gameService.processCommand(
            AviatorRestCommand(
                tenantId = tenantId,
                principal = player,
                commandId = "cmd-loop-bet-1",
                roundId = roundId,
                handId = "hand_primary",
                action = "PLACE_BET",
                wagerMinor = 400L,
                currency = "USD",
                correlationId = "corr-loop-bet-1",
            ),
        )

        assertEquals(AviatorCommandAckStatus.ACCEPTED, betAck.status)
        assertEquals(400L, betAck.result?.wagerMinor)
        assertEquals(600L, ledgerStore.findBalance(tenantId, "PLAYER:$playerId", "USD"))
        assertEquals(400L, ledgerStore.findBalance(tenantId, "ESCROW:GAME:$gameId", "USD"))

        gameService.createOrUpdateRound(
            CreateOrUpdateRoundCommand(
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                phase = GameRoundPhase.FLYING,
                roundVersion = 2L,
                expectedVersion = 1L,
            ),
        )
        val hintBatch = hintTransport.batches.singleOrNull()
        assertTrue(hintBatch != null, "expected one committed phase hint batch")
        assertEquals("tenant:$tenantId:player:$playerId", hintBatch!!.first)
        assertEquals("round-loop-1", hintBatch.second.single().payload["roundId"])
        assertEquals("FLYING", hintBatch.second.single().payload["phase"])

        val playerLegs = ledgerStore.findAllLegsForTenant(tenantId).filter { it.accountReference.contains(playerId) }
        assertEquals(2, playerLegs.size)
        assertTrue(playerLegs.all { it.accountReference == "PLAYER:$playerId" })
        assertTrue(ledgerStore.findAllLegsForTenant(tenantId).none { it.accountReference.startsWith("player:") })
        assertTrue(ledgerStore.findAllLegsForTenant(tenantId).none { it.accountReference.startsWith("PLAYER_WALLET:") })

        eventJournalStore.saveEvent(
            GameEventRecord(
                eventId = UUID.randomUUID(),
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                sequenceId = 1L,
                eventName = "gameState",
                payloadJson = "{}",
                targetScope = "ROUND",
                targetOwnerId = null,
                timestampMillis = now.toEpochMilli(),
                createdAt = now,
                roundVersion = 1L,
            ),
        )
        eventJournalStore.saveEvent(
            GameEventRecord(
                eventId = UUID.randomUUID(),
                tenantId = tenantId,
                gameId = gameId,
                roundId = roundId,
                sequenceId = 2L,
                eventName = "gameState",
                payloadJson = "{}",
                targetScope = "ROUND",
                targetOwnerId = null,
                timestampMillis = now.toEpochMilli(),
                createdAt = now,
                roundVersion = 2L,
            ),
        )
        val invariants = AviatorFinancialInvariantChecker(ledgerStore, gameStore, eventJournalStore, fairnessStore)
            .check(tenantId, gameId, roundId)
        assertTrue(invariants.violations.isEmpty(), invariants.violations.toString())
    }
}
