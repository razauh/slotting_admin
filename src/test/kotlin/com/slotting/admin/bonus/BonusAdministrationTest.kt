package com.slotting.admin.bonus

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BonusAdministrationTest {

    private val now = Instant.parse("2026-09-18T23:55:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        BonusAdministrationBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        BonusAdministrationBinding.isBound = true
    }

    private fun adminPrincipal(
        id: String = "admin-maker-1",
        tenantId: String = "tenant-1",
        roles: Set<AdminRole> = setOf(AdminRole.SUPER_ADMIN)
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = roles
        )
    }

    private fun playerPrincipal(
        id: String = "player-1",
        tenantId: String = "tenant-1"
    ): AuthenticatedPrincipal {
        return AuthenticatedPrincipal(
            id = id,
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet()
        )
    }

    // =========================================================================
    // BONUS-003-01-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `BONUS-003-01-T001 Administer approved bonus grants produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        BonusAdministrationBinding.checkBound()

        val store = InMemoryBonusAdministrationStore()
        val alertSink = InMemoryBonusAlertSink()
        val thresholdMinorUnits = 10_000L // $100.00
        val service = BonusAdministrationService(
            store = store,
            highValueThresholdMinorUnits = thresholdMinorUnits,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-casino-1"
        val playerId1 = UUID.randomUUID()
        val adminMaker = adminPrincipal("admin-maker-1", tenantId)
        val adminChecker = adminPrincipal("admin-checker-2", tenantId)

        // Seed wallet 1: $100 cash (10,000 units), $0 bonus
        val initialWallet1 = PlayerWalletBuckets(
            tenantId = tenantId,
            playerId = playerId1,
            currencyCode = "USD",
            cashMinorUnits = 10_000L,
            bonusMinorUnits = 0L,
            lockedCashMinorUnits = 0L,
            version = 1L
        )
        store.saveWallet(initialWallet1)

        // Step 1: Standard-value grant (<= threshold, e.g. $50.00 = 5,000 units)
        // Should execute directly with structured reason, updating wallet and ledger immediately
        val standardGrantCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId1,
            bonusType = BonusGrantType.LOYALTY_REWARD,
            amountMinorUnits = 5_000L,
            currencyCode = "USD",
            wageringRequirementMultiplier = 15.0,
            grantReason = "VIP tier 1 monthly loyalty reward credit",
            idempotencyKey = "std-grant-1",
            correlationId = "corr-std-1",
            causationId = "caus-std-1",
            expectedVersion = 1L
        )
        val stdResult = service.administerGrant(standardGrantCmd)

        assertFalse(stdResult.requiresApproval)
        assertNull(stdResult.proposalId)
        assertNotNull(stdResult.grantId)
        assertEquals(5_000L, stdResult.newBonusBalanceMinorUnits)
        assertEquals(2L, stdResult.serverVersion)

        // Verify wallet was updated
        val walletAfterStd = store.findWallet(tenantId, playerId1, "USD")
        assertNotNull(walletAfterStd)
        assertEquals(5_000L, walletAfterStd.bonusMinorUnits)
        assertEquals(2L, walletAfterStd.version)

        // Step 2: High-value grant (> threshold, e.g. $250.00 = 25,000 units)
        // Must NOT edit balance directly! Must route to four-eyes approval queue
        val highValueGrantCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId1,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 25_000L,
            currencyCode = "USD",
            wageringRequirementMultiplier = 20.0,
            grantReason = "System outage goodwill compensation resolution",
            idempotencyKey = "high-grant-1",
            correlationId = "corr-high-1",
            causationId = "caus-high-1",
            expectedVersion = 2L
        )
        val highResult = service.administerGrant(highValueGrantCmd)

        // Assert high-value decision gate: never direct projection edit
        assertTrue(highResult.requiresApproval)
        assertNotNull(highResult.proposalId)
        assertNull(highResult.grantId)
        // Wallet balance remains 5,000L, NOT yet incremented!
        assertEquals(5_000L, highResult.newBonusBalanceMinorUnits)
        assertEquals(2L, highResult.serverVersion)

        val proposalId = highResult.proposalId!!
        val pendingProposals = service.getPendingProposals(tenantId)
        assertEquals(1, pendingProposals.size)
        assertEquals(proposalId, pendingProposals[0].proposalId)
        assertEquals(BonusProposalStatus.PENDING_APPROVAL, pendingProposals[0].status)

        // Wallet is still untouched
        val walletBeforeApproval = store.findWallet(tenantId, playerId1, "USD")
        assertNotNull(walletBeforeApproval)
        assertEquals(5_000L, walletBeforeApproval.bonusMinorUnits)
        assertEquals(2L, walletBeforeApproval.version)

        // Step 3: Four-eyes checker approval by distinct administrator
        val approveCmd = ApproveBonusProposalCommand(
            checkerPrincipal = adminChecker,
            tenantId = tenantId,
            proposalId = proposalId,
            checkerReason = "Verified incident ticket and approved compensation",
            idempotencyKey = "approve-prop-1",
            correlationId = "corr-app-1",
            causationId = "caus-app-1",
            expectedWalletVersion = 2L
        )
        val approveResult = service.approveProposal(approveCmd)

        assertNotNull(approveResult.grantId)
        assertEquals(adminMaker.id, approveResult.makerId)
        assertEquals(adminChecker.id, approveResult.checkerId)
        assertEquals(30_000L, approveResult.newBonusBalanceMinorUnits) // 5,000 + 25,000
        assertEquals(3L, approveResult.serverVersion)

        // Verify proposal is now APPROVED and pending queue is empty
        val updatedProposal = service.getProposal(tenantId, proposalId)
        assertNotNull(updatedProposal)
        assertEquals(BonusProposalStatus.APPROVED, updatedProposal.status)
        assertEquals(adminChecker.id, updatedProposal.checkerPrincipalId)
        assertTrue(service.getPendingProposals(tenantId).isEmpty())

        // Verify wallet updated
        val walletAfterApproval = store.findWallet(tenantId, playerId1, "USD")
        assertNotNull(walletAfterApproval)
        assertEquals(30_000L, walletAfterApproval.bonusMinorUnits)
        assertEquals(3L, walletAfterApproval.version)

        // Step 4: Double-entry ledger balance conservation: debits == credits
        val allLedger = store.getLedgerEntries(tenantId)
        assertTrue(allLedger.isNotEmpty())
        for (entry in allLedger) {
            assertTrue(entry.amountMinorUnits > 0L)
            assertFalse(entry.debitAccount.isBlank())
            assertFalse(entry.creditAccount.isBlank())
            assertFalse(entry.debitAccount == entry.creditAccount)
        }

        val totalDebits = allLedger.groupBy { it.debitAccount }.values.sumOf { list -> list.sumOf { e -> e.amountMinorUnits } }
        val totalCredits = allLedger.groupBy { it.creditAccount }.values.sumOf { list -> list.sumOf { e -> e.amountMinorUnits } }
        assertEquals(totalDebits, totalCredits)

        // Step 5: Evidence references and audit events
        assertFalse(stdResult.evidenceReference.isBlank())
        assertFalse(highResult.evidenceReference.isBlank())
        assertFalse(approveResult.evidenceReference.isBlank())
        assertEquals("BONUS_GRANT_DIRECT_POSTED", stdResult.auditEvent.type)
        assertEquals("BONUS_GRANT_PROPOSAL_SUBMITTED", highResult.auditEvent.type)
        assertEquals("BONUS_GRANT_APPROVED", approveResult.auditEvent.type)
    }

    // =========================================================================
    // BONUS-003-01-T002: Negative, Boundary, and Security Gaps
    // =========================================================================

    @Test
    fun `BONUS-003-01-T002 Negative boundary and security scenarios fail closed`() {
        BonusAdministrationBinding.isBound = true

        val store = InMemoryBonusAdministrationStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusAdministrationService(
            store = store,
            highValueThresholdMinorUnits = 10_000L,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-sec-1"
        val playerId = UUID.randomUUID()
        val adminMaker = adminPrincipal("admin-maker-1", tenantId)
        val adminChecker = adminPrincipal("admin-checker-2", tenantId)
        val player = playerPrincipal(playerId.toString(), tenantId)

        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 1_000L,
                bonusMinorUnits = 0L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // 1. Self-grant prevention: Admin cannot grant bonus to own player account (FORBIDDEN)
        val selfGrantCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = UUID.fromString("00000000-0000-0000-0000-000000000001"), // Same as adminMaker.id
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 1_000L,
            currencyCode = "USD",
            grantReason = "Self-grant attempt for personal play",
            idempotencyKey = "self-grant-1",
            correlationId = "corr-self",
            causationId = "caus-self",
            expectedVersion = 1L
        )
        // Set principal ID to match playerId
        val selfGrantPrincipal = adminPrincipal(id = "00000000-0000-0000-0000-000000000001", tenantId = tenantId)
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(selfGrantCmd.copy(principal = selfGrantPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex1.code)

        // 2. Unreasoned grant prevention: Blank reason or reason < 10 chars fails closed (INVALID)
        val unreasonedCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 1_000L,
            currencyCode = "USD",
            grantReason = "too short", // Less than 10 characters
            idempotencyKey = "unreasoned-1",
            correlationId = "corr-unr",
            causationId = "caus-unr",
            expectedVersion = 1L
        )
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(unreasonedCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex2.code)

        // Blank reason
        val blankReasonCmd = unreasonedCmd.copy(grantReason = "   ", idempotencyKey = "blank-reason-1")
        val ex2b = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(blankReasonCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex2b.code)

        // Create a legitimate high-value proposal for checker testing
        val highValueCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 20_000L,
            currencyCode = "USD",
            grantReason = "Legitimate high-value grant proposal",
            idempotencyKey = "high-val-prop",
            correlationId = "corr-hvp",
            causationId = "caus-hvp",
            expectedVersion = 1L
        )
        val propRes = service.administerGrant(highValueCmd)
        val proposalId = propRes.proposalId!!

        // 3. Segregation of duties: Maker cannot approve their own proposal! (FORBIDDEN)
        val makerSelfApprove = ApproveBonusProposalCommand(
            checkerPrincipal = adminMaker, // Maker attempting to approve own proposal!
            tenantId = tenantId,
            proposalId = proposalId,
            checkerReason = "Maker self-approval attempt",
            idempotencyKey = "self-approve-1",
            correlationId = "corr-sa",
            causationId = "caus-sa",
            expectedWalletVersion = 1L
        )
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.approveProposal(makerSelfApprove)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex3.code)

        // 4. Non-admin (player) attempting to administer grant fails closed (FORBIDDEN)
        val playerAdministerCmd = AdministerBonusGrantCommand(
            principal = player,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 1_000L,
            currencyCode = "USD",
            grantReason = "Player attempting grant administration",
            idempotencyKey = "player-admin-1",
            correlationId = "corr-pa",
            causationId = "caus-pa",
            expectedVersion = 1L
        )
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(playerAdministerCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex4.code)

        // 5. Cross-tenant request rejected (FORBIDDEN)
        val crossTenantAdmin = adminPrincipal("admin-cross", "attacker-tenant")
        val crossTenantCmd = AdministerBonusGrantCommand(
            principal = crossTenantAdmin,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 1_000L,
            currencyCode = "USD",
            grantReason = "Cross-tenant grant attempt",
            idempotencyKey = "cross-tenant-1",
            correlationId = "corr-ct",
            causationId = "caus-ct",
            expectedVersion = 1L
        )
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(crossTenantCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex5.code)

        // 6. Unauthenticated request rejected (UNAUTHENTICATED)
        val unauthCmd = AdministerBonusGrantCommand(
            principal = null,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 1_000L,
            currencyCode = "USD",
            grantReason = "Unauthenticated grant attempt",
            idempotencyKey = "unauth-1",
            correlationId = "corr-ua",
            causationId = "caus-ua",
            expectedVersion = 1L
        )
        val ex6 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(unauthCmd)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex6.code)

        // 7. Stale wallet version rejected (STALE)
        val staleCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 1_000L,
            currencyCode = "USD",
            grantReason = "Stale version grant attempt",
            idempotencyKey = "stale-1",
            correlationId = "corr-stale",
            causationId = "caus-stale",
            expectedVersion = 999L
        )
        val ex7 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(staleCmd)
        }
        assertEquals(AuthErrorCode.STALE, ex7.code)

        // 8. Negative amount rejected (INVALID)
        val negativeCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = -500L,
            currencyCode = "USD",
            grantReason = "Negative amount grant attempt",
            idempotencyKey = "neg-1",
            correlationId = "corr-neg",
            causationId = "caus-neg",
            expectedVersion = 1L
        )
        val ex8 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(negativeCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex8.code)
    }

    // =========================================================================
    // BONUS-003-01-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `BONUS-003-01-T003 Idempotency replays, conflict detection, and concurrent execution maintain balance conservation`() {
        BonusAdministrationBinding.isBound = true

        val store = InMemoryBonusAdministrationStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusAdministrationService(
            store = store,
            highValueThresholdMinorUnits = 10_000L,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-idem-1"
        val playerId = UUID.randomUUID()
        val adminMaker = adminPrincipal("admin-maker-1", tenantId)
        val adminChecker = adminPrincipal("admin-checker-2", tenantId)

        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 5_000L,
                bonusMinorUnits = 0L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // 1. Direct grant idempotency replay
        val directGrantCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 2_000L,
            currencyCode = "USD",
            grantReason = "Idempotent direct grant test case",
            idempotencyKey = "idem-direct-key",
            correlationId = "corr-id-1",
            causationId = "caus-id-1",
            expectedVersion = 1L
        )
        val res1 = service.administerGrant(directGrantCmd)
        val res2 = service.administerGrant(directGrantCmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.grantId, res2.grantId)
        assertEquals(res1.serverVersion, res2.serverVersion)

        val walletAfterIdem = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterIdem)
        assertEquals(2L, walletAfterIdem.version) // Only incremented once
        assertEquals(2_000L, walletAfterIdem.bonusMinorUnits)

        // 2. Conflict detection on modified payload with same key
        val conflictCmd = directGrantCmd.copy(amountMinorUnits = 3_000L)
        val conflictEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.administerGrant(conflictCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictEx.code)

        // 3. Approval idempotency replay
        val highCmd = AdministerBonusGrantCommand(
            principal = adminMaker,
            tenantId = tenantId,
            playerId = playerId,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 20_000L,
            currencyCode = "USD",
            grantReason = "High value grant proposal for idempotency test",
            idempotencyKey = "idem-high-key",
            correlationId = "corr-ih-1",
            causationId = "caus-ih-1",
            expectedVersion = 2L
        )
        val propRes = service.administerGrant(highCmd)
        val proposalId = propRes.proposalId!!

        val approveCmd = ApproveBonusProposalCommand(
            checkerPrincipal = adminChecker,
            tenantId = tenantId,
            proposalId = proposalId,
            checkerReason = "Approved proposal for idempotency verification",
            idempotencyKey = "idem-approve-key",
            correlationId = "corr-ia-1",
            causationId = "caus-ia-1",
            expectedWalletVersion = 2L
        )
        val appRes1 = service.approveProposal(approveCmd)
        val appRes2 = service.approveProposal(approveCmd)

        assertEquals(appRes1.resultId, appRes2.resultId)
        assertEquals(appRes1.grantId, appRes2.grantId)
        assertEquals(appRes1.serverVersion, appRes2.serverVersion)

        val walletAfterApproveIdem = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterApproveIdem)
        assertEquals(3L, walletAfterApproveIdem.version)
        assertEquals(22_000L, walletAfterApproveIdem.bonusMinorUnits)

        // 4. 16-thread concurrent execution across distinct players
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)
        val concurrentResults = ConcurrentHashMap<Int, AdministerBonusGrantResult>()

        val concurrentPlayers = (0 until threadCount).map { i ->
            val pId = UUID.randomUUID()
            store.saveWallet(
                PlayerWalletBuckets(
                    tenantId = tenantId,
                    playerId = pId,
                    currencyCode = "USD",
                    cashMinorUnits = 1_000L,
                    bonusMinorUnits = 0L,
                    lockedCashMinorUnits = 0L,
                    version = 1L
                )
            )
            pId
        }

        for (i in 0 until threadCount) {
            val pId = concurrentPlayers[i]
            executor.submit {
                try {
                    val res = service.administerGrant(
                        AdministerBonusGrantCommand(
                            principal = adminMaker,
                            tenantId = tenantId,
                            playerId = pId,
                            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                            amountMinorUnits = 5_000L,
                            currencyCode = "USD",
                            grantReason = "Concurrent grant administration test $i",
                            idempotencyKey = "concurrent-grant-$i",
                            correlationId = "corr-cg-$i",
                            causationId = "caus-cg-$i",
                            expectedVersion = 1L
                        )
                    )
                    concurrentResults[i] = res
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()

        assertEquals(threadCount, concurrentResults.size)
        for (i in 0 until threadCount) {
            val res = concurrentResults[i]
            assertNotNull(res)
            assertEquals(5_000L, res.newBonusBalanceMinorUnits)
            assertFalse(res.requiresApproval)
        }
    }

    // =========================================================================
    // BONUS-003-01-T004: Migration Integrity, Recovery, and Observability
    // =========================================================================

    @Test
    fun `BONUS-003-01-T004 Migration integrity recovery and observability verification`() {
        BonusAdministrationBinding.isBound = true

        // 1. Migration integrity: Check Flyway migration scripts
        val migrationDir = File("src/main/resources/db/migration")
        if (migrationDir.exists()) {
            val files = migrationDir.listFiles()?.map { it.name } ?: emptyList()
            for (filename in files) {
                if (filename.startsWith("V") && filename.contains("__")) {
                    val versionPart = filename.substring(1, filename.indexOf("__"))
                    val versionNum = versionPart.toIntOrNull()
                    if (versionNum != null) {
                        assertTrue(
                            versionNum <= 16,
                            "Migration version $versionNum exceeds V16 limit! Found: $filename"
                        )
                    }
                }
            }
        }

        // 2. Recovery and Restart: State survives across service instances
        val store = InMemoryBonusAdministrationStore()
        val alertSink = InMemoryBonusAlertSink()

        val service1 = BonusAdministrationService(
            store = store,
            highValueThresholdMinorUnits = 10_000L,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-recovery-1"
        val playerId = UUID.randomUUID()
        val adminMaker = adminPrincipal("admin-maker-1", tenantId)
        val adminChecker = adminPrincipal("admin-checker-2", tenantId)

        store.saveWallet(
            PlayerWalletBuckets(
                tenantId = tenantId,
                playerId = playerId,
                currencyCode = "USD",
                cashMinorUnits = 5_000L,
                bonusMinorUnits = 0L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        // Submit high-value grant proposal on Service 1
        val propRes = service1.administerGrant(
            AdministerBonusGrantCommand(
                principal = adminMaker,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                amountMinorUnits = 50_000L,
                currencyCode = "USD",
                grantReason = "Recovery test high-value proposal",
                idempotencyKey = "rec-prop-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )
        val proposalId = propRes.proposalId!!

        // Simulate service restart: instantiate fresh Service 2 sharing underlying store
        val service2 = BonusAdministrationService(
            store = store,
            highValueThresholdMinorUnits = 10_000L,
            alertSink = alertSink,
            clock = clock
        )

        // Verify Service 2 can inspect pending proposal and approve it
        val recoveredProposal = service2.getProposal(tenantId, proposalId)
        assertNotNull(recoveredProposal)
        assertEquals(BonusProposalStatus.PENDING_APPROVAL, recoveredProposal.status)

        val appRes = service2.approveProposal(
            ApproveBonusProposalCommand(
                checkerPrincipal = adminChecker,
                tenantId = tenantId,
                proposalId = proposalId,
                checkerReason = "Approved after service recovery rehearsal",
                idempotencyKey = "rec-app-1",
                correlationId = "corr-rec-2",
                causationId = "caus-rec-2",
                expectedWalletVersion = 1L
            )
        )
        assertEquals(50_000L, appRes.newBonusBalanceMinorUnits)

        // 3. Observability & Redaction
        val alerts = alertSink.alerts
        for (alert in alerts) {
            assertFalse(alert.contains("password", ignoreCase = true))
            assertFalse(alert.contains("secret", ignoreCase = true))
            assertFalse(alert.contains("token", ignoreCase = true))
        }

        assertEquals("corr-rec-2", appRes.auditEvent.correlationId)
        assertEquals("caus-rec-2", appRes.auditEvent.causationId)
        assertEquals("BONUS_GRANT_APPROVED", appRes.outboxEvent.type)
    }
}
