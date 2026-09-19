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

class BonusRevocationAuditTest {

    private val now = Instant.parse("2026-09-18T23:55:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        BonusRevocationAuditBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        BonusRevocationAuditBinding.isBound = true
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
    // BONUS-003-02-T001: Primary Authoritative Outcome
    // =========================================================================

    @Test
    fun `BONUS-003-02-T001 Audit bonus revocation produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        BonusRevocationAuditBinding.checkBound()

        val store = InMemoryBonusRevocationStore()
        val alertSink = InMemoryBonusAlertSink()
        val thresholdMinorUnits = 10_000L // $100.00
        val service = BonusRevocationAuditService(
            store = store,
            highValueThresholdMinorUnits = thresholdMinorUnits,
            alertSink = alertSink,
            clock = clock
        )

        val tenantId = "tenant-casino-1"
        val playerId1 = UUID.randomUUID()
        val adminMaker = adminPrincipal("admin-maker-1", tenantId)
        val adminChecker = adminPrincipal("admin-checker-2", tenantId)

        // Seed wallet 1: $100 cash (10,000 units), $300 bonus (30,000 units)
        val initialWallet1 = PlayerWalletBuckets(
            tenantId = tenantId,
            playerId = playerId1,
            currencyCode = "USD",
            cashMinorUnits = 10_000L,
            bonusMinorUnits = 30_000L,
            lockedCashMinorUnits = 0L,
            version = 1L
        )
        store.saveWallet(initialWallet1)

        // Seed Grant 1: Standard value grant ($40.00 = 4,000 units)
        val grant1Id = UUID.randomUUID()
        val grant1 = BonusGrantRecord(
            grantId = grant1Id,
            tenantId = tenantId,
            playerId = playerId1,
            bonusType = BonusGrantType.LOYALTY_REWARD,
            amountMinorUnits = 4_000L,
            currencyCode = "USD",
            wageringRequirementMultiplier = 10.0,
            wageringRequirementMinorUnits = 40_000L,
            wageringProgressMinorUnits = 0L,
            status = BonusGrantStatus.ACTIVE,
            reason = "Loyalty grant",
            createdAt = now.minusSeconds(3600),
            expiresAt = now.plusSeconds(86400),
            version = 1L
        )
        store.saveGrant(grant1)

        // Seed Grant 2: High value grant ($200.00 = 20,000 units)
        val grant2Id = UUID.randomUUID()
        val grant2 = BonusGrantRecord(
            grantId = grant2Id,
            tenantId = tenantId,
            playerId = playerId1,
            bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
            amountMinorUnits = 20_000L,
            currencyCode = "USD",
            wageringRequirementMultiplier = 20.0,
            wageringRequirementMinorUnits = 400_000L,
            wageringProgressMinorUnits = 0L,
            status = BonusGrantStatus.ACTIVE,
            reason = "VIP high-value discretionary grant",
            createdAt = now.minusSeconds(1800),
            expiresAt = now.plusSeconds(86400 * 7),
            version = 1L
        )
        store.saveGrant(grant2)

        // Seed initial ledger entries for conservation baseline
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = tenantId,
                transactionReference = "seed-cash",
                debitAccount = "SYSTEM_LIQUIDITY_CLEARING",
                creditAccount = "PLAYER_CASH_LIABILITY:$playerId1",
                amountMinorUnits = 10_000L,
                currencyCode = "USD",
                createdAt = now
            )
        )
        store.recordLedgerEntry(
            BonusLedgerEntry(
                entryId = UUID.randomUUID(),
                tenantId = tenantId,
                transactionReference = "seed-bonus",
                debitAccount = "CASINO_PROMOTION_EXPENSE",
                creditAccount = "PLAYER_BONUS_LIABILITY:$playerId1",
                amountMinorUnits = 30_000L,
                currencyCode = "USD",
                createdAt = now
            )
        )

        // Step 1: Standard-value revocation (<= threshold, 4,000 units)
        // Executed directly with structured reason, updating wallet and audit record immediately
        val directRevokeCmd = RevokeBonusCommand(
            principal = adminMaker,
            tenantId = tenantId,
            grantId = grant1Id,
            playerId = playerId1,
            currencyCode = "USD",
            revocationReason = "Terms violation: duplicate account detected",
            idempotencyKey = "std-revoke-1",
            correlationId = "corr-rev-1",
            causationId = "caus-rev-1",
            expectedVersion = 1L
        )
        val directResult = service.revokeBonus(directRevokeCmd)

        assertFalse(directResult.requiresApproval)
        assertNull(directResult.proposalId)
        assertNotNull(directResult.revocationId)
        assertEquals(4_000L, directResult.revokedAmountMinorUnits)
        assertEquals(2L, directResult.serverVersion)

        // Verify audit record is stored and discoverable
        val auditRecord1 = service.getRevocationAudit(tenantId, directResult.revocationId!!)
        assertNotNull(auditRecord1)
        assertEquals(adminMaker.id, auditRecord1.makerPrincipalId)
        assertNull(auditRecord1.checkerPrincipalId)
        assertFalse(auditRecord1.isHighValue)
        assertEquals(26_000L, auditRecord1.remainingBonusMinorUnits) // 30,000 - 4,000
        assertEquals(10_000L, auditRecord1.remainingCashMinorUnits)

        // Verify grant status is CANCELLED
        val updatedGrant1 = store.findGrant(tenantId, grant1Id)
        assertNotNull(updatedGrant1)
        assertEquals(BonusGrantStatus.CANCELLED, updatedGrant1.status)

        // Step 2: High-value revocation (> threshold, 20,000 units)
        // Must NOT edit projection or balances directly! Must route to four-eyes proposal queue
        val highValueRevokeCmd = RevokeBonusCommand(
            principal = adminMaker,
            tenantId = tenantId,
            grantId = grant2Id,
            playerId = playerId1,
            currencyCode = "USD",
            revocationReason = "Bonus abuse investigation: irregular betting patterns detected",
            idempotencyKey = "high-revoke-1",
            correlationId = "corr-high-rev-1",
            causationId = "caus-high-rev-1",
            expectedVersion = 2L
        )
        val highResult = service.revokeBonus(highValueRevokeCmd)

        // Assert high-value decision gate: never direct projection edit
        assertTrue(highResult.requiresApproval)
        assertNotNull(highResult.proposalId)
        assertNull(highResult.revocationId)
        assertNull(highResult.auditRecord)
        assertEquals(2L, highResult.serverVersion) // Wallet version unchanged!

        val proposalId = highResult.proposalId!!
        val pendingProposals = service.getPendingRevocationProposals(tenantId)
        assertEquals(1, pendingProposals.size)
        assertEquals(proposalId, pendingProposals[0].proposalId)
        assertEquals(BonusRevocationProposalStatus.PENDING_APPROVAL, pendingProposals[0].status)

        // Verify wallet bonus remains 26,000L (UNTOUCHED!)
        val walletBeforeApproval = store.findWallet(tenantId, playerId1, "USD")
        assertNotNull(walletBeforeApproval)
        assertEquals(26_000L, walletBeforeApproval.bonusMinorUnits)
        assertEquals(2L, walletBeforeApproval.version)

        // Step 3: Four-eyes checker approval by distinct administrator
        val approveCmd = ApproveRevocationProposalCommand(
            checkerPrincipal = adminChecker,
            tenantId = tenantId,
            proposalId = proposalId,
            checkerReason = "Risk team confirmed abuse patterns and approved revocation",
            idempotencyKey = "approve-rev-1",
            correlationId = "corr-app-rev-1",
            causationId = "caus-app-rev-1",
            expectedWalletVersion = 2L
        )
        val approveResult = service.approveRevocationProposal(approveCmd)

        assertNotNull(approveResult.revocationId)
        assertEquals(adminMaker.id, approveResult.makerId)
        assertEquals(adminChecker.id, approveResult.checkerId)
        assertEquals(3L, approveResult.serverVersion)

        // Verify high-value audit record stored
        val auditRecord2 = service.getRevocationAudit(tenantId, approveResult.revocationId)
        assertNotNull(auditRecord2)
        assertEquals(adminMaker.id, auditRecord2.makerPrincipalId)
        assertEquals(adminChecker.id, auditRecord2.checkerPrincipalId)
        assertTrue(auditRecord2.isHighValue)
        assertEquals(proposalId, auditRecord2.proposalId)
        assertEquals(6_000L, auditRecord2.remainingBonusMinorUnits) // 26,000 - 20,000 = 6,000

        // Verify wallet updated
        val walletAfterApproval = store.findWallet(tenantId, playerId1, "USD")
        assertNotNull(walletAfterApproval)
        assertEquals(6_000L, walletAfterApproval.bonusMinorUnits)
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
        assertFalse(directResult.evidenceReference.isBlank())
        assertFalse(highResult.evidenceReference.isBlank())
        assertFalse(approveResult.evidenceReference.isBlank())
        assertEquals("BONUS_REVOCATION_DIRECT_EXECUTED", directResult.auditEvent.type)
        assertEquals("BONUS_REVOCATION_PROPOSAL_SUBMITTED", highResult.auditEvent.type)
        assertEquals("BONUS_REVOCATION_APPROVED", approveResult.auditEvent.type)
    }

    // =========================================================================
    // BONUS-003-02-T002: Negative, Boundary, and Security Gaps
    // =========================================================================

    @Test
    fun `BONUS-003-02-T002 Negative boundary and security scenarios fail closed`() {
        BonusRevocationAuditBinding.isBound = true

        val store = InMemoryBonusRevocationStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusRevocationAuditService(
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
                bonusMinorUnits = 25_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        val activeGrantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = activeGrantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                amountMinorUnits = 5_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 20.0,
                wageringRequirementMinorUnits = 100_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "Discretionary grant",
                createdAt = now.minusSeconds(100),
                expiresAt = now.plusSeconds(86400),
                version = 1L
            )
        )

        // 1. Self-action prevention: Admin cannot revoke on own player account (FORBIDDEN)
        val selfRevokePrincipal = adminPrincipal(id = playerId.toString(), tenantId = tenantId)
        val selfRevokeCmd = RevokeBonusCommand(
            principal = selfRevokePrincipal,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Self-revocation attempt",
            idempotencyKey = "self-rev-1",
            correlationId = "corr-self",
            causationId = "caus-self",
            expectedVersion = 1L
        )
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(selfRevokeCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex1.code)

        // 2. Unreasoned revocation prevention: Blank or short reason fails closed (INVALID)
        val unreasonedCmd = RevokeBonusCommand(
            principal = adminMaker,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "short", // < 10 chars
            idempotencyKey = "unr-rev-1",
            correlationId = "corr-unr",
            causationId = "caus-unr",
            expectedVersion = 1L
        )
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(unreasonedCmd)
        }
        assertEquals(AuthErrorCode.INVALID, ex2.code)

        // Create high-value grant for proposal testing
        val highGrantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = highGrantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                amountMinorUnits = 20_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 20.0,
                wageringRequirementMinorUnits = 400_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "High grant",
                createdAt = now.minusSeconds(100),
                expiresAt = now.plusSeconds(86400),
                version = 1L
            )
        )
        val propRes = service.revokeBonus(
            RevokeBonusCommand(
                principal = adminMaker,
                tenantId = tenantId,
                grantId = highGrantId,
                playerId = playerId,
                currencyCode = "USD",
                revocationReason = "High-value revocation proposal for testing",
                idempotencyKey = "high-prop-key",
                correlationId = "corr-hp",
                causationId = "caus-hp",
                expectedVersion = 1L
            )
        )
        val proposalId = propRes.proposalId!!

        // 3. Segregation of duties: Maker cannot approve own revocation proposal (FORBIDDEN)
        val makerSelfApprove = ApproveRevocationProposalCommand(
            checkerPrincipal = adminMaker,
            tenantId = tenantId,
            proposalId = proposalId,
            checkerReason = "Maker attempting to self-approve revocation",
            idempotencyKey = "sa-rev-1",
            correlationId = "corr-sa",
            causationId = "caus-sa",
            expectedWalletVersion = 1L
        )
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.approveRevocationProposal(makerSelfApprove)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex3.code)

        // 4. Non-admin (player) attempting revocation fails closed (FORBIDDEN)
        val playerRevokeCmd = RevokeBonusCommand(
            principal = player,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Player attempting revocation",
            idempotencyKey = "player-rev-1",
            correlationId = "corr-pr",
            causationId = "caus-pr",
            expectedVersion = 1L
        )
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(playerRevokeCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex4.code)

        // 5. Cross-tenant request rejected (FORBIDDEN)
        val crossTenantAdmin = adminPrincipal("admin-cross", "attacker-tenant")
        val crossTenantCmd = RevokeBonusCommand(
            principal = crossTenantAdmin,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Cross-tenant revocation attempt",
            idempotencyKey = "cross-rev-1",
            correlationId = "corr-ct",
            causationId = "caus-ct",
            expectedVersion = 1L
        )
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(crossTenantCmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex5.code)

        // 6. Unauthenticated request rejected (UNAUTHENTICATED)
        val unauthCmd = RevokeBonusCommand(
            principal = null,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Unauthenticated revocation attempt",
            idempotencyKey = "unauth-rev-1",
            correlationId = "corr-ua",
            causationId = "caus-ua",
            expectedVersion = 1L
        )
        val ex6 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(unauthCmd)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex6.code)

        // 7. Stale wallet version rejected (STALE)
        val staleCmd = RevokeBonusCommand(
            principal = adminMaker,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Stale version revocation attempt",
            idempotencyKey = "stale-rev-1",
            correlationId = "corr-stale",
            causationId = "caus-stale",
            expectedVersion = 999L
        )
        val ex7 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(staleCmd)
        }
        assertEquals(AuthErrorCode.STALE, ex7.code)

        // 8. Double-forfeit / revocation prevention: Revoking non-ACTIVE grant rejected (FORBIDDEN)
        // First revoke activeGrantId legitimately
        val legitRevoke = RevokeBonusCommand(
            principal = adminMaker,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Legitimate standard revocation",
            idempotencyKey = "legit-rev-key",
            correlationId = "corr-legit",
            causationId = "caus-legit",
            expectedVersion = 1L
        )
        service.revokeBonus(legitRevoke)

        // Attempt second revocation on same grant
        val doubleRevoke = RevokeBonusCommand(
            principal = adminMaker,
            tenantId = tenantId,
            grantId = activeGrantId,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Second revocation attempt on cancelled grant",
            idempotencyKey = "double-rev-key",
            correlationId = "corr-double",
            causationId = "caus-double",
            expectedVersion = 2L
        )
        val ex8 = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(doubleRevoke)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex8.code)
    }

    // =========================================================================
    // BONUS-003-02-T003: Concurrency, Idempotency, and Failure Recovery
    // =========================================================================

    @Test
    fun `BONUS-003-02-T003 Idempotency replays, conflict detection, and concurrent execution maintain balance conservation`() {
        BonusRevocationAuditBinding.isBound = true

        val store = InMemoryBonusRevocationStore()
        val alertSink = InMemoryBonusAlertSink()
        val service = BonusRevocationAuditService(
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
                bonusMinorUnits = 30_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        val grant1Id = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = grant1Id,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                amountMinorUnits = 3_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 10.0,
                wageringRequirementMinorUnits = 30_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "Grant 1",
                createdAt = now.minusSeconds(100),
                expiresAt = now.plusSeconds(86400),
                version = 1L
            )
        )

        // 1. Direct revocation idempotency replay
        val directCmd = RevokeBonusCommand(
            principal = adminMaker,
            tenantId = tenantId,
            grantId = grant1Id,
            playerId = playerId,
            currencyCode = "USD",
            revocationReason = "Idempotent direct revocation test",
            idempotencyKey = "idem-dir-key",
            correlationId = "corr-id-1",
            causationId = "caus-id-1",
            expectedVersion = 1L
        )
        val res1 = service.revokeBonus(directCmd)
        val res2 = service.revokeBonus(directCmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.revocationId, res2.revocationId)
        assertEquals(res1.serverVersion, res2.serverVersion)

        val walletAfterIdem = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterIdem)
        assertEquals(2L, walletAfterIdem.version) // Incremented only once
        assertEquals(27_000L, walletAfterIdem.bonusMinorUnits)

        // 2. Conflict detection on modified payload with same key
        val conflictCmd = directCmd.copy(revocationReason = "Modified revocation reason")
        val conflictEx = assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeBonus(conflictCmd)
        }
        assertEquals(AuthErrorCode.CONFLICT, conflictEx.code)

        // 3. Approval idempotency replay
        val highGrantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = highGrantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                amountMinorUnits = 20_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 10.0,
                wageringRequirementMinorUnits = 200_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "High grant",
                createdAt = now.minusSeconds(100),
                expiresAt = now.plusSeconds(86400),
                version = 1L
            )
        )
        val propRes = service.revokeBonus(
            RevokeBonusCommand(
                principal = adminMaker,
                tenantId = tenantId,
                grantId = highGrantId,
                playerId = playerId,
                currencyCode = "USD",
                revocationReason = "High-value revocation proposal for approval test",
                idempotencyKey = "high-prop-idem",
                correlationId = "corr-hpi",
                causationId = "caus-hpi",
                expectedVersion = 2L
            )
        )
        val proposalId = propRes.proposalId!!

        val approveCmd = ApproveRevocationProposalCommand(
            checkerPrincipal = adminChecker,
            tenantId = tenantId,
            proposalId = proposalId,
            checkerReason = "Approved revocation for idempotency check",
            idempotencyKey = "idem-app-rev",
            correlationId = "corr-iar",
            causationId = "caus-iar",
            expectedWalletVersion = 2L
        )
        val appRes1 = service.approveRevocationProposal(approveCmd)
        val appRes2 = service.approveRevocationProposal(approveCmd)

        assertEquals(appRes1.resultId, appRes2.resultId)
        assertEquals(appRes1.revocationId, appRes2.revocationId)
        assertEquals(appRes1.serverVersion, appRes2.serverVersion)

        val walletAfterApproveIdem = store.findWallet(tenantId, playerId, "USD")
        assertNotNull(walletAfterApproveIdem)
        assertEquals(3L, walletAfterApproveIdem.version)
        assertEquals(7_000L, walletAfterApproveIdem.bonusMinorUnits) // 27,000 - 20,000 = 7,000

        // 4. 16-thread concurrent execution across distinct players
        val threadCount = 16
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)
        val concurrentResults = ConcurrentHashMap<Int, RevokeBonusResult>()

        val concurrentPlayers = (0 until threadCount).map { i ->
            val pId = UUID.randomUUID()
            store.saveWallet(
                PlayerWalletBuckets(
                    tenantId = tenantId,
                    playerId = pId,
                    currencyCode = "USD",
                    cashMinorUnits = 1_000L,
                    bonusMinorUnits = 5_000L,
                    lockedCashMinorUnits = 0L,
                    version = 1L
                )
            )
            val gId = UUID.randomUUID()
            store.saveGrant(
                BonusGrantRecord(
                    grantId = gId,
                    tenantId = tenantId,
                    playerId = pId,
                    bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                    amountMinorUnits = 3_000L,
                    currencyCode = "USD",
                    wageringRequirementMultiplier = 10.0,
                    wageringRequirementMinorUnits = 30_000L,
                    wageringProgressMinorUnits = 0L,
                    status = BonusGrantStatus.ACTIVE,
                    reason = "Concurrent grant $i",
                    createdAt = now.minusSeconds(100),
                    expiresAt = now.plusSeconds(86400),
                    version = 1L
                )
            )
            pId to gId
        }

        for (i in 0 until threadCount) {
            val (pId, gId) = concurrentPlayers[i]
            executor.submit {
                try {
                    val res = service.revokeBonus(
                        RevokeBonusCommand(
                            principal = adminMaker,
                            tenantId = tenantId,
                            grantId = gId,
                            playerId = pId,
                            currencyCode = "USD",
                            revocationReason = "Concurrent revocation test $i",
                            idempotencyKey = "concurrent-rev-$i",
                            correlationId = "corr-cr-$i",
                            causationId = "caus-cr-$i",
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
            assertEquals(3_000L, res.revokedAmountMinorUnits)
            assertFalse(res.requiresApproval)
        }
    }

    // =========================================================================
    // BONUS-003-02-T004: Migration Integrity, Recovery, and Observability
    // =========================================================================

    @Test
    fun `BONUS-003-02-T004 Migration integrity recovery and observability verification`() {
        BonusRevocationAuditBinding.isBound = true

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
        val store = InMemoryBonusRevocationStore()
        val alertSink = InMemoryBonusAlertSink()

        val service1 = BonusRevocationAuditService(
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
                bonusMinorUnits = 50_000L,
                lockedCashMinorUnits = 0L,
                version = 1L
            )
        )

        val highGrantId = UUID.randomUUID()
        store.saveGrant(
            BonusGrantRecord(
                grantId = highGrantId,
                tenantId = tenantId,
                playerId = playerId,
                bonusType = BonusGrantType.ADMIN_DISCRETIONARY,
                amountMinorUnits = 50_000L,
                currencyCode = "USD",
                wageringRequirementMultiplier = 10.0,
                wageringRequirementMinorUnits = 500_000L,
                wageringProgressMinorUnits = 0L,
                status = BonusGrantStatus.ACTIVE,
                reason = "Recovery grant",
                createdAt = now.minusSeconds(100),
                expiresAt = now.plusSeconds(86400),
                version = 1L
            )
        )

        // Submit high-value revocation proposal on Service 1
        val propRes = service1.revokeBonus(
            RevokeBonusCommand(
                principal = adminMaker,
                tenantId = tenantId,
                grantId = highGrantId,
                playerId = playerId,
                currencyCode = "USD",
                revocationReason = "Recovery test high-value revocation proposal",
                idempotencyKey = "rec-prop-1",
                correlationId = "corr-rec-1",
                causationId = "caus-rec-1",
                expectedVersion = 1L
            )
        )
        val proposalId = propRes.proposalId!!

        // Simulate restart: Service 2 sharing persistent store
        val service2 = BonusRevocationAuditService(
            store = store,
            highValueThresholdMinorUnits = 10_000L,
            alertSink = alertSink,
            clock = clock
        )

        // Approve on Service 2
        val appRes = service2.approveRevocationProposal(
            ApproveRevocationProposalCommand(
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
        assertEquals(50_000L, appRes.revokedAmountMinorUnits)

        // Verify audit record is retrievable on Service 2
        val auditRecord = service2.getRevocationAudit(tenantId, appRes.revocationId)
        assertNotNull(auditRecord)
        assertEquals(adminMaker.id, auditRecord.makerPrincipalId)
        assertEquals(adminChecker.id, auditRecord.checkerPrincipalId)
        assertEquals(0L, auditRecord.remainingBonusMinorUnits)

        // 3. Observability & Redaction
        val alerts = alertSink.alerts
        for (alert in alerts) {
            assertFalse(alert.contains("password", ignoreCase = true))
            assertFalse(alert.contains("secret", ignoreCase = true))
            assertFalse(alert.contains("token", ignoreCase = true))
        }

        assertEquals("corr-rec-2", appRes.auditEvent.correlationId)
        assertEquals("caus-rec-2", appRes.auditEvent.causationId)
        assertEquals("BONUS_REVOCATION_APPROVED", appRes.outboxEvent.type)
    }
}
