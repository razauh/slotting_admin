package com.slotting.admin.governance

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class StoreDistributionEligibilityTest {
    private val now = Instant.parse("2026-09-19T08:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "sec-admin-1",
        tenantId = "tenant-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private fun sessionDirectory(
        active: Boolean = true,
        expiresAt: Instant = now.plus(Duration.ofHours(1)),
        failing: Boolean = false,
    ) = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            if (failing) throw RuntimeException("Session directory down")
            return AdminSessionStatus(active = active, breakGlass = false, expiresAt = expiresAt)
        }
    }

    private fun sampleMarketLicence(
        tenantId: String = "tenant-1",
        marketId: String = "US-NJ",
        operatorId: String = "operator-prime",
        status: MarketLicenceStatus = MarketLicenceStatus.ACTIVE,
        storeChannels: Set<String> = setOf("GOOGLE_PLAY_STORE", "DIRECT_DOWNLOAD"),
        expiresAt: Instant = now.plusSeconds(86400 * 365),
    ) = MarketLicenceEntry(
        matrixId = UUID.randomUUID(),
        tenantId = tenantId,
        marketId = marketId,
        operatorId = operatorId,
        licenceNumber = "LIC-NJ-2026-001",
        authorizedStoreChannels = storeChannels,
        qualifiedSignatory = "General Counsel",
        effectiveFrom = now.minusSeconds(3600),
        expiresAt = expiresAt,
        status = status,
        evidenceReference = "EVID-LIC-1",
        version = 1L,
    )

    private fun sampleStoreCommand(
        principal: AuthenticatedPrincipal? = securityAdmin,
        sessionId: String = "sess-1",
        tenantId: String = "tenant-1",
        applicationId: String = "com.slotting.game",
        marketId: String = "US-NJ",
        operatorId: String = "operator-prime",
        storeChannel: String = "GOOGLE_PLAY_STORE",
        qualifiedSignatory: String = "Store Compliance VP",
        effectiveFrom: Instant = now.minusSeconds(3600),
        expiresAt: Instant = now.plusSeconds(86400 * 365),
        idempotencyKey: String = "idem-store-1",
        correlationId: String = "corr-store-1",
        causationId: String = "cause-store-1",
        expectedVersion: Long = 1L,
    ) = ApproveStoreDistributionCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        applicationId = applicationId,
        marketId = marketId,
        operatorId = operatorId,
        storeChannel = storeChannel,
        qualifiedSignatory = qualifiedSignatory,
        effectiveFrom = effectiveFrom,
        expiresAt = expiresAt,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun service(
        sessionDir: AdminSessionDirectory = sessionDirectory(),
        marketStore: MarketLicenceStore = InMemoryMarketLicenceStore(),
        store: StoreDistributionStore = InMemoryStoreDistributionStore(),
    ) = StoreDistributionEligibilityService(
        sessions = sessionDir,
        marketLicenceStore = marketStore,
        store = store,
        clock = clock,
    )

    @Test
    fun `GOV-001-02-T001 Approve store distribution eligibility produces the required authoritative outcome`() {
        val marketStore = InMemoryMarketLicenceStore()
        val marketLicence = sampleMarketLicence()
        marketStore.entries["tenant-1:US-NJ:operator-prime"] = marketLicence

        val store = InMemoryStoreDistributionStore()
        val s = service(marketStore = marketStore, store = store)

        val cmd = sampleStoreCommand()
        val res = s.approveStoreDistribution(cmd)

        // 1. Authoritative approval outcome
        assertEquals(StoreDistributionStatus.ACTIVE, res.status)
        assertEquals("tenant-1", res.tenantId)
        assertEquals("com.slotting.game", res.applicationId)
        assertEquals("US-NJ", res.marketId)
        assertEquals("GOOGLE_PLAY_STORE", res.storeChannel)
        assertFalse(res.directEligibilityGranted)
        assertFalse(res.financialMutationPermitted)

        // 2. Evaluation returns GO
        val evalCmd = EvaluateStoreDistributionCommand(
            tenantId = "tenant-1",
            applicationId = "com.slotting.game",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            correlationId = "corr-eval-1",
            causationId = "cause-eval-1",
        )
        val evaluation = s.evaluateStoreDistribution(evalCmd)
        assertEquals(StoreDistributionDecision.GO, evaluation.decision)
        assertEquals(StoreDistributionReason.ELIGIBLE_AND_APPROVED, evaluation.reason)
        assertEquals(res.distributionId, evaluation.distributionId)
        assertFalse(evaluation.directEligibilityGranted)
        assertFalse(evaluation.financialMutationPermitted)

        // 3. Replay with identical idempotency returns cached result
        val replay = s.approveStoreDistribution(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.distributionId, replay.distributionId)
        assertEquals(res.status, replay.status)

        // 4. Audit & Outbox verification
        assertEquals(1, store.audit.size)
        assertEquals("STORE_DISTRIBUTION_APPROVED", store.audit[0].type)
        assertEquals(1, store.outbox.size)
        assertEquals("StoreDistributionApproved", store.outbox[0].type)
    }

    @Test
    fun `GOV-001-02-T002 Approve store distribution eligibility rejects invalid, boundary, unauthorized, and stale input`() {
        val marketStore = InMemoryMarketLicenceStore()
        val marketLicence = sampleMarketLicence()
        marketStore.entries["tenant-1:US-NJ:operator-prime"] = marketLicence

        val store = InMemoryStoreDistributionStore()
        val s = service(marketStore = marketStore, store = store)

        // 1. Unauthenticated principal
        val unauthCmd = sampleStoreCommand(principal = null)
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveStoreDistribution(unauthCmd) }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex1.code)

        // 2. Cross-tenant principal
        val crossTenantCmd = sampleStoreCommand(tenantId = "tenant-other")
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveStoreDistribution(crossTenantCmd) }
        assertEquals(AuthErrorCode.FORBIDDEN, ex2.code)

        // 3. Expired session
        val expiredSessionService = service(
            sessionDir = sessionDirectory(expiresAt = now.minusSeconds(10)),
            marketStore = marketStore,
            store = store,
        )
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.approveStoreDistribution(sampleStoreCommand())
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex3.code)

        // 4. Unauthorized role
        val supportPrincipal = AuthenticatedPrincipal(
            id = "support-1",
            tenantId = "tenant-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPPORT),
        )
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveStoreDistribution(sampleStoreCommand(principal = supportPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex4.code)

        // 5. Blank qualifiedSignatory
        val blankSigCmd = sampleStoreCommand(qualifiedSignatory = "")
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveStoreDistribution(blankSigCmd) }
        assertEquals(AuthErrorCode.INVALID, ex5.code)

        // 6. Invalid dates: expiresAt before effectiveFrom
        val invalidDatesCmd = sampleStoreCommand(effectiveFrom = now, expiresAt = now.minusSeconds(10))
        val ex6 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveStoreDistribution(invalidDatesCmd) }
        assertEquals(AuthErrorCode.INVALID, ex6.code)

        // 7. Prerequisite check: market licence missing
        val missingLicenceCmd = sampleStoreCommand(marketId = "US-UNKNOWN")
        val ex7 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveStoreDistribution(missingLicenceCmd) }
        assertEquals(AuthErrorCode.INVALID, ex7.code)

        // 8. Prerequisite check: market licence revoked
        val revokedLicence = sampleMarketLicence(marketId = "US-REV", status = MarketLicenceStatus.REVOKED)
        marketStore.entries["tenant-1:US-REV:operator-prime"] = revokedLicence
        val revokedLicenceCmd = sampleStoreCommand(marketId = "US-REV")
        val ex8 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveStoreDistribution(revokedLicenceCmd) }
        assertEquals(AuthErrorCode.FORBIDDEN, ex8.code)

        // 9. Stale/absent store distribution evaluation check -> NO-GO
        val absentEval = s.evaluateStoreDistribution(EvaluateStoreDistributionCommand(
            tenantId = "tenant-1",
            applicationId = "com.slotting.game",
            marketId = "US-PA",
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            correlationId = "c",
            causationId = "c",
        ))
        assertEquals(StoreDistributionDecision.NO_GO, absentEval.decision)
        assertEquals(StoreDistributionReason.MISSING_APPROVAL, absentEval.reason)

        // 10. Expired store distribution approval -> NO-GO
        val shortExpiryCmd = sampleStoreCommand(
            idempotencyKey = "idem-short",
            marketId = "US-NJ",
            storeChannel = "DIRECT_DOWNLOAD",
            effectiveFrom = now.minusSeconds(100),
            expiresAt = now.plusSeconds(5), // expires in 5s
        )
        s.approveStoreDistribution(shortExpiryCmd)
        val laterClock = Clock.fixed(now.plusSeconds(10), ZoneOffset.UTC)
        val laterService = StoreDistributionEligibilityService(
            sessions = sessionDirectory(),
            marketLicenceStore = marketStore,
            store = store,
            clock = laterClock,
        )
        val expiredEval = laterService.evaluateStoreDistribution(EvaluateStoreDistributionCommand(
            tenantId = "tenant-1",
            applicationId = "com.slotting.game",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            storeChannel = "DIRECT_DOWNLOAD",
            correlationId = "c",
            causationId = "c",
        ))
        assertEquals(StoreDistributionDecision.NO_GO, expiredEval.decision)
        assertEquals(StoreDistributionReason.STALE_OR_EXPIRED, expiredEval.reason)

        // 11. Rollback / revocation check
        val activeCmd = sampleStoreCommand(
            idempotencyKey = "idem-revoke-target",
            applicationId = "com.slotting.game.beta",
            storeChannel = "GOOGLE_PLAY_STORE",
        )
        s.approveStoreDistribution(activeCmd)

        val revokeCmd = RevokeStoreDistributionCommand(
            principal = securityAdmin,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            applicationId = "com.slotting.game.beta",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            revocationReason = "Store distribution eligibility revoked due to compliance update",
            qualifiedSignatory = "Head of Regulatory Affairs",
            idempotencyKey = "idem-revoke-store-1",
            correlationId = "corr-rev-1",
            causationId = "cause-rev-1",
            expectedVersion = 1L,
        )
        val revokeRes = s.rollbackOrRevokeStoreDistribution(revokeCmd)
        assertEquals(StoreDistributionStatus.REVOKED, revokeRes.status)

        val revokedEval = s.evaluateStoreDistribution(EvaluateStoreDistributionCommand(
            tenantId = "tenant-1",
            applicationId = "com.slotting.game.beta",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            correlationId = "c",
            causationId = "c",
        ))
        assertEquals(StoreDistributionDecision.NO_GO, revokedEval.decision)
        assertEquals(StoreDistributionReason.REVOKED, revokedEval.reason)
    }

    @Test
    fun `GOV-001-02-T003 Approve store distribution eligibility survives concurrency, duplicate delivery, and dependency failure`() {
        val marketStore = InMemoryMarketLicenceStore()
        val marketLicence = sampleMarketLicence(marketId = "US-MI")
        marketStore.entries["tenant-1:US-MI:operator-prime"] = marketLicence

        val store = InMemoryStoreDistributionStore()
        val s = service(marketStore = marketStore, store = store)

        // 1. Changed payload with same idempotency key -> CONFLICT
        val cmd1 = sampleStoreCommand(idempotencyKey = "idem-conflict", marketId = "US-MI", storeChannel = "GOOGLE_PLAY_STORE")
        s.approveStoreDistribution(cmd1)

        val cmdConflict = sampleStoreCommand(idempotencyKey = "idem-conflict", marketId = "US-MI", storeChannel = "DIRECT_DOWNLOAD")
        val exConflict = assertFailsWith<AuthenticationFailure.Rejected> { s.approveStoreDistribution(cmdConflict) }
        assertEquals(AuthErrorCode.CONFLICT, exConflict.code)

        // 2. Concurrency test: 8 threads race on identical approval command
        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val endGate = CountDownLatch(threadCount)
        val results = mutableListOf<StoreDistributionApprovalResult>()
        val raceCmd = sampleStoreCommand(idempotencyKey = "idem-race-store-1", marketId = "US-MI", storeChannel = "DIRECT_DOWNLOAD")

        for (i in 0 until threadCount) {
            pool.submit {
                try {
                    startGate.await()
                    val res = s.approveStoreDistribution(raceCmd)
                    synchronized(results) { results.add(res) }
                } finally {
                    endGate.countDown()
                }
            }
        }
        startGate.countDown()
        endGate.await()
        pool.shutdown()

        assertEquals(threadCount, results.size)
        val firstResultId = results[0].resultId
        assertTrue(results.all { it.resultId == firstResultId })
        assertTrue(results.all { it.status == StoreDistributionStatus.ACTIVE })

        // 3. Dependency failure: session directory throws -> DEPENDENCY_UNAVAILABLE
        val failingService = service(sessionDir = sessionDirectory(failing = true), marketStore = marketStore, store = store)
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.approveStoreDistribution(sampleStoreCommand(idempotencyKey = "idem-dep-fail", marketId = "US-MI"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)
    }

    @Test
    fun `GOV-001-02-T004 Approve store distribution eligibility remains compatible, recoverable, observable, and lifecycle-safe`() {
        val marketStore = InMemoryMarketLicenceStore()
        val marketLicence = sampleMarketLicence(marketId = "UK-GC")
        marketStore.entries["tenant-1:UK-GC:operator-prime"] = marketLicence

        val store = InMemoryStoreDistributionStore()
        val s1 = service(marketStore = marketStore, store = store)

        val cmd = sampleStoreCommand(idempotencyKey = "idem-lifecycle-store-1", marketId = "UK-GC")
        val res1 = s1.approveStoreDistribution(cmd)

        // Recreate service instance pointing to same store (simulating service restart)
        val s2 = service(marketStore = marketStore, store = store)
        val res2 = s2.approveStoreDistribution(cmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.status, res2.status)
        assertEquals(res1.distributionId, res2.distributionId)
        assertEquals(res1.evidenceReference, res2.evidenceReference)

        // Observability check
        val auditRecord = store.audit.first { it.resultId == res1.resultId }
        assertEquals("STORE_DISTRIBUTION_APPROVED", auditRecord.type)
        assertEquals("corr-store-1", auditRecord.correlationId)
        assertEquals("cause-store-1", auditRecord.causationId)

        val outboxRecord = store.outbox.first { it.resultId == res1.resultId }
        assertEquals("StoreDistributionApproved", outboxRecord.type)
        assertEquals(now, outboxRecord.createdAt)

        // Assert contract: Accept only qualified owner signatures and expiry; stale/absent = NO-GO; audit decision changes; rollback revokes market
        assertFalse(res1.directEligibilityGranted)
        assertFalse(res1.financialMutationPermitted)
    }
}
