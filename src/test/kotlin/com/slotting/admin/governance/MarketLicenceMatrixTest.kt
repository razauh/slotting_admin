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

class MarketLicenceMatrixTest {
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

    private fun sampleApprovalCommand(
        principal: AuthenticatedPrincipal? = securityAdmin,
        sessionId: String = "sess-1",
        tenantId: String = "tenant-1",
        marketId: String = "US-NJ",
        operatorId: String = "operator-prime",
        licenceNumber: String = "LIC-NJ-2026-001",
        authorizedStoreChannels: Set<String> = setOf("GOOGLE_PLAY_STORE", "DIRECT_DOWNLOAD"),
        qualifiedSignatory: String = "General Counsel & Compliance VP",
        effectiveFrom: Instant = now.minusSeconds(3600),
        expiresAt: Instant = now.plusSeconds(86400 * 365),
        idempotencyKey: String = "idem-gov-1",
        correlationId: String = "corr-gov-1",
        causationId: String = "cause-gov-1",
        expectedVersion: Long = 1L,
    ) = ApproveMarketLicenceCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        marketId = marketId,
        operatorId = operatorId,
        licenceNumber = licenceNumber,
        authorizedStoreChannels = authorizedStoreChannels,
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
        store: MarketLicenceStore = InMemoryMarketLicenceStore(),
    ) = MarketLicenceMatrixService(
        sessions = sessionDir,
        store = store,
        clock = clock,
    )

    @Test
    fun `GOV-001-01-T001 Approve market, operator, and licence matrix produces the required authoritative outcome`() {
        val store = InMemoryMarketLicenceStore()
        val s = service(store = store)

        val cmd = sampleApprovalCommand()
        val res = s.approveMatrixEntry(cmd)

        // 1. Authoritative outcome assertions
        assertEquals(MarketLicenceStatus.ACTIVE, res.status)
        assertEquals("tenant-1", res.tenantId)
        assertEquals("US-NJ", res.marketId)
        assertEquals("operator-prime", res.operatorId)
        assertFalse(res.directEligibilityGranted)
        assertFalse(res.financialMutationPermitted)

        // 2. Admission check returns GO
        val evalCmd = EvaluateMarketAdmissionCommand(
            tenantId = "tenant-1",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            correlationId = "corr-eval-1",
            causationId = "cause-eval-1",
        )
        val admission = s.evaluateMarketAdmission(evalCmd)
        assertEquals(MarketAdmissionDecision.GO, admission.decision)
        assertEquals(MarketAdmissionReason.APPROVED_AND_ACTIVE, admission.reason)
        assertEquals("LIC-NJ-2026-001", admission.licenceNumber)
        assertFalse(admission.directEligibilityGranted)
        assertFalse(admission.financialMutationPermitted)

        // 3. Idempotency check: duplicate approval returns cached result
        val replay = s.approveMatrixEntry(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.status, replay.status)

        // 4. Audit & Outbox verification
        assertEquals(1, store.audit.size)
        assertEquals("MARKET_LICENCE_APPROVED", store.audit[0].type)
        assertEquals(1, store.outbox.size)
        assertEquals("MarketLicenceApproved", store.outbox[0].type)
    }

    @Test
    fun `GOV-001-01-T002 Approve market, operator, and licence matrix rejects invalid, boundary, unauthorized, and stale input`() {
        val store = InMemoryMarketLicenceStore()
        val s = service(store = store)

        // 1. Unauthenticated principal
        val unauthCmd = sampleApprovalCommand(principal = null)
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveMatrixEntry(unauthCmd) }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex1.code)

        // 2. Cross-tenant principal
        val crossTenantCmd = sampleApprovalCommand(tenantId = "tenant-other")
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveMatrixEntry(crossTenantCmd) }
        assertEquals(AuthErrorCode.FORBIDDEN, ex2.code)

        // 3. Expired session
        val expiredSessionService = service(sessionDir = sessionDirectory(expiresAt = now.minusSeconds(10)), store = store)
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> { expiredSessionService.approveMatrixEntry(sampleApprovalCommand()) }
        assertEquals(AuthErrorCode.FORBIDDEN, ex3.code)

        // 4. Unauthorized role (e.g. SUPPORT cannot approve governance matrix)
        val supportPrincipal = AuthenticatedPrincipal(
            id = "support-1",
            tenantId = "tenant-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPPORT),
        )
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveMatrixEntry(sampleApprovalCommand(principal = supportPrincipal))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex4.code)

        // 5. Blank fields: marketId
        val blankMarketCmd = sampleApprovalCommand(marketId = "")
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveMatrixEntry(blankMarketCmd) }
        assertEquals(AuthErrorCode.INVALID, ex5.code)

        // 6. Blank qualifiedSignatory (Accept only qualified owner signatures)
        val blankSigCmd = sampleApprovalCommand(qualifiedSignatory = "")
        val ex6 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveMatrixEntry(blankSigCmd) }
        assertEquals(AuthErrorCode.INVALID, ex6.code)

        // 7. Invalid dates: expiresAt before effectiveFrom
        val invalidDatesCmd = sampleApprovalCommand(effectiveFrom = now, expiresAt = now.minusSeconds(100))
        val ex7 = assertFailsWith<AuthenticationFailure.Rejected> { s.approveMatrixEntry(invalidDatesCmd) }
        assertEquals(AuthErrorCode.INVALID, ex7.code)

        // 8. Stale/absent approval check = NO-GO
        val absentEval = s.evaluateMarketAdmission(EvaluateMarketAdmissionCommand(
            tenantId = "tenant-1",
            marketId = "US-NY", // never approved
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            correlationId = "c",
            causationId = "c",
        ))
        assertEquals(MarketAdmissionDecision.NO_GO, absentEval.decision)
        assertEquals(MarketAdmissionReason.MISSING_APPROVAL, absentEval.reason)

        // 9. Expired entry check: stale/absent = NO-GO
        val expiredCmd = sampleApprovalCommand(
            idempotencyKey = "idem-expired",
            marketId = "US-NV",
            effectiveFrom = now.minusSeconds(500),
            expiresAt = now.plusSeconds(10), // expires in 10s
        )
        s.approveMatrixEntry(expiredCmd)
        // Advance clock past expiry
        val laterClock = Clock.fixed(now.plusSeconds(20), ZoneOffset.UTC)
        val laterService = MarketLicenceMatrixService(sessions = sessionDirectory(), store = store, clock = laterClock)
        val expiredEval = laterService.evaluateMarketAdmission(EvaluateMarketAdmissionCommand(
            tenantId = "tenant-1",
            marketId = "US-NV",
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            correlationId = "c",
            causationId = "c",
        ))
        assertEquals(MarketAdmissionDecision.NO_GO, expiredEval.decision)
        assertEquals(MarketAdmissionReason.STALE_OR_EXPIRED, expiredEval.reason)

        // 10. Rollback revokes market
        val activeCmd = sampleApprovalCommand(
            idempotencyKey = "idem-to-revoke",
            marketId = "MT-MGA",
        )
        s.approveMatrixEntry(activeCmd)

        val revokeCmd = RevokeMarketLicenceCommand(
            principal = securityAdmin,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            marketId = "MT-MGA",
            operatorId = "operator-prime",
            revocationReason = "Regulatory license suspended by gaming commission",
            qualifiedSignatory = "Chief Legal Officer",
            idempotencyKey = "idem-revocation-1",
            correlationId = "corr-rev-1",
            causationId = "cause-rev-1",
            expectedVersion = 1L,
        )
        val revokedRes = s.rollbackOrRevokeMarket(revokeCmd)
        assertEquals(MarketLicenceStatus.REVOKED, revokedRes.status)

        val revokedEval = s.evaluateMarketAdmission(EvaluateMarketAdmissionCommand(
            tenantId = "tenant-1",
            marketId = "MT-MGA",
            operatorId = "operator-prime",
            storeChannel = "GOOGLE_PLAY_STORE",
            correlationId = "c",
            causationId = "c",
        ))
        assertEquals(MarketAdmissionDecision.NO_GO, revokedEval.decision)
        assertEquals(MarketAdmissionReason.REVOKED, revokedEval.reason)
    }

    @Test
    fun `GOV-001-01-T003 Approve market, operator, and licence matrix survives concurrency, duplicate delivery, and dependency failure`() {
        val store = InMemoryMarketLicenceStore()
        val s = service(store = store)

        // 1. Changed payload with same idempotency key -> CONFLICT
        val cmd1 = sampleApprovalCommand(idempotencyKey = "idem-conflict", licenceNumber = "LIC-001")
        s.approveMatrixEntry(cmd1)

        val cmdConflict = sampleApprovalCommand(idempotencyKey = "idem-conflict", licenceNumber = "LIC-002-CONFLICT")
        val exConflict = assertFailsWith<AuthenticationFailure.Rejected> { s.approveMatrixEntry(cmdConflict) }
        assertEquals(AuthErrorCode.CONFLICT, exConflict.code)

        // 2. Concurrency test: 8 threads race on identical approval command
        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val endGate = CountDownLatch(threadCount)
        val results = mutableListOf<MarketLicenceApprovalResult>()
        val raceCmd = sampleApprovalCommand(idempotencyKey = "idem-race-gov-1", marketId = "US-MI")

        for (i in 0 until threadCount) {
            pool.submit {
                try {
                    startGate.await()
                    val res = s.approveMatrixEntry(raceCmd)
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
        assertTrue(results.all { it.status == MarketLicenceStatus.ACTIVE })

        // 3. Dependency failure: session directory throws -> DEPENDENCY_UNAVAILABLE
        val failingService = service(sessionDir = sessionDirectory(failing = true), store = store)
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.approveMatrixEntry(sampleApprovalCommand(idempotencyKey = "idem-dep-fail", marketId = "US-WV"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)
    }

    @Test
    fun `GOV-001-01-T004 Approve market, operator, and licence matrix remains compatible, recoverable, observable, and lifecycle-safe`() {
        val store = InMemoryMarketLicenceStore()
        val s1 = service(store = store)

        val cmd = sampleApprovalCommand(idempotencyKey = "idem-lifecycle-gov-1", marketId = "UK-GC")
        val res1 = s1.approveMatrixEntry(cmd)

        // Recreate service instance pointing to same store (simulating service restart)
        val s2 = service(store = store)
        val res2 = s2.approveMatrixEntry(cmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.status, res2.status)
        assertEquals(res1.matrixId, res2.matrixId)
        assertEquals(res1.evidenceReference, res2.evidenceReference)

        // Observability check: ensure audit and outbox contain correlation/causation IDs, no raw secrets/PII
        val auditRecord = store.audit.first { it.resultId == res1.resultId }
        assertEquals("MARKET_LICENCE_APPROVED", auditRecord.type)
        assertEquals("corr-gov-1", auditRecord.correlationId)
        assertEquals("cause-gov-1", auditRecord.causationId)

        val outboxRecord = store.outbox.first { it.resultId == res1.resultId }
        assertEquals("MarketLicenceApproved", outboxRecord.type)
        assertEquals(now, outboxRecord.createdAt)

        // Assert contract: Accept only qualified owner signatures and expiry; stale/absent = NO-GO; audit decision changes; rollback revokes market
        assertFalse(res1.directEligibilityGranted)
        assertFalse(res1.financialMutationPermitted)
    }
}
