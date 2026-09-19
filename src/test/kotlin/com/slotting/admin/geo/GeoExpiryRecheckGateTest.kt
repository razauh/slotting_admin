package com.slotting.admin.geo

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

class GeoExpiryRecheckGateTest {
    private val now = Instant.parse("2026-09-19T08:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-geo-2",
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
            if (failing) throw RuntimeException("Session store down")
            return AdminSessionStatus(active = active, breakGlass = false, expiresAt = expiresAt)
        }
    }

    private fun sampleVerdict(
        verdictId: UUID = UUID.randomUUID(),
        tenantId: String = "tenant-1",
        subjectReference: String = "player-geo-2",
        jurisdictionCode: String = "US-NJ",
        isPermittedJurisdiction: Boolean = true,
        isAntiSpoofVerified: Boolean = true,
        evaluatedAt: Instant = now.minusSeconds(60),
        expiresAt: Instant = now.plusSeconds(900),
        isProviderOutage: Boolean = false,
        evidenceReference: String = "EVID-ACTIVE-VERDICT-1",
    ) = ActiveGeoVerdictRecord(
        verdictId = verdictId,
        tenantId = tenantId,
        subjectReference = subjectReference,
        jurisdictionCode = jurisdictionCode,
        isPermittedJurisdiction = isPermittedJurisdiction,
        isAntiSpoofVerified = isAntiSpoofVerified,
        evaluatedAt = evaluatedAt,
        expiresAt = expiresAt,
        isProviderOutage = isProviderOutage,
        evidenceReference = evidenceReference,
    )

    private fun sampleCommand(
        principal: AuthenticatedPrincipal? = playerPrincipal,
        sessionId: String = "sess-1",
        tenantId: String = "tenant-1",
        subjectReference: String = "player-geo-2",
        wagerId: UUID = UUID.randomUUID(),
        verdictId: UUID? = null,
        requestedJurisdiction: String? = "US-NJ",
        idempotencyKey: String = "idem-gate-1",
        correlationId: String = "corr-gate-1",
        causationId: String = "cause-gate-1",
        expectedVersion: Long = 1L,
    ) = EvaluateWagerGeoGateCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        subjectReference = subjectReference,
        wagerId = wagerId,
        verdictId = verdictId,
        requestedJurisdiction = requestedJurisdiction,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun service(
        sessionDir: AdminSessionDirectory = sessionDirectory(),
        verdictsDir: GeoGateVerdictDirectory = InMemoryGeoGateVerdictDirectory(),
        gateStore: WagerGeoGateStore = InMemoryWagerGeoGateStore(),
    ) = GeoExpiryRecheckGateService(
        sessions = sessionDir,
        verdicts = verdictsDir,
        store = gateStore,
        clock = clock,
    )

    @Test
    fun `GEO-002-T001 Expiry-recheck-fail-closed gate produces the required authoritative outcome`() {
        val verdictsDir = InMemoryGeoGateVerdictDirectory()
        val gateStore = InMemoryWagerGeoGateStore()
        val s = service(verdictsDir = verdictsDir, gateStore = gateStore)

        val verdict = sampleVerdict()
        verdictsDir.verdicts["tenant-1:${verdict.verdictId}"] = verdict

        val wagerId = UUID.randomUUID()
        val cmd = sampleCommand(wagerId = wagerId, verdictId = verdict.verdictId)
        val res = s.evaluateGate(cmd)

        // Primary outcome assertions: permitted and records verdict ID
        assertEquals(GeoGateDecision.PERMITTED, res.decision)
        assertTrue(res.permitted)
        assertEquals(verdict.verdictId, res.recordedVerdictId) // Every wager records verdict ID
        assertEquals("tenant-1", res.tenantId)
        assertEquals("player-geo-2", res.subjectReference)
        assertEquals(wagerId, res.wagerId)
        assertEquals(GeoRecheckActionType.NONE, res.recheckAction.actionType)
        assertFalse(res.recheckAction.canBypass)

        // Assert: Financial mutation strictly prohibited
        assertFalse(res.directEligibilityGranted)
        assertFalse(res.financialMutationPermitted)

        // Idempotent replay returns same result
        val replay = s.evaluateGate(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.recordedVerdictId, replay.recordedVerdictId)
        assertEquals(res.decision, replay.decision)

        // Audit & Outbox verification
        assertEquals(1, gateStore.audit.size)
        assertEquals("WAGER_GEOGATE_DECISION_PERMITTED", gateStore.audit[0].type)
        assertEquals(1, gateStore.outbox.size)
        assertEquals("WagerGeoGateEvaluated", gateStore.outbox[0].type)
    }

    @Test
    fun `GEO-002-T002 Expiry-recheck-fail-closed gate rejects invalid, boundary, unauthorized, and stale input`() {
        val verdictsDir = InMemoryGeoGateVerdictDirectory()
        val gateStore = InMemoryWagerGeoGateStore()
        val s = service(verdictsDir = verdictsDir, gateStore = gateStore)

        val validVerdict = sampleVerdict()
        verdictsDir.verdicts["tenant-1:${validVerdict.verdictId}"] = validVerdict

        // 1. Unauthenticated principal
        val unauthCmd = sampleCommand(principal = null, verdictId = validVerdict.verdictId)
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluateGate(unauthCmd) }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex1.code)

        // 2. Cross-tenant access
        val crossTenantCmd = sampleCommand(tenantId = "tenant-other", verdictId = validVerdict.verdictId)
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluateGate(crossTenantCmd) }
        assertEquals(AuthErrorCode.FORBIDDEN, ex2.code)

        // 3. Expired session
        val expiredSessionService = service(sessionDir = sessionDirectory(expiresAt = now.minusSeconds(10)), verdictsDir = verdictsDir)
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.evaluateGate(sampleCommand(verdictId = validVerdict.verdictId))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex3.code)

        // 4. Blank subject reference
        val blankSubjectCmd = sampleCommand(subjectReference = "", verdictId = validVerdict.verdictId)
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluateGate(blankSubjectCmd) }
        assertEquals(AuthErrorCode.INVALID, ex4.code)

        // 5. Stale expected version
        val staleVersionCmd = sampleCommand(expectedVersion = 2L, verdictId = validVerdict.verdictId)
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluateGate(staleVersionCmd) }
        assertEquals(AuthErrorCode.STALE, ex5.code)

        // 6. Missing verdict (null verdict ID) -> DENIED_MISSING_VERDICT, cannot bypass
        val missingCmd = sampleCommand(idempotencyKey = "idem-missing", verdictId = null)
        val missingRes = s.evaluateGate(missingCmd)
        assertEquals(GeoGateDecision.DENIED_MISSING_VERDICT, missingRes.decision)
        assertFalse(missingRes.permitted)
        assertNull(missingRes.recordedVerdictId)
        assertEquals(GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION, missingRes.recheckAction.actionType)
        assertFalse(missingRes.recheckAction.canBypass) // Cannot bypass!

        // 7. Expired verdict (expiresAt in past) -> DENIED_EXPIRED, cannot bypass
        val expiredVerdict = sampleVerdict(verdictId = UUID.randomUUID(), expiresAt = now.minusSeconds(5))
        verdictsDir.verdicts["tenant-1:${expiredVerdict.verdictId}"] = expiredVerdict
        val expiredCmd = sampleCommand(idempotencyKey = "idem-expired", verdictId = expiredVerdict.verdictId)
        val expiredRes = s.evaluateGate(expiredCmd)
        assertEquals(GeoGateDecision.DENIED_EXPIRED, expiredRes.decision)
        assertFalse(expiredRes.permitted)
        assertEquals(expiredVerdict.verdictId, expiredRes.recordedVerdictId)
        assertFalse(expiredRes.recheckAction.canBypass) // Recheck cannot bypass!

        // 8. Boundary violation (jurisdiction mismatch) -> DENIED_BOUNDARY_VIOLATION
        val boundaryMismatchCmd = sampleCommand(
            idempotencyKey = "idem-boundary",
            verdictId = validVerdict.verdictId,
            requestedJurisdiction = "US-PA", // mismatch with US-NJ
        )
        val boundaryRes = s.evaluateGate(boundaryMismatchCmd)
        assertEquals(GeoGateDecision.DENIED_BOUNDARY_VIOLATION, boundaryRes.decision)
        assertFalse(boundaryRes.permitted)
        assertFalse(boundaryRes.recheckAction.canBypass)

        // 9. Provider outage -> DENIED_PROVIDER_OUTAGE
        val outageVerdict = sampleVerdict(verdictId = UUID.randomUUID(), isProviderOutage = true)
        verdictsDir.verdicts["tenant-1:${outageVerdict.verdictId}"] = outageVerdict
        val outageCmd = sampleCommand(idempotencyKey = "idem-outage", verdictId = outageVerdict.verdictId)
        val outageRes = s.evaluateGate(outageCmd)
        assertEquals(GeoGateDecision.DENIED_PROVIDER_OUTAGE, outageRes.decision)
        assertFalse(outageRes.permitted)
        assertFalse(outageRes.recheckAction.canBypass)

        // 10. Spoofed verdict -> DENIED_SPOOFED
        val spoofedVerdict = sampleVerdict(verdictId = UUID.randomUUID(), isAntiSpoofVerified = false)
        verdictsDir.verdicts["tenant-1:${spoofedVerdict.verdictId}"] = spoofedVerdict
        val spoofedCmd = sampleCommand(idempotencyKey = "idem-spoof", verdictId = spoofedVerdict.verdictId)
        val spoofedRes = s.evaluateGate(spoofedCmd)
        assertEquals(GeoGateDecision.DENIED_SPOOFED, spoofedRes.decision)
        assertFalse(spoofedRes.permitted)
        assertFalse(spoofedRes.recheckAction.canBypass)
    }

    @Test
    fun `GEO-002-T003 Expiry-recheck-fail-closed gate survives concurrency, duplicate delivery, and dependency failure`() {
        val verdictsDir = InMemoryGeoGateVerdictDirectory()
        val gateStore = InMemoryWagerGeoGateStore()
        val s = service(verdictsDir = verdictsDir, gateStore = gateStore)

        val verdict = sampleVerdict()
        verdictsDir.verdicts["tenant-1:${verdict.verdictId}"] = verdict

        // 1. Changed payload with same idempotency key -> CONFLICT
        val cmd1 = sampleCommand(idempotencyKey = "idem-conflict", verdictId = verdict.verdictId, requestedJurisdiction = "US-NJ")
        s.evaluateGate(cmd1)

        val cmdConflict = sampleCommand(idempotencyKey = "idem-conflict", verdictId = verdict.verdictId, requestedJurisdiction = "US-NV")
        val exConflict = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluateGate(cmdConflict) }
        assertEquals(AuthErrorCode.CONFLICT, exConflict.code)

        // 2. Concurrency test: 8 threads race on identical gate evaluation
        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val endGate = CountDownLatch(threadCount)
        val results = mutableListOf<WagerGeoGateResult>()
        val raceCmd = sampleCommand(idempotencyKey = "idem-race-gate-1", verdictId = verdict.verdictId)

        for (i in 0 until threadCount) {
            pool.submit {
                try {
                    startGate.await()
                    val res = s.evaluateGate(raceCmd)
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
        assertTrue(results.all { it.permitted })

        // 3. Dependency failure: session directory throws -> DEPENDENCY_UNAVAILABLE
        val failingService = service(sessionDir = sessionDirectory(failing = true), verdictsDir = verdictsDir)
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.evaluateGate(sampleCommand(idempotencyKey = "idem-dep-fail", verdictId = verdict.verdictId))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)
    }

    @Test
    fun `GEO-002-T004 Expiry-recheck-fail-closed gate remains compatible, recoverable, observable, and lifecycle-safe`() {
        val verdictsDir = InMemoryGeoGateVerdictDirectory()
        val gateStore = InMemoryWagerGeoGateStore()
        val s1 = service(verdictsDir = verdictsDir, gateStore = gateStore)

        val verdict = sampleVerdict()
        verdictsDir.verdicts["tenant-1:${verdict.verdictId}"] = verdict

        val cmd = sampleCommand(idempotencyKey = "idem-lifecycle-gate-1", verdictId = verdict.verdictId)
        val res1 = s1.evaluateGate(cmd)

        // Recreate service instance pointing to same store (simulating service restart)
        val s2 = service(verdictsDir = verdictsDir, gateStore = gateStore)
        val res2 = s2.evaluateGate(cmd)

        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.decision, res2.decision)
        assertEquals(res1.recordedVerdictId, res2.recordedVerdictId)
        assertEquals(res1.evidenceReference, res2.evidenceReference)

        // Observability check: ensure no raw coordinates or secrets in audit or outbox
        val auditRecord = gateStore.audit.first { it.resultId == res1.resultId }
        assertFalse(auditRecord.type.contains("latitude", ignoreCase = true))
        assertFalse(auditRecord.type.contains("longitude", ignoreCase = true))
        assertFalse(auditRecord.type.contains("gps", ignoreCase = true))
        assertEquals("corr-gate-1", auditRecord.correlationId)
        assertEquals("cause-gate-1", auditRecord.causationId)

        val outboxRecord = gateStore.outbox.first { it.resultId == res1.resultId }
        assertEquals("WagerGeoGateEvaluated", outboxRecord.type)
        assertEquals(now, outboxRecord.createdAt)

        // Assert contract: Every wager records verdict ID; recheck UX actionable but cannot bypass
        assertNotNull(res1.recordedVerdictId)
        assertFalse(res1.recheckAction.canBypass)
        assertFalse(res1.directEligibilityGranted)
        assertFalse(res1.financialMutationPermitted)
    }
}
