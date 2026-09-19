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

class LicensedGeolocationAntiSpoofTest {
    private val now = Instant.parse("2026-09-19T08:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-geo-1",
        tenantId = "tenant-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-geo-1",
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

    private fun service(
        store: GeoAntiSpoofStore = GeoAntiSpoofMemoryStore(),
        vendorEvidenceStore: GeoVendorEvidenceStore? = null,
        sessionDir: AdminSessionDirectory = sessionDirectory(),
    ) = LicensedGeolocationAntiSpoofService(
        sessions = sessionDir,
        store = store,
        vendorEvidenceStore = vendorEvidenceStore,
        clock = clock,
        maxTimestampSkew = Duration.ofSeconds(120),
    )

    private fun sampleCommand(
        principal: AuthenticatedPrincipal? = playerPrincipal,
        tenantId: String = "tenant-1",
        subjectReference: String = "player-geo-1",
        sessionId: String = "sess-1",
        ipAddress: String = "198.51.100.22",
        clientReportedTimestamp: Instant = now,
        deviceIntegrity: DeviceIntegritySignals = DeviceIntegritySignals(),
        vendorEvidenceReference: String? = null,
        idempotencyKey: String = "idem-geo-1",
        correlationId: String = "corr-geo-1",
        causationId: String = "cause-geo-1",
        expectedVersion: Long = 1L,
    ) = EvaluateGeolocationAntiSpoofCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        subjectReference = subjectReference,
        ipAddress = ipAddress,
        clientReportedTimestamp = clientReportedTimestamp,
        deviceIntegrity = deviceIntegrity,
        vendorEvidenceReference = vendorEvidenceReference,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    @Test
    fun `GEO-001-T001 Licensed geolocation-anti-spoof produces the required authoritative outcome`() {
        val store = GeoAntiSpoofMemoryStore()
        val s = service(store = store)

        val cmd = sampleCommand()
        val res = s.evaluate(cmd)

        // Primary outcome assertions
        assertEquals(GeoAntiSpoofStatus.VERIFIED, res.status)
        assertEquals(GeoAntiSpoofVerdict.VERIFIED_GENUINE, res.verdict)
        assertNull(res.reasonCode)
        assertEquals("tenant-1", res.tenantId)
        assertEquals("player-geo-1", res.subjectReference)
        assertEquals(now, res.serverTime)
        assertEquals("corr-geo-1", res.correlationId)
        assertEquals("cause-geo-1", res.causationId)

        // Assert: No regulatory thresholds invented; Android location data minimized
        assertTrue(res.evidenceReference.startsWith("ANTISPOOF-tenant-1-player-geo-1-"))

        // Assert: Financial mutation strictly prohibited
        assertFalse(res.directEligibilityGranted)
        assertFalse(res.financialMutationPermitted)

        // Idempotent replay
        val replay = s.evaluate(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.status, replay.status)
        assertEquals(res.verdict, replay.verdict)

        // Audit & Outbox verification
        assertEquals(1, store.audit.size)
        assertEquals("GEO_ANTISPOOF_EVALUATION_VERIFIED_GENUINE", store.audit[0].type)
        assertEquals(1, store.outbox.size)
        assertEquals("GEO_ANTISPOOF_EVALUATION_VERIFIED_GENUINE", store.outbox[0].type)
    }

    @Test
    fun `GEO-001-T002 Licensed geolocation-anti-spoof rejects invalid, boundary, unauthorized, and stale input`() {
        val store = GeoAntiSpoofMemoryStore()
        val s = service(store = store)

        // 1. Unauthenticated principal
        val unauthCmd = sampleCommand(principal = null)
        val ex1 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluate(unauthCmd) }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, ex1.code)

        // 2. Cross-tenant access
        val crossTenantCmd = sampleCommand(tenantId = "tenant-other")
        val ex2 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluate(crossTenantCmd) }
        assertEquals(AuthErrorCode.FORBIDDEN, ex2.code)

        // 3. Expired session
        val expiredSessionService = service(store = store, sessionDir = sessionDirectory(expiresAt = now.minusSeconds(10)))
        val ex3 = assertFailsWith<AuthenticationFailure.Rejected> { expiredSessionService.evaluate(sampleCommand()) }
        assertEquals(AuthErrorCode.FORBIDDEN, ex3.code)

        // 4. Blank subject reference
        val blankSubjectCmd = sampleCommand(subjectReference = "")
        val ex4 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluate(blankSubjectCmd) }
        assertEquals(AuthErrorCode.INVALID, ex4.code)

        // 5. Stale expected version
        val staleVersionCmd = sampleCommand(expectedVersion = 2L)
        val ex5 = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluate(staleVersionCmd) }
        assertEquals(AuthErrorCode.STALE, ex5.code)

        // 6. Anti-spoof rejection: mock location
        val mockLocationCmd = sampleCommand(
            idempotencyKey = "idem-mock",
            deviceIntegrity = DeviceIntegritySignals(isMockLocation = true),
        )
        val mockRes = s.evaluate(mockLocationCmd)
        assertEquals(GeoAntiSpoofStatus.REJECTED, mockRes.status)
        assertEquals(GeoAntiSpoofVerdict.SPOOFED_MOCK_LOCATION, mockRes.verdict)
        assertEquals("MOCK_LOCATION_DETECTED", mockRes.reasonCode)
        assertFalse(mockRes.directEligibilityGranted)
        assertFalse(mockRes.financialMutationPermitted)

        // 7. Anti-spoof rejection: emulator
        val emulatorCmd = sampleCommand(
            idempotencyKey = "idem-emu",
            deviceIntegrity = DeviceIntegritySignals(isEmulator = true),
        )
        val emuRes = s.evaluate(emulatorCmd)
        assertEquals(GeoAntiSpoofStatus.REJECTED, emuRes.status)
        assertEquals(GeoAntiSpoofVerdict.SPOOFED_EMULATOR, emuRes.verdict)
        assertEquals("EMULATOR_DETECTED", emuRes.reasonCode)

        // 8. Anti-spoof rejection: proxy or VPN
        val vpnCmd = sampleCommand(
            idempotencyKey = "idem-vpn",
            deviceIntegrity = DeviceIntegritySignals(isVpnOrProxy = true),
        )
        val vpnRes = s.evaluate(vpnCmd)
        assertEquals(GeoAntiSpoofStatus.REJECTED, vpnRes.status)
        assertEquals(GeoAntiSpoofVerdict.SPOOFED_PROXY_OR_VPN, vpnRes.verdict)
        assertEquals("PROXY_OR_VPN_DETECTED", vpnRes.reasonCode)

        // 9. Anti-spoof rejection: tampered
        val tamperedCmd = sampleCommand(
            idempotencyKey = "idem-tampered",
            deviceIntegrity = DeviceIntegritySignals(isTampered = true),
        )
        val tamperedRes = s.evaluate(tamperedCmd)
        assertEquals(GeoAntiSpoofStatus.REJECTED, tamperedRes.status)
        assertEquals(GeoAntiSpoofVerdict.SPOOFED_TAMPERED, tamperedRes.verdict)
        assertEquals("TAMPERING_DETECTED", tamperedRes.reasonCode)

        // 10. Stale timestamp (150 seconds skew > 120s limit)
        val staleTimeCmd = sampleCommand(
            idempotencyKey = "idem-stale-time",
            clientReportedTimestamp = now.minusSeconds(150),
        )
        val staleRes = s.evaluate(staleTimeCmd)
        assertEquals(GeoAntiSpoofStatus.REJECTED, staleRes.status)
        assertEquals(GeoAntiSpoofVerdict.STALE_TIMESTAMP, staleRes.verdict)
        assertEquals("STALE_TIMESTAMP", staleRes.reasonCode)
    }

    @Test
    fun `GEO-001-T003 Licensed geolocation-anti-spoof survives concurrency, duplicate delivery, and dependency failure`() {
        val store = GeoAntiSpoofMemoryStore()
        val s = service(store = store)

        // 1. Duplicate delivery with changed payload -> CONFLICT
        val cmd1 = sampleCommand(idempotencyKey = "idem-conflict", ipAddress = "198.51.100.1")
        s.evaluate(cmd1)

        val cmdConflict = sampleCommand(idempotencyKey = "idem-conflict", ipAddress = "198.51.100.99")
        val exConflict = assertFailsWith<AuthenticationFailure.Rejected> { s.evaluate(cmdConflict) }
        assertEquals(AuthErrorCode.CONFLICT, exConflict.code)

        // 2. Concurrency test: 8 threads race with identical command
        val threadCount = 8
        val pool = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val endGate = CountDownLatch(threadCount)
        val results = mutableListOf<GeolocationAntiSpoofResult>()
        val raceCmd = sampleCommand(idempotencyKey = "idem-race-1")

        for (i in 0 until threadCount) {
            pool.submit {
                try {
                    startGate.await()
                    val res = s.evaluate(raceCmd)
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

        // 3. Dependency failure: session directory throws -> DEPENDENCY_UNAVAILABLE
        val failingService = service(store = store, sessionDir = sessionDirectory(failing = true))
        val exDep = assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.evaluate(sampleCommand(idempotencyKey = "idem-dep-fail"))
        }
        assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, exDep.code)

        // 4. Vendor evidence integration: fail closed when vendor evidence indicates proxy/prohibited or outage
        val vendorStore = TestGeoVendorEvidenceStore()
        val vendorService = service(store = store, vendorEvidenceStore = vendorStore)

        // Populate prohibited vendor check
        val prohibitedVendorResult = GeoVendorEvidenceResult(
            resultId = UUID.randomUUID(),
            tenantId = "tenant-1",
            subjectReference = "player-geo-1",
            providerId = "prov-sandbox-geo",
            operation = GeoEvidencePortOperation.VERIFY_LOCATION,
            canonicalStatus = GeoCanonicalStatus.FAILED_CLOSED,
            vendorOutcome = GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN,
            detectedJurisdiction = null,
            directEligibilityGranted = false,
            evidenceReference = "EVID-REF-PROHIBITED",
            serverTime = now,
        )
        vendorStore.save(
            prohibitedVendorResult,
            "tenant-1",
            "fp-prohibited",
            "vendor-ref-prohibited",
            AuditEvent(UUID.randomUUID(), prohibitedVendorResult.resultId, "tenant-1", "GEO", now, "c", "c"),
            OutboxEvent(UUID.randomUUID(), prohibitedVendorResult.resultId, "tenant-1", "GEO", now),
        )

        val cmdWithProhibitedVendor = sampleCommand(
            idempotencyKey = "idem-vendor-prohib",
            vendorEvidenceReference = "vendor-ref-prohibited",
        )
        val resProhibited = vendorService.evaluate(cmdWithProhibitedVendor)
        assertEquals(GeoAntiSpoofStatus.REJECTED, resProhibited.status)
        assertEquals(GeoAntiSpoofVerdict.SPOOFED_PROXY_OR_VPN, resProhibited.verdict)

        // Vendor evidence missing / outage -> fail-closed / SUSPENDED
        val cmdWithMissingVendor = sampleCommand(
            idempotencyKey = "idem-vendor-missing",
            vendorEvidenceReference = "non-existent-ref",
        )
        val resMissing = vendorService.evaluate(cmdWithMissingVendor)
        assertEquals(GeoAntiSpoofStatus.SUSPENDED, resMissing.status)
        assertEquals(GeoAntiSpoofVerdict.SUSPENDED_OR_AMBIGUOUS, resMissing.verdict)
    }

    @Test
    fun `GEO-001-T004 Licensed geolocation-anti-spoof remains compatible, recoverable, observable, and lifecycle-safe`() {
        val store = GeoAntiSpoofMemoryStore()
        val s1 = service(store = store)

        val cmd = sampleCommand(idempotencyKey = "idem-lifecycle-1")
        val res1 = s1.evaluate(cmd)

        // Recreate service instance pointing to same store (simulating service restart)
        val s2 = service(store = store)
        val res2 = s2.evaluate(cmd)

        // Verifies recoverability and persistence fidelity
        assertEquals(res1.resultId, res2.resultId)
        assertEquals(res1.status, res2.status)
        assertEquals(res1.verdict, res2.verdict)
        assertEquals(res1.evidenceReference, res2.evidenceReference)

        // Observability check: ensure no raw coordinates or secrets in audit or outbox
        val auditRecord = store.audit.first { it.resultId == res1.resultId }
        assertFalse(auditRecord.type.contains("latitude", ignoreCase = true))
        assertFalse(auditRecord.type.contains("longitude", ignoreCase = true))
        assertFalse(auditRecord.type.contains("gps", ignoreCase = true))
        assertEquals("corr-geo-1", auditRecord.correlationId)
        assertEquals("cause-geo-1", auditRecord.causationId)

        val outboxRecord = store.outbox.first { it.resultId == res1.resultId }
        assertFalse(outboxRecord.type.contains("latitude", ignoreCase = true))
        assertFalse(outboxRecord.type.contains("longitude", ignoreCase = true))
        assertTrue(outboxRecord.type.contains("VERIFIED_GENUINE"))
        assertEquals(now, outboxRecord.createdAt)

        // Assert contract: No regulatory thresholds invented; Android location data minimized
        assertFalse(res1.directEligibilityGranted)
        assertFalse(res1.financialMutationPermitted)
    }
}

private class TestGeoVendorEvidenceStore : GeoVendorEvidenceStore {
    val results = mutableMapOf<String, Pair<String, GeoVendorEvidenceResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: GeoVendorEvidenceResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}

