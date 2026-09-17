package com.slotting.admin.geo

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class GeolocationVendorEvidencePortTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-006-02-T001 Define geolocation vendor evidence port produces the required authoritative outcome`() {
        val store = GeoVendorEvidenceMemoryStore()
        val adapter = SandboxGeoVendorAdapter("prov-sandbox-geo")
        val service = service(store, mapOf("prov-sandbox-geo" to adapter))

        // 1. Execute canonical VERIFY_LOCATION through Geolocation vendor evidence port
        val cmd = command(
            subjectReference = "player-geo-001",
            operation = GeoEvidencePortOperation.VERIFY_LOCATION,
            checkType = GeoCheckType.LOGIN_LOCATION,
            providerId = "prov-sandbox-geo",
            ipAddress = "198.51.100.42",
            idempotencyKey = "key-geo-verify-001",
            correlationId = "corr-geo-1",
            causationId = "cause-geo-1",
        )
        val res = service.executeOperation(cmd)

        // Assert: Vendor outages/ambiguity fail closed; retain minimal evidence under approved policy
        assertEquals(GeoCanonicalStatus.EVIDENCE_COLLECTED, res.canonicalStatus)
        assertEquals(GeoVendorOutcome.PERMITTED_JURISDICTION, res.vendorOutcome)
        assertEquals("player-geo-001", res.subjectReference)
        assertEquals("EVID-GEO-player-geo-001", res.evidenceReference)
        assertEquals("US-NJ", res.detectedJurisdiction)

        // Assert: client/vendor grants eligibility is strictly prevented!
        assertFalse(res.directEligibilityGranted)

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.executeOperation(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.evidenceReference, replay.evidenceReference)

        // 3. Ingest signed vendor webhook
        val webhookCmd = GeoWebhookEvidenceCommand(
            tenantId = "tenant-1",
            providerId = "prov-sandbox-geo",
            signatureHeader = "valid-geo-sig",
            rawPayload = "{\"subjectReference\":\"player-geo-001\",\"checkType\":\"LOGIN_LOCATION\",\"outcome\":\"PERMITTED_JURISDICTION\",\"detectedJurisdiction\":\"US-NJ\",\"checkReference\":\"EXT-GEO-001\"}",
            idempotencyKey = "key-geo-webhook-001",
            correlationId = "corr-geo-wh-1",
            causationId = "cause-geo-wh-1",
        )
        val webhookRes = service.processWebhook(webhookCmd)
        assertEquals(GeoCanonicalStatus.EVIDENCE_COLLECTED, webhookRes.canonicalStatus)
        assertEquals(GeoVendorOutcome.PERMITTED_JURISDICTION, webhookRes.vendorOutcome)
        assertFalse(webhookRes.directEligibilityGranted)

        // Assert: Observability & audit verification without secret/PII disclosure (no raw coordinates)
        assertEquals(2, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-geo-1", store.audit[0].correlationId)
        assertEquals("cause-geo-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-006-02-T002 Define geolocation vendor evidence port rejects invalid, boundary, unauthorized, and stale input`() {
        val store = GeoVendorEvidenceMemoryStore()
        val adapter = SandboxGeoVendorAdapter("prov-sandbox-geo")
        val service = service(store, mapOf("prov-sandbox-geo" to adapter))

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Missing MANAGE_SECURITY permission
        val unauthorizedAdmin = AuthenticatedPrincipal("admin-read", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        val restrictedPolicy = AdminRbacPolicy(true)
        val restrictedService = GeolocationVendorEvidencePortService(restrictedPolicy, TestGeoPortActiveSessionDirectory(), store, mapOf("prov-sandbox-geo" to adapter), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            restrictedService.executeOperation(command(principal = unauthorizedAdmin, idempotencyKey = "key-unauth-perm"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = GeolocationVendorEvidencePortService(AdminRbacPolicy(true), TestGeoPortExpiredSessionDirectory(), store, mapOf("prov-sandbox-geo" to adapter), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.executeOperation(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(subjectReference = "  ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank IP address
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(ipAddress = "   ", idempotencyKey = "key-blank-ip"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(expectedVersion = 3L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Unknown provider
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(providerId = "prov-unknown", idempotencyKey = "key-unknown-prov"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Invalid webhook signature
        val badWebhookCmd = GeoWebhookEvidenceCommand(
            tenantId = "tenant-1",
            providerId = "prov-sandbox-geo",
            signatureHeader = "invalid-sig",
            rawPayload = "{\"subjectReference\":\"player-geo-001\",\"checkType\":\"LOGIN_LOCATION\",\"outcome\":\"PERMITTED_JURISDICTION\",\"detectedJurisdiction\":\"US-NJ\",\"checkReference\":\"EXT-GEO-001\"}",
            idempotencyKey = "key-bad-wh-sig",
            correlationId = "corr-wh-bad",
            causationId = "cause-wh-bad",
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(badWebhookCmd)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Conflicting replay with different payload
        service.executeOperation(command(idempotencyKey = "key-conflict-geo"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(subjectReference = "different-geo-player", idempotencyKey = "key-conflict-geo"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-006-02-T003 Define geolocation vendor evidence port survives concurrency, duplicate delivery, and dependency failure`() {
        val store = GeoVendorEvidenceMemoryStore()
        val adapter = SandboxGeoVendorAdapter("prov-sandbox-geo")
        val service = service(store, mapOf("prov-sandbox-geo" to adapter))

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-geo-001")
        val calls = (1..4).map {
            pool.submit<GeoVendorEvidenceResult> {
                gate.await()
                service.executeOperation(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on vendor adapter -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingAdapter = FailingGeoVendorAdapter("prov-failing-geo")
        val failingService = service(store, mapOf("prov-failing-geo" to failingAdapter))
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.executeOperation(command(providerId = "prov-failing-geo", idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Vendor ambiguity / indeterminate outcome -> fails closed (SUSPENDED)
        val indeterminateAdapter = AmbiguousGeoVendorAdapter("prov-ambiguous-geo", GeoVendorOutcome.INDETERMINATE)
        val ambiguousService = service(store, mapOf("prov-ambiguous-geo" to indeterminateAdapter))
        val ambiguousRes = ambiguousService.executeOperation(command(providerId = "prov-ambiguous-geo", idempotencyKey = "key-ambig-geo"))
        assertEquals(GeoCanonicalStatus.SUSPENDED, ambiguousRes.canonicalStatus)
        assertEquals(GeoVendorOutcome.INDETERMINATE, ambiguousRes.vendorOutcome)
        assertFalse(ambiguousRes.directEligibilityGranted)

        // 4. Vendor outage outcome -> fails closed (SUSPENDED)
        val outageAdapter = AmbiguousGeoVendorAdapter("prov-outage-geo", GeoVendorOutcome.OUTAGE)
        val outageService = service(store, mapOf("prov-outage-geo" to outageAdapter))
        val outageRes = outageService.executeOperation(command(providerId = "prov-outage-geo", idempotencyKey = "key-outage-geo"))
        assertEquals(GeoCanonicalStatus.SUSPENDED, outageRes.canonicalStatus)
        assertEquals(GeoVendorOutcome.OUTAGE, outageRes.vendorOutcome)
        assertFalse(outageRes.directEligibilityGranted)

        // 5. Prohibited jurisdiction -> fails closed (FAILED_CLOSED)
        val prohibitedAdapter = AmbiguousGeoVendorAdapter("prov-prohibited-geo", GeoVendorOutcome.PROHIBITED_JURISDICTION, "UNKNOWN")
        val prohibitedService = service(store, mapOf("prov-prohibited-geo" to prohibitedAdapter))
        val prohibitedRes = prohibitedService.executeOperation(command(providerId = "prov-prohibited-geo", idempotencyKey = "key-prohibited-geo"))
        assertEquals(GeoCanonicalStatus.FAILED_CLOSED, prohibitedRes.canonicalStatus)
        assertEquals(GeoVendorOutcome.PROHIBITED_JURISDICTION, prohibitedRes.vendorOutcome)
        assertFalse(prohibitedRes.directEligibilityGranted)

        // 6. Suspected proxy / spoofing -> fails closed (FAILED_CLOSED)
        val proxyAdapter = AmbiguousGeoVendorAdapter("prov-proxy-geo", GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN)
        val proxyService = service(store, mapOf("prov-proxy-geo" to proxyAdapter))
        val proxyRes = proxyService.executeOperation(command(providerId = "prov-proxy-geo", idempotencyKey = "key-proxy-geo"))
        assertEquals(GeoCanonicalStatus.FAILED_CLOSED, proxyRes.canonicalStatus)
        assertEquals(GeoVendorOutcome.SUSPECTED_PROXY_OR_VPN, proxyRes.vendorOutcome)
        assertFalse(proxyRes.directEligibilityGranted)

        pool.shutdown()
    }

    @Test
    fun `ADR-006-02-T004 Define geolocation vendor evidence port remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = GeoVendorEvidenceMemoryStore()
        val adapter = SandboxGeoVendorAdapter("prov-sandbox-geo")
        val service = service(store, mapOf("prov-sandbox-geo" to adapter))

        val cmd = command(
            subjectReference = "player-geo-reboot-001",
            idempotencyKey = "key-reboot-geo",
            correlationId = "corr-reboot-geo-1",
            causationId = "cause-reboot-geo-1",
        )
        val first = service.executeOperation(cmd)

        val restartedService = service(store, mapOf("prov-sandbox-geo" to adapter))
        val second = restartedService.executeOperation(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.directEligibilityGranted)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("GEO_VENDOR_CHECK_VERIFY_LOCATION", store.audit[0].type)
        assertEquals("corr-reboot-geo-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-geo-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: GeoVendorEvidenceStore, adapters: Map<String, GeoVendorAdapter>) =
        GeolocationVendorEvidencePortService(AdminRbacPolicy(true), TestGeoPortActiveSessionDirectory(), store, adapters, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-geo-001",
        operation: GeoEvidencePortOperation = GeoEvidencePortOperation.VERIFY_LOCATION,
        checkType: GeoCheckType = GeoCheckType.LOGIN_LOCATION,
        providerId: String = "prov-sandbox-geo",
        ipAddress: String = "198.51.100.42",
        idempotencyKey: String = "key-geo-cmd-001",
        correlationId: String = "corr-geo-default",
        causationId: String = "cause-geo-default",
        expectedVersion: Long = 1L,
    ) = GeoVendorEvidenceCommand(
        principal = principal,
        sessionId = "session-geo-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        operation = operation,
        checkType = checkType,
        providerId = providerId,
        ipAddress = ipAddress,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestGeoPortActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-geo-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:00:00Z"))
        else null
}

private class TestGeoPortExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:00:00Z"))
}

private class SandboxGeoVendorAdapter(override val providerId: String) : GeoVendorAdapter {
    override fun executeCheck(command: GeoVendorEvidenceCommand): GeoVendorExecutionResponse =
        GeoVendorExecutionResponse(
            vendorCheckReference = "EXT-GEO-${command.subjectReference}",
            outcome = GeoVendorOutcome.PERMITTED_JURISDICTION,
            detectedJurisdiction = "US-NJ",
            minimalEvidenceReference = "EVID-GEO-${command.subjectReference}",
        )

    override fun verifyWebhook(signature: String, rawPayload: String): GeoCanonicalWebhookEvidence? {
        if (signature != "valid-geo-sig") return null
        return GeoCanonicalWebhookEvidence(
            subjectReference = "player-geo-001",
            checkType = GeoCheckType.LOGIN_LOCATION,
            outcome = GeoVendorOutcome.PERMITTED_JURISDICTION,
            detectedJurisdiction = "US-NJ",
            vendorCheckReference = "EXT-GEO-001",
        )
    }
}

private class FailingGeoVendorAdapter(override val providerId: String) : GeoVendorAdapter {
    override fun executeCheck(command: GeoVendorEvidenceCommand): GeoVendorExecutionResponse =
        error("geo vendor unavailable")

    override fun verifyWebhook(signature: String, rawPayload: String): GeoCanonicalWebhookEvidence? =
        error("geo vendor unavailable")
}

private class AmbiguousGeoVendorAdapter(
    override val providerId: String,
    private val forcedOutcome: GeoVendorOutcome,
    private val forcedJurisdiction: String? = null,
) : GeoVendorAdapter {
    override fun executeCheck(command: GeoVendorEvidenceCommand): GeoVendorExecutionResponse =
        GeoVendorExecutionResponse(
            vendorCheckReference = "EXT-GEO-AMBIG-${command.subjectReference}",
            outcome = forcedOutcome,
            detectedJurisdiction = forcedJurisdiction,
            minimalEvidenceReference = "EVID-GEO-AMBIG-${command.subjectReference}",
        )

    override fun verifyWebhook(signature: String, rawPayload: String): GeoCanonicalWebhookEvidence? = null
}

private class GeoVendorEvidenceMemoryStore : GeoVendorEvidenceStore {
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
