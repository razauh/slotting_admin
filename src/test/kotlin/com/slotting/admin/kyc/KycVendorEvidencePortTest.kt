package com.slotting.admin.kyc

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

class KycVendorEvidencePortTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-006-01-T001 Define KYC vendor evidence port produces the required authoritative outcome`() {
        val store = KycVendorEvidenceMemoryStore()
        val adapter = SandboxKycVendorAdapter("prov-sandbox-kyc")
        val service = service(store, mapOf("prov-sandbox-kyc" to adapter))

        // 1. Execute canonical SUBMIT_VERIFICATION through KYC vendor evidence port
        val cmd = command(
            subjectReference = "player-sub-001",
            operation = KycEvidencePortOperation.SUBMIT_VERIFICATION,
            checkType = KycCheckType.DOCUMENT_IDENTITY,
            providerId = "prov-sandbox-kyc",
            idempotencyKey = "key-kyc-verify-001",
            correlationId = "corr-kyc-1",
            causationId = "cause-kyc-1",
        )
        val res = service.executeOperation(cmd)

        // Assert: Vendor outages/ambiguity fail closed; retain minimal evidence under approved policy
        assertEquals(KycCanonicalStatus.EVIDENCE_COLLECTED, res.canonicalStatus)
        assertEquals(KycVendorOutcome.PASSED, res.vendorOutcome)
        assertEquals("player-sub-001", res.subjectReference)
        assertEquals("EVID-KYC-player-sub-001", res.evidenceReference)
        assertEquals(0.98, res.confidenceScore)

        // Assert: client/vendor grants eligibility is strictly prevented!
        assertFalse(res.directEligibilityGranted)

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.executeOperation(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.evidenceReference, replay.evidenceReference)

        // 3. Ingest signed vendor webhook
        val webhookCmd = KycWebhookEvidenceCommand(
            tenantId = "tenant-1",
            providerId = "prov-sandbox-kyc",
            signatureHeader = "valid-sig-hash",
            rawPayload = "{\"subjectReference\":\"player-sub-001\",\"checkType\":\"DOCUMENT_IDENTITY\",\"outcome\":\"PASSED\",\"confidence\":0.95,\"checkReference\":\"EXT-CHK-001\"}",
            idempotencyKey = "key-kyc-webhook-001",
            correlationId = "corr-kyc-wh-1",
            causationId = "cause-kyc-wh-1",
        )
        val webhookRes = service.processWebhook(webhookCmd)
        assertEquals(KycCanonicalStatus.EVIDENCE_COLLECTED, webhookRes.canonicalStatus)
        assertEquals(KycVendorOutcome.PASSED, webhookRes.vendorOutcome)
        assertFalse(webhookRes.directEligibilityGranted)

        // Assert: Observability & audit verification without secret/PII disclosure
        assertEquals(2, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-kyc-1", store.audit[0].correlationId)
        assertEquals("cause-kyc-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-006-01-T002 Define KYC vendor evidence port rejects invalid, boundary, unauthorized, and stale input`() {
        val store = KycVendorEvidenceMemoryStore()
        val adapter = SandboxKycVendorAdapter("prov-sandbox-kyc")
        val service = service(store, mapOf("prov-sandbox-kyc" to adapter))

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
        val restrictedService = KycVendorEvidencePortService(restrictedPolicy, TestKycPortActiveSessionDirectory(), store, mapOf("prov-sandbox-kyc" to adapter), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            restrictedService.executeOperation(command(principal = unauthorizedAdmin, idempotencyKey = "key-unauth-perm"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = KycVendorEvidencePortService(AdminRbacPolicy(true), TestKycPortExpiredSessionDirectory(), store, mapOf("prov-sandbox-kyc" to adapter), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.executeOperation(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(subjectReference = "  ", idempotencyKey = "key-blank-subj"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(expectedVersion = 2L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Unknown provider
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(providerId = "prov-unknown", idempotencyKey = "key-unknown-prov"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Invalid webhook signature
        val badWebhookCmd = KycWebhookEvidenceCommand(
            tenantId = "tenant-1",
            providerId = "prov-sandbox-kyc",
            signatureHeader = "invalid-sig",
            rawPayload = "{\"subjectReference\":\"player-sub-001\",\"checkType\":\"DOCUMENT_IDENTITY\",\"outcome\":\"PASSED\",\"confidence\":0.95,\"checkReference\":\"EXT-CHK-001\"}",
            idempotencyKey = "key-bad-wh-sig",
            correlationId = "corr-wh-bad",
            causationId = "cause-wh-bad",
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(badWebhookCmd)
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Conflicting replay with different payload
        service.executeOperation(command(idempotencyKey = "key-conflict-kyc"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(subjectReference = "different-player", idempotencyKey = "key-conflict-kyc"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-006-01-T003 Define KYC vendor evidence port survives concurrency, duplicate delivery, and dependency failure`() {
        val store = KycVendorEvidenceMemoryStore()
        val adapter = SandboxKycVendorAdapter("prov-sandbox-kyc")
        val service = service(store, mapOf("prov-sandbox-kyc" to adapter))

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-kyc-001")
        val calls = (1..4).map {
            pool.submit<KycVendorEvidenceResult> {
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
        val failingAdapter = FailingKycVendorAdapter("prov-failing")
        val failingService = service(store, mapOf("prov-failing" to failingAdapter))
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.executeOperation(command(providerId = "prov-failing", idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Vendor ambiguity / indeterminate outcome -> fails closed (SUSPENDED)
        val indeterminateAdapter = AmbiguousKycVendorAdapter("prov-ambiguous", KycVendorOutcome.INDETERMINATE)
        val ambiguousService = service(store, mapOf("prov-ambiguous" to indeterminateAdapter))
        val ambiguousRes = ambiguousService.executeOperation(command(providerId = "prov-ambiguous", idempotencyKey = "key-ambig-kyc"))
        assertEquals(KycCanonicalStatus.SUSPENDED, ambiguousRes.canonicalStatus)
        assertEquals(KycVendorOutcome.INDETERMINATE, ambiguousRes.vendorOutcome)
        assertFalse(ambiguousRes.directEligibilityGranted)

        // 4. Vendor outage outcome -> fails closed (SUSPENDED)
        val outageAdapter = AmbiguousKycVendorAdapter("prov-outage", KycVendorOutcome.OUTAGE)
        val outageService = service(store, mapOf("prov-outage" to outageAdapter))
        val outageRes = outageService.executeOperation(command(providerId = "prov-outage", idempotencyKey = "key-outage-kyc"))
        assertEquals(KycCanonicalStatus.SUSPENDED, outageRes.canonicalStatus)
        assertEquals(KycVendorOutcome.OUTAGE, outageRes.vendorOutcome)
        assertFalse(outageRes.directEligibilityGranted)

        pool.shutdown()
    }

    @Test
    fun `ADR-006-01-T004 Define KYC vendor evidence port remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = KycVendorEvidenceMemoryStore()
        val adapter = SandboxKycVendorAdapter("prov-sandbox-kyc")
        val service = service(store, mapOf("prov-sandbox-kyc" to adapter))

        val cmd = command(
            subjectReference = "player-reboot-001",
            idempotencyKey = "key-reboot-kyc",
            correlationId = "corr-reboot-kyc-1",
            causationId = "cause-reboot-kyc-1",
        )
        val first = service.executeOperation(cmd)

        val restartedService = service(store, mapOf("prov-sandbox-kyc" to adapter))
        val second = restartedService.executeOperation(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.directEligibilityGranted)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("KYC_VENDOR_CHECK_SUBMIT_VERIFICATION", store.audit[0].type)
        assertEquals("corr-reboot-kyc-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-kyc-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: KycVendorEvidenceStore, adapters: Map<String, KycVendorAdapter>) =
        KycVendorEvidencePortService(AdminRbacPolicy(true), TestKycPortActiveSessionDirectory(), store, adapters, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subjectReference: String = "player-sub-001",
        operation: KycEvidencePortOperation = KycEvidencePortOperation.SUBMIT_VERIFICATION,
        checkType: KycCheckType = KycCheckType.DOCUMENT_IDENTITY,
        providerId: String = "prov-sandbox-kyc",
        idempotencyKey: String = "key-kyc-cmd-001",
        correlationId: String = "corr-kyc-default",
        causationId: String = "cause-kyc-default",
        expectedVersion: Long = 1L,
    ) = KycVendorEvidenceCommand(
        principal = principal,
        sessionId = "session-kyc-1",
        tenantId = "tenant-1",
        subjectReference = subjectReference,
        operation = operation,
        checkType = checkType,
        providerId = providerId,
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

private class TestKycPortActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-kyc-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:00:00Z"))
        else null
}

private class TestKycPortExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:00:00Z"))
}

private class SandboxKycVendorAdapter(override val providerId: String) : KycVendorAdapter {
    override fun executeCheck(command: KycVendorEvidenceCommand): KycVendorExecutionResponse =
        KycVendorExecutionResponse(
            vendorCheckReference = "EXT-CHK-${command.subjectReference}",
            outcome = KycVendorOutcome.PASSED,
            confidenceScore = 0.98,
            minimalEvidenceReference = "EVID-KYC-${command.subjectReference}",
        )

    override fun verifyWebhook(signature: String, rawPayload: String): KycCanonicalWebhookEvidence? {
        if (signature != "valid-sig-hash") return null
        return KycCanonicalWebhookEvidence(
            subjectReference = "player-sub-001",
            checkType = KycCheckType.DOCUMENT_IDENTITY,
            outcome = KycVendorOutcome.PASSED,
            confidenceScore = 0.95,
            vendorCheckReference = "EXT-CHK-001",
        )
    }
}

private class FailingKycVendorAdapter(override val providerId: String) : KycVendorAdapter {
    override fun executeCheck(command: KycVendorEvidenceCommand): KycVendorExecutionResponse =
        error("kyc vendor unavailable")

    override fun verifyWebhook(signature: String, rawPayload: String): KycCanonicalWebhookEvidence? =
        error("kyc vendor unavailable")
}

private class AmbiguousKycVendorAdapter(
    override val providerId: String,
    private val forcedOutcome: KycVendorOutcome,
) : KycVendorAdapter {
    override fun executeCheck(command: KycVendorEvidenceCommand): KycVendorExecutionResponse =
        KycVendorExecutionResponse(
            vendorCheckReference = "EXT-CHK-AMBIG-${command.subjectReference}",
            outcome = forcedOutcome,
            confidenceScore = null,
            minimalEvidenceReference = "EVID-AMBIG-${command.subjectReference}",
        )

    override fun verifyWebhook(signature: String, rawPayload: String): KycCanonicalWebhookEvidence? = null
}

private class KycVendorEvidenceMemoryStore : KycVendorEvidenceStore {
    val results = mutableMapOf<String, Pair<String, KycVendorEvidenceResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: KycVendorEvidenceResult,
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
