package com.slotting.admin.aml

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

class SanctionsPepScreeningTest {
    private val now = Instant.parse("2026-09-17T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `AML-001-01-T001 Screen sanctions and PEP status produces the required authoritative outcome`() {
        val store = SanctionsPepScreeningMemoryStore()
        val adapter = SandboxSanctionsPepVendorAdapter("prov-sandbox-aml")
        val service = service(store, mapOf("prov-sandbox-aml" to adapter))

        // 1. Screen sanctions hit subject -> must place on HOLD and queue AML review (hit/rule breach NOT ignored!)
        val hitCmd = command(
            subject = ScreeningSubject("player-aml-hit-001", "Hit Person", "1980-01-01", "IR"),
            checkType = ScreeningCheckType.SANCTIONS_AND_PEP,
            idempotencyKey = "key-aml-screen-hit-001",
            correlationId = "corr-aml-hit-1",
            causationId = "cause-aml-hit-1",
        )
        val hitRes = service.screenSubject(hitCmd)

        // Assert: Thresholds are approved config; fail closed/hold policy explicit; decision provenance retained
        assertEquals(SanctionsPepOutcome.SANCTION_HIT, hitRes.outcome)
        assertEquals(ScreeningDecisionStatus.HOLD, hitRes.status)
        assertNotNull(hitRes.amlCaseReference)
        assertFalse(hitRes.financialAuthorityCreated) // Outcome cannot create financial authority
        assertFalse(hitRes.moneyMutated)             // Cannot mutate money
        assertEquals("player-aml-hit-001", hitRes.subjectReference)
        assertEquals("EVID-AML-player-aml-hit-001", hitRes.evidenceReference)

        // Provenance assertions
        assertEquals("prov-sandbox-aml", hitRes.provenance.providerId)
        assertEquals(1L, hitRes.provenance.configVersion)
        assertEquals(0.80, hitRes.provenance.appliedThreshold)
        assertEquals(0.95, hitRes.provenance.observedScore)
        assertTrue(hitRes.provenance.matchedLists.contains("OFAC_SDN"))

        // Assert: Queued AML review case created atomically in store
        val queuedCase = store.queuedItems[hitRes.amlCaseReference]
        assertNotNull(queuedCase)
        assertEquals(AmlReviewState.QUEUED, queuedCase.state)

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.screenSubject(hitCmd)
        assertEquals(hitRes.resultId, replay.resultId)
        assertEquals(hitRes.evidenceReference, replay.evidenceReference)

        // 3. Screen clear subject -> must be CLEARED with no AML queue case
        val clearCmd = command(
            subject = ScreeningSubject("player-aml-clear-001", "Clean Person", "1990-05-15", "GB"),
            checkType = ScreeningCheckType.SANCTIONS_AND_PEP,
            idempotencyKey = "key-aml-screen-clear-001",
            correlationId = "corr-aml-clear-1",
            causationId = "cause-aml-clear-1",
        )
        val clearRes = service.screenSubject(clearCmd)
        assertEquals(SanctionsPepOutcome.CLEAR, clearRes.outcome)
        assertEquals(ScreeningDecisionStatus.CLEARED, clearRes.status)
        assertNull(clearRes.amlCaseReference)

        // Assert: Observability & audit verification without secret/PII disclosure
        assertEquals(2, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-aml-hit-1", store.audit[0].correlationId)
        assertEquals("cause-aml-hit-1", store.audit[0].causationId)
    }

    @Test
    fun `AML-001-01-T002 Screen sanctions and PEP status rejects invalid, boundary, unauthorized, and stale input`() {
        val store = SanctionsPepScreeningMemoryStore()
        val adapter = SandboxSanctionsPepVendorAdapter("prov-sandbox-aml")
        val service = service(store, mapOf("prov-sandbox-aml" to adapter))

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant admin
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(principal = admin(tenantId = "other-tenant"), idempotencyKey = "key-cross-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Role lacking MANAGE_SECURITY permission (e.g. Support agent)
        val supportAdmin = AuthenticatedPrincipal("admin-support", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(principal = supportAdmin, idempotencyKey = "key-support-unauth"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive / expired session
        val expiredSessionService = SanctionsPepScreeningService(AdminRbacPolicy(true), TestAmlScreeningExpiredSessionDirectory(), store, ApprovedThresholdConfig(), mapOf("prov-sandbox-aml" to adapter), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.screenSubject(command(idempotencyKey = "key-expired-sess"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Blank subject reference
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(subject = ScreeningSubject("   ", "Some Name"), idempotencyKey = "key-blank-ref"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank full name
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(subject = ScreeningSubject("sub-001", "   "), idempotencyKey = "key-blank-name"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(expectedVersion = 2L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Unknown provider
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(providerId = "prov-unknown", idempotencyKey = "key-unknown-prov"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Conflicting replay with different payload
        service.screenSubject(command(idempotencyKey = "key-conflict-aml"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.screenSubject(command(subject = ScreeningSubject("diff-sub", "Different Name"), idempotencyKey = "key-conflict-aml"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `AML-001-01-T003 Screen sanctions and PEP status survives concurrency, duplicate delivery, and dependency failure`() {
        val store = SanctionsPepScreeningMemoryStore()
        val adapter = SandboxSanctionsPepVendorAdapter("prov-sandbox-aml")
        val service = service(store, mapOf("prov-sandbox-aml" to adapter))

        // 1. Concurrency: duplicate submissions race with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val cmd = command(idempotencyKey = "key-concurrent-aml-001")
        val calls = (1..4).map {
            pool.submit<SanctionsPepScreeningResult> {
                gate.await()
                service.screenSubject(cmd)
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on vendor adapter -> fails closed (DEPENDENCY_UNAVAILABLE)
        val failingAdapter = FailingSanctionsPepVendorAdapter("prov-failing-aml")
        val failingService = service(store, mapOf("prov-failing-aml" to failingAdapter))
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.screenSubject(command(providerId = "prov-failing-aml", idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Indeterminate vendor outcome -> fails closed to HOLD
        val indeterminateAdapter = IndeterminateSanctionsPepVendorAdapter("prov-ambig-aml")
        val ambiguousService = service(store, mapOf("prov-ambig-aml" to indeterminateAdapter))
        val ambigRes = ambiguousService.screenSubject(command(providerId = "prov-ambig-aml", idempotencyKey = "key-ambig-aml"))
        assertEquals(SanctionsPepOutcome.INDETERMINATE, ambigRes.outcome)
        assertEquals(ScreeningDecisionStatus.HOLD, ambigRes.status)
        assertNotNull(ambigRes.amlCaseReference)

        pool.shutdown()
    }

    @Test
    fun `AML-001-01-T004 Screen sanctions and PEP status remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: committed rows/constraints on admin_aml_review_queue in V8
        val migration = File("src/main/resources/db/migration/V8__aml_review_queue.sql").readText()
        assertTrue(migration.contains("admin_aml_review_queue"))
        assertTrue(migration.contains("admin_aml_review_result"))
        assertTrue(migration.contains("check (state in ('QUEUED','CLAIMED','APPROVED','REJECTED'))"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("balance"))

        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = SanctionsPepScreeningMemoryStore()
        val adapter = SandboxSanctionsPepVendorAdapter("prov-sandbox-aml")
        val service = service(store, mapOf("prov-sandbox-aml" to adapter))

        val cmd = command(
            subject = ScreeningSubject("player-aml-reboot-001", "Reboot Person"),
            idempotencyKey = "key-reboot-aml",
            correlationId = "corr-reboot-aml-1",
            causationId = "cause-reboot-aml-1",
        )
        val first = service.screenSubject(cmd)

        val restartedService = service(store, mapOf("prov-sandbox-aml" to adapter))
        val second = restartedService.screenSubject(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)
        assertFalse(second.financialAuthorityCreated)
        assertFalse(second.moneyMutated)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("AML_SANCTIONS_PEP_SCREENING", store.audit[0].type)
        assertEquals("corr-reboot-aml-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-aml-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: SanctionsPepScreeningStore, adapters: Map<String, SanctionsPepVendorAdapter>) =
        SanctionsPepScreeningService(AdminRbacPolicy(true), TestAmlScreeningActiveSessionDirectory(), store, ApprovedThresholdConfig(), adapters, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        subject: ScreeningSubject = ScreeningSubject("player-sub-default", "Default Person"),
        checkType: ScreeningCheckType = ScreeningCheckType.SANCTIONS_AND_PEP,
        providerId: String = "prov-sandbox-aml",
        idempotencyKey: String = "key-aml-cmd-001",
        correlationId: String = "corr-aml-default",
        causationId: String = "cause-aml-default",
        expectedVersion: Long = 1L,
    ) = SanctionsPepScreeningCommand(
        principal = principal,
        sessionId = "session-aml-screen-1",
        tenantId = "tenant-1",
        subject = subject,
        checkType = checkType,
        providerId = providerId,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-aml-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-aml-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class TestAmlScreeningActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-aml-screen-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T19:00:00Z"))
        else null
}

private class TestAmlScreeningExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-17T17:00:00Z"))
}

private class SandboxSanctionsPepVendorAdapter(override val providerId: String) : SanctionsPepVendorAdapter {
    override fun screen(subject: ScreeningSubject, checkType: ScreeningCheckType): SanctionsPepVendorResponse {
        return if (subject.fullName.contains("Hit", ignoreCase = true)) {
            SanctionsPepVendorResponse(
                matchScore = 0.95,
                matchedLists = listOf("OFAC_SDN", "EU_CONSOLIDATED"),
                indeterminate = false,
            )
        } else {
            SanctionsPepVendorResponse(
                matchScore = 0.05,
                matchedLists = emptyList(),
                indeterminate = false,
            )
        }
    }
}

private class FailingSanctionsPepVendorAdapter(override val providerId: String) : SanctionsPepVendorAdapter {
    override fun screen(subject: ScreeningSubject, checkType: ScreeningCheckType): SanctionsPepVendorResponse =
        error("aml screening vendor unavailable")
}

private class IndeterminateSanctionsPepVendorAdapter(override val providerId: String) : SanctionsPepVendorAdapter {
    override fun screen(subject: ScreeningSubject, checkType: ScreeningCheckType): SanctionsPepVendorResponse =
        SanctionsPepVendorResponse(matchScore = 0.50, matchedLists = emptyList(), indeterminate = true)
}

private class SanctionsPepScreeningMemoryStore : SanctionsPepScreeningStore {
    val results = mutableMapOf<String, Pair<String, SanctionsPepScreeningResult>>()
    val queuedItems = mutableMapOf<String, AmlQueueItem>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: SanctionsPepScreeningResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queuedAmlItem: AmlQueueItem?,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        queuedAmlItem?.let { queuedItems[it.caseReference] = it }
        this.audit += audit
        this.outbox += outbox
    }
}
