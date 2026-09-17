package com.slotting.admin.rg

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class RgReviewQueueTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-003-04-T001 Operate responsible-gaming review queue produces authoritative outcome`() {
        val store = RgMemoryStore()
        val service = service(store)
        val claimed = service.operate(command(action = RgReviewAction.CLAIM, reason = RgReviewReason.REVIEW_REQUIRED))
        val decided = service.operate(
            command(
                action = RgReviewAction.APPROVE,
                reason = RgReviewReason.HIGH_RISK_ACTION,
                expectedVersion = claimed.item.serverVersion,
                secondApproverId = "admin-2",
            )
        )

        assertEquals(RgReviewState.APPROVED, decided.item.state)
        assertEquals("admin-1", claimed.item.claimedBy)
        assertEquals(2, store.audit.size)
        assertEquals(2, store.outbox.size)
        assertEquals(listOf("admin-2"), store.secondApprovers)
        assertEquals(listOf(RgReviewReason.REVIEW_REQUIRED, RgReviewReason.HIGH_RISK_ACTION), store.reasons)
        assertNull(decided.item.claimExpiresAt)
        assertNull(decided.item.claimedBy)
        assertEquals("RG_REVIEW_CLAIM", store.audit[0].type)
        assertEquals("RG_REVIEW_APPROVE", store.audit[1].type)
        assertEquals("corr-1", store.audit[0].correlationId)
        assertEquals("cause-1", store.audit[0].causationId)
    }

    @Test
    fun `ADMIN-003-04-T002 Operate responsible-gaming review queue rejects invalid boundary unauthorized and stale input`() {
        val store = RgMemoryStore()
        val service = service(store)
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = null)) }
            .also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = admin(tenantId = "tenant-other"))) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(caseReference = "unknown")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(caseReference = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(caseReference = "a".repeat(129))) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(sessionId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(correlationId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(causationId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(expectedVersion = 4)) }
            .also { assertEquals(AuthErrorCode.STALE, it.code) }

        val claimed = service.operate(command(action = RgReviewAction.CLAIM))
        // Self second-approver rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = RgReviewAction.APPROVE, expectedVersion = claimed.item.serverVersion, secondApproverId = "admin-1"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        // Missing second-approver when dual approval required
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = RgReviewAction.APPROVE, expectedVersion = claimed.item.serverVersion, secondApproverId = null))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test
    fun `ADMIN-003-04-T003 Operate responsible-gaming review queue survives concurrency duplicate delivery and dependency failure`() {
        val store = RgMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<RgReviewResult> {
                gate.await()
                service.operate(command(action = RgReviewAction.CLAIM))
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }
        pool.shutdown()

        assertEquals(2, outcomes.count { it.isSuccess })
        assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals(1, store.items["tenant-1:rg-1"]?.serverVersion)
        assertEquals(1, service.operate(command(action = RgReviewAction.CLAIM)).item.serverVersion)

        // Conflicting replay with different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = RgReviewAction.CLAIM, reason = RgReviewReason.HIGH_RISK_ACTION))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = RgReviewAction.RELEASE, expectedVersion = 0, idempotencyKey = "stale"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Dependency unavailable
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(command(action = RgReviewAction.RELEASE, expectedVersion = 1, idempotencyKey = "dependency"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-003-04-T004 Operate responsible-gaming review queue remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V9__rg_review_queue.sql").readText()
        assertTrue(migration.contains("admin_rg_review_queue"))
        assertTrue(migration.contains("second_approver_id"))
        assertTrue(migration.contains("claim_expires_at"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("balance"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: RgMemoryStore) = RgReviewQueue(AdminRbacPolicy(true), ActiveRgSessionDirectory(), store, clock)
    private fun serviceWithDependencyFailure(store: RgMemoryStore) = RgReviewQueue(AdminRbacPolicy(true), FailingRgSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        caseReference: String = "rg-1",
        action: RgReviewAction = RgReviewAction.CLAIM,
        reason: RgReviewReason = RgReviewReason.REVIEW_REQUIRED,
        expectedVersion: Long = 0,
        secondApproverId: String? = null,
        idempotencyKey: String = "key-${action.name}-$expectedVersion",
        sessionId: String = "session-1",
        correlationId: String = "corr-1",
        causationId: String = "cause-1",
    ) = RgReviewCommand(principal, sessionId, "tenant-1", caseReference, action, reason, idempotencyKey, correlationId, causationId, expectedVersion, secondApproverId)

    private fun admin(tenantId: String = "tenant-1") = AuthenticatedPrincipal("admin-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private fun player() = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveRgSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-1") AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z")) else null
}

private class FailingRgSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus = error("session dependency unavailable")
}

private class RgMemoryStore : RgQueueStore {
    val items = mutableMapOf("tenant-1:rg-1" to RgQueueItem("rg-1", RgReviewState.QUEUED, null, null, 0L))
    val results = mutableMapOf<String, Pair<String, RgReviewResult>>()
    val secondApprovers = mutableListOf<String>()
    val reasons = mutableListOf<RgReviewReason>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findItem(tenantId: String, caseReference: String) = synchronized(this) { items["$tenantId:$caseReference"] }
    override fun save(
        result: RgReviewResult,
        tenantId: String,
        reason: RgReviewReason,
        secondApproverId: String?,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        items["$tenantId:${result.item.caseReference}"] = result.item
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        secondApproverId?.let { secondApprovers += it }
        reasons += reason
        this.audit += audit
        this.outbox += outbox
    }
}
