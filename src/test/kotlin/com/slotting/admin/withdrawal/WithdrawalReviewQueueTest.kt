package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class WithdrawalReviewQueueTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-003-01-T001 Operate withdrawal review queue produces authoritative outcome`() {
        val store = QueueMemoryStore()
        val service = service(store)
        val claimed = service.operate(command(action = WithdrawalReviewAction.CLAIM))
        val decided = service.operate(command(action = WithdrawalReviewAction.APPROVE, expectedVersion = claimed.item.serverVersion, secondApproverId = "admin-2"))

        assertEquals(WithdrawalReviewState.APPROVED, decided.item.state)
        assertEquals("admin-1", claimed.item.claimedBy)
        assertEquals(2, store.audit.size)
        assertEquals(2, store.outbox.size)
        assertTrue(store.reasons.all { it == WithdrawalReviewReason.REVIEW_REQUIRED })
        assertTrue(decided.item.claimExpiresAt == null)
    }

    @Test
    fun `ADMIN-003-01-T002 Operate withdrawal review queue rejects invalid boundary unauthorized and stale input`() {
        val store = QueueMemoryStore()
        val service = service(store)
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(withdrawalReference = "unknown")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(withdrawalReference = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(action = WithdrawalReviewAction.CLAIM, expectedVersion = 4)) }
            .also { assertEquals(AuthErrorCode.STALE, it.code) }
        val claimed = service.operate(command(action = WithdrawalReviewAction.CLAIM))
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(action = WithdrawalReviewAction.APPROVE, expectedVersion = claimed.item.serverVersion, secondApproverId = "admin-1")) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test
    fun `ADMIN-003-01-T003 Operate withdrawal review queue survives concurrency duplicate delivery and dependency failure`() {
        val store = QueueMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map { pool.submit<WithdrawalReviewResult> { gate.await(); service.operate(command(action = WithdrawalReviewAction.CLAIM)) } }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }
        pool.shutdown()
        assertEquals(2, outcomes.count { it.isSuccess })
        assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals(1, store.items["tenant-1:withdrawal-1"]?.serverVersion)
        assertEquals(1, service.operate(command(action = WithdrawalReviewAction.CLAIM)).item.serverVersion)
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(action = WithdrawalReviewAction.RELEASE, expectedVersion = 0, idempotencyKey = "stale")) }
            .also { assertEquals(AuthErrorCode.STALE, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { serviceWithDependencyFailure(store).operate(command(action = WithdrawalReviewAction.RELEASE, expectedVersion = 1, idempotencyKey = "dependency")) }
            .also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-003-01-T004 Operate withdrawal review queue remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V6__withdrawal_review_queue.sql").readText()
        assertTrue(migration.contains("admin_withdrawal_review_queue"))
        assertTrue(migration.contains("reason_code"))
        assertTrue(migration.contains("claim_expires_at"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("balance"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: QueueMemoryStore) = WithdrawalReviewQueue(AdminRbacPolicy(true), ActiveQueueSessionDirectory(), store, clock)
    private fun serviceWithDependencyFailure(store: QueueMemoryStore) = WithdrawalReviewQueue(AdminRbacPolicy(true), FailingQueueSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal = admin(),
        withdrawalReference: String = "withdrawal-1",
        action: WithdrawalReviewAction = WithdrawalReviewAction.CLAIM,
        expectedVersion: Long = 0,
        secondApproverId: String? = null,
        idempotencyKey: String = "key-${action.name}-$expectedVersion",
    ) = WithdrawalReviewCommand(principal, "session-1", "tenant-1", withdrawalReference, action, WithdrawalReviewReason.REVIEW_REQUIRED, idempotencyKey, "corr-1", "cause-1", expectedVersion, secondApproverId)

    private fun admin() = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(com.slotting.admin.auth.AdminRole.SUPER_ADMIN))
    private fun player() = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveQueueSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-1") AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z")) else null
}

private class FailingQueueSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus = error("session dependency unavailable")
}

private class QueueMemoryStore : WithdrawalQueueStore {
    val items = mutableMapOf("tenant-1:withdrawal-1" to WithdrawalQueueItem("withdrawal-1", WithdrawalReviewState.QUEUED, null, null, 0L))
    val results = mutableMapOf<String, Pair<String, WithdrawalReviewResult>>()
    val reasons = mutableListOf<WithdrawalReviewReason>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()
    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findItem(tenantId: String, withdrawalReference: String) = synchronized(this) { items["$tenantId:$withdrawalReference"] }
    override fun save(result: WithdrawalReviewResult, tenantId: String, reason: WithdrawalReviewReason, secondApproverId: String?, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent) = synchronized(this) {
        items["$tenantId:${result.item.withdrawalReference}"] = result.item
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        reasons += reason
        this.audit += audit
        this.outbox += outbox
    }
}
