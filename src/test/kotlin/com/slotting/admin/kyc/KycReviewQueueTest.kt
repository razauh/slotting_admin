package com.slotting.admin.kyc

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class KycReviewQueueTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test fun `ADMIN-003-02-T001 Operate KYC review queue produces authoritative outcome`() {
        val store = KycMemoryStore(); val service = service(store)
        val claimed = service.operate(command(action = KycReviewAction.CLAIM))
        val decided = service.operate(command(action = KycReviewAction.APPROVE, expectedVersion = claimed.item.serverVersion, secondApproverId = "admin-2"))
        assertEquals(KycReviewState.APPROVED, decided.item.state); assertEquals("admin-1", claimed.item.claimedBy)
        assertEquals(2, store.audit.size); assertEquals(2, store.outbox.size); assertEquals(listOf("admin-2"), store.secondApprovers)
        assertNull(decided.item.claimExpiresAt); assertNull(decided.item.claimedBy)
    }

    @Test fun `ADMIN-003-02-T002 Operate KYC review queue rejects invalid boundary unauthorized and stale input`() {
        val store = KycMemoryStore(); val service = service(store)
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(caseReference = "unknown")) }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(caseReference = "")) }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(expectedVersion = 4)) }.also { assertEquals(AuthErrorCode.STALE, it.code) }
        val claimed = service.operate(command(action = KycReviewAction.CLAIM))
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(action = KycReviewAction.APPROVE, expectedVersion = claimed.item.serverVersion, secondApproverId = "admin-1")) }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test fun `ADMIN-003-02-T003 Operate KYC review queue survives concurrency duplicate delivery and dependency failure`() {
        val store = KycMemoryStore(); val service = service(store); val gate = CountDownLatch(1); val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map { pool.submit<KycReviewResult> { gate.await(); service.operate(command(action = KycReviewAction.CLAIM)) } }; gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }; pool.shutdown()
        assertEquals(2, outcomes.count { it.isSuccess }); assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size); assertEquals(1, store.outbox.size); assertEquals(1, store.items["tenant-1:kyc-1"]?.serverVersion)
        assertEquals(1, service.operate(command(action = KycReviewAction.CLAIM)).item.serverVersion)
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(action = KycReviewAction.RELEASE, expectedVersion = 0, idempotencyKey = "stale")) }.also { assertEquals(AuthErrorCode.STALE, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { serviceWithDependencyFailure(store).operate(command(action = KycReviewAction.RELEASE, expectedVersion = 1, idempotencyKey = "dependency")) }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test fun `ADMIN-003-02-T004 Operate KYC review queue remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V7__kyc_review_queue.sql").readText()
        assertTrue(migration.contains("admin_kyc_review_queue")); assertTrue(migration.contains("second_approver_id")); assertTrue(migration.contains("claim_expires_at")); assertTrue(migration.contains("foreign key")); assertTrue(!migration.contains("balance")); assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: KycMemoryStore) = KycReviewQueue(AdminRbacPolicy(true), ActiveKycSessionDirectory(), store, clock)
    private fun serviceWithDependencyFailure(store: KycMemoryStore) = KycReviewQueue(AdminRbacPolicy(true), FailingKycSessionDirectory(), store, clock)
    private fun command(principal: AuthenticatedPrincipal = admin(), caseReference: String = "kyc-1", action: KycReviewAction = KycReviewAction.CLAIM, expectedVersion: Long = 0, secondApproverId: String? = null, idempotencyKey: String = "key-${action.name}-$expectedVersion") = KycReviewCommand(principal, "session-1", "tenant-1", caseReference, action, KycReviewReason.REVIEW_REQUIRED, idempotencyKey, "corr-1", "cause-1", expectedVersion, secondApproverId)
    private fun admin() = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))
    private fun player() = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveKycSessionDirectory : AdminSessionDirectory { override fun find(tenantId: String, principalId: String, sessionId: String) = if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-1") AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z")) else null }
private class FailingKycSessionDirectory : AdminSessionDirectory { override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus = error("session dependency unavailable") }
private class KycMemoryStore : KycQueueStore {
    val items = mutableMapOf("tenant-1:kyc-1" to KycQueueItem("kyc-1", KycReviewState.QUEUED, null, null, 0L)); val results = mutableMapOf<String, Pair<String, KycReviewResult>>(); val secondApprovers = mutableListOf<String>(); val audit = mutableListOf<AuditEvent>(); val outbox = mutableListOf<OutboxEvent>()
    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findItem(tenantId: String, caseReference: String) = synchronized(this) { items["$tenantId:$caseReference"] }
    override fun save(result: KycReviewResult, tenantId: String, reason: KycReviewReason, secondApproverId: String?, queryFingerprint: String, idempotencyKey: String, audit: AuditEvent, outbox: OutboxEvent) = synchronized(this) { items["$tenantId:${result.item.caseReference}"] = result.item; results["$tenantId:$idempotencyKey"] = queryFingerprint to result; secondApproverId?.let { secondApprovers += it }; this.audit += audit; this.outbox += outbox }
}
