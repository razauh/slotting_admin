package com.slotting.admin.adjustment

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class ManualAdjustmentTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-004-T001 Manual adjustment UI produces authoritative outcome`() {
        val store = AdjustmentMemoryStore()
        val service = service(store)

        // 1. Preview balanced batch
        val preview = service.operate(command(action = ManualAdjustmentAction.PREVIEW))
        assertTrue(preview.isBalanced)
        assertEquals(5000L, preview.totalDebits)
        assertEquals(5000L, preview.totalCredits)
        assertEquals(ManualAdjustmentState.PREVIEWED, preview.item.state)

        // 2. Propose balanced batch
        val proposed = service.operate(command(action = ManualAdjustmentAction.PROPOSE, idempotencyKey = "key-propose"))
        assertEquals(ManualAdjustmentState.PENDING_APPROVAL, proposed.item.state)
        assertEquals("admin-1", proposed.item.makerId)

        // 3. Approve batch with distinct checker
        val approved = service.operate(
            command(
                principal = admin(id = "admin-2"),
                action = ManualAdjustmentAction.APPROVE,
                expectedVersion = proposed.item.serverVersion,
                secondApproverId = "admin-2",
                idempotencyKey = "key-approve",
            )
        )
        assertEquals(ManualAdjustmentState.APPROVED, approved.item.state)
        assertEquals("admin-2", approved.item.secondApproverId)
        assertNotNull(approved.item.postingReference)
        assertTrue(approved.item.postingReference!!.startsWith("posting:"))
        assertTrue(approved.receiptReference.startsWith("receipt:"))

        // Verify audit and outbox events
        assertEquals(3, store.audit.size)
        assertEquals(3, store.outbox.size)
        assertEquals("ADJUSTMENT_PREVIEW", store.audit[0].type)
        assertEquals("ADJUSTMENT_PROPOSE", store.audit[1].type)
        assertEquals("ADJUSTMENT_APPROVE", store.audit[2].type)
        assertEquals("corr-1", store.audit[0].correlationId)
        assertEquals("cause-1", store.audit[0].causationId)
    }

    @Test
    fun `ADMIN-004-T002 Manual adjustment UI rejects invalid boundary unauthorized and stale input`() {
        val store = AdjustmentMemoryStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = null)) }
            .also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = admin(tenantId = "tenant-other"))) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unbalanced batch (direct balance form / single-sided override)
        val unbalancedLegs = listOf(
            AdjustmentLeg("player-account", 5000L, AdjustmentLegDirection.CREDIT),
            AdjustmentLeg("suspense-account", 4000L, AdjustmentLegDirection.DEBIT),
        )
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(legs = unbalancedLegs)) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Empty legs
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(legs = emptyList())) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank reference or evidence
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(adjustmentReference = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(evidenceReference = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(sessionId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(currencyCode = "invalid")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Propose batch
        val proposed = service.operate(command(action = ManualAdjustmentAction.PROPOSE, idempotencyKey = "prop-1"))

        // Stale version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = ManualAdjustmentAction.APPROVE, expectedVersion = 99, secondApproverId = "admin-2"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Self-approval rejected: maker trying to approve
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(principal = admin(id = "admin-1"), action = ManualAdjustmentAction.APPROVE, expectedVersion = proposed.item.serverVersion, secondApproverId = "admin-2"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Self-approval rejected: maker set as second approver
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(principal = admin(id = "admin-2"), action = ManualAdjustmentAction.APPROVE, expectedVersion = proposed.item.serverVersion, secondApproverId = "admin-1"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Missing second approver
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = ManualAdjustmentAction.APPROVE, expectedVersion = proposed.item.serverVersion, secondApproverId = null))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test
    fun `ADMIN-004-T003 Manual adjustment UI survives concurrency duplicate delivery and dependency failure`() {
        val store = AdjustmentMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<ManualAdjustmentResult> {
                gate.await()
                service.operate(command(action = ManualAdjustmentAction.PROPOSE, idempotencyKey = "race-propose"))
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }
        pool.shutdown()

        assertEquals(2, outcomes.count { it.isSuccess })
        assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // Conflicting replay with different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = ManualAdjustmentAction.PROPOSE,
                    reason = ManualAdjustmentReason.DISPUTE_RESOLUTION,
                    idempotencyKey = "race-propose",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = ManualAdjustmentAction.APPROVE, expectedVersion = 0, secondApproverId = "admin-2", idempotencyKey = "stale-app"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(command(action = ManualAdjustmentAction.APPROVE, expectedVersion = 1, secondApproverId = "admin-2", idempotencyKey = "dep-app"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-004-T004 Manual adjustment UI remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V10__manual_adjustment.sql").readText()
        assertTrue(migration.contains("admin_manual_adjustment_batch"))
        assertTrue(migration.contains("admin_manual_adjustment_result"))
        assertTrue(migration.contains("posting_reference"))
        assertTrue(migration.contains("second_approver_id"))
        assertTrue(migration.contains("total_debits = total_credits"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: AdjustmentMemoryStore) =
        ManualAdjustmentService(AdminRbacPolicy(true), ActiveAdjustmentSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: AdjustmentMemoryStore) =
        ManualAdjustmentService(AdminRbacPolicy(true), FailingAdjustmentSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        adjustmentReference: String = "adj-1",
        action: ManualAdjustmentAction = ManualAdjustmentAction.PREVIEW,
        reason: ManualAdjustmentReason = ManualAdjustmentReason.GOODWILL_CREDIT,
        evidenceReference: String = "ticket-12345",
        currencyCode: String = "USD",
        legs: List<AdjustmentLeg> = defaultLegs(),
        idempotencyKey: String = "key-${action.name}",
        expectedVersion: Long = 0L,
        secondApproverId: String? = null,
        sessionId: String = "session-1",
        correlationId: String = "corr-1",
        causationId: String = "cause-1",
    ) = ManualAdjustmentCommand(
        principal,
        sessionId,
        "tenant-1",
        adjustmentReference,
        action,
        reason,
        evidenceReference,
        currencyCode,
        legs,
        idempotencyKey,
        correlationId,
        causationId,
        expectedVersion,
        secondApproverId,
    )

    private fun defaultLegs() = listOf(
        AdjustmentLeg("player-wallet", 5000L, AdjustmentLegDirection.CREDIT),
        AdjustmentLeg("goodwill-expense", 5000L, AdjustmentLegDirection.DEBIT),
    )

    private fun admin(id: String = "admin-1", tenantId: String = "tenant-1") =
        AuthenticatedPrincipal(id, tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveAdjustmentSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && (principalId == "admin-1" || principalId == "admin-2") && sessionId == "session-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingAdjustmentSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class AdjustmentMemoryStore : ManualAdjustmentStore {
    val items = mutableMapOf<String, ManualAdjustmentBatch>()
    val results = mutableMapOf<String, Pair<String, ManualAdjustmentResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findItem(tenantId: String, adjustmentReference: String) = synchronized(this) { items["$tenantId:$adjustmentReference"] }
    override fun save(
        result: ManualAdjustmentResult,
        tenantId: String,
        reason: ManualAdjustmentReason,
        evidenceReference: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        items["$tenantId:${result.item.adjustmentReference}"] = result.item
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
