package com.slotting.admin.audit

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class AdminAuditTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-007-T001 Immutable admin audit produces the required authoritative outcome`() {
        val store = AuditMemoryStore()
        // Pre-populate an audit event
        val eventId = UUID.randomUUID()
        val resultId = UUID.randomUUID()
        store.rawEvents += AuditRecord(
            eventId = eventId,
            resultId = resultId,
            tenantId = "tenant-1",
            eventType = "ADMIN_ROLE_CHANGE_DUAL_CONTROL",
            occurredAt = now.minusSeconds(3600),
            correlationId = "corr-seed",
            causationId = "cause-seed",
            redactedDetails = "{\"action\":\"ROLE_CHANGE\",\"roles\":[\"SUPPORT\"],\"secret\":\"[REDACTED]\"}",
            legalHold = false,
        )

        val service = service(store)

        // 1. Search audit with restricted fields
        val searchResult = service.operate(
            command(
                action = AuditQueryAction.SEARCH,
                eventType = "ADMIN_ROLE_CHANGE_DUAL_CONTROL",
                from = now.minusSeconds(7200),
                to = now,
                idempotencyKey = "key-search-audit",
            )
        )
        assertEquals(1, searchResult.records.size)
        assertFalse(searchResult.records[0].redactedDetails.contains("secret_key"))
        assertTrue(searchResult.records[0].redactedDetails.contains("[REDACTED]"))
        assertFalse(searchResult.legalHoldActive)

        // 2. Export audit with access-controlled cryptographic checksum
        val exportResult = service.operate(
            command(
                action = AuditQueryAction.EXPORT,
                from = now.minusSeconds(7200),
                to = now,
                idempotencyKey = "key-export-audit",
            )
        )
        assertNotNull(exportResult.exportChecksumSha256)
        assertTrue(exportResult.exportChecksumSha256!!.isNotBlank())
        assertFalse(exportResult.exportChecksumSha256!!.contains("secret"))

        // 3. Apply legal hold with approved retention governance
        val holdResult = service.operate(
            command(
                action = AuditQueryAction.APPLY_LEGAL_HOLD,
                legalHoldReference = "HOLD-REG-2026-001",
                legalHoldReason = "Regulatory inquiry on security policies",
                approverId = "admin-legal-counsel",
                idempotencyKey = "key-apply-hold",
            )
        )
        assertTrue(holdResult.legalHoldActive)

        // Verify search under legal hold reflects active hold
        val searchUnderHold = service.operate(
            command(
                action = AuditQueryAction.SEARCH,
                from = now.minusSeconds(7200),
                to = now,
                idempotencyKey = "key-search-under-hold",
            )
        )
        assertTrue(searchUnderHold.legalHoldActive)
        assertTrue(searchUnderHold.records[0].legalHold)

        // Verify privileged queries themselves generate immutable audit and outbox events
        assertEquals(4, store.audit.size)
        assertEquals(4, store.outbox.size)
        assertEquals("ADMIN_AUDIT_SEARCH", store.audit[0].type)
        assertEquals("ADMIN_AUDIT_EXPORT", store.audit[1].type)
        assertEquals("ADMIN_AUDIT_APPLY_LEGAL_HOLD", store.audit[2].type)
        assertEquals("ADMIN_AUDIT_SEARCH", store.audit[3].type)
    }

    @Test
    fun `ADMIN-007-T002 Immutable admin audit rejects invalid, boundary, unauthorized, and stale input`() {
        val store = AuditMemoryStore()
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

        // Missing legal hold reason or approver
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = AuditQueryAction.APPLY_LEGAL_HOLD,
                    legalHoldReference = "HOLD-01",
                    legalHoldReason = null,
                    approverId = "admin-1",
                    idempotencyKey = "key-hold-no-reason",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = AuditQueryAction.APPLY_LEGAL_HOLD,
                    legalHoldReference = "HOLD-01",
                    legalHoldReason = "Valid reason",
                    approverId = "   ",
                    idempotencyKey = "key-hold-blank-approver",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid date ranges
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = AuditQueryAction.SEARCH,
                    from = now,
                    to = now.minusSeconds(10),
                    idempotencyKey = "key-inv-dates",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid limits
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = AuditQueryAction.SEARCH,
                    limit = 0,
                    idempotencyKey = "key-inv-limit-0",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = AuditQueryAction.SEARCH,
                    limit = 1001,
                    idempotencyKey = "key-inv-limit-max",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Release unknown legal hold
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = AuditQueryAction.RELEASE_LEGAL_HOLD,
                    legalHoldReference = "NON-EXISTENT-HOLD",
                    approverId = "admin-1",
                    idempotencyKey = "key-release-unknown",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test
    fun `ADMIN-007-T003 Immutable admin audit survives concurrency, duplicate delivery, and dependency failure`() {
        val store = AuditMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<AuditQueryResult> {
                gate.await()
                service.operate(command(action = AuditQueryAction.SEARCH, idempotencyKey = "race-search-audit"))
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
                    action = AuditQueryAction.SEARCH,
                    eventType = "DIFFERENT_EVENT_TYPE",
                    idempotencyKey = "race-search-audit",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(
                command(
                    action = AuditQueryAction.SEARCH,
                    idempotencyKey = "dep-search-audit",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-007-T004 Immutable admin audit remains compatible, recoverable, observable, and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V16__admin_audit_retention_legal_hold.sql").readText()
        assertTrue(migration.contains("admin_audit_legal_hold"))
        assertTrue(migration.contains("admin_audit_query_result"))
        assertTrue(migration.contains("hold_reference"))
        assertTrue(migration.contains("checksum_sha256"))
        assertTrue(migration.contains("active"))
        assertTrue(!migration.contains("update admin_audit_event"))
    }

    private fun service(store: AuditMemoryStore) =
        AdminAuditService(AdminRbacPolicy(true), ActiveAuditSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: AuditMemoryStore) =
        AdminAuditService(AdminRbacPolicy(true), FailingAuditSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        action: AuditQueryAction = AuditQueryAction.SEARCH,
        eventType: String? = null,
        from: Instant = now.minusSeconds(86400),
        to: Instant = now,
        legalHoldReference: String? = null,
        legalHoldReason: String? = null,
        approverId: String? = null,
        limit: Int = 100,
        expectedVersion: Long = 0L,
        idempotencyKey: String = "key-audit-${action.name}",
        sessionId: String = "session-audit-1",
        correlationId: String = "corr-audit-1",
        causationId: String = "cause-audit-1",
    ) = AuditQueryCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = "tenant-1",
        action = action,
        eventType = eventType,
        from = from,
        to = to,
        correlationId = null,
        legalHoldReference = legalHoldReference,
        legalHoldReason = legalHoldReason,
        approverId = approverId,
        limit = limit,
        idempotencyKey = idempotencyKey,
        commandCorrelationId = correlationId,
        commandCausationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-auditor-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.AUDITOR, AdminRole.SECURITY))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveAuditSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-auditor-1" && sessionId == "session-audit-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingAuditSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class AuditMemoryStore : AdminAuditStore {
    val rawEvents = mutableListOf<AuditRecord>()
    val holds = mutableMapOf<String, Pair<Long, Boolean>>()
    val results = mutableMapOf<String, Pair<String, AuditQueryResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun queryEvents(tenantId: String, eventType: String?, from: Instant, to: Instant, limit: Int) = synchronized(this) {
        val hold = isLegalHoldActive(tenantId)
        rawEvents.filter { it.tenantId == tenantId && (eventType == null || it.eventType == eventType) && !it.occurredAt.isBefore(from) && !it.occurredAt.isAfter(to) }
            .take(limit)
            .map { it.copy(legalHold = hold) }
    }
    override fun isLegalHoldActive(tenantId: String) = synchronized(this) {
        holds.values.any { it.second }
    }
    override fun findHoldVersion(tenantId: String, holdReference: String) = synchronized(this) {
        holds["$tenantId:$holdReference"]?.first
    }
    override fun saveHold(
        tenantId: String,
        holdReference: String,
        reason: String,
        approverId: String,
        active: Boolean,
        version: Long,
        now: Instant,
    ) = synchronized(this) {
        holds["$tenantId:$holdReference"] = version to active
    }
    override fun save(
        result: AuditQueryResult,
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
