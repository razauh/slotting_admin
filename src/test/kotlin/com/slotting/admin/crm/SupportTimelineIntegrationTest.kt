package com.slotting.admin.crm

import com.slotting.admin.auth.*
import com.slotting.admin.player.AccessReasonCode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SupportTimelineIntegrationTest {
    private val now = Instant.parse("2026-09-18T22:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Enforce fail-closed gate before each test run
        SupportTimelineIntegrationBinding.isBound = false
    }

    @AfterEach
    fun tearDown() {
        // Restore bound state
        SupportTimelineIntegrationBinding.isBound = true
    }

    // =========================================================================
    // CRM-003-T001: Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `CRM-003-T001 Support timeline integration produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        assertFailsWith<AssertionError> {
            SupportTimelineIntegrationBinding.checkBound()
        }.also {
            assertEquals("copied balances diverge", it.message)
        }

        val store = InMemorySupportTimelineStore()
        val ledgerResolver = FakeLedgerReferenceResolver()
        val service = createService(store, ledgerResolver)

        val ingestCmd = IngestSupportTimelineEventCommand(
            principal = adminPrincipal(),
            sessionId = "session-tl-1",
            tenantId = "tenant-1",
            playerReference = "player-tl-001",
            eventType = TimelineEventType.LEDGER_REFERENCE,
            summary = "Deposit transaction completed",
            details = mapOf("channel" to "CARD", "method" to "VISA"),
            authoritativeLedgerPointer = "LEDGER-TX-998822",
            idempotencyKey = "idemp-ingest-001",
            correlationId = "corr-ingest-001",
            causationId = "caus-ingest-001",
        )

        // Verify service invocation fails closed with protected risk assertion when unbound
        SupportTimelineIntegrationBinding.isBound = false
        assertFailsWith<AssertionError> {
            service.ingestTimelineEvent(ingestCmd)
        }.also {
            assertEquals("copied balances diverge", it.message)
        }

        SupportTimelineIntegrationBinding.isBound = true

        // 2. Ingest events into support timeline (one support note, one ledger reference)
        ledgerResolver.registerPointer("tenant-1", "LEDGER-TX-998822")
        val item1 = service.ingestTimelineEvent(ingestCmd)
        assertEquals(TimelineEventType.LEDGER_REFERENCE, item1.eventType)
        assertEquals("LEDGER-TX-998822", item1.authoritativeLedgerPointer)

        service.ingestTimelineEvent(
            IngestSupportTimelineEventCommand(
                principal = adminPrincipal(),
                sessionId = "session-tl-1",
                tenantId = "tenant-1",
                playerReference = "player-tl-001",
                eventType = TimelineEventType.SUPPORT_NOTE,
                summary = "Customer called regarding account verification",
                details = mapOf("callDuration" to "180s", "agentId" to "agent-007"),
                idempotencyKey = "idemp-ingest-002",
                correlationId = "corr-ingest-002",
                causationId = "caus-ingest-002",
            )
        )

        // 3. Authoritative query of support timeline
        val queryCmd = QuerySupportTimelineCommand(
            principal = adminPrincipal(),
            sessionId = "session-tl-1",
            tenantId = "tenant-1",
            playerReference = "player-tl-001",
            accessReason = AccessReasonCode.SUPPORT_REQUEST,
            idempotencyKey = "idemp-query-001",
            correlationId = "corr-query-001",
            causationId = "caus-query-001",
        )
        val queryResult = service.queryTimeline(queryCmd)

        // Assert: No duplicate authority; balances never copied; financial record stays in ledger
        assertEquals("player-tl-001", queryResult.playerReference)
        assertEquals(2, queryResult.items.size)
        assertEquals(1, queryResult.authoritativeLedgerPointerCount)
        assertFalse(queryResult.hasDuplicateFinancialAuthority, "Must have no duplicate financial authority")
        assertTrue(queryResult.balanceSourceIsAuthoritativeLedgerOnly, "Financial record stays in ledger only")
        assertFalse(queryResult.moneyMutated, "Support timeline queries never mutate money")
        assertFalse(queryResult.financialAuthorityCreated)
        assertEquals(1L, queryResult.version)
        assertEquals(now, queryResult.serverTime)
        assertTrue(queryResult.evidenceReference.startsWith("EVID-SUPP-TL-tenant-1-player-tl-001-SUPPORT_REQUEST-v1"))

        // Replay returns cached identical query result
        val replay = service.queryTimeline(queryCmd)
        assertEquals(queryResult.resultId, replay.resultId)
        assertEquals(queryResult.evidenceReference, replay.evidenceReference)

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("SUPPORT_TIMELINE_QUERIED_SUPPORT_REQUEST", store.audit[0].type)
        assertEquals("corr-query-001", store.audit[0].correlationId)
        assertEquals("caus-query-001", store.audit[0].causationId)
    }

    // =========================================================================
    // CRM-003-T002: Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `CRM-003-T002 Support timeline integration rejects invalid boundary unauthorized and stale input`() {
        SupportTimelineIntegrationBinding.isBound = true

        val store = InMemorySupportTimelineStore()
        val ledgerResolver = FakeLedgerReferenceResolver()
        val service = createService(store, ledgerResolver)

        // 1. Attempts to mutate money or create duplicate financial authority in timeline
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.ingestTimelineEvent(
                createIngestCommand(
                    requestsFinancialMutation = true,
                    idempotencyKey = "idemp-fail-fin-mut",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.ingestTimelineEvent(
                createIngestCommand(
                    duplicateFinancialAuthority = true,
                    idempotencyKey = "idemp-fail-dup-auth",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.ingestTimelineEvent(
                createIngestCommand(
                    financialBalanceMinorUnits = 10000L,
                    idempotencyKey = "idemp-fail-bal-mut",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Secret and excess PII leakage attempts
        val prohibitedKeys = listOf("password", "rawPassword", "apiKey", "secretToken", "pan", "cvv", "ssn")
        for (key in prohibitedKeys) {
            assertFailsWith<AuthenticationFailure.Rejected> {
                service.ingestTimelineEvent(
                    createIngestCommand(
                        details = mapOf(key to "unredacted-secret-val"),
                        idempotencyKey = "idemp-fail-secret-$key",
                    )
                )
            }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        }

        // 3. Unverified ledger pointer
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.ingestTimelineEvent(
                createIngestCommand(
                    eventType = TimelineEventType.LEDGER_REFERENCE,
                    authoritativeLedgerPointer = "UNKNOWN-LEDGER-POINTER",
                    idempotencyKey = "idemp-fail-unverified-pointer",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 4. Unauthenticated principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(
                createQueryCommand(
                    principal = null,
                    idempotencyKey = "idemp-fail-unauth",
                )
            )
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 5. Player principal attempting internal support timeline access
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(
                createQueryCommand(
                    principal = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet()),
                    idempotencyKey = "idemp-fail-player",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Cross-tenant principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(
                createQueryCommand(
                    principal = adminPrincipal("tenant-2"),
                    tenantId = "tenant-1",
                    idempotencyKey = "idemp-fail-cross-tenant",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Expired admin session
        val expiredSessionService = SupportTimelineIntegrationService(
            policy = AdminRbacPolicy(true),
            sessions = TestSupportTimelineExpiredSessionDirectory(),
            store = store,
            ledgerResolver = ledgerResolver,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.queryTimeline(createQueryCommand(idempotencyKey = "idemp-fail-expired"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Blank required fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(createQueryCommand(playerReference = "   ", idempotencyKey = "idemp-fail-blank-p"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(createQueryCommand(sessionId = "   ", idempotencyKey = "idemp-fail-blank-s"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(createQueryCommand(correlationId = "   ", idempotencyKey = "idemp-fail-blank-c"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 9. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(createQueryCommand(expectedVersion = 2L, idempotencyKey = "idemp-fail-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 10. Conflicting replay with different access reason under same idempotency key
        service.queryTimeline(createQueryCommand(idempotencyKey = "idemp-conflict-base", accessReason = AccessReasonCode.SUPPORT_REQUEST))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.queryTimeline(createQueryCommand(idempotencyKey = "idemp-conflict-base", accessReason = AccessReasonCode.AUDIT_REVIEW))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // CRM-003-T003: Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `CRM-003-T003 Support timeline integration survives concurrency duplicate delivery and dependency failure`() {
        SupportTimelineIntegrationBinding.isBound = true

        val store = InMemorySupportTimelineStore()
        val ledgerResolver = FakeLedgerReferenceResolver()
        val service = createService(store, ledgerResolver)

        // 1. Concurrency: 8 threads race with identical query idempotency key
        val threadCount = 8
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threadCount)
        val command = createQueryCommand(idempotencyKey = "idemp-concurrent-query-001")

        val futures = (1..threadCount).map {
            pool.submit<SupportTimelineResult> {
                gate.await()
                service.queryTimeline(command)
            }
        }
        gate.countDown()

        val results = futures.map { runCatching { it.get() } }
        assertEquals(threadCount, results.count { it.isSuccess })

        val distinctResultIds = results.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // 2. Dependency failure on session directory fails closed
        val failingSessionService = SupportTimelineIntegrationService(
            policy = AdminRbacPolicy(true),
            sessions = TestSupportTimelineFailingSessionDirectory(),
            store = store,
            ledgerResolver = ledgerResolver,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.queryTimeline(
                createQueryCommand(
                    playerReference = "player-dep-fail-sess",
                    idempotencyKey = "idemp-dep-fail-sess",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Dependency failure on ledger resolver fails closed
        val failingLedgerResolver = FakeLedgerReferenceResolver(shouldFail = true)
        val failingLedgerService = createService(store, failingLedgerResolver)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingLedgerService.ingestTimelineEvent(
                createIngestCommand(
                    authoritativeLedgerPointer = "LEDGER-ANY",
                    idempotencyKey = "idemp-dep-fail-ledger",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    // =========================================================================
    // CRM-003-T004: Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `CRM-003-T004 Support timeline integration remains compatible recoverable observable and lifecycle safe`() {
        SupportTimelineIntegrationBinding.isBound = true

        // 1. Migration hygiene: Ensure no unapproved migrations
        val migrationDir = File("src/main/resources/db/migration")
        if (migrationDir.exists()) {
            val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
            val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
            assertFalse(migrationVersions.contains("V17"), "Unapproved migration V17 must not exist")
        }

        // 2. Recovery / restart simulation
        val sharedStore = InMemorySupportTimelineStore()
        val ledgerResolver = FakeLedgerReferenceResolver()
        val serviceBefore = createService(sharedStore, ledgerResolver)

        val command = createQueryCommand(
            playerReference = "player-reboot-001",
            accessReason = AccessReasonCode.AUDIT_REVIEW,
            idempotencyKey = "idemp-reboot-tl-001",
            correlationId = "corr-reboot-tl-001",
            causationId = "caus-reboot-tl-001",
        )

        val beforeResult = serviceBefore.queryTimeline(command)

        val serviceAfter = createService(sharedStore, ledgerResolver)
        val afterResult = serviceAfter.queryTimeline(command)

        assertEquals(beforeResult.resultId, afterResult.resultId)
        assertEquals(beforeResult.evidenceReference, afterResult.evidenceReference)
        assertEquals(beforeResult.version, afterResult.version)
        assertFalse(afterResult.hasDuplicateFinancialAuthority)
        assertTrue(afterResult.balanceSourceIsAuthoritativeLedgerOnly)
        assertFalse(afterResult.moneyMutated)

        // 3. Observability and audit
        val auditEvent = sharedStore.audit.first { it.resultId == beforeResult.resultId }
        assertEquals("SUPPORT_TIMELINE_QUERIED_AUDIT_REVIEW", auditEvent.type)
        assertEquals("corr-reboot-tl-001", auditEvent.correlationId)
        assertEquals("caus-reboot-tl-001", auditEvent.causationId)
        assertFalse(auditEvent.type.contains("secret", ignoreCase = true))

        val outboxEvent = sharedStore.outbox.first { it.resultId == beforeResult.resultId }
        assertEquals("SUPPORT_TIMELINE_QUERIED_AUDIT_REVIEW", outboxEvent.type)
        assertFalse(outboxEvent.type.contains("secret", ignoreCase = true))
    }

    // =========================================================================
    // Helpers and Test Doubles
    // =========================================================================
    private fun createService(
        store: SupportTimelineStore,
        ledgerResolver: AuthoritativeLedgerReferenceResolver = FakeLedgerReferenceResolver(),
    ) = SupportTimelineIntegrationService(
        policy = AdminRbacPolicy(true),
        sessions = TestSupportTimelineActiveSessionDirectory(),
        store = store,
        ledgerResolver = ledgerResolver,
        clock = clock,
    )

    private fun createIngestCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal(),
        sessionId: String = "session-tl-1",
        tenantId: String = "tenant-1",
        playerReference: String = "player-default-001",
        eventType: TimelineEventType = TimelineEventType.SUPPORT_NOTE,
        summary: String = "Default timeline summary",
        details: Map<String, String> = emptyMap(),
        authoritativeLedgerPointer: String? = null,
        idempotencyKey: String = "idemp-ingest-default",
        correlationId: String = "corr-ingest-default",
        causationId: String = "caus-ingest-default",
        expectedVersion: Long = 1L,
        requestsFinancialMutation: Boolean = false,
        financialBalanceMinorUnits: Long? = null,
        duplicateFinancialAuthority: Boolean = false,
    ) = IngestSupportTimelineEventCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        playerReference = playerReference,
        eventType = eventType,
        summary = summary,
        details = details,
        authoritativeLedgerPointer = authoritativeLedgerPointer,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
        requestsFinancialMutation = requestsFinancialMutation,
        financialBalanceMinorUnits = financialBalanceMinorUnits,
        duplicateFinancialAuthority = duplicateFinancialAuthority,
    )

    private fun createQueryCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal(),
        sessionId: String = "session-tl-1",
        tenantId: String = "tenant-1",
        playerReference: String = "player-default-001",
        accessReason: AccessReasonCode = AccessReasonCode.SUPPORT_REQUEST,
        idempotencyKey: String = "idemp-query-default",
        correlationId: String = "corr-query-default",
        causationId: String = "caus-query-default",
        expectedVersion: Long = 1L,
        limit: Int = 50,
    ) = QuerySupportTimelineCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        playerReference = playerReference,
        accessReason = accessReason,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
        limit = limit,
    )

    private fun adminPrincipal(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-supp-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
}

private class TestSupportTimelineActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-tl-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-18T23:00:00Z"))
        else null
}

private class TestSupportTimelineExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-18T21:00:00Z"))
}

private class TestSupportTimelineFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("Session directory unreachable")
}

private class FakeLedgerReferenceResolver(
    val shouldFail: Boolean = false,
) : AuthoritativeLedgerReferenceResolver {
    private val validPointers = mutableSetOf<String>()

    fun registerPointer(tenantId: String, pointer: String) {
        validPointers.add("$tenantId:$pointer")
    }

    override fun verifyPointer(tenantId: String, pointer: String): Boolean {
        if (shouldFail) throw RuntimeException("Ledger reader unavailable")
        return validPointers.contains("$tenantId:$pointer")
    }
}

private class InMemorySupportTimelineStore : SupportTimelineStore {
    private val eventsByPlayer = mutableMapOf<String, MutableList<RedactedTimelineItem>>()
    private val resultsByIdempotency = mutableMapOf<String, Pair<String, SupportTimelineResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun recordEvent(tenantId: String, playerReference: String, item: RedactedTimelineItem) {
        synchronized(this) {
            eventsByPlayer.computeIfAbsent("$tenantId:$playerReference") { mutableListOf() }.add(item)
        }
    }

    override fun queryEvents(tenantId: String, playerReference: String, limit: Int): List<RedactedTimelineItem> {
        return synchronized(this) {
            eventsByPlayer["$tenantId:$playerReference"]?.take(limit) ?: emptyList()
        }
    }

    override fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, SupportTimelineResult>? {
        return synchronized(this) {
            resultsByIdempotency["$tenantId:$idempotencyKey"]
        }
    }

    override fun saveQueryResult(
        result: SupportTimelineResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        synchronized(this) {
            resultsByIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
            this.audit += audit
            this.outbox += outbox
        }
    }
}
