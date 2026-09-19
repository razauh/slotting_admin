package com.slotting.admin.crm

import com.slotting.admin.auth.*
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

class ExternalCrmContractTest {
    private val now = Instant.parse("2026-09-18T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Enforce fail-closed gate before each test run
        ExternalCrmContractBinding.isBound = false
    }

    @AfterEach
    fun tearDown() {
        // Restore bound state to prevent cross-test contamination
        ExternalCrmContractBinding.isBound = true
    }

    // =========================================================================
    // CRM-001-T001: Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `CRM-001-T001 External CRM contract events produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        assertFailsWith<AssertionError> {
            ExternalCrmContractBinding.checkBound()
        }.also {
            assertEquals("CRM can mutate authority/receives excess PII", it.message)
        }

        val store = InMemoryExternalCrmStore()
        val crmPort = FakeExternalCrmPort()
        val service = createService(store, crmPort)

        // 2. Dispatch canonical PLAYER_REGISTERED lifecycle event with minimized payload
        val registerCmd = createCommand(
            eventType = ExternalCrmEventType.PLAYER_REGISTERED,
            payload = ExternalCrmEventPayload(
                externalCrmId = "CRM-PLAYER-1001",
                playerReference = "usr-reg-001",
                maskedEmail = "u***@example.com",
                locale = "en-US",
                countryCode = "US",
                tier = "STANDARD",
                marketingConsent = true,
                attributes = mapOf("acquisitionSource" to "ORGANIC_SEARCH"),
            ),
            idempotencyKey = "idemp-crm-reg-001",
            correlationId = "corr-crm-001",
            causationId = "caus-crm-001",
        )

        // Verify service invocation fails closed with protected risk assertion when unbound
        ExternalCrmContractBinding.isBound = false
        assertFailsWith<AssertionError> {
            service.publishCrmEvent(registerCmd)
        }.also {
            assertEquals("CRM can mutate authority/receives excess PII", it.message)
        }

        ExternalCrmContractBinding.isBound = true

        val regResult = service.publishCrmEvent(registerCmd)

        // Assert: Invariants and outcome
        assertEquals(ExternalCrmEventStatus.DISPATCHED, regResult.status)
        assertEquals("usr-reg-001", regResult.playerReference)
        assertEquals("CRM-PLAYER-1001", regResult.externalCrmId)
        assertEquals(ExternalCrmEventType.PLAYER_REGISTERED, regResult.eventType)
        assertTrue(regResult.financialRecordInLedgerOnly, "Financial record must stay in ledger")
        assertFalse(regResult.moneyMutated, "CRM event publication must never mutate money")
        assertFalse(regResult.suppressionPropagated)
        assertFalse(regResult.deletionPropagated)
        assertEquals(1L, regResult.version)
        assertEquals("ACK-CRM-PLAYER-1001", regResult.externalAckToken)
        assertTrue(regResult.evidenceReference.startsWith("EVID-CRM-EVT-tenant-1-usr-reg-001-PLAYER_REGISTERED"))
        assertEquals(now, regResult.serverTime)

        // 3. Replay with identical idempotency key returns identical result
        val replayResult = service.publishCrmEvent(registerCmd)
        assertEquals(regResult.resultId, replayResult.resultId)
        assertEquals(regResult.evidenceReference, replayResult.evidenceReference)
        assertEquals(regResult.serverTime, replayResult.serverTime)

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        val audit = store.audit[0]
        assertEquals("CRM_EXTERNAL_EVENT_PLAYER_REGISTERED", audit.type)
        assertEquals("corr-crm-001", audit.correlationId)
        assertEquals("caus-crm-001", audit.causationId)

        // 4. Dispatch MARKETING_SUPPRESSED (e.g. self-exclusion / marketing opt-out)
        val suppressCmd = createCommand(
            eventType = ExternalCrmEventType.MARKETING_SUPPRESSED,
            payload = ExternalCrmEventPayload(
                externalCrmId = "CRM-PLAYER-1001",
                playerReference = "usr-reg-001",
                maskedEmail = "u***@example.com",
                suppressionReason = "SELF_EXCLUSION_REQUESTED",
            ),
            idempotencyKey = "idemp-crm-sup-001",
            correlationId = "corr-crm-002",
            causationId = "caus-crm-002",
        )

        val suppressResult = service.publishCrmEvent(suppressCmd)
        assertEquals(ExternalCrmEventStatus.SUPPRESSED_CONFIRMED, suppressResult.status)
        assertTrue(suppressResult.suppressionPropagated, "Suppression must be propagated to external CRM")
        assertFalse(suppressResult.deletionPropagated)
        assertTrue(suppressResult.financialRecordInLedgerOnly)
        assertFalse(suppressResult.moneyMutated)
        assertTrue(crmPort.suppressedPlayers.contains("usr-reg-001"))

        // 5. Dispatch ACCOUNT_DELETED (GDPR right-to-be-forgotten / erasure)
        val deleteCmd = createCommand(
            eventType = ExternalCrmEventType.ACCOUNT_DELETED,
            payload = ExternalCrmEventPayload(
                externalCrmId = "CRM-PLAYER-1001",
                playerReference = "usr-reg-001",
                maskedEmail = "u***@example.com",
            ),
            idempotencyKey = "idemp-crm-del-001",
            correlationId = "corr-crm-003",
            causationId = "caus-crm-003",
        )

        val deleteResult = service.publishCrmEvent(deleteCmd)
        assertEquals(ExternalCrmEventStatus.DELETED_CONFIRMED, deleteResult.status)
        assertFalse(deleteResult.suppressionPropagated)
        assertTrue(deleteResult.deletionPropagated, "Deletion must be propagated to external CRM")
        assertTrue(deleteResult.financialRecordInLedgerOnly)
        assertFalse(deleteResult.moneyMutated)
        assertTrue(crmPort.deletedPlayers.contains("usr-reg-001"))
    }

    // =========================================================================
    // CRM-001-T002: Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `CRM-001-T002 External CRM contract events rejects invalid boundary unauthorized and stale input`() {
        ExternalCrmContractBinding.isBound = true

        val store = InMemoryExternalCrmStore()
        val crmPort = FakeExternalCrmPort()
        val service = createService(store, crmPort)

        // 1. CRM changes money attempt 1: attemptsFinancialMutation flag
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    attemptsFinancialMutation = true,
                    idempotencyKey = "idemp-fail-fin-mut",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. CRM changes money attempt 2: non-zero financial balance attached
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    financialBalanceMinorUnits = 50000L,
                    idempotencyKey = "idemp-fail-balance",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. CRM changes money attempt 3: payload attributes contain financial fields
        val financialAttributeKeys = listOf(
            "walletId",
            "accountBalance",
            "creditAdjustment",
            "bankAccountNumber",
            "cardPan",
            "wagerAmount",
            "ledgerReference",
        )
        for (finKey in financialAttributeKeys) {
            assertFailsWith<AuthenticationFailure.Rejected> {
                service.publishCrmEvent(
                    createCommand(
                        payload = ExternalCrmEventPayload(
                            externalCrmId = "CRM-EXT-1",
                            playerReference = "usr-1",
                            attributes = mapOf(finKey to "1000"),
                        ),
                        idempotencyKey = "idemp-fail-fin-attr-$finKey",
                    )
                )
            }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        }

        // 4. Excess PII / raw secrets in payload attributes
        val piiAttributeKeys = listOf(
            "ssn",
            "socialSecurityNumber",
            "passportNumber",
            "nationalId",
            "rawPassword",
            "apiSecret",
            "privateKey",
        )
        for (piiKey in piiAttributeKeys) {
            assertFailsWith<AuthenticationFailure.Rejected> {
                service.publishCrmEvent(
                    createCommand(
                        payload = ExternalCrmEventPayload(
                            externalCrmId = "CRM-EXT-1",
                            playerReference = "usr-1",
                            attributes = mapOf(piiKey to "unredacted-secret-value"),
                        ),
                        idempotencyKey = "idemp-fail-pii-$piiKey",
                    )
                )
            }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        }

        // 5. Unmasked raw email (contains @ but missing *)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    payload = ExternalCrmEventPayload(
                        externalCrmId = "CRM-EXT-1",
                        playerReference = "usr-1",
                        maskedEmail = "john.doe@example.com", // Plain raw email not masked!
                    ),
                    idempotencyKey = "idemp-fail-unmasked-email",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Unauthenticated principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    principal = null,
                    idempotencyKey = "idemp-fail-unauth",
                )
            )
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 7. Non-admin player principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    principal = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet()),
                    idempotencyKey = "idemp-fail-player",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Cross-tenant principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    principal = AuthenticatedPrincipal("admin-cross", "other-tenant", PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN)),
                    idempotencyKey = "idemp-fail-cross-tenant",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 9. Expired session
        val expiredSessionService = ExternalCrmContractService(
            policy = AdminRbacPolicy(true),
            sessions = TestExternalCrmExpiredSessionDirectory(),
            crmPort = crmPort,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.publishCrmEvent(createCommand(idempotencyKey = "idemp-fail-expired"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 10. Blank required fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    payload = ExternalCrmEventPayload(externalCrmId = "CRM-1", playerReference = "   "),
                    idempotencyKey = "idemp-fail-blank-player",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    payload = ExternalCrmEventPayload(externalCrmId = "   ", playerReference = "usr-1"),
                    idempotencyKey = "idemp-fail-blank-crmid",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    sessionId = "  ",
                    idempotencyKey = "idemp-fail-blank-session",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 11. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    expectedVersion = 3L,
                    idempotencyKey = "idemp-fail-stale-ver",
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 12. Conflicting replay with differing payload under identical idempotency key
        service.publishCrmEvent(createCommand(idempotencyKey = "idemp-conflict-base"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.publishCrmEvent(
                createCommand(
                    payload = ExternalCrmEventPayload(
                        externalCrmId = "DIFFERENT-CRM-ID",
                        playerReference = "usr-1",
                    ),
                    idempotencyKey = "idemp-conflict-base",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // CRM-001-T003: Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `CRM-001-T003 External CRM contract events survives concurrency duplicate delivery and dependency failure`() {
        ExternalCrmContractBinding.isBound = true

        val store = InMemoryExternalCrmStore()
        val crmPort = FakeExternalCrmPort()
        val service = createService(store, crmPort)

        // 1. Concurrency: 8 threads race with the exact same idempotency key concurrently
        val threadCount = 8
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threadCount)
        val command = createCommand(idempotencyKey = "idemp-concurrent-crm-001")

        val futures = (1..threadCount).map {
            pool.submit<ExternalCrmEventResult> {
                gate.await()
                service.publishCrmEvent(command)
            }
        }
        gate.countDown()

        val results = futures.map { runCatching { it.get() } }
        assertEquals(threadCount, results.count { it.isSuccess })

        // Invariant: Exactly one canonical result produced and reused
        val distinctResultIds = results.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)
        val distinctAckTokens = results.mapNotNull { it.getOrNull()?.externalAckToken }.toSet()
        assertEquals(1, distinctAckTokens.size)

        // Invariant: Exactly 1 audit record and 1 outbox entry persisted
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // 2. Dependency failure on CRM port fails closed
        val failingPort = FakeExternalCrmPort(shouldFail = true)
        val serviceWithFailingPort = createService(store, failingPort)
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithFailingPort.publishCrmEvent(createCommand(idempotencyKey = "idemp-dep-fail-crm"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Dependency failure on session directory fails closed
        val failingSessionService = ExternalCrmContractService(
            policy = AdminRbacPolicy(true),
            sessions = TestExternalCrmFailingSessionDirectory(),
            crmPort = crmPort,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.publishCrmEvent(createCommand(idempotencyKey = "idemp-dep-fail-session"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    // =========================================================================
    // CRM-001-T004: Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `CRM-001-T004 External CRM contract events remains compatible recoverable observable and lifecycle safe`() {
        ExternalCrmContractBinding.isBound = true

        // 1. Flyway migration guardrail: Ensure no unapproved migrations
        val migrationDir = File("src/main/resources/db/migration")
        if (migrationDir.exists()) {
            val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
            val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
            assertFalse(migrationVersions.contains("V17"), "Unapproved migration V17 must not exist")
        }

        // 2. Recovery / restart simulation: persistent store retains events across reboots
        val sharedStore = InMemoryExternalCrmStore()
        val crmPort = FakeExternalCrmPort()
        val serviceBeforeReboot = createService(sharedStore, crmPort)

        val command = createCommand(
            eventType = ExternalCrmEventType.PLAYER_TIER_UPDATED,
            payload = ExternalCrmEventPayload(
                externalCrmId = "CRM-TIER-009",
                playerReference = "usr-vip-999",
                maskedEmail = "v***@example.com",
                tier = "VIP_GOLD",
            ),
            idempotencyKey = "idemp-reboot-tier-001",
            correlationId = "corr-reboot-001",
            causationId = "caus-reboot-001",
        )

        val beforeResult = serviceBeforeReboot.publishCrmEvent(command)
        assertEquals(ExternalCrmEventStatus.DISPATCHED, beforeResult.status)

        // Instantiate brand new service representing post-restart system
        val serviceAfterReboot = createService(sharedStore, crmPort)
        val afterResult = serviceAfterReboot.publishCrmEvent(command)

        assertEquals(beforeResult.resultId, afterResult.resultId)
        assertEquals(beforeResult.evidenceReference, afterResult.evidenceReference)
        assertEquals(beforeResult.serverTime, afterResult.serverTime)
        assertTrue(afterResult.financialRecordInLedgerOnly)
        assertFalse(afterResult.moneyMutated)

        // 3. Observability and secret redaction
        val auditEvent = sharedStore.audit.first { it.resultId == beforeResult.resultId }
        assertEquals("CRM_EXTERNAL_EVENT_PLAYER_TIER_UPDATED", auditEvent.type)
        assertEquals("corr-reboot-001", auditEvent.correlationId)
        assertEquals("caus-reboot-001", auditEvent.causationId)
        assertFalse(auditEvent.type.contains("secret", ignoreCase = true))

        val outboxEvent = sharedStore.outbox.first { it.resultId == beforeResult.resultId }
        assertEquals("CRM_EXTERNAL_EVENT_PLAYER_TIER_UPDATED", outboxEvent.type)
        assertFalse(outboxEvent.type.contains("secret", ignoreCase = true))
    }

    // =========================================================================
    // Test Helpers and Test Doubles
    // =========================================================================
    private fun createService(
        store: ExternalCrmEventStore,
        crmPort: ExternalCrmPort = FakeExternalCrmPort(),
    ) = ExternalCrmContractService(
        policy = AdminRbacPolicy(true),
        sessions = TestExternalCrmActiveSessionDirectory(),
        crmPort = crmPort,
        store = store,
        clock = clock,
    )

    private fun createCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal(),
        sessionId: String = "session-crm-1",
        tenantId: String = "tenant-1",
        eventType: ExternalCrmEventType = ExternalCrmEventType.PLAYER_REGISTERED,
        payload: ExternalCrmEventPayload = ExternalCrmEventPayload(
            externalCrmId = "CRM-EXT-1",
            playerReference = "usr-1",
            maskedEmail = "u***@example.com",
            locale = "en-US",
            countryCode = "US",
            tier = "STANDARD",
        ),
        idempotencyKey: String = "idemp-crm-cmd-1",
        correlationId: String = "corr-crm-default",
        causationId: String = "caus-crm-default",
        expectedVersion: Long = 1L,
        financialBalanceMinorUnits: Long? = null,
        attemptsFinancialMutation: Boolean = false,
    ) = PublishExternalCrmEventCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        eventType = eventType,
        payload = payload,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
        financialBalanceMinorUnits = financialBalanceMinorUnits,
        attemptsFinancialMutation = attemptsFinancialMutation,
    )

    private fun adminPrincipal(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-crm-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
}

private class TestExternalCrmActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-crm-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-18T19:00:00Z"))
        else null
}

private class TestExternalCrmExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-18T17:00:00Z"))
}

private class TestExternalCrmFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("Session store network failure")
}

private class FakeExternalCrmPort(
    val shouldFail: Boolean = false,
) : ExternalCrmPort {
    val suppressedPlayers = mutableSetOf<String>()
    val deletedPlayers = mutableSetOf<String>()

    override fun dispatchEvent(
        tenantId: String,
        eventType: ExternalCrmEventType,
        payload: ExternalCrmEventPayload,
    ): ExternalCrmDispatchResult {
        if (shouldFail) throw RuntimeException("CRM API connection refused")
        return ExternalCrmDispatchResult(
            success = true,
            ackToken = "ACK-${payload.externalCrmId}",
            dispatchedAt = Instant.now(),
        )
    }

    override fun propagateSuppression(
        tenantId: String,
        playerReference: String,
        externalCrmId: String,
        reason: String,
    ): ExternalCrmDispatchResult {
        if (shouldFail) throw RuntimeException("CRM suppression endpoint unreachable")
        suppressedPlayers.add(playerReference)
        return ExternalCrmDispatchResult(
            success = true,
            ackToken = "ACK-SUPPRESS-$externalCrmId",
            dispatchedAt = Instant.now(),
        )
    }

    override fun propagateDeletion(
        tenantId: String,
        playerReference: String,
        externalCrmId: String,
    ): ExternalCrmDispatchResult {
        if (shouldFail) throw RuntimeException("CRM deletion endpoint unreachable")
        deletedPlayers.add(playerReference)
        return ExternalCrmDispatchResult(
            success = true,
            ackToken = "ACK-DELETE-$externalCrmId",
            dispatchedAt = Instant.now(),
        )
    }
}

private class InMemoryExternalCrmStore : ExternalCrmEventStore {
    val results = mutableMapOf<String, Pair<String, ExternalCrmEventResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: ExternalCrmEventResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = fingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
