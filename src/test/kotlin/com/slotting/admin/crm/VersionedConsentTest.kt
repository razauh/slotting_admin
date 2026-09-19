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

class VersionedConsentTest {
    private val now = Instant.parse("2026-09-18T19:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Enforce fail-closed gate before each test run
        VersionedConsentBinding.isBound = false
    }

    @AfterEach
    fun tearDown() {
        // Restore bound state
        VersionedConsentBinding.isBound = true
    }

    // =========================================================================
    // CRM-002-01-T001: Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `CRM-002-01-T001 Record versioned communication consent produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        assertFailsWith<AssertionError> {
            VersionedConsentBinding.checkBound()
        }.also {
            assertEquals("marketing without consent/self-excluded promo", it.message)
        }

        val store = InMemoryVersionedConsentStore()
        val exclusionDir = FakePlayerExclusionDirectory()
        val service = createService(store, exclusionDir)

        val cmd1 = createCommand(
            playerId = "usr-consent-001",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            state = ConsentState.CONSENTED,
            policyVersion = "2026.1",
            vipTier = VipTier.NONE,
            expectedVersion = 1L,
            idempotencyKey = "idemp-consent-001",
            correlationId = "corr-consent-001",
            causationId = "caus-consent-001",
        )

        // Verify service invocation fails closed with protected risk assertion when unbound
        VersionedConsentBinding.isBound = false
        assertFailsWith<AssertionError> {
            service.recordConsent(cmd1)
        }.also {
            assertEquals("marketing without consent/self-excluded promo", it.message)
        }

        VersionedConsentBinding.isBound = true

        // 2. Authoritative consent recording (Version 1)
        val res1 = service.recordConsent(cmd1)
        assertEquals(ConsentState.CONSENTED, res1.state)
        assertEquals("usr-consent-001", res1.playerId)
        assertEquals(ConsentChannel.EMAIL, res1.channel)
        assertEquals(ConsentPurpose.MARKETING_PROMOTIONS, res1.purpose)
        assertEquals("2026.1", res1.policyVersion)
        assertEquals(VipTier.NONE, res1.vipTier)
        assertFalse(res1.vipGrantsFinancialPrivilege, "VIP tag grants no financial privilege")
        assertFalse(res1.vipGrantsAdminPrivilege, "VIP tag grants no admin privilege")
        assertFalse(res1.moneyMutated, "Consent recording must never mutate money")
        assertFalse(res1.financialAuthorityCreated)
        assertEquals(1L, res1.version)
        assertEquals(now, res1.updatedAt)
        assertTrue(res1.evidenceReference.startsWith("EVID-CONSENT-tenant-1-usr-consent-001-EMAIL-MARKETING_PROMOTIONS-v1"))

        // Replay returns identical record
        val replay = service.recordConsent(cmd1)
        assertEquals(res1.recordId, replay.recordId)
        assertEquals(res1.evidenceReference, replay.evidenceReference)

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("COMMUNICATION_CONSENT_CONSENTED", store.audit[0].type)
        assertEquals("corr-consent-001", store.audit[0].correlationId)
        assertEquals("caus-consent-001", store.audit[0].causationId)

        // 3. Admin updates consent with VIP tag (VIP_GOLD) (Version 2)
        val cmd2 = createCommand(
            playerId = "usr-consent-001",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            state = ConsentState.CONSENTED,
            policyVersion = "2026.1",
            vipTier = VipTier.VIP_GOLD,
            expectedVersion = 2L,
            idempotencyKey = "idemp-consent-002",
            correlationId = "corr-consent-002",
            causationId = "caus-consent-002",
        )
        val res2 = service.recordConsent(cmd2)
        assertEquals(2L, res2.version)
        assertEquals(VipTier.VIP_GOLD, res2.vipTier)
        assertFalse(res2.vipGrantsFinancialPrivilege, "VIP tag grants no financial privilege")
        assertFalse(res2.vipGrantsAdminPrivilege, "VIP tag grants no admin privilege")
        assertFalse(res2.moneyMutated)

        // 4. Player self-service consent withdrawal (Version 3)
        val cmd3 = createCommand(
            principal = playerPrincipal("usr-consent-001"),
            playerId = "usr-consent-001",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            state = ConsentState.WITHDRAWN,
            policyVersion = "2026.1",
            vipTier = VipTier.NONE,
            expectedVersion = 3L,
            idempotencyKey = "idemp-consent-003",
            correlationId = "corr-consent-003",
            causationId = "caus-consent-003",
        )
        val res3 = service.recordConsent(cmd3)
        assertEquals(3L, res3.version)
        assertEquals(ConsentState.WITHDRAWN, res3.state)
        assertEquals(VipTier.VIP_GOLD, res3.vipTier, "Player maintains authoritative VIP tier but withdraws consent")
        assertFalse(res3.vipGrantsFinancialPrivilege)
        assertFalse(res3.vipGrantsAdminPrivilege)
        assertFalse(res3.moneyMutated)
    }

    // =========================================================================
    // CRM-002-01-T002: Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `CRM-002-01-T002 Record versioned communication consent rejects invalid boundary unauthorized and stale input`() {
        VersionedConsentBinding.isBound = true

        val store = InMemoryVersionedConsentStore()
        val exclusionDir = FakePlayerExclusionDirectory()
        val service = createService(store, exclusionDir)

        // 1. Marketing without consent / Self-excluded promo prevention
        exclusionDir.exclude("tenant-1", "usr-self-excluded-99")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    playerId = "usr-self-excluded-99",
                    purpose = ConsentPurpose.MARKETING_PROMOTIONS,
                    state = ConsentState.CONSENTED,
                    idempotencyKey = "idemp-fail-self-excluded-marketing",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    playerId = "usr-self-excluded-99",
                    purpose = ConsentPurpose.NEWSLETTER,
                    state = ConsentState.CONSENTED,
                    idempotencyKey = "idemp-fail-self-excluded-newsletter",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. VIP tag attempting to grant financial or admin privilege
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    requestsFinancialPrivilege = true,
                    idempotencyKey = "idemp-fail-fin-priv",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    requestsAdminPrivilege = true,
                    idempotencyKey = "idemp-fail-admin-priv",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    financialBalanceAdjustmentMinorUnits = 10000L,
                    idempotencyKey = "idemp-fail-balance-mut",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Player trying to self-assign VIP tier
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    principal = playerPrincipal("usr-regular-1"),
                    playerId = "usr-regular-1",
                    vipTier = VipTier.VIP_PLATINUM, // Player cannot grant self VIP status
                    idempotencyKey = "idemp-fail-player-self-vip",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    principal = null,
                    idempotencyKey = "idemp-fail-unauth",
                )
            )
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 5. Cross-tenant principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    principal = adminPrincipal("tenant-2"),
                    tenantId = "tenant-1",
                    idempotencyKey = "idemp-fail-cross-tenant",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Player attempting to alter another player's consent (IDOR)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(
                createCommand(
                    principal = playerPrincipal("usr-alice"),
                    playerId = "usr-bob",
                    idempotencyKey = "idemp-fail-idor",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Expired session for admin
        val expiredSessionService = VersionedConsentService(
            policy = AdminRbacPolicy(true),
            sessions = TestConsentExpiredSessionDirectory(),
            exclusionDirectory = exclusionDir,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.recordConsent(createCommand(idempotencyKey = "idemp-fail-expired"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Blank required fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(createCommand(playerId = "   ", idempotencyKey = "idemp-fail-blank-player"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(createCommand(policyVersion = "   ", idempotencyKey = "idemp-fail-blank-policy"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(createCommand(sessionId = "   ", idempotencyKey = "idemp-fail-blank-session"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(createCommand(correlationId = "   ", idempotencyKey = "idemp-fail-blank-corr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(createCommand(causationId = "   ", idempotencyKey = "idemp-fail-blank-caus"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 9. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(createCommand(expectedVersion = 5L, idempotencyKey = "idemp-fail-stale-version"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 10. Conflicting replay with different state under same idempotency key
        service.recordConsent(createCommand(idempotencyKey = "idemp-conflict-base", state = ConsentState.CONSENTED))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.recordConsent(createCommand(idempotencyKey = "idemp-conflict-base", state = ConsentState.WITHDRAWN))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // CRM-002-01-T003: Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `CRM-002-01-T003 Record versioned communication consent survives concurrency duplicate delivery and dependency failure`() {
        VersionedConsentBinding.isBound = true

        val store = InMemoryVersionedConsentStore()
        val exclusionDir = FakePlayerExclusionDirectory()
        val service = createService(store, exclusionDir)

        // 1. Concurrency: 8 threads race to submit identical consent update with same idempotency key
        val threadCount = 8
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threadCount)
        val command = createCommand(idempotencyKey = "idemp-concurrent-consent-001")

        val futures = (1..threadCount).map {
            pool.submit<VersionedConsentRecord> {
                gate.await()
                service.recordConsent(command)
            }
        }
        gate.countDown()

        val results = futures.map { runCatching { it.get() } }
        assertEquals(threadCount, results.count { it.isSuccess })

        val distinctRecordIds = results.mapNotNull { it.getOrNull()?.recordId }.toSet()
        assertEquals(1, distinctRecordIds.size)

        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // 2. Dependency failure on session directory fails closed
        val failingSessionService = VersionedConsentService(
            policy = AdminRbacPolicy(true),
            sessions = TestConsentFailingSessionDirectory(),
            exclusionDirectory = exclusionDir,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.recordConsent(
                createCommand(
                    playerId = "usr-dep-fail-sess",
                    idempotencyKey = "idemp-dep-fail-sess",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Dependency failure on exclusion directory fails closed
        val failingExclusionDir = FakePlayerExclusionDirectory(shouldFail = true)
        val failingExclusionService = createService(store, failingExclusionDir)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingExclusionService.recordConsent(
                createCommand(
                    playerId = "usr-dep-fail-excl",
                    idempotencyKey = "idemp-dep-fail-excl",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    // =========================================================================
    // CRM-002-01-T004: Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `CRM-002-01-T004 Record versioned communication consent remains compatible recoverable observable and lifecycle safe`() {
        VersionedConsentBinding.isBound = true

        // 1. Migration hygiene: Ensure no unapproved migrations
        val migrationDir = File("src/main/resources/db/migration")
        if (migrationDir.exists()) {
            val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
            val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
            assertFalse(migrationVersions.contains("V17"), "Unapproved migration V17 must not exist")
        }

        // 2. Recovery / restart simulation
        val sharedStore = InMemoryVersionedConsentStore()
        val exclusionDir = FakePlayerExclusionDirectory()
        val serviceBefore = createService(sharedStore, exclusionDir)

        val command = createCommand(
            playerId = "usr-reboot-001",
            channel = ConsentChannel.SMS,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            state = ConsentState.CONSENTED,
            policyVersion = "2026.2",
            idempotencyKey = "idemp-reboot-consent-001",
            correlationId = "corr-reboot-001",
            causationId = "caus-reboot-001",
        )

        val beforeResult = serviceBefore.recordConsent(command)

        val serviceAfter = createService(sharedStore, exclusionDir)
        val afterResult = serviceAfter.recordConsent(command)

        assertEquals(beforeResult.recordId, afterResult.recordId)
        assertEquals(beforeResult.evidenceReference, afterResult.evidenceReference)
        assertEquals(beforeResult.version, afterResult.version)
        assertFalse(afterResult.vipGrantsFinancialPrivilege)
        assertFalse(afterResult.vipGrantsAdminPrivilege)
        assertFalse(afterResult.moneyMutated)

        // 3. Observability and audit
        val auditEvent = sharedStore.audit.first { it.resultId == beforeResult.recordId }
        assertEquals("COMMUNICATION_CONSENT_CONSENTED", auditEvent.type)
        assertEquals("corr-reboot-001", auditEvent.correlationId)
        assertEquals("caus-reboot-001", auditEvent.causationId)
        assertFalse(auditEvent.type.contains("secret", ignoreCase = true))

        val outboxEvent = sharedStore.outbox.first { it.resultId == beforeResult.recordId }
        assertEquals("COMMUNICATION_CONSENT_CONSENTED", outboxEvent.type)
        assertFalse(outboxEvent.type.contains("secret", ignoreCase = true))
    }

    // =========================================================================
    // Helpers and Test Doubles
    // =========================================================================
    private fun createService(
        store: VersionedConsentStore,
        exclusionDir: PlayerExclusionDirectory = FakePlayerExclusionDirectory(),
    ) = VersionedConsentService(
        policy = AdminRbacPolicy(true),
        sessions = TestConsentActiveSessionDirectory(),
        exclusionDirectory = exclusionDir,
        store = store,
        clock = clock,
    )

    private fun createCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal(),
        sessionId: String = "session-consent-1",
        tenantId: String = "tenant-1",
        playerId: String = "usr-consent-default",
        channel: ConsentChannel = ConsentChannel.EMAIL,
        purpose: ConsentPurpose = ConsentPurpose.MARKETING_PROMOTIONS,
        state: ConsentState = ConsentState.CONSENTED,
        policyVersion: String = "2026.1",
        vipTier: VipTier = VipTier.NONE,
        idempotencyKey: String = "idemp-consent-cmd-default",
        correlationId: String = "corr-consent-default",
        causationId: String = "caus-consent-default",
        expectedVersion: Long = 1L,
        requestsAdminPrivilege: Boolean = false,
        requestsFinancialPrivilege: Boolean = false,
        financialBalanceAdjustmentMinorUnits: Long? = null,
    ) = RecordVersionedConsentCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        playerId = playerId,
        channel = channel,
        purpose = purpose,
        state = state,
        policyVersion = policyVersion,
        vipTier = vipTier,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
        requestsAdminPrivilege = requestsAdminPrivilege,
        requestsFinancialPrivilege = requestsFinancialPrivilege,
        financialBalanceAdjustmentMinorUnits = financialBalanceAdjustmentMinorUnits,
    )

    private fun adminPrincipal(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-consent-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))

    private fun playerPrincipal(playerId: String, tenantId: String = "tenant-1") =
        AuthenticatedPrincipal(playerId, tenantId, PrincipalKind.PLAYER, emptySet())
}

private class TestConsentActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-consent-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-18T20:00:00Z"))
        else null
}

private class TestConsentExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-18T18:00:00Z"))
}

private class TestConsentFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("Session directory unreachable")
}

private class FakePlayerExclusionDirectory(
    val shouldFail: Boolean = false,
) : PlayerExclusionDirectory {
    private val excludedPlayers = mutableSetOf<String>()

    fun exclude(tenantId: String, playerId: String) {
        excludedPlayers.add("$tenantId:$playerId")
    }

    override fun isSelfExcluded(tenantId: String, playerId: String): Boolean {
        if (shouldFail) throw RuntimeException("Exclusion service timeout")
        return excludedPlayers.contains("$tenantId:$playerId")
    }
}

private class InMemoryVersionedConsentStore : VersionedConsentStore {
    private val recordsByKey = mutableMapOf<String, VersionedConsentRecord>()
    private val resultsByIdempotency = mutableMapOf<String, Pair<String, VersionedConsentRecord>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findLatest(
        tenantId: String,
        playerId: String,
        channel: ConsentChannel,
        purpose: ConsentPurpose,
    ): VersionedConsentRecord? = synchronized(this) {
        recordsByKey["$tenantId:$playerId:${channel.name}:${purpose.name}"]
    }

    override fun findByIdempotency(
        tenantId: String,
        idempotencyKey: String,
    ): Pair<String, VersionedConsentRecord>? = synchronized(this) {
        resultsByIdempotency["$tenantId:$idempotencyKey"]
    }

    override fun save(
        record: VersionedConsentRecord,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        recordsByKey["$tenantId:${record.playerId}:${record.channel.name}:${record.purpose.name}"] = record
        resultsByIdempotency["$tenantId:$idempotencyKey"] = fingerprint to record
        this.audit += audit
        this.outbox += outbox
    }
}
