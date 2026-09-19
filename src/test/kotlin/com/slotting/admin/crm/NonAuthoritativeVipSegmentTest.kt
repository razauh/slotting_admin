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

class NonAuthoritativeVipSegmentTest {
    private val now = Instant.parse("2026-09-18T21:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Enforce fail-closed gate before each test run
        NonAuthoritativeVipSegmentBinding.isBound = false
    }

    @AfterEach
    fun tearDown() {
        // Restore bound state
        NonAuthoritativeVipSegmentBinding.isBound = true
    }

    // =========================================================================
    // CRM-002-03-T001: Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `CRM-002-03-T001 Control non-authoritative VIP tags and segments produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        assertFailsWith<AssertionError> {
            NonAuthoritativeVipSegmentBinding.checkBound()
        }.also {
            assertEquals("marketing without consent/self-excluded promo", it.message)
        }

        val store = InMemoryVipSegmentStore()
        val exclusionDir = FakeVipExclusionDirectory()
        val service = createService(store, exclusionDir)

        val cmd1 = createCommand(
            playerId = "usr-vip-001",
            operation = VipSegmentOperation.ASSIGN_VIP_TIER,
            targetVipTier = VipTier.VIP_GOLD,
            justification = "High loyalty turnover",
            expectedVersion = 1L,
            idempotencyKey = "idemp-vip-001",
            correlationId = "corr-vip-001",
            causationId = "caus-vip-001",
        )

        // Verify service invocation fails closed with protected risk assertion when unbound
        NonAuthoritativeVipSegmentBinding.isBound = false
        assertFailsWith<AssertionError> {
            service.controlVipSegment(cmd1)
        }.also {
            assertEquals("marketing without consent/self-excluded promo", it.message)
        }

        NonAuthoritativeVipSegmentBinding.isBound = true

        // 2. Authoritative execution of ASSIGN_VIP_TIER (Version 1)
        val res1 = service.controlVipSegment(cmd1)
        assertEquals(VipTier.VIP_GOLD, res1.vipTier)
        assertEquals("usr-vip-001", res1.playerId)
        assertEquals(VipSegmentOperation.ASSIGN_VIP_TIER, res1.operation)
        assertFalse(res1.isAuthoritative, "VIP tags are strictly non-authoritative CRM metadata")
        assertFalse(res1.vipGrantsFinancialPrivilege, "VIP tag grants no financial privilege")
        assertFalse(res1.vipGrantsAdminPrivilege, "VIP tag grants no admin privilege")
        assertFalse(res1.moneyMutated, "VIP tag control must never mutate money")
        assertFalse(res1.financialAuthorityCreated)
        assertFalse(res1.marketingSuppressedForExclusion)
        assertEquals(1L, res1.version)
        assertEquals(now, res1.serverTime)
        assertTrue(res1.evidenceReference.startsWith("EVID-VIP-SEG-tenant-1-usr-vip-001-ASSIGN_VIP_TIER-v1"))

        // Replay with identical idempotency key returns identical result
        val replay = service.controlVipSegment(cmd1)
        assertEquals(res1.resultId, replay.resultId)
        assertEquals(res1.evidenceReference, replay.evidenceReference)

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("VIP_SEGMENT_ASSIGN_VIP_TIER", store.audit[0].type)
        assertEquals("corr-vip-001", store.audit[0].correlationId)
        assertEquals("caus-vip-001", store.audit[0].causationId)

        // 3. Assigning marketing segments (Version 2)
        val cmd2 = createCommand(
            playerId = "usr-vip-001",
            operation = VipSegmentOperation.ASSIGN_SEGMENTS,
            targetSegments = setOf("HIGH_ROLLER", "LOYALTY_TIER_3"),
            justification = "Quarterly segmentation review",
            expectedVersion = 2L,
            idempotencyKey = "idemp-vip-002",
            correlationId = "corr-vip-002",
            causationId = "caus-vip-002",
        )
        val res2 = service.controlVipSegment(cmd2)
        assertEquals(2L, res2.version)
        assertEquals(VipTier.VIP_GOLD, res2.vipTier)
        assertTrue(res2.segments.contains("HIGH_ROLLER"))
        assertTrue(res2.segments.contains("LOYALTY_TIER_3"))
        assertFalse(res2.vipGrantsFinancialPrivilege)
        assertFalse(res2.vipGrantsAdminPrivilege)
        assertFalse(res2.moneyMutated)

        // 4. Tagging self-excluded player maintains suppression flag
        exclusionDir.exclude("tenant-1", "usr-self-excluded-vip")
        val cmdExcl = createCommand(
            playerId = "usr-self-excluded-vip",
            operation = VipSegmentOperation.ASSIGN_VIP_TIER,
            targetVipTier = VipTier.VIP_PLATINUM,
            justification = "Player account audit tagging",
            expectedVersion = 1L,
            idempotencyKey = "idemp-vip-excl-001",
        )
        val resExcl = service.controlVipSegment(cmdExcl)
        assertEquals(VipTier.VIP_PLATINUM, resExcl.vipTier)
        assertTrue(resExcl.marketingSuppressedForExclusion, "Self-excluded player must maintain marketing suppression")
        assertFalse(resExcl.vipGrantsFinancialPrivilege)
        assertFalse(resExcl.vipGrantsAdminPrivilege)
        assertFalse(resExcl.moneyMutated)
    }

    // =========================================================================
    // CRM-002-03-T002: Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `CRM-002-03-T002 Control non-authoritative VIP tags and segments rejects invalid boundary unauthorized and stale input`() {
        NonAuthoritativeVipSegmentBinding.isBound = true

        val store = InMemoryVipSegmentStore()
        val exclusionDir = FakeVipExclusionDirectory()
        val service = createService(store, exclusionDir)

        // 1. Force marketing eligibility for self-excluded player via VIP tag
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(
                createCommand(
                    forceMarketingEligibilityForSelfExcluded = true,
                    idempotencyKey = "idemp-fail-force-mktg",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. VIP privilege escalation attempts (financial / admin)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(
                createCommand(
                    requestsFinancialPrivilege = true,
                    idempotencyKey = "idemp-fail-fin-priv",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(
                createCommand(
                    requestsAdminPrivilege = true,
                    idempotencyKey = "idemp-fail-admin-priv",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(
                createCommand(
                    financialBalanceAdjustmentMinorUnits = 50000L,
                    idempotencyKey = "idemp-fail-balance-mut",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Prohibited segment names attempting to bypass authority
        val prohibitedSegments = listOf("SUPER_ADMIN", "UNLIMITED_CREDIT", "BALANCE_OVERRIDE", "BYPASS_KYC")
        for (seg in prohibitedSegments) {
            assertFailsWith<AuthenticationFailure.Rejected> {
                service.controlVipSegment(
                    createCommand(
                        targetSegments = setOf(seg),
                        idempotencyKey = "idemp-fail-seg-$seg",
                    )
                )
            }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        }

        // 4. Player principal attempting self-assignment
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(
                createCommand(
                    principal = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet()),
                    idempotencyKey = "idemp-fail-player-principal",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Cross-tenant principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(
                createCommand(
                    principal = adminPrincipal("tenant-2"),
                    tenantId = "tenant-1",
                    idempotencyKey = "idemp-fail-cross-tenant",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(
                createCommand(
                    principal = null,
                    idempotencyKey = "idemp-fail-unauth",
                )
            )
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 7. Expired admin session
        val expiredSessionService = NonAuthoritativeVipSegmentService(
            policy = AdminRbacPolicy(true),
            sessions = TestVipExpiredSessionDirectory(),
            exclusionDirectory = exclusionDir,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.controlVipSegment(createCommand(idempotencyKey = "idemp-fail-expired"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Blank required fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(createCommand(playerId = "   ", idempotencyKey = "idemp-fail-blank-player"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(createCommand(justification = "   ", idempotencyKey = "idemp-fail-blank-just"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(createCommand(sessionId = "   ", idempotencyKey = "idemp-fail-blank-sess"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(createCommand(correlationId = "   ", idempotencyKey = "idemp-fail-blank-corr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(createCommand(causationId = "   ", idempotencyKey = "idemp-fail-blank-caus"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 9. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(createCommand(expectedVersion = 5L, idempotencyKey = "idemp-fail-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 10. Conflicting replay with different target VIP tier under same idempotency key
        service.controlVipSegment(createCommand(idempotencyKey = "idemp-conflict-base", targetVipTier = VipTier.VIP_BRONZE))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.controlVipSegment(createCommand(idempotencyKey = "idemp-conflict-base", targetVipTier = VipTier.VIP_GOLD))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // CRM-002-03-T003: Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `CRM-002-03-T003 Control non-authoritative VIP tags and segments survives concurrency duplicate delivery and dependency failure`() {
        NonAuthoritativeVipSegmentBinding.isBound = true

        val store = InMemoryVipSegmentStore()
        val exclusionDir = FakeVipExclusionDirectory()
        val service = createService(store, exclusionDir)

        // 1. Concurrency: 8 threads race with identical idempotency key
        val threadCount = 8
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threadCount)
        val command = createCommand(idempotencyKey = "idemp-concurrent-vip-001")

        val futures = (1..threadCount).map {
            pool.submit<VipSegmentControlResult> {
                gate.await()
                service.controlVipSegment(command)
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
        val failingSessionService = NonAuthoritativeVipSegmentService(
            policy = AdminRbacPolicy(true),
            sessions = TestVipFailingSessionDirectory(),
            exclusionDirectory = exclusionDir,
            store = store,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.controlVipSegment(
                createCommand(
                    playerId = "usr-dep-fail-sess",
                    idempotencyKey = "idemp-dep-fail-sess",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Dependency failure on exclusion directory fails closed
        val failingExclusionDir = FakeVipExclusionDirectory(shouldFail = true)
        val failingExclusionService = createService(store, failingExclusionDir)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingExclusionService.controlVipSegment(
                createCommand(
                    playerId = "usr-dep-fail-excl",
                    idempotencyKey = "idemp-dep-fail-excl",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    // =========================================================================
    // CRM-002-03-T004: Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `CRM-002-03-T004 Control non-authoritative VIP tags and segments remains compatible recoverable observable and lifecycle safe`() {
        NonAuthoritativeVipSegmentBinding.isBound = true

        // 1. Migration hygiene: Ensure no unapproved migrations
        val migrationDir = File("src/main/resources/db/migration")
        if (migrationDir.exists()) {
            val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
            val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
            assertFalse(migrationVersions.contains("V17"), "Unapproved migration V17 must not exist")
        }

        // 2. Recovery / restart simulation
        val sharedStore = InMemoryVipSegmentStore()
        val exclusionDir = FakeVipExclusionDirectory()

        val serviceBefore = createService(sharedStore, exclusionDir)
        val command = createCommand(
            playerId = "usr-reboot-vip-001",
            operation = VipSegmentOperation.ASSIGN_VIP_TIER,
            targetVipTier = VipTier.VIP_SILVER,
            idempotencyKey = "idemp-reboot-vip-001",
            correlationId = "corr-reboot-vip-001",
            causationId = "caus-reboot-vip-001",
        )

        val beforeResult = serviceBefore.controlVipSegment(command)
        assertEquals(VipTier.VIP_SILVER, beforeResult.vipTier)

        val serviceAfter = createService(sharedStore, exclusionDir)
        val afterResult = serviceAfter.controlVipSegment(command)

        assertEquals(beforeResult.resultId, afterResult.resultId)
        assertEquals(beforeResult.evidenceReference, afterResult.evidenceReference)
        assertEquals(beforeResult.version, afterResult.version)
        assertFalse(afterResult.isAuthoritative)
        assertFalse(afterResult.vipGrantsFinancialPrivilege)
        assertFalse(afterResult.vipGrantsAdminPrivilege)
        assertFalse(afterResult.moneyMutated)

        // 3. Observability and audit
        val auditEvent = sharedStore.audit.first { it.resultId == beforeResult.resultId }
        assertEquals("VIP_SEGMENT_ASSIGN_VIP_TIER", auditEvent.type)
        assertEquals("corr-reboot-vip-001", auditEvent.correlationId)
        assertEquals("caus-reboot-vip-001", auditEvent.causationId)
        assertFalse(auditEvent.type.contains("secret", ignoreCase = true))

        val outboxEvent = sharedStore.outbox.first { it.resultId == beforeResult.resultId }
        assertEquals("VIP_SEGMENT_ASSIGN_VIP_TIER", outboxEvent.type)
        assertFalse(outboxEvent.type.contains("secret", ignoreCase = true))
    }

    // =========================================================================
    // Helpers and Test Doubles
    // =========================================================================
    private fun createService(
        store: VipSegmentStore,
        exclusionDir: PlayerExclusionDirectory = FakeVipExclusionDirectory(),
    ) = NonAuthoritativeVipSegmentService(
        policy = AdminRbacPolicy(true),
        sessions = TestVipActiveSessionDirectory(),
        exclusionDirectory = exclusionDir,
        store = store,
        clock = clock,
    )

    private fun createCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal(),
        sessionId: String = "session-vip-1",
        tenantId: String = "tenant-1",
        playerId: String = "usr-vip-default",
        operation: VipSegmentOperation = VipSegmentOperation.ASSIGN_VIP_TIER,
        targetVipTier: VipTier = VipTier.VIP_BRONZE,
        targetSegments: Set<String> = emptySet(),
        justification: String = "Standard VIP assessment",
        idempotencyKey: String = "idemp-vip-cmd-default",
        correlationId: String = "corr-vip-default",
        causationId: String = "caus-vip-default",
        expectedVersion: Long = 1L,
        requestsAdminPrivilege: Boolean = false,
        requestsFinancialPrivilege: Boolean = false,
        financialBalanceAdjustmentMinorUnits: Long? = null,
        forceMarketingEligibilityForSelfExcluded: Boolean = false,
    ) = ControlVipSegmentCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        playerId = playerId,
        operation = operation,
        targetVipTier = targetVipTier,
        targetSegments = targetSegments,
        justification = justification,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
        requestsAdminPrivilege = requestsAdminPrivilege,
        requestsFinancialPrivilege = requestsFinancialPrivilege,
        financialBalanceAdjustmentMinorUnits = financialBalanceAdjustmentMinorUnits,
        forceMarketingEligibilityForSelfExcluded = forceMarketingEligibilityForSelfExcluded,
    )

    private fun adminPrincipal(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-vip-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
}

private class TestVipActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-vip-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-18T22:00:00Z"))
        else null
}

private class TestVipExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-18T20:00:00Z"))
}

private class TestVipFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("Session directory unreachable")
}

private class FakeVipExclusionDirectory(
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

private class InMemoryVipSegmentStore : VipSegmentStore {
    private val profilesByPlayer = mutableMapOf<String, VipSegmentProfile>()
    private val resultsByIdempotency = mutableMapOf<String, Pair<String, VipSegmentControlResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findLatest(
        tenantId: String,
        playerId: String,
    ): VipSegmentProfile? = synchronized(this) {
        profilesByPlayer["$tenantId:$playerId"]
    }

    override fun findByIdempotency(
        tenantId: String,
        idempotencyKey: String,
    ): Pair<String, VipSegmentControlResult>? = synchronized(this) {
        resultsByIdempotency["$tenantId:$idempotencyKey"]
    }

    override fun save(
        profile: VipSegmentProfile,
        result: VipSegmentControlResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        profilesByPlayer["$tenantId:${profile.playerId}"] = profile
        resultsByIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
