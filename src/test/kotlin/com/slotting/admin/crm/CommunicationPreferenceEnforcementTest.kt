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

class CommunicationPreferenceEnforcementTest {
    private val now = Instant.parse("2026-09-18T20:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @BeforeEach
    fun setUp() {
        // Enforce fail-closed gate before each test run
        CommunicationPreferenceEnforcementBinding.isBound = false
    }

    @AfterEach
    fun tearDown() {
        // Restore bound state
        CommunicationPreferenceEnforcementBinding.isBound = true
    }

    // =========================================================================
    // CRM-002-02-T001: Produces required authoritative outcome
    // =========================================================================
    @Test
    fun `CRM-002-02-T001 Enforce communication preferences produces the required authoritative outcome`() {
        // 1. Fail-closed gate verification: When unbound, throws protected risk assertion
        assertFailsWith<AssertionError> {
            CommunicationPreferenceEnforcementBinding.checkBound()
        }.also {
            assertEquals("marketing without consent/self-excluded promo", it.message)
        }

        val consentStore = InMemoryEnforcementConsentStore()
        val enforcementStore = InMemoryCommunicationEnforcementStore()
        val exclusionDir = FakeEnforcementExclusionDirectory()
        val dispatchPort = FakeCommunicationDispatchPort()
        val service = createService(consentStore, enforcementStore, exclusionDir, dispatchPort)

        val cmdAllowed = createCommand(
            playerId = "usr-consented-001",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            campaignReference = "CAMP-AUTUMN-2026",
            idempotencyKey = "idemp-enforce-001",
            correlationId = "corr-enforce-001",
            causationId = "caus-enforce-001",
        )

        // Verify service invocation fails closed with protected risk assertion when unbound
        CommunicationPreferenceEnforcementBinding.isBound = false
        assertFailsWith<AssertionError> {
            service.enforcePreference(cmdAllowed)
        }.also {
            assertEquals("marketing without consent/self-excluded promo", it.message)
        }

        CommunicationPreferenceEnforcementBinding.isBound = true

        // Populate valid active consent in consentStore
        consentStore.seed(
            VersionedConsentRecord(
                recordId = UUID.randomUUID(),
                tenantId = "tenant-1",
                playerId = "usr-consented-001",
                channel = ConsentChannel.EMAIL,
                purpose = ConsentPurpose.MARKETING_PROMOTIONS,
                state = ConsentState.CONSENTED,
                policyVersion = "2026.1",
                vipTier = VipTier.NONE,
                vipGrantsFinancialPrivilege = false,
                vipGrantsAdminPrivilege = false,
                moneyMutated = false,
                financialAuthorityCreated = false,
                version = 1L,
                updatedAt = now,
                evidenceReference = "EVID-CONSENT-1",
            )
        )

        // 2. Authoritative preference enforcement: ALLOWED for consented player
        val resAllowed = service.enforcePreference(cmdAllowed)
        assertEquals(EnforcementDecision.ALLOWED, resAllowed.decision)
        assertTrue(resAllowed.isAllowed)
        assertEquals("usr-consented-001", resAllowed.playerId)
        assertEquals(ConsentChannel.EMAIL, resAllowed.channel)
        assertEquals(ConsentPurpose.MARKETING_PROMOTIONS, resAllowed.purpose)
        assertEquals(VipTier.NONE, resAllowed.effectiveVipTier)
        assertFalse(resAllowed.vipGrantsFinancialPrivilege, "VIP tag grants no financial privilege")
        assertFalse(resAllowed.vipGrantsAdminPrivilege, "VIP tag grants no admin privilege")
        assertFalse(resAllowed.moneyMutated, "Preference enforcement must never mutate money")
        assertFalse(resAllowed.financialAuthorityCreated)
        assertEquals(1L, resAllowed.version)
        assertEquals(now, resAllowed.serverTime)
        assertTrue(resAllowed.evidenceReference.startsWith("EVID-ENFORCE-tenant-1-usr-consented-001-EMAIL-ALLOWED"))
        assertEquals(1, dispatchPort.dispatches.size)

        // Replay with identical idempotency key returns cached result
        val replay = service.enforcePreference(cmdAllowed)
        assertEquals(resAllowed.resultId, replay.resultId)
        assertEquals(resAllowed.evidenceReference, replay.evidenceReference)

        // Verify audit and outbox emission
        assertEquals(1, enforcementStore.audit.size)
        assertEquals(1, enforcementStore.outbox.size)
        assertEquals("COMMUNICATION_ENFORCEMENT_ALLOWED", enforcementStore.audit[0].type)
        assertEquals("corr-enforce-001", enforcementStore.audit[0].correlationId)
        assertEquals("caus-enforce-001", enforcementStore.audit[0].causationId)

        // 3. BLOCKED_NO_CONSENT: Player without any consent record
        val cmdNoConsent = createCommand(
            playerId = "usr-no-consent-002",
            channel = ConsentChannel.SMS,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            idempotencyKey = "idemp-enforce-002",
        )
        val resNoConsent = service.enforcePreference(cmdNoConsent)
        assertEquals(EnforcementDecision.BLOCKED_NO_CONSENT, resNoConsent.decision)
        assertFalse(resNoConsent.isAllowed)

        // 4. BLOCKED_WITHDRAWN: Player with WITHDRAWN consent
        consentStore.seed(
            VersionedConsentRecord(
                recordId = UUID.randomUUID(),
                tenantId = "tenant-1",
                playerId = "usr-withdrawn-003",
                channel = ConsentChannel.EMAIL,
                purpose = ConsentPurpose.MARKETING_PROMOTIONS,
                state = ConsentState.WITHDRAWN,
                policyVersion = "2026.1",
                vipTier = VipTier.VIP_SILVER,
                vipGrantsFinancialPrivilege = false,
                vipGrantsAdminPrivilege = false,
                moneyMutated = false,
                financialAuthorityCreated = false,
                version = 2L,
                updatedAt = now,
                evidenceReference = "EVID-CONSENT-2",
            )
        )
        val cmdWithdrawn = createCommand(
            playerId = "usr-withdrawn-003",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            idempotencyKey = "idemp-enforce-003",
        )
        val resWithdrawn = service.enforcePreference(cmdWithdrawn)
        assertEquals(EnforcementDecision.BLOCKED_WITHDRAWN, resWithdrawn.decision)
        assertFalse(resWithdrawn.isAllowed)
        assertEquals(VipTier.VIP_SILVER, resWithdrawn.effectiveVipTier)
        assertFalse(resWithdrawn.vipGrantsFinancialPrivilege)

        // 5. BLOCKED_SELF_EXCLUDED: Self-excluded player with VIP_PLATINUM and CONSENTED state
        consentStore.seed(
            VersionedConsentRecord(
                recordId = UUID.randomUUID(),
                tenantId = "tenant-1",
                playerId = "usr-vip-self-excluded-004",
                channel = ConsentChannel.EMAIL,
                purpose = ConsentPurpose.MARKETING_PROMOTIONS,
                state = ConsentState.CONSENTED,
                policyVersion = "2026.1",
                vipTier = VipTier.VIP_PLATINUM,
                vipGrantsFinancialPrivilege = false,
                vipGrantsAdminPrivilege = false,
                moneyMutated = false,
                financialAuthorityCreated = false,
                version = 1L,
                updatedAt = now,
                evidenceReference = "EVID-CONSENT-3",
            )
        )
        exclusionDir.exclude("tenant-1", "usr-vip-self-excluded-004")

        val cmdSelfExcluded = createCommand(
            playerId = "usr-vip-self-excluded-004",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            idempotencyKey = "idemp-enforce-004",
        )
        val resSelfExcluded = service.enforcePreference(cmdSelfExcluded)
        assertEquals(EnforcementDecision.BLOCKED_SELF_EXCLUDED, resSelfExcluded.decision)
        assertFalse(resSelfExcluded.isAllowed, "Self-excluded player must never receive promotional communications")
        assertEquals(VipTier.VIP_PLATINUM, resSelfExcluded.effectiveVipTier)
        assertFalse(resSelfExcluded.vipGrantsFinancialPrivilege)
        assertFalse(resSelfExcluded.vipGrantsAdminPrivilege)

        // 6. Transactional essential notices allowed even without marketing consent
        val cmdTransactional = createCommand(
            playerId = "usr-no-consent-002",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.TRANSACTIONAL_ESSENTIAL,
            idempotencyKey = "idemp-enforce-005",
        )
        val resTransactional = service.enforcePreference(cmdTransactional)
        assertEquals(EnforcementDecision.ALLOWED, resTransactional.decision)
        assertTrue(resTransactional.isAllowed)
    }

    // =========================================================================
    // CRM-002-02-T002: Rejects invalid, boundary, unauthorized, and stale input
    // =========================================================================
    @Test
    fun `CRM-002-02-T002 Enforce communication preferences rejects invalid boundary unauthorized and stale input`() {
        CommunicationPreferenceEnforcementBinding.isBound = true

        val consentStore = InMemoryEnforcementConsentStore()
        val enforcementStore = InMemoryCommunicationEnforcementStore()
        val exclusionDir = FakeEnforcementExclusionDirectory()
        val service = createService(consentStore, enforcementStore, exclusionDir)

        // 1. VIP tag bypass consent attempt
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(
                createCommand(
                    bypassConsentForVip = true,
                    idempotencyKey = "idemp-fail-bypass-vip",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. VIP privilege escalation attempts (financial / admin)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(
                createCommand(
                    requestsFinancialPrivilege = true,
                    idempotencyKey = "idemp-fail-fin-priv",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(
                createCommand(
                    requestsAdminPrivilege = true,
                    idempotencyKey = "idemp-fail-admin-priv",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(
                createCommand(
                    financialBalanceAdjustmentMinorUnits = 5000L,
                    idempotencyKey = "idemp-fail-balance-mut",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(
                createCommand(
                    principal = null,
                    idempotencyKey = "idemp-fail-unauth",
                )
            )
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 4. Player principal attempting operator enforcement
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(
                createCommand(
                    principal = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet()),
                    idempotencyKey = "idemp-fail-player",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 5. Cross-tenant principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(
                createCommand(
                    principal = adminPrincipal("tenant-2"),
                    tenantId = "tenant-1",
                    idempotencyKey = "idemp-fail-cross-tenant",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 6. Expired session
        val expiredSessionService = CommunicationPreferenceEnforcementService(
            policy = AdminRbacPolicy(true),
            sessions = TestEnforcementExpiredSessionDirectory(),
            exclusionDirectory = exclusionDir,
            consentStore = consentStore,
            enforcementStore = enforcementStore,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            expiredSessionService.enforcePreference(createCommand(idempotencyKey = "idemp-fail-expired"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 7. Blank required fields
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(createCommand(playerId = "   ", idempotencyKey = "idemp-fail-blank-player"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(createCommand(campaignReference = "   ", idempotencyKey = "idemp-fail-blank-camp"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(createCommand(sessionId = "   ", idempotencyKey = "idemp-fail-blank-sess"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(createCommand(correlationId = "   ", idempotencyKey = "idemp-fail-blank-corr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(createCommand(causationId = "   ", idempotencyKey = "idemp-fail-blank-caus"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(createCommand(expectedVersion = 2L, idempotencyKey = "idemp-fail-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 9. Conflicting replay with differing payload for same idempotency key
        service.enforcePreference(createCommand(idempotencyKey = "idemp-conflict-base", channel = ConsentChannel.EMAIL))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.enforcePreference(createCommand(idempotencyKey = "idemp-conflict-base", channel = ConsentChannel.SMS))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // CRM-002-02-T003: Survives concurrency, duplicate delivery, and dependency failure
    // =========================================================================
    @Test
    fun `CRM-002-02-T003 Enforce communication preferences survives concurrency duplicate delivery and dependency failure`() {
        CommunicationPreferenceEnforcementBinding.isBound = true

        val consentStore = InMemoryEnforcementConsentStore()
        val enforcementStore = InMemoryCommunicationEnforcementStore()
        val exclusionDir = FakeEnforcementExclusionDirectory()
        val service = createService(consentStore, enforcementStore, exclusionDir)

        // 1. Concurrency: 8 threads race with identical idempotency key
        val threadCount = 8
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threadCount)
        val command = createCommand(idempotencyKey = "idemp-concurrent-enforce-001")

        val futures = (1..threadCount).map {
            pool.submit<CommunicationEnforcementResult> {
                gate.await()
                service.enforcePreference(command)
            }
        }
        gate.countDown()

        val results = futures.map { runCatching { it.get() } }
        assertEquals(threadCount, results.count { it.isSuccess })

        val distinctResultIds = results.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        assertEquals(1, enforcementStore.audit.size)
        assertEquals(1, enforcementStore.outbox.size)

        // 2. Dependency failure on session directory fails closed
        val failingSessionService = CommunicationPreferenceEnforcementService(
            policy = AdminRbacPolicy(true),
            sessions = TestEnforcementFailingSessionDirectory(),
            exclusionDirectory = exclusionDir,
            consentStore = consentStore,
            enforcementStore = enforcementStore,
            clock = clock,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingSessionService.enforcePreference(
                createCommand(
                    playerId = "usr-dep-fail-sess",
                    idempotencyKey = "idemp-dep-fail-sess",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Dependency failure on exclusion directory fails closed
        val failingExclusionDir = FakeEnforcementExclusionDirectory(shouldFail = true)
        val failingExclusionService = createService(consentStore, enforcementStore, failingExclusionDir)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingExclusionService.enforcePreference(
                createCommand(
                    playerId = "usr-dep-fail-excl",
                    idempotencyKey = "idemp-dep-fail-excl",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 4. Dependency failure on dispatch port fails closed
        consentStore.seed(
            VersionedConsentRecord(
                recordId = UUID.randomUUID(),
                tenantId = "tenant-1",
                playerId = "usr-dep-fail-port",
                channel = ConsentChannel.EMAIL,
                purpose = ConsentPurpose.MARKETING_PROMOTIONS,
                state = ConsentState.CONSENTED,
                policyVersion = "2026.1",
                vipTier = VipTier.NONE,
                vipGrantsFinancialPrivilege = false,
                vipGrantsAdminPrivilege = false,
                moneyMutated = false,
                financialAuthorityCreated = false,
                version = 1L,
                updatedAt = now,
                evidenceReference = "EVID-PORT-FAIL",
            )
        )
        val failingDispatchPort = FakeCommunicationDispatchPort(shouldFail = true)
        val failingDispatchService = createService(consentStore, enforcementStore, exclusionDir, failingDispatchPort)
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingDispatchService.enforcePreference(
                createCommand(
                    playerId = "usr-dep-fail-port",
                    idempotencyKey = "idemp-dep-fail-port",
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    // =========================================================================
    // CRM-002-02-T004: Remains compatible, recoverable, observable, and lifecycle-safe
    // =========================================================================
    @Test
    fun `CRM-002-02-T004 Enforce communication preferences remains compatible recoverable observable and lifecycle safe`() {
        CommunicationPreferenceEnforcementBinding.isBound = true

        // 1. Migration hygiene: Ensure no unapproved migrations
        val migrationDir = File("src/main/resources/db/migration")
        if (migrationDir.exists()) {
            val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
            val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
            assertFalse(migrationVersions.contains("V17"), "Unapproved migration V17 must not exist")
        }

        // 2. Recovery / restart simulation
        val sharedConsentStore = InMemoryEnforcementConsentStore()
        val sharedEnforcementStore = InMemoryCommunicationEnforcementStore()
        val exclusionDir = FakeEnforcementExclusionDirectory()

        sharedConsentStore.seed(
            VersionedConsentRecord(
                recordId = UUID.randomUUID(),
                tenantId = "tenant-1",
                playerId = "usr-reboot-pref-001",
                channel = ConsentChannel.EMAIL,
                purpose = ConsentPurpose.MARKETING_PROMOTIONS,
                state = ConsentState.CONSENTED,
                policyVersion = "2026.1",
                vipTier = VipTier.VIP_GOLD,
                vipGrantsFinancialPrivilege = false,
                vipGrantsAdminPrivilege = false,
                moneyMutated = false,
                financialAuthorityCreated = false,
                version = 1L,
                updatedAt = now,
                evidenceReference = "EVID-REBOOT-1",
            )
        )

        val serviceBefore = createService(sharedConsentStore, sharedEnforcementStore, exclusionDir)
        val command = createCommand(
            playerId = "usr-reboot-pref-001",
            channel = ConsentChannel.EMAIL,
            purpose = ConsentPurpose.MARKETING_PROMOTIONS,
            campaignReference = "CAMP-REBOOT-001",
            idempotencyKey = "idemp-reboot-pref-001",
            correlationId = "corr-reboot-pref-001",
            causationId = "caus-reboot-pref-001",
        )

        val beforeResult = serviceBefore.enforcePreference(command)
        assertEquals(EnforcementDecision.ALLOWED, beforeResult.decision)

        val serviceAfter = createService(sharedConsentStore, sharedEnforcementStore, exclusionDir)
        val afterResult = serviceAfter.enforcePreference(command)

        assertEquals(beforeResult.resultId, afterResult.resultId)
        assertEquals(beforeResult.evidenceReference, afterResult.evidenceReference)
        assertEquals(beforeResult.version, afterResult.version)
        assertFalse(afterResult.vipGrantsFinancialPrivilege)
        assertFalse(afterResult.vipGrantsAdminPrivilege)
        assertFalse(afterResult.moneyMutated)

        // 3. Observability and audit
        val auditEvent = sharedEnforcementStore.audit.first { it.resultId == beforeResult.resultId }
        assertEquals("COMMUNICATION_ENFORCEMENT_ALLOWED", auditEvent.type)
        assertEquals("corr-reboot-pref-001", auditEvent.correlationId)
        assertEquals("caus-reboot-pref-001", auditEvent.causationId)
        assertFalse(auditEvent.type.contains("secret", ignoreCase = true))

        val outboxEvent = sharedEnforcementStore.outbox.first { it.resultId == beforeResult.resultId }
        assertEquals("COMMUNICATION_ENFORCEMENT_ALLOWED", outboxEvent.type)
        assertFalse(outboxEvent.type.contains("secret", ignoreCase = true))
    }

    // =========================================================================
    // Helpers and Test Doubles
    // =========================================================================
    private fun createService(
        consentStore: VersionedConsentStore,
        enforcementStore: CommunicationEnforcementStore,
        exclusionDir: PlayerExclusionDirectory = FakeEnforcementExclusionDirectory(),
        dispatchPort: CommunicationDispatchPort? = null,
    ) = CommunicationPreferenceEnforcementService(
        policy = AdminRbacPolicy(true),
        sessions = TestEnforcementActiveSessionDirectory(),
        exclusionDirectory = exclusionDir,
        consentStore = consentStore,
        enforcementStore = enforcementStore,
        dispatchPort = dispatchPort,
        clock = clock,
    )

    private fun createCommand(
        principal: AuthenticatedPrincipal? = adminPrincipal(),
        sessionId: String = "session-enforce-1",
        tenantId: String = "tenant-1",
        playerId: String = "usr-enforce-default",
        channel: ConsentChannel = ConsentChannel.EMAIL,
        purpose: ConsentPurpose = ConsentPurpose.MARKETING_PROMOTIONS,
        campaignReference: String = "CAMP-DEFAULT-001",
        idempotencyKey: String = "idemp-enforce-cmd-default",
        correlationId: String = "corr-enforce-default",
        causationId: String = "caus-enforce-default",
        expectedVersion: Long = 1L,
        requestsAdminPrivilege: Boolean = false,
        requestsFinancialPrivilege: Boolean = false,
        financialBalanceAdjustmentMinorUnits: Long? = null,
        bypassConsentForVip: Boolean = false,
    ) = EnforceCommunicationPreferenceCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        playerId = playerId,
        channel = channel,
        purpose = purpose,
        campaignReference = campaignReference,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
        requestsAdminPrivilege = requestsAdminPrivilege,
        requestsFinancialPrivilege = requestsFinancialPrivilege,
        financialBalanceAdjustmentMinorUnits = financialBalanceAdjustmentMinorUnits,
        bypassConsentForVip = bypassConsentForVip,
    )

    private fun adminPrincipal(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-enforce-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
}

private class TestEnforcementActiveSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && sessionId == "session-enforce-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-18T21:00:00Z"))
        else null
}

private class TestEnforcementExpiredSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        AdminSessionStatus(false, false, Instant.parse("2026-09-18T19:00:00Z"))
}

private class TestEnforcementFailingSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("Session directory unreachable")
}

private class FakeEnforcementExclusionDirectory(
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

private class InMemoryEnforcementConsentStore : VersionedConsentStore {
    private val recordsByKey = mutableMapOf<String, VersionedConsentRecord>()

    fun seed(record: VersionedConsentRecord) {
        recordsByKey["${record.tenantId}:${record.playerId}:${record.channel.name}:${record.purpose.name}"] = record
    }

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
    ): Pair<String, VersionedConsentRecord>? = null

    override fun save(
        record: VersionedConsentRecord,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        seed(record)
    }
}

private class InMemoryCommunicationEnforcementStore : CommunicationEnforcementStore {
    private val resultsByIdempotency = mutableMapOf<String, Pair<String, CommunicationEnforcementResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(
        tenantId: String,
        idempotencyKey: String,
    ): Pair<String, CommunicationEnforcementResult>? = synchronized(this) {
        resultsByIdempotency["$tenantId:$idempotencyKey"]
    }

    override fun save(
        result: CommunicationEnforcementResult,
        tenantId: String,
        fingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        resultsByIdempotency["$tenantId:$idempotencyKey"] = fingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}

private class FakeCommunicationDispatchPort(
    val shouldFail: Boolean = false,
) : CommunicationDispatchPort {
    val dispatches = mutableListOf<String>()

    override fun dispatchMessage(
        tenantId: String,
        playerId: String,
        channel: ConsentChannel,
        purpose: ConsentPurpose,
        campaignReference: String,
    ): CommunicationDispatchOutcome {
        if (shouldFail) throw RuntimeException("Dispatch transport connection refused")
        dispatches.add("$tenantId:$playerId:$campaignReference")
        return CommunicationDispatchOutcome(
            dispatched = true,
            dispatchToken = "DISPATCH-${UUID.randomUUID()}",
            timestamp = Instant.now(),
        )
    }
}
