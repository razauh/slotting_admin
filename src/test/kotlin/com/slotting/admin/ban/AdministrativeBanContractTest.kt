package com.slotting.admin.ban

import com.slotting.admin.auth.*
import com.slotting.admin.identity.*
import com.slotting.admin.restriction.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.UUID

/**
 * TC-027 TDD Contract Test Suite: Durable Temporary/Permanent Administrative Bans and Unban.
 * Covers:
 * - RBAC & session authorization before replay (dedicated RESTRICTIONS_MANAGE permission)
 * - Permanent ban vs Temporary ban with precise UTC expiry boundary
 * - Immutable unban/reversal action preserving full history
 * - Multi-device active session invalidation
 * - Concurrency, CAS versioning, and idempotency
 * - TC-026 policy matrix integration (denies gaming/auth, preserves support, holds pending withdrawals)
 * - Separation from RG, fraud, KYC, and closure
 */
class AdministrativeBanContractTest {

    private val tenantId = "tenant-prod-bravo"
    private val subjectRef = "player-sub-9900"
    private val playerId = UUID.randomUUID()
    private val fixedNow = Instant.parse("2026-09-26T12:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-agent-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "support-agent-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-agent-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.AUDITOR), // Lacks RESTRICTIONS_MANAGE
        kind = PrincipalKind.ADMIN
    )

    private val crossTenantAdmin = AuthenticatedPrincipal(
        id = "admin-other-01",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPER_ADMIN),
        kind = PrincipalKind.ADMIN
    )

    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var sessions: FakeAdminSessionDirectory
    private lateinit var banStore: InMemoryAdministrativeBanStore
    private lateinit var restrictionStore: InMemoryServerRestrictionStore
    private lateinit var deviceStore: InMemoryDeviceInventoryStore
    private lateinit var banService: AdministrativeBanService
    private lateinit var tc026Evaluator: ServerRestrictionEvaluator

    class FakeAdminSessionDirectory : AdminSessionDirectory {
        private val sessions = mutableMapOf<String, AdminSessionStatus>()

        fun putSession(tenantId: String, principalId: String, sessionId: String, status: AdminSessionStatus) {
            sessions["$tenantId:$principalId:$sessionId"] = status
        }

        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
            sessions["$tenantId:$principalId:$sessionId"]
    }

    @BeforeEach
    fun setUp() {
        rbacPolicy = AdminRbacPolicy(dualControlRequired = false)
        sessions = FakeAdminSessionDirectory()
        banStore = InMemoryAdministrativeBanStore()
        restrictionStore = InMemoryServerRestrictionStore()
        deviceStore = InMemoryDeviceInventoryStore()

        banService = AdministrativeBanService(
            policy = rbacPolicy,
            sessions = sessions,
            banStore = banStore,
            restrictionStore = restrictionStore,
            deviceStore = deviceStore,
            clock = clock
        )

        tc026Evaluator = DefaultServerRestrictionEvaluator(restrictionStore, null, clock)

        // Setup valid admin session
        sessions.putSession(
            tenantId,
            adminPrincipal.id,
            "session-adm-01",
            AdminSessionStatus(active = true, breakGlass = false, expiresAt = fixedNow.plus(2, ChronoUnit.HOURS))
        )
        sessions.putSession(
            tenantId,
            supportPrincipal.id,
            "session-sup-01",
            AdminSessionStatus(active = true, breakGlass = false, expiresAt = fixedNow.plus(2, ChronoUnit.HOURS))
        )
        sessions.putSession(
            tenantId,
            auditorPrincipal.id,
            "session-aud-01",
            AdminSessionStatus(active = true, breakGlass = false, expiresAt = fixedNow.plus(2, ChronoUnit.HOURS))
        )
    }

    private fun validIssueCommand(
        banType: BanType = BanType.PERMANENT,
        expiresAt: Instant? = null,
        effectiveFrom: Instant = fixedNow.minus(10, ChronoUnit.MINUTES),
        principal: AuthenticatedPrincipal = adminPrincipal,
        sessionId: String = "session-adm-01",
        idempotencyKey: String = "idem-${UUID.randomUUID()}",
        expectedVersion: Long = 1L
    ): IssueBanCommand = IssueBanCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        subjectReference = subjectRef,
        banType = banType,
        reasonCategory = BanReasonCategory.TERMS_OF_SERVICE_VIOLATION,
        reasonCode = "TOS_FRAUD_CHARGEBACK",
        permittedNote = "Account banned for Terms of Service violation",
        internalNote = "Internal investigation case ref #9982",
        effectiveFrom = effectiveFrom,
        expiresAt = expiresAt,
        caseReferenceId = "CASE-BAN-9900",
        correlationId = "corr-001",
        causationId = "cause-001",
        expectedVersion = expectedVersion,
        idempotencyKey = idempotencyKey
    )

    private fun validReverseCommand(
        banId: UUID,
        principal: AuthenticatedPrincipal = adminPrincipal,
        sessionId: String = "session-adm-01",
        idempotencyKey: String = "idem-rev-${UUID.randomUUID()}",
        expectedVersion: Long = 1L
    ): ReverseBanCommand = ReverseBanCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        subjectReference = subjectRef,
        banId = banId,
        reversalReason = "Appeal approved after review of documentation",
        caseReferenceId = "CASE-BAN-9900",
        correlationId = "corr-rev-001",
        causationId = "cause-rev-001",
        expectedVersion = expectedVersion,
        idempotencyKey = idempotencyKey
    )

    // =========================================================================
    // 1. Authorization, Tenant, and Session Invariants
    // =========================================================================

    @Nested
    @DisplayName("1. RBAC and Session Authorization Contracts")
    inner class AuthorizationTests {
        @Test
        fun `Unauthenticated command throws UNAUTHENTICATED`() {
            val cmd = validIssueCommand().copy(principal = null)
            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.issueBan(cmd)
            }
            assertEquals(AuthErrorCode.UNAUTHENTICATED, ex.code)
        }

        @Test
        fun `Cross-tenant administrator throws FORBIDDEN`() {
            val cmd = validIssueCommand(principal = crossTenantAdmin)
            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.issueBan(cmd)
            }
            assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
        }

        @Test
        fun `Principal lacking RESTRICTIONS_MANAGE permission throws FORBIDDEN`() {
            val cmd = validIssueCommand(principal = auditorPrincipal, sessionId = "session-aud-01")
            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.issueBan(cmd)
            }
            assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
        }

        @Test
        fun `Support role with RESTRICTIONS_MANAGE is permitted`() {
            val cmd = validIssueCommand(principal = supportPrincipal, sessionId = "session-sup-01")
            val res = banService.issueBan(cmd)
            assertEquals(BanStatus.ACTIVE, res.ban.status)
        }

        @Test
        fun `Expired session throws FORBIDDEN`() {
            sessions.putSession(
                tenantId,
                adminPrincipal.id,
                "session-expired",
                AdminSessionStatus(active = true, breakGlass = false, expiresAt = fixedNow.minus(1, ChronoUnit.MINUTES))
            )
            val cmd = validIssueCommand(sessionId = "session-expired")
            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.issueBan(cmd)
            }
            assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
        }
    }

    // =========================================================================
    // 2. Permanent vs Temporary Ban & Expiry Boundaries
    // =========================================================================

    @Nested
    @DisplayName("2. Ban Types and Expiry Boundaries")
    inner class BanTypesAndExpiryTests {
        @Test
        fun `Permanent ban has no expiry and remains active indefinitely`() {
            val cmd = validIssueCommand(banType = BanType.PERMANENT, expiresAt = null)
            val res = banService.issueBan(cmd)

            assertNull(res.ban.expiresAt)
            assertEquals(BanStatus.ACTIVE, res.ban.status)
            assertTrue(res.ban.isEffectiveAt(fixedNow))
            assertTrue(res.ban.isEffectiveAt(fixedNow.plus(3650, ChronoUnit.DAYS))) // 10 years later

            // Integration with TC-026 restriction store:
            val active = restrictionStore.findActiveRestrictions(tenantId, subjectRef, fixedNow)
            assertEquals(1, active.size)
            assertEquals(RestrictionSource.ADMINISTRATIVE_BAN, active[0].source)
            assertNull(active[0].expiresAt)
        }

        @Test
        fun `Permanent ban rejecting non-null expiry`() {
            assertThrows(IllegalArgumentException::class.java) {
                validIssueCommand(banType = BanType.PERMANENT, expiresAt = fixedNow.plus(1, ChronoUnit.DAYS))
            }
        }

        @Test
        fun `Temporary ban requires future expiry timestamp`() {
            assertThrows(IllegalArgumentException::class.java) {
                validIssueCommand(banType = BanType.TEMPORARY, expiresAt = null)
            }

            val cmd = validIssueCommand(banType = BanType.TEMPORARY, expiresAt = fixedNow.minus(1, ChronoUnit.MINUTES))
            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.issueBan(cmd)
            }
            assertEquals(AuthErrorCode.INVALID, ex.code)
        }

        @Test
        fun `Temporary ban is active before expiry and inactive exactly at expiry`() {
            val expiry = fixedNow.plus(7, ChronoUnit.DAYS)
            val cmd = validIssueCommand(banType = BanType.TEMPORARY, expiresAt = expiry)
            val res = banService.issueBan(cmd)

            assertEquals(expiry, res.ban.expiresAt)
            assertTrue(res.ban.isEffectiveAt(expiry.minusMillis(1)), "Must be active 1ms before expiry")
            assertFalse(res.ban.isEffectiveAt(expiry), "Must be inactive at exact expiry boundary")
            assertFalse(res.ban.isEffectiveAt(expiry.plusMillis(1)), "Must be inactive after expiry")

            // evaluateExpiry transitions status to EXPIRED
            val expiredBan = banService.evaluateExpiry(tenantId, subjectRef, expiry)
            assertNotNull(expiredBan)
            assertEquals(BanStatus.EXPIRED, expiredBan?.status)

            // TC-026 restriction store no longer returns expired ban
            val activeRestrictions = restrictionStore.findActiveRestrictions(tenantId, subjectRef, expiry)
            assertTrue(activeRestrictions.isEmpty(), "Expired ban must not be returned as active restriction")
        }

        @Test
        fun `Future effective ban is not active before effectiveFrom`() {
            val futureEffective = fixedNow.plus(1, ChronoUnit.DAYS)
            val cmd = validIssueCommand(banType = BanType.PERMANENT, effectiveFrom = futureEffective)
            val res = banService.issueBan(cmd)

            assertFalse(res.ban.isEffectiveAt(fixedNow), "Must not be effective before effectiveFrom")
            assertTrue(res.ban.isEffectiveAt(futureEffective), "Must be effective at effectiveFrom")
        }
    }

    // =========================================================================
    // 3. Unban and Reversal (Immutable History)
    // =========================================================================

    @Nested
    @DisplayName("3. Immutable Unban and Reversal")
    inner class UnbanReversalTests {
        @Test
        fun `Unban records reversal without deleting ban record`() {
            val issueRes = banService.issueBan(validIssueCommand(banType = BanType.PERMANENT))
            val banId = issueRes.ban.banId

            val revCmd = validReverseCommand(banId = banId, expectedVersion = 1L)
            val revRes = banService.reverseBan(revCmd)

            assertEquals(BanStatus.REVERSED, revRes.ban.status)
            assertEquals(adminPrincipal.id, revRes.ban.reversedBy)
            assertEquals(revCmd.reversalReason, revRes.ban.reversalReason)
            assertEquals(2L, revRes.ban.version)
            assertEquals(fixedNow, revRes.ban.reversedAt)

            // History remains immutable: ban record is preserved in banStore
            val allBans = banStore.findAllBansForSubject(tenantId, subjectRef)
            assertEquals(1, allBans.size)
            assertEquals(banId, allBans[0].banId)
            assertEquals(BanStatus.REVERSED, allBans[0].status)

            // Active ban lookup returns null
            assertNull(banStore.findActiveBanBySubject(tenantId, subjectRef, fixedNow))

            // TC-026 restriction store is updated: no active restriction
            val activeRestrictions = restrictionStore.findActiveRestrictions(tenantId, subjectRef, fixedNow)
            assertTrue(activeRestrictions.isEmpty())
        }

        @Test
        fun `Unban with stale version throws STALE`() {
            val issueRes = banService.issueBan(validIssueCommand())
            val revCmd = validReverseCommand(banId = issueRes.ban.banId, expectedVersion = 999L)

            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.reverseBan(revCmd)
            }
            assertEquals(AuthErrorCode.STALE, ex.code)
        }

        @Test
        fun `Concurrent or repeated unban on already reversed ban throws CONFLICT`() {
            val issueRes = banService.issueBan(validIssueCommand())
            banService.reverseBan(validReverseCommand(banId = issueRes.ban.banId, expectedVersion = 1L))

            // Second unban attempt with a new idempotency key
            val secondRevCmd = validReverseCommand(
                banId = issueRes.ban.banId,
                idempotencyKey = "different-idem-key",
                expectedVersion = 2L
            )
            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.reverseBan(secondRevCmd)
            }
            assertEquals(AuthErrorCode.CONFLICT, ex.code)
        }
    }

    // =========================================================================
    // 4. Double Ban and Conflict Prevention
    // =========================================================================

    @Nested
    @DisplayName("4. Double Ban and Conflict Invariants")
    inner class DoubleBanTests {
        @Test
        fun `Attempting to issue ban when active ban already exists throws CONFLICT`() {
            banService.issueBan(validIssueCommand(idempotencyKey = "ban-1"))

            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.issueBan(validIssueCommand(idempotencyKey = "ban-2"))
            }
            assertEquals(AuthErrorCode.CONFLICT, ex.code)
        }
    }

    // =========================================================================
    // 5. Session Revocation Across Devices
    // =========================================================================

    @Nested
    @DisplayName("5. Active Session and Device Revocation")
    inner class SessionDeviceRevocationTests {
        @Test
        fun `Issuing ban automatically revokes all active device sessions for the player`() {
            // Setup 2 active device sessions for this player
            val sess1 = DeviceSessionRecord(
                sessionId = UUID.randomUUID(),
                familyId = UUID.randomUUID(),
                tenantId = tenantId,
                playerId = playerId,
                deviceMetadata = DeviceMetadata(
                    deviceId = "dev-android-01",
                    deviceModel = "Pixel 8",
                    osVersion = "Android 14",
                    clientIp = "192.168.1.10",
                    userAgent = "SlottingApp/1.0"
                ),
                status = DeviceSessionStatus.ACTIVE,
                createdAt = fixedNow.minus(1, ChronoUnit.HOURS),
                lastSeenAt = fixedNow
            )
            val sess2 = DeviceSessionRecord(
                sessionId = UUID.randomUUID(),
                familyId = UUID.randomUUID(),
                tenantId = tenantId,
                playerId = playerId,
                deviceMetadata = DeviceMetadata(
                    deviceId = "dev-web-01",
                    deviceModel = "Desktop",
                    osVersion = "Linux",
                    clientIp = "192.168.1.11",
                    userAgent = "Chrome/120"
                ),
                status = DeviceSessionStatus.ACTIVE,
                createdAt = fixedNow.minus(30, ChronoUnit.MINUTES),
                lastSeenAt = fixedNow
            )
            deviceStore.saveSession(sess1)
            deviceStore.saveSession(sess2)

            assertEquals(2, deviceStore.findSessionsByPlayer(tenantId, playerId).count { it.status == DeviceSessionStatus.ACTIVE })

            // Issue ban using playerId string as subjectReference
            val cmd = validIssueCommand().copy(subjectReference = playerId.toString())
            val res = banService.issueBan(cmd)

            assertEquals(2, res.sessionsRevokedCount)

            // Both sessions must now be REVOKED
            val postBanSessions = deviceStore.findSessionsByPlayer(tenantId, playerId)
            assertEquals(0, postBanSessions.count { it.status == DeviceSessionStatus.ACTIVE })
            assertTrue(postBanSessions.all { it.status == DeviceSessionStatus.REVOKED })
        }
    }

    // =========================================================================
    // 6. Direct API Enforcement via TC-026 Policy Matrix
    // =========================================================================

    @Nested
    @DisplayName("6. TC-026 Policy Matrix Integration")
    inner class Tc026IntegrationTests {
        @Test
        fun `Banned player is denied authentication and wagering, but support is allowed and pending withdrawal is held`() {
            banService.issueBan(validIssueCommand())

            // TC-026 Evaluator checks:
            val authResult = tc026Evaluator.evaluate(
                OperationEvaluationContext(
                    operation = ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION,
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    now = fixedNow
                )
            )
            assertEquals(AccessDecision.DENY, authResult.compositeAccess)

            val wagerResult = tc026Evaluator.evaluate(
                OperationEvaluationContext(
                    operation = ServerOperation.WAGER,
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    now = fixedNow
                )
            )
            assertEquals(AccessDecision.DENY, wagerResult.compositeAccess)

            // Support is ALLOWED for appeal/remediation
            val supportResult = tc026Evaluator.evaluate(
                OperationEvaluationContext(
                    operation = ServerOperation.SUPPORT_ACCESS,
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    now = fixedNow
                )
            )
            assertEquals(AccessDecision.ALLOW, supportResult.compositeAccess)

            // Pending withdrawal is HELD, not completed or cancelled blindly
            val withdrawalResult = tc026Evaluator.evaluate(
                OperationEvaluationContext(
                    operation = ServerOperation.WITHDRAWAL,
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    now = fixedNow
                )
            )
            assertEquals(AccessDecision.DENY, withdrawalResult.compositeAccess)
            assertEquals(FinancialDisposition.HOLD, withdrawalResult.financialDisposition)
        }
    }

    // =========================================================================
    // 7. Idempotency & Replay Protection
    // =========================================================================

    @Nested
    @DisplayName("7. Idempotency and Replay Protection")
    inner class IdempotencyTests {
        @Test
        fun `Identical issue ban command replay returns cached result`() {
            val cmd = validIssueCommand(idempotencyKey = "replay-key-01")
            val res1 = banService.issueBan(cmd)
            val res2 = banService.issueBan(cmd)

            assertEquals(res1.ban.banId, res2.ban.banId)
            assertEquals(res1.ban.version, res2.ban.version)
        }

        @Test
        fun `Same idempotency key with mutated payload throws CONFLICT`() {
            val key = "replay-key-02"
            val cmd1 = validIssueCommand(idempotencyKey = key, banType = BanType.PERMANENT)
            banService.issueBan(cmd1)

            val cmd2 = validIssueCommand(idempotencyKey = key, banType = BanType.TEMPORARY, expiresAt = fixedNow.plus(2, ChronoUnit.DAYS))
            val ex = assertThrows(AuthenticationFailure.Rejected::class.java) {
                banService.issueBan(cmd2)
            }
            assertEquals(AuthErrorCode.CONFLICT, ex.code)
        }
    }

    // =========================================================================
    // 8. Distinction from RG, Fraud, and KYC
    // =========================================================================

    @Nested
    @DisplayName("8. Distinction from Other Restriction Sources")
    inner class DistinctionTests {
        @Test
        fun `Administrative ban records remain strictly distinct from RG, fraud, KYC, and closure records`() {
            // Add RG restriction in TC-026 store
            val rgRecord = ServerRestrictionRecord(
                tenantId = tenantId,
                subjectReference = subjectRef,
                source = RestrictionSource.RESPONSIBLE_GAMING,
                reasonCode = "RG_SELF_EXCLUSION",
                safeUserMessage = "Self excluded",
                effectiveFrom = fixedNow.minus(1, ChronoUnit.DAYS),
                evidenceReference = "EVID-RG-01"
            )
            restrictionStore.saveRestriction(rgRecord)

            // Now issue an Administrative Ban
            val banRes = banService.issueBan(validIssueCommand())

            // TC-026 store must contain 2 distinct records
            val allRestrictions = restrictionStore.findActiveRestrictions(tenantId, subjectRef, fixedNow)
            assertEquals(2, allRestrictions.size)

            val rg = allRestrictions.first { it.source == RestrictionSource.RESPONSIBLE_GAMING }
            assertEquals(rgRecord.restrictionId, rg.restrictionId)

            val ban = allRestrictions.first { it.source == RestrictionSource.ADMINISTRATIVE_BAN }
            assertEquals(banRes.restrictionRecord.restrictionId, ban.restrictionId)
            assertEquals("TOS_FRAUD_CHARGEBACK", ban.reasonCode)
        }
    }

    // =========================================================================
    // 9. Process Restart and Durable Recovery
    // =========================================================================

    @Nested
    @DisplayName("9. Process Restart and Recovery")
    inner class RestartRecoveryTests {
        @Test
        fun `Ban survives service restart and continues authoritative enforcement`() {
            val issueRes = banService.issueBan(validIssueCommand())

            // Simulate process restart: new service instance with fresh session directory and same durable store
            val newSessions = FakeAdminSessionDirectory()
            val restartedService = AdministrativeBanService(
                policy = rbacPolicy,
                sessions = newSessions,
                banStore = banStore,
                restrictionStore = restrictionStore,
                deviceStore = deviceStore,
                clock = clock
            )

            val activeBan = restartedService.evaluateExpiry(tenantId, subjectRef, fixedNow)
            assertNotNull(activeBan)
            assertEquals(issueRes.ban.banId, activeBan?.banId)
            assertEquals(BanStatus.ACTIVE, activeBan?.status)

            // Direct API enforcement persists
            val authRes = tc026Evaluator.evaluate(
                OperationEvaluationContext(
                    operation = ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION,
                    tenantId = tenantId,
                    subjectReference = subjectRef,
                    now = fixedNow
                )
            )
            assertEquals(AccessDecision.DENY, authRes.compositeAccess)
        }
    }
}
