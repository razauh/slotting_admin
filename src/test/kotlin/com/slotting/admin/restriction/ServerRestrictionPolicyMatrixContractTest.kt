package com.slotting.admin.restriction

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
 * TC-026 TDD Contract Test Suite: Distinct Server Restriction Sources and Operation Policy Matrix.
 * Encodes the approved deterministic baseline for:
 * - Dual-axis decision: AccessDecision (DENY > STEP_UP > ALLOW) and FinancialDisposition (HOLD, CANCEL, etc.)
 * - Scope handling: WholeAccount vs Scoped (ProviderScoped)
 * - Multiple simultaneous active restrictions and provenance retention
 * - Durable store authority over cache (cache loss cannot unlock)
 * - Restart and audit invariants
 */
class ServerRestrictionPolicyMatrixContractTest {

    private val tenantId = "tenant-prod-alpha"
    private val subjectRef = "player-sub-8812"
    private val fixedNow = Instant.parse("2026-09-26T12:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    private lateinit var store: InMemoryServerRestrictionStore
    private lateinit var cache: InMemoryEphemeralRestrictionCache
    private lateinit var evaluator: ServerRestrictionEvaluator
    private lateinit var gate: ServerRestrictionEnforcementGate

    @BeforeEach
    fun setUp() {
        store = InMemoryServerRestrictionStore()
        cache = InMemoryEphemeralRestrictionCache()
        evaluator = DefaultServerRestrictionEvaluator(store, cache, clock)
        gate = ServerRestrictionEnforcementGate(evaluator)
    }

    private fun addRestriction(
        source: RestrictionSource,
        scope: RestrictionScope = RestrictionScope.WholeAccount,
        reasonCode: String = "${source.name}_REASON",
        effectiveFrom: Instant = fixedNow.minus(1, ChronoUnit.HOURS),
        expiresAt: Instant? = null,
        evidenceRef: String = "EVID-${UUID.randomUUID()}",
        ruleVersion: Long = 1L
    ): ServerRestrictionRecord {
        val record = ServerRestrictionRecord(
            tenantId = tenantId,
            subjectReference = subjectRef,
            source = source,
            reasonCode = reasonCode,
            safeUserMessage = "Account restricted due to $source",
            scope = scope,
            effectiveFrom = effectiveFrom,
            expiresAt = expiresAt,
            evidenceReference = evidenceRef,
            ruleVersion = ruleVersion,
            issuer = "ADMIN_TEST"
        )
        store.saveRestriction(record)
        return record
    }

    private fun context(
        operation: ServerOperation,
        providerId: String? = null,
        isSensitiveDataExport: Boolean = false,
        isRemediationFlow: Boolean = false,
        isDedicatedLegalAccessPath: Boolean = false,
        pendingOperationType: PendingOperationType? = null,
        unwageredBalanceOnly: Boolean = false
    ): OperationEvaluationContext = OperationEvaluationContext(
        operation = operation,
        tenantId = tenantId,
        subjectReference = subjectRef,
        providerId = providerId,
        isSensitiveDataExport = isSensitiveDataExport,
        isRemediationFlow = isRemediationFlow,
        isDedicatedLegalAccessPath = isDedicatedLegalAccessPath,
        pendingOperationType = pendingOperationType,
        unwageredBalanceOnly = unwageredBalanceOnly,
        now = fixedNow
    )

    // =========================================================================
    // 1. Single Restriction × Operation Base Combinations
    // =========================================================================

    @Nested
    @DisplayName("1. Administrative Ban Matrix")
    inner class AdministrativeBanTests {
        @BeforeEach
        fun setupBan() {
            addRestriction(RestrictionSource.ADMINISTRATIVE_BAN)
        }

        @Test
        fun `Authentication is DENIED`() {
            val res = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
        }

        @Test
        fun `New Game Session is DENIED`() {
            val res = evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
        }

        @Test
        fun `Wager is DENIED`() {
            val res = evaluator.evaluate(context(ServerOperation.WAGER))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
        }

        @Test
        fun `Deposit is DENIED`() {
            val res = evaluator.evaluate(context(ServerOperation.DEPOSIT))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
        }

        @Test
        fun `Withdrawal access is DENIED and pending disposition is HOLD`() {
            val res = evaluator.evaluate(context(ServerOperation.WITHDRAWAL))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }

        @Test
        fun `Support Access is ALLOWED for appeal and remediation`() {
            val res = evaluator.evaluate(context(ServerOperation.SUPPORT_ACCESS))
            assertEquals(AccessDecision.ALLOW, res.compositeAccess)
        }

        @Test
        fun `KYC Submission is ALLOWED for appeal remediation`() {
            val res = evaluator.evaluate(context(ServerOperation.KYC_COMPLIANCE_SUBMISSION))
            assertEquals(AccessDecision.ALLOW, res.compositeAccess)
        }

        @Test
        fun `Account Data Access is ALLOWED only through dedicated legal access path`() {
            val normal = evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS, isDedicatedLegalAccessPath = false))
            assertEquals(AccessDecision.DENY, normal.compositeAccess)

            val legal = evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS, isDedicatedLegalAccessPath = true))
            assertEquals(AccessDecision.ALLOW, legal.compositeAccess)
        }

        @Test
        fun `Pending Operations disposition is HOLD`() {
            val res = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS))
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }
    }

    @Nested
    @DisplayName("2. Fraud and Security Flag Matrix")
    inner class FraudSecurityTests {
        @BeforeEach
        fun setupFraud() {
            addRestriction(RestrictionSource.FRAUD_SECURITY)
        }

        @Test
        fun `Authentication is DENIED by default, STEP_UP on remediation flow`() {
            val normal = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION, isRemediationFlow = false))
            assertEquals(AccessDecision.DENY, normal.compositeAccess)

            val rem = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION, isRemediationFlow = true))
            assertEquals(AccessDecision.STEP_UP, rem.compositeAccess)
        }

        @Test
        fun `Gaming and Wagering and Deposits are DENIED`() {
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.WAGER)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.DEPOSIT)).compositeAccess)
        }

        @Test
        fun `Withdrawal access is DENIED and disposition is HOLD`() {
            val res = evaluator.evaluate(context(ServerOperation.WITHDRAWAL))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }

        @Test
        fun `Support and KYC remediation are ALLOWED`() {
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.SUPPORT_ACCESS)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.KYC_COMPLIANCE_SUBMISSION)).compositeAccess)
        }

        @Test
        fun `Account Data Access requires STEP_UP for sensitive export, otherwise ALLOWED`() {
            val normal = evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS, isSensitiveDataExport = false))
            assertEquals(AccessDecision.ALLOW, normal.compositeAccess)

            val sensitive = evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS, isSensitiveDataExport = true))
            assertEquals(AccessDecision.STEP_UP, sensitive.compositeAccess)
        }

        @Test
        fun `Pending Operations disposition is HOLD`() {
            val res = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS))
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }
    }

    @Nested
    @DisplayName("3. Responsible Gaming Restriction Matrix")
    inner class ResponsibleGamingTests {
        @BeforeEach
        fun setupRg() {
            addRestriction(RestrictionSource.RESPONSIBLE_GAMING)
        }

        @Test
        fun `Authentication is ALLOWED on RG remediation surfaces`() {
            val res = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION))
            assertEquals(AccessDecision.ALLOW, res.compositeAccess)
        }

        @Test
        fun `Gambling and Deposits are strictly DENIED`() {
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.WAGER)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.DEPOSIT)).compositeAccess)
        }

        @Test
        fun `Withdrawal of unwagered funds is ALLOWED without new wagering`() {
            val normal = evaluator.evaluate(context(ServerOperation.WITHDRAWAL, unwageredBalanceOnly = false))
            assertEquals(AccessDecision.ALLOW, normal.compositeAccess)

            val unwagered = evaluator.evaluate(context(ServerOperation.WITHDRAWAL, unwageredBalanceOnly = true))
            assertEquals(AccessDecision.ALLOW, unwagered.compositeAccess)
        }

        @Test
        fun `Support, KYC, and Account Data Access are ALLOWED`() {
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.SUPPORT_ACCESS)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.KYC_COMPLIANCE_SUBMISSION)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS)).compositeAccess)
        }

        @Test
        fun `Pending Operations - Payout completes, active bets cancel, other financial holds`() {
            val payout = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, pendingOperationType = PendingOperationType.PAYOUT))
            assertEquals(FinancialDisposition.PAYOUT, payout.financialDisposition)

            val bet = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, pendingOperationType = PendingOperationType.ACTIVE_BET))
            assertEquals(FinancialDisposition.CANCEL, bet.financialDisposition)

            val general = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, pendingOperationType = PendingOperationType.GENERAL_FINANCIAL))
            assertEquals(FinancialDisposition.HOLD, general.financialDisposition)
        }
    }

    @Nested
    @DisplayName("4. KYC and AML Hold Matrix")
    inner class KycAmlHoldTests {
        @BeforeEach
        fun setupKyc() {
            addRestriction(RestrictionSource.KYC_AML)
        }

        @Test
        fun `Authentication and KYC submission are ALLOWED for remediation`() {
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.KYC_COMPLIANCE_SUBMISSION)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.SUPPORT_ACCESS)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS)).compositeAccess)
        }

        @Test
        fun `Gambling, Deposits, and Withdrawals are DENIED with HOLD`() {
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.WAGER)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.DEPOSIT)).compositeAccess)

            val w = evaluator.evaluate(context(ServerOperation.WITHDRAWAL))
            assertEquals(AccessDecision.DENY, w.compositeAccess)
            assertEquals(FinancialDisposition.HOLD, w.financialDisposition)
        }

        @Test
        fun `Pending Operations disposition is HOLD until verification cleared`() {
            val res = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS))
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }
    }

    @Nested
    @DisplayName("5. Provider-Only Scoped Restriction Matrix")
    inner class ProviderScopedTests {
        private val blockedGameProvider = "provider-spribe"
        private val allowedGameProvider = "provider-evolution"
        private val blockedPaymentProvider = "rail-upi-paytm"
        private val allowedPaymentProvider = "rail-imps-bank"

        @BeforeEach
        fun setupProviderRestrictions() {
            addRestriction(
                source = RestrictionSource.PROVIDER_RESTRICTION,
                scope = RestrictionScope.ProviderScoped(blockedGameProvider, ProviderCategory.GAME)
            )
            addRestriction(
                source = RestrictionSource.PROVIDER_RESTRICTION,
                scope = RestrictionScope.ProviderScoped(blockedPaymentProvider, ProviderCategory.PAYMENT)
            )
        }

        @Test
        fun `Provider restriction does not restrict whole account authentication or data access`() {
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.SUPPORT_ACCESS)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS)).compositeAccess)
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.KYC_COMPLIANCE_SUBMISSION)).compositeAccess)
        }

        @Test
        fun `Game Session and Wager DENIED only for restricted game provider, ALLOWED for others`() {
            val blockedGame = evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION, providerId = blockedGameProvider))
            assertEquals(AccessDecision.DENY, blockedGame.compositeAccess)

            val allowedGame = evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION, providerId = allowedGameProvider))
            assertEquals(AccessDecision.ALLOW, allowedGame.compositeAccess)

            val blockedWager = evaluator.evaluate(context(ServerOperation.WAGER, providerId = blockedGameProvider))
            assertEquals(AccessDecision.DENY, blockedWager.compositeAccess)

            val allowedWager = evaluator.evaluate(context(ServerOperation.WAGER, providerId = allowedGameProvider))
            assertEquals(AccessDecision.ALLOW, allowedWager.compositeAccess)
        }

        @Test
        fun `Deposit and Withdrawal DENIED only when required route matches blocked provider`() {
            val blockedDep = evaluator.evaluate(context(ServerOperation.DEPOSIT, providerId = blockedPaymentProvider))
            assertEquals(AccessDecision.DENY, blockedDep.compositeAccess)

            val allowedDep = evaluator.evaluate(context(ServerOperation.DEPOSIT, providerId = allowedPaymentProvider))
            assertEquals(AccessDecision.ALLOW, allowedDep.compositeAccess)

            val blockedWd = evaluator.evaluate(context(ServerOperation.WITHDRAWAL, providerId = blockedPaymentProvider))
            assertEquals(AccessDecision.DENY, blockedWd.compositeAccess)
            assertEquals(FinancialDisposition.HOLD, blockedWd.financialDisposition)

            val allowedWd = evaluator.evaluate(context(ServerOperation.WITHDRAWAL, providerId = allowedPaymentProvider))
            assertEquals(AccessDecision.ALLOW, allowedWd.compositeAccess)
            assertNotEquals(FinancialDisposition.HOLD, allowedWd.financialDisposition)
        }

        @Test
        fun `Pending Operations on affected provider are HELD, unaffected are COMPLETED`() {
            val affected = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, providerId = blockedPaymentProvider))
            assertEquals(FinancialDisposition.HOLD, affected.financialDisposition)

            val unaffected = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, providerId = allowedPaymentProvider))
            assertEquals(FinancialDisposition.COMPLETE, unaffected.financialDisposition)
        }
    }

    @Nested
    @DisplayName("6. Account Closure Matrix")
    inner class AccountClosureTests {
        @BeforeEach
        fun setupClosure() {
            addRestriction(RestrictionSource.ACCOUNT_CLOSURE)
        }

        @Test
        fun `Normal authentication is DENIED, dedicated legal access path is ALLOWED`() {
            val normal = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION, isDedicatedLegalAccessPath = false))
            assertEquals(AccessDecision.DENY, normal.compositeAccess)

            val legal = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION, isDedicatedLegalAccessPath = true))
            assertEquals(AccessDecision.ALLOW, legal.compositeAccess)
        }

        @Test
        fun `Gambling and Deposits are DENIED`() {
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.WAGER)).compositeAccess)
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.DEPOSIT)).compositeAccess)
        }

        @Test
        fun `Support is ALLOWED and Account Data Access is ALLOWED via legal path`() {
            assertEquals(AccessDecision.ALLOW, evaluator.evaluate(context(ServerOperation.SUPPORT_ACCESS)).compositeAccess)

            val normalData = evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS, isDedicatedLegalAccessPath = false))
            assertEquals(AccessDecision.DENY, normalData.compositeAccess)

            val legalData = evaluator.evaluate(context(ServerOperation.ACCOUNT_DATA_ACCESS, isDedicatedLegalAccessPath = true))
            assertEquals(AccessDecision.ALLOW, legalData.compositeAccess)
        }

        @Test
        fun `Withdrawal access DENIED with HOLD until closure settlement requirements satisfied`() {
            val res = evaluator.evaluate(context(ServerOperation.WITHDRAWAL))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }

        @Test
        fun `Pending Operations are HELD until closure settlement logic determines final disposition`() {
            val res = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS))
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }
    }

    // =========================================================================
    // 2. Composition and Precedence (Multiple Simultaneous Restrictions)
    // =========================================================================

    @Nested
    @DisplayName("7. Multiple Simultaneous Restrictions & Precedence")
    inner class MultipleRestrictionsPrecedenceTests {
        @Test
        fun `Simultaneous RG and Administrative Ban - Strictest Access DENY wins and all provenance is retained`() {
            val rg = addRestriction(RestrictionSource.RESPONSIBLE_GAMING, reasonCode = "RG_SELF_EXCLUSION")
            val ban = addRestriction(RestrictionSource.ADMINISTRATIVE_BAN, reasonCode = "ADMIN_CHARGEBACK_BAN")

            // In RG alone, Auth is ALLOW. In Ban, Auth is DENY. Composite MUST be DENY.
            val res = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION))
            assertEquals(AccessDecision.DENY, res.compositeAccess)

            // Provenance check: Both restrictions MUST be retained in contributingRestrictions
            assertEquals(2, res.contributingRestrictions.size)
            val sources = res.contributingRestrictions.map { it.source }
            assertTrue(sources.contains(RestrictionSource.RESPONSIBLE_GAMING))
            assertTrue(sources.contains(RestrictionSource.ADMINISTRATIVE_BAN))

            val rgContrib = res.contributingRestrictions.first { it.source == RestrictionSource.RESPONSIBLE_GAMING }
            assertEquals(rg.restrictionId, rgContrib.restrictionId)
            assertEquals("RG_SELF_EXCLUSION", rgContrib.reasonCode)
            assertEquals(AccessDecision.ALLOW, rgContrib.individualAccess)

            val banContrib = res.contributingRestrictions.first { it.source == RestrictionSource.ADMINISTRATIVE_BAN }
            assertEquals(ban.restrictionId, banContrib.restrictionId)
            assertEquals("ADMIN_CHARGEBACK_BAN", banContrib.reasonCode)
            assertEquals(AccessDecision.DENY, banContrib.individualAccess)
        }

        @Test
        fun `Simultaneous Fraud and KYC - Remediated Auth requires STEP_UP over ALLOW`() {
            addRestriction(RestrictionSource.KYC_AML) // KYC allows auth for remediation
            addRestriction(RestrictionSource.FRAUD_SECURITY) // Fraud requires STEP_UP on remediation

            val res = evaluator.evaluate(context(ServerOperation.AUTHENTICATION_OR_SESSION_CONTINUATION, isRemediationFlow = true))
            assertEquals(AccessDecision.STEP_UP, res.compositeAccess)
            assertEquals(2, res.contributingRestrictions.size)
        }

        @Test
        fun `Financial disposition selects safest HOLD over payout when combined with fraud`() {
            // RG alone would permit PAYOUT for pending financial payout
            addRestriction(RestrictionSource.RESPONSIBLE_GAMING)
            // Fraud requires HOLD on all pending financial operations
            addRestriction(RestrictionSource.FRAUD_SECURITY)

            val res = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, pendingOperationType = PendingOperationType.PAYOUT))
            assertEquals(FinancialDisposition.HOLD, res.financialDisposition)
        }

        @Test
        fun `Removing one restriction does not erase remaining active restrictions`() {
            val ban = addRestriction(RestrictionSource.ADMINISTRATIVE_BAN)
            val kyc = addRestriction(RestrictionSource.KYC_AML)

            // Both active: Wager is DENIED
            assertEquals(AccessDecision.DENY, evaluator.evaluate(context(ServerOperation.WAGER)).compositeAccess)

            // Revoke ban
            store.revokeRestriction(tenantId, ban.restrictionId, "ADMIN_UNBAN", fixedNow)
            cache.clear() // Simulate cache eviction

            // KYC is still active: Wager MUST still be DENIED
            val postRevoke = evaluator.evaluate(context(ServerOperation.WAGER))
            assertEquals(AccessDecision.DENY, postRevoke.compositeAccess)
            assertEquals(1, postRevoke.contributingRestrictions.size)
            assertEquals(RestrictionSource.KYC_AML, postRevoke.contributingRestrictions[0].source)
        }
    }

    // =========================================================================
    // 3. Expiry, Inactive, and Temporal Dynamics
    // =========================================================================

    @Nested
    @DisplayName("8. Temporal Expiry and Activation Dynamics")
    inner class TemporalDynamicsTests {
        @Test
        fun `Expired restriction is ignored and not evaluated`() {
            addRestriction(
                source = RestrictionSource.ADMINISTRATIVE_BAN,
                effectiveFrom = fixedNow.minus(2, ChronoUnit.DAYS),
                expiresAt = fixedNow.minus(1, ChronoUnit.HOURS) // Expired 1 hour ago
            )

            val res = evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION))
            assertEquals(AccessDecision.ALLOW, res.compositeAccess)
            assertTrue(res.contributingRestrictions.isEmpty())
        }

        @Test
        fun `Future restriction not yet effective is ignored`() {
            addRestriction(
                source = RestrictionSource.ADMINISTRATIVE_BAN,
                effectiveFrom = fixedNow.plus(1, ChronoUnit.HOURS) // Becomes active in 1 hour
            )

            val res = evaluator.evaluate(context(ServerOperation.NEW_GAME_SESSION))
            assertEquals(AccessDecision.ALLOW, res.compositeAccess)
            assertTrue(res.contributingRestrictions.isEmpty())
        }

        @Test
        fun `Permanent restriction with null expiry remains effective indefinitely`() {
            addRestriction(
                source = RestrictionSource.ADMINISTRATIVE_BAN,
                effectiveFrom = fixedNow.minus(10, ChronoUnit.DAYS),
                expiresAt = null
            )

            val futureCtx = OperationEvaluationContext(
                operation = ServerOperation.NEW_GAME_SESSION,
                tenantId = tenantId,
                subjectReference = subjectRef,
                now = fixedNow.plus(365, ChronoUnit.DAYS)
            )
            val res = evaluator.evaluate(futureCtx)
            assertEquals(AccessDecision.DENY, res.compositeAccess)
        }

        @Test
        fun `Restriction activated while an operation is pending produces HOLD on re-evaluation`() {
            // Initially unrestricted
            val initRes = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, pendingOperationType = PendingOperationType.PAYOUT))
            assertEquals(FinancialDisposition.COMPLETE, initRes.financialDisposition)

            // Fraud flag placed
            addRestriction(RestrictionSource.FRAUD_SECURITY)
            cache.evict(tenantId, subjectRef)

            // Re-evaluation of pending operation transitions to HOLD
            val reEval = evaluator.evaluate(context(ServerOperation.PENDING_FINANCIAL_OPERATIONS, pendingOperationType = PendingOperationType.PAYOUT))
            assertEquals(FinancialDisposition.HOLD, reEval.financialDisposition)
        }
    }

    // =========================================================================
    // 4. Cache Dynamics, Loss, and Restart Recovery
    // =========================================================================

    @Nested
    @DisplayName("9. Cache Invariants and Process Restart")
    inner class CacheAndRestartTests {
        @Test
        fun `Cache miss queries durable store and populates cache (cache hit on subsequent query)`() {
            addRestriction(RestrictionSource.ADMINISTRATIVE_BAN)

            assertEquals(0, cache.getStats().hits)
            assertEquals(0, cache.getStats().misses)

            // 1st query: Cache miss -> loads from store
            evaluator.evaluate(context(ServerOperation.WAGER))
            assertEquals(1, cache.getStats().misses)

            // 2nd query: Cache hit
            evaluator.evaluate(context(ServerOperation.WAGER))
            assertEquals(1, cache.getStats().hits)
        }

        @Test
        fun `Cache loss or flush NEVER unlocks restricted operations`() {
            addRestriction(RestrictionSource.ADMINISTRATIVE_BAN)

            // Populate cache
            val initial = evaluator.evaluate(context(ServerOperation.WAGER))
            assertEquals(AccessDecision.DENY, initial.compositeAccess)

            // Simulate total cache flush / Redis crash
            cache.clear()
            assertEquals(1, cache.getStats().evictions)

            // Operation MUST still be DENIED from durable store
            val postFlush = evaluator.evaluate(context(ServerOperation.WAGER))
            assertEquals(AccessDecision.DENY, postFlush.compositeAccess)
            assertEquals(1, postFlush.contributingRestrictions.size)
        }

        @Test
        fun `Process restart with cold cache converges on identical authoritative decisions`() {
            val ban = addRestriction(RestrictionSource.ADMINISTRATIVE_BAN, ruleVersion = 42L)

            // Cold restart: new cache instance, same durable store
            val freshCache = InMemoryEphemeralRestrictionCache()
            val restartedEvaluator = DefaultServerRestrictionEvaluator(store, freshCache, clock)

            val res = restartedEvaluator.evaluate(context(ServerOperation.WAGER))
            assertEquals(AccessDecision.DENY, res.compositeAccess)
            assertEquals(ban.restrictionId, res.contributingRestrictions[0].restrictionId)
            assertEquals(42L, res.contributingRestrictions[0].ruleVersion)
        }
    }

    // =========================================================================
    // 5. Authoritative Boundary Enforcement Gate Tests
    // =========================================================================

    @Nested
    @DisplayName("10. Authoritative Enforcement Gate Contracts")
    inner class EnforcementGateTests {
        @Test
        fun `Gate throws ServerRestrictionDeniedException when composite access is DENY`() {
            addRestriction(RestrictionSource.ADMINISTRATIVE_BAN)

            val ex = assertThrows(ServerRestrictionDeniedException::class.java) {
                gate.enforce(context(ServerOperation.WAGER))
            }
            assertEquals(AccessDecision.DENY, ex.result.compositeAccess)
            assertEquals(ServerOperation.WAGER, ex.result.operation)
        }

        @Test
        fun `Gate throws ServerRestrictionStepUpRequiredException when composite access is STEP_UP`() {
            addRestriction(RestrictionSource.FRAUD_SECURITY)

            val ex = assertThrows(ServerRestrictionStepUpRequiredException::class.java) {
                gate.enforce(context(ServerOperation.ACCOUNT_DATA_ACCESS, isSensitiveDataExport = true))
            }
            assertEquals(AccessDecision.STEP_UP, ex.result.compositeAccess)
        }

        @Test
        fun `Gate succeeds and returns result when composite access is ALLOW`() {
            // No restriction
            val result = gate.enforce(context(ServerOperation.WAGER))
            assertEquals(AccessDecision.ALLOW, result.compositeAccess)
            assertTrue(result.isAllowed)
            assertFalse(result.isDenied)
        }
    }
}
