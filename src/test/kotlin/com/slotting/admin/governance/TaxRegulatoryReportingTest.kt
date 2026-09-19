package com.slotting.admin.governance

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class TaxRegulatoryReportingTest {
    private val now = Instant.parse("2026-09-19T08:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val securityAdmin = AuthenticatedPrincipal(
        id = "sec-admin-1",
        tenantId = "tenant-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private fun sessionDirectory(
        active: Boolean = true,
        expiresAt: Instant = now.plus(Duration.ofHours(1)),
        failing: Boolean = false,
    ) = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            if (failing) throw RuntimeException("Session directory down")
            return AdminSessionStatus(active = active, breakGlass = false, expiresAt = expiresAt)
        }
    }

    private fun sampleMarketLicence(
        tenantId: String = "tenant-1",
        marketId: String = "US-NJ",
        operatorId: String = "operator-prime",
        status: MarketLicenceStatus = MarketLicenceStatus.ACTIVE,
        expiresAt: Instant = now.plusSeconds(86400 * 365),
    ) = MarketLicenceEntry(
        matrixId = UUID.randomUUID(),
        tenantId = tenantId,
        marketId = marketId,
        operatorId = operatorId,
        licenceNumber = "LIC-NJ-2026-001",
        authorizedStoreChannels = setOf("GOOGLE_PLAY_STORE"),
        qualifiedSignatory = "General Counsel",
        effectiveFrom = now.minusSeconds(3600),
        expiresAt = expiresAt,
        status = status,
        evidenceReference = "EVID-LIC-1",
        version = 1L,
    )

    private fun sampleTaxRule() = TaxRuleSpecification(
        ggrTaxRatePercent = 15.0,
        withholdingTaxRatePercent = 24.0,
        withholdingThresholdMinorUnits = 120000L,
        reportingFrequency = ReportingFrequency.MONTHLY,
        regulatoryBodyCode = "DGE_NJ",
    )

    private fun sampleApproveCommand(
        principal: AuthenticatedPrincipal? = securityAdmin,
        sessionId: String = "sess-1",
        tenantId: String = "tenant-1",
        marketId: String = "US-NJ",
        operatorId: String = "operator-prime",
        taxRule: TaxRuleSpecification = sampleTaxRule(),
        qualifiedSignatory: String = "Tax Director & Compliance VP",
        effectiveFrom: Instant = now.minusSeconds(3600),
        expiresAt: Instant = now.plusSeconds(86400 * 365),
        idempotencyKey: String = "idem-tax-1",
        correlationId: String = "corr-tax-1",
        causationId: String = "cause-tax-1",
        expectedVersion: Long = 1L,
    ) = ApproveTaxReportingRulesCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        marketId = marketId,
        operatorId = operatorId,
        taxRule = taxRule,
        qualifiedSignatory = qualifiedSignatory,
        effectiveFrom = effectiveFrom,
        expiresAt = expiresAt,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun service(
        sessionDir: AdminSessionDirectory = sessionDirectory(),
        marketStore: MarketLicenceStore = InMemoryMarketLicenceStore(),
        store: TaxRegulatoryReportingStore = InMemoryTaxRegulatoryReportingStore(),
    ) = TaxRegulatoryReportingService(
        sessions = sessionDir,
        marketLicenceStore = marketStore,
        store = store,
        clock = clock,
    )

    @Test
    fun `GOV-001-03-T001 Approve tax and regulatory reporting rules produces the required authoritative outcome`() {
        val marketStore = InMemoryMarketLicenceStore()
        val marketLicence = sampleMarketLicence()
        marketStore.entries["tenant-1:US-NJ:operator-prime"] = marketLicence

        val store = InMemoryTaxRegulatoryReportingStore()
        val s = service(marketStore = marketStore, store = store)

        val cmd = sampleApproveCommand()
        val res = s.approveTaxReportingRules(cmd)

        // 1. Authoritative approval outcome
        assertEquals(TaxReportingStatus.ACTIVE, res.status)
        assertEquals("tenant-1", res.tenantId)
        assertEquals("US-NJ", res.marketId)
        assertEquals("operator-prime", res.operatorId)
        assertFalse(res.directEligibilityGranted, "directEligibilityGranted must be false")
        assertFalse(res.financialMutationPermitted, "financialMutationPermitted must be false")
        assertTrue(res.evidenceReference.startsWith("GOV-TAX-tenant-1-US-NJ-operator-prime-"))
        assertEquals(now, res.serverTime)

        // 2. Evaluation produces GO
        val eval = s.evaluateTaxReportingReadiness(
            EvaluateTaxReportingCommand(
                tenantId = "tenant-1",
                marketId = "US-NJ",
                operatorId = "operator-prime",
                correlationId = "corr-eval-1",
                causationId = "cause-eval-1",
            )
        )
        assertEquals(TaxReportingDecision.GO, eval.decision)
        assertEquals(TaxReportingReason.APPROVED_AND_ACTIVE, eval.reason)
        assertEquals(15.0, eval.taxRule?.ggrTaxRatePercent)
        assertEquals(24.0, eval.taxRule?.withholdingTaxRatePercent)
        assertEquals(120000L, eval.taxRule?.withholdingThresholdMinorUnits)
        assertEquals(ReportingFrequency.MONTHLY, eval.taxRule?.reportingFrequency)
        assertEquals("DGE_NJ", eval.taxRule?.regulatoryBodyCode)
        assertFalse(eval.directEligibilityGranted)
        assertFalse(eval.financialMutationPermitted)

        // 3. Audit and Outbox events published
        assertEquals(1, store.audit.size)
        val audit = store.audit[0]
        assertEquals("TAX_REPORTING_RULES_APPROVED", audit.type)
        assertEquals("tenant-1", audit.tenantId)
        assertEquals("corr-tax-1", audit.correlationId)

        assertEquals(1, store.outbox.size)
        val outbox = store.outbox[0]
        assertEquals("TaxReportingRulesApproved", outbox.type)
        assertEquals("tenant-1", outbox.tenantId)
    }

    @Test
    fun `GOV-001-03-T002 Missing approval, stale approval, or missing prerequisite results in NO-GO`() {
        val marketStore = InMemoryMarketLicenceStore()
        val store = InMemoryTaxRegulatoryReportingStore()
        val s = service(marketStore = marketStore, store = store)

        // Missing approval -> NO-GO with MISSING_APPROVAL
        val evalMissing = s.evaluateTaxReportingReadiness(
            EvaluateTaxReportingCommand(
                tenantId = "tenant-1",
                marketId = "US-NJ",
                operatorId = "operator-prime",
                correlationId = "corr-eval-miss",
                causationId = "cause-eval-miss",
            )
        )
        assertEquals(TaxReportingDecision.NO_GO, evalMissing.decision)
        assertEquals(TaxReportingReason.MISSING_APPROVAL, evalMissing.reason)
        assertFalse(evalMissing.directEligibilityGranted)
        assertFalse(evalMissing.financialMutationPermitted)

        // Set up active market licence and approve tax rules
        val marketLicence = sampleMarketLicence()
        marketStore.entries["tenant-1:US-NJ:operator-prime"] = marketLicence

        s.approveTaxReportingRules(
            sampleApproveCommand(
                effectiveFrom = now.minusSeconds(3600),
                expiresAt = now.plusSeconds(5), // expires in 5s
            )
        )

        val laterClock = Clock.fixed(now.plusSeconds(10), ZoneOffset.UTC)
        val laterService = TaxRegulatoryReportingService(
            sessions = sessionDirectory(),
            marketLicenceStore = marketStore,
            store = store,
            clock = laterClock,
        )

        // Expired approval -> NO-GO with STALE_OR_EXPIRED
        val evalExpired = laterService.evaluateTaxReportingReadiness(
            EvaluateTaxReportingCommand(
                tenantId = "tenant-1",
                marketId = "US-NJ",
                operatorId = "operator-prime",
                correlationId = "corr-eval-exp",
                causationId = "cause-eval-exp",
            )
        )
        assertEquals(TaxReportingDecision.NO_GO, evalExpired.decision)
        assertEquals(TaxReportingReason.STALE_OR_EXPIRED, evalExpired.reason)

        // Clear and approve with valid dates, but revoke underlying market licence
        val store2 = InMemoryTaxRegulatoryReportingStore()
        val s2 = service(marketStore = marketStore, store = store2)
        s2.approveTaxReportingRules(sampleApproveCommand(idempotencyKey = "idem-tax-active"))

        // Revoke underlying market licence (GOV-001-01 dependency)
        marketStore.entries["tenant-1:US-NJ:operator-prime"] = marketLicence.copy(status = MarketLicenceStatus.REVOKED)

        val evalLicenceRevoked = s2.evaluateTaxReportingReadiness(
            EvaluateTaxReportingCommand(
                tenantId = "tenant-1",
                marketId = "US-NJ",
                operatorId = "operator-prime",
                correlationId = "corr-eval-lic-rev",
                causationId = "cause-eval-lic-rev",
            )
        )
        assertEquals(TaxReportingDecision.NO_GO, evalLicenceRevoked.decision)
        assertEquals(TaxReportingReason.MARKET_LICENCE_REVOKED, evalLicenceRevoked.reason)

        // Remove underlying market licence completely
        marketStore.entries.remove("tenant-1:US-NJ:operator-prime")
        val evalLicenceMissing = s2.evaluateTaxReportingReadiness(
            EvaluateTaxReportingCommand(
                tenantId = "tenant-1",
                marketId = "US-NJ",
                operatorId = "operator-prime",
                correlationId = "corr-eval-lic-miss",
                causationId = "cause-eval-lic-miss",
            )
        )
        assertEquals(TaxReportingDecision.NO_GO, evalLicenceMissing.decision)
        assertEquals(TaxReportingReason.MARKET_LICENCE_MISSING, evalLicenceMissing.reason)
    }

    @Test
    fun `GOV-001-03-T003 Rollback revokes market tax rules and publishes audit and outbox events`() {
        val marketStore = InMemoryMarketLicenceStore()
        val marketLicence = sampleMarketLicence()
        marketStore.entries["tenant-1:US-NJ:operator-prime"] = marketLicence

        val store = InMemoryTaxRegulatoryReportingStore()
        val s = service(marketStore = marketStore, store = store)

        // 1. Initial Approval
        val appCmd = sampleApproveCommand()
        val appRes = s.approveTaxReportingRules(appCmd)
        assertEquals(TaxReportingStatus.ACTIVE, appRes.status)

        // Verify active GO
        val evalActive = s.evaluateTaxReportingReadiness(
            EvaluateTaxReportingCommand(
                tenantId = "tenant-1",
                marketId = "US-NJ",
                operatorId = "operator-prime",
                correlationId = "corr-eval-1",
                causationId = "cause-eval-1",
            )
        )
        assertEquals(TaxReportingDecision.GO, evalActive.decision)

        // 2. Rollback / Revocation
        val revokeCmd = RevokeTaxReportingRulesCommand(
            principal = securityAdmin,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            revocationReason = "Regulatory compliance audit failed",
            qualifiedSignatory = "Chief Risk Officer",
            idempotencyKey = "idem-revoke-1",
            correlationId = "corr-revoke-1",
            causationId = "cause-revoke-1",
            expectedVersion = 1L,
        )

        val revokeRes = s.rollbackOrRevokeTaxReportingRules(revokeCmd)
        assertEquals(TaxReportingStatus.REVOKED, revokeRes.status)
        assertFalse(revokeRes.directEligibilityGranted)
        assertFalse(revokeRes.financialMutationPermitted)

        // 3. Evaluation after revocation yields NO-GO with REVOKED
        val evalRevoked = s.evaluateTaxReportingReadiness(
            EvaluateTaxReportingCommand(
                tenantId = "tenant-1",
                marketId = "US-NJ",
                operatorId = "operator-prime",
                correlationId = "corr-eval-2",
                causationId = "cause-eval-2",
            )
        )
        assertEquals(TaxReportingDecision.NO_GO, evalRevoked.decision)
        assertEquals(TaxReportingReason.REVOKED, evalRevoked.reason)

        // 4. Audit & Outbox events for revocation
        assertEquals(2, store.audit.size)
        val revAudit = store.audit[1]
        assertEquals("TAX_REPORTING_RULES_REVOKED", revAudit.type)
        assertEquals("corr-revoke-1", revAudit.correlationId)

        assertEquals(2, store.outbox.size)
        val revOutbox = store.outbox[1]
        assertEquals("TaxReportingRulesRevoked", revOutbox.type)

        // 5. Idempotent repeat call to revocation returns identical outcome
        val repeatRevoke = s.rollbackOrRevokeTaxReportingRules(revokeCmd)
        assertEquals(TaxReportingStatus.REVOKED, repeatRevoke.status)
        assertEquals(revokeRes.resultId, repeatRevoke.resultId)
    }

    @Test
    fun `GOV-001-03-T004 Authority boundary, concurrent updates, and idempotency guarantees are enforced`() {
        val marketStore = InMemoryMarketLicenceStore()
        val marketLicence = sampleMarketLicence()
        marketStore.entries["tenant-1:US-NJ:operator-prime"] = marketLicence

        val store = InMemoryTaxRegulatoryReportingStore()
        val s = service(marketStore = marketStore, store = store)

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveTaxReportingRules(sampleApproveCommand(principal = null))
        }

        // 2. Cross-tenant rejected
        val otherTenantAdmin = AuthenticatedPrincipal(
            id = "sec-admin-2",
            tenantId = "tenant-2",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveTaxReportingRules(sampleApproveCommand(principal = otherTenantAdmin))
        }

        // 3. Missing SECURITY or SUPER_ADMIN role rejected
        val supportPrincipal = AuthenticatedPrincipal(
            id = "supp-admin-1",
            tenantId = "tenant-1",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPPORT),
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveTaxReportingRules(sampleApproveCommand(principal = supportPrincipal))
        }

        // 4. Expired admin session rejected
        val sExpired = service(
            sessionDir = sessionDirectory(expiresAt = now.minusSeconds(10)),
            marketStore = marketStore,
            store = store,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            sExpired.approveTaxReportingRules(sampleApproveCommand())
        }

        // 5. Invalid tax rate (> 100% or < 0%) rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveTaxReportingRules(
                sampleApproveCommand(
                    taxRule = sampleTaxRule().copy(ggrTaxRatePercent = 105.0)
                )
            )
        }
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveTaxReportingRules(
                sampleApproveCommand(
                    taxRule = sampleTaxRule().copy(withholdingTaxRatePercent = -5.0)
                )
            )
        }

        // 6. Blank qualified owner signature rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveTaxReportingRules(sampleApproveCommand(qualifiedSignatory = "   "))
        }

        // 7. Successful initial approval
        val cmd = sampleApproveCommand(idempotencyKey = "idem-multithread")
        val initialRes = s.approveTaxReportingRules(cmd)
        assertEquals(TaxReportingStatus.ACTIVE, initialRes.status)

        // 8. Idempotency replay returns exact cached outcome
        val replayed = s.approveTaxReportingRules(cmd)
        assertEquals(initialRes.resultId, replayed.resultId)

        // 9. Idempotency key conflict with mismatched payload rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            s.approveTaxReportingRules(
                cmd.copy(
                    taxRule = sampleTaxRule().copy(ggrTaxRatePercent = 20.0)
                )
            )
        }

        // 10. Concurrent revocation with expectedVersion collision
        val executor = Executors.newFixedThreadPool(2)
        val latch = CountDownLatch(1)
        val revokeCmd1 = RevokeTaxReportingRulesCommand(
            principal = securityAdmin,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            revocationReason = "Revocation 1",
            qualifiedSignatory = "VP Risk",
            idempotencyKey = "idem-race-1",
            correlationId = "corr-race-1",
            causationId = "cause-race-1",
            expectedVersion = 1L,
        )
        val revokeCmd2 = RevokeTaxReportingRulesCommand(
            principal = securityAdmin,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            marketId = "US-NJ",
            operatorId = "operator-prime",
            revocationReason = "Revocation 2",
            qualifiedSignatory = "VP Risk",
            idempotencyKey = "idem-race-2",
            correlationId = "corr-race-2",
            causationId = "cause-race-2",
            expectedVersion = 1L,
        )

        val results = mutableListOf<Result<TaxReportingApprovalResult>>()
        val fut1 = executor.submit(java.util.concurrent.Callable {
            latch.await()
            runCatching { s.rollbackOrRevokeTaxReportingRules(revokeCmd1) }
        })
        val fut2 = executor.submit(java.util.concurrent.Callable {
            latch.await()
            runCatching { s.rollbackOrRevokeTaxReportingRules(revokeCmd2) }
        })

        latch.countDown()
        results.add(fut1.get())
        results.add(fut2.get())
        executor.shutdown()

        val successCount = results.count { it.isSuccess }
        val conflictCount = results.count { it.isFailure && it.exceptionOrNull() is AuthenticationFailure.Rejected }

        assertEquals(1, successCount, "Exactly one concurrent update should succeed")
        assertEquals(1, conflictCount, "The other concurrent update must fail with optimistic lock conflict")
    }
}
