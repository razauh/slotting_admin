package com.slotting.admin.privacy

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ComplianceGovernanceContractTest {

    private val fixedNow = Instant.parse("2026-09-26T12:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)
    private val tenantId = "tenant-compliance-test"

    // RBAC Principals
    private val policyMakerPrincipal = AuthenticatedPrincipal(
        id = "admin-maker-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val policyCheckerPrincipal = AuthenticatedPrincipal(
        id = "admin-checker-02",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "admin-auditor-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val supportPrincipal = AuthenticatedPrincipal(
        id = "admin-support-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val rbacPolicy = AdminRbacPolicy(dualControlRequired = true)
    private val auditEvents = mutableListOf<AuditEvent>()

    // Adapters
    private lateinit var authAdapter: AuthenticationStoreAdapter
    private lateinit var ledgerAdapter: LedgerStoreAdapter
    private lateinit var kycAdapter: KycStoreAdapter
    private lateinit var fraudAdapter: FraudStoreAdapter
    private lateinit var rgAdapter: ResponsibleGamingStoreAdapter
    private lateinit var supportAdapter: SupportStoreAdapter
    private lateinit var suppressionAdapter: NotificationSuppressionAdapter
    private lateinit var externalProviderAdapter: ExternalPrivacyProviderAdapter

    private lateinit var complianceService: ComplianceGovernanceService
    private lateinit var dsarOrchestrator: DsarOrchestrationService

    @BeforeEach
    fun setUp() {
        auditEvents.clear()

        authAdapter = AuthenticationStoreAdapter()
        ledgerAdapter = LedgerStoreAdapter()
        kycAdapter = KycStoreAdapter()
        fraudAdapter = FraudStoreAdapter()
        rgAdapter = ResponsibleGamingStoreAdapter()
        supportAdapter = SupportStoreAdapter()
        suppressionAdapter = NotificationSuppressionAdapter()

        val extConfig = ExternalPrivacyProviderConfig(
            providerId = "provider-analytics-01",
            providerType = "ANALYTICS",
            endpointUrl = "https://analytics-privacy.example.internal/dsar",
            encryptedApiKey = byteArrayOf(1, 2, 3),
            iv = byteArrayOf(4, 5, 6),
            supportsAutomatedErasure = true,
        )
        externalProviderAdapter = ExternalPrivacyProviderAdapter(extConfig)

        complianceService = ComplianceGovernanceService(
            rbacPolicy = rbacPolicy,
            clock = clock,
            auditSink = { auditEvents.add(it) },
        )

        dsarOrchestrator = DsarOrchestrationService(
            rbacPolicy = rbacPolicy,
            complianceService = complianceService,
            adapters = listOf(
                authAdapter,
                ledgerAdapter,
                kycAdapter,
                fraudAdapter,
                rgAdapter,
                supportAdapter,
                suppressionAdapter,
                externalProviderAdapter,
            ),
            clock = clock,
            auditSink = { auditEvents.add(it) },
        )
    }

    @Test
    fun `test 1 - Maker-Checker Enforcement - Creator cannot approve or activate own retention policy`() {
        // 1. Maker creates draft policy
        val draftPolicy = complianceService.createPolicy(
            principal = policyMakerPrincipal,
            config = RetentionPolicyConfig(
                dataCategory = DataCategory.SESSION_DATA,
                jurisdiction = "GLOBAL",
                purpose = "Operational Session Tracking",
                policyReference = "POL-SESSION-001",
                retentionDuration = 90,
                durationUnit = DurationUnit.DAYS,
                retentionStartTrigger = RetentionTrigger.LAST_ACTIVITY,
                postRetentionAction = PostRetentionAction.DELETE,
                priority = 10,
                createdBy = policyMakerPrincipal.id,
            )
        )
        assertEquals(PolicyApprovalStatus.DRAFT, draftPolicy.approvalStatus)
        assertEquals(policyMakerPrincipal.id, draftPolicy.createdBy)

        // 2. Maker attempts to approve own policy -> MUST fail
        val approveEx = assertFailsWith<IllegalStateException> {
            complianceService.approvePolicy(policyMakerPrincipal, draftPolicy.policyId)
        }
        assertTrue(approveEx.message!!.contains("Maker-checker violation"))

        // 3. Maker attempts to activate own policy -> MUST fail
        val activateEx = assertFailsWith<IllegalStateException> {
            complianceService.activatePolicy(policyMakerPrincipal, draftPolicy.policyId)
        }
        assertTrue(activateEx.message!!.contains("Maker-checker violation"))

        // 4. Distinct checker approves and activates -> SUCCEEDS
        val approved = complianceService.approvePolicy(policyCheckerPrincipal, draftPolicy.policyId)
        assertEquals(PolicyApprovalStatus.APPROVED, approved.approvalStatus)
        assertEquals(policyCheckerPrincipal.id, approved.approvedBy)

        val activated = complianceService.activatePolicy(policyCheckerPrincipal, draftPolicy.policyId)
        assertEquals(PolicyApprovalStatus.ACTIVE, activated.approvalStatus)
        assertEquals(policyCheckerPrincipal.id, activated.activatedBy)

        // 5. Verify policy is discoverable as active
        val activeFound = complianceService.findActivePolicy(DataCategory.SESSION_DATA, "GLOBAL", RetentionTrigger.LAST_ACTIVITY)
        assertNotNull(activeFound)
        assertEquals("POL-SESSION-001", activeFound.policyReference)
    }

    @Test
    fun `test 2 - Legal Hold Precedence - Scoped hold blocks destructive action while unheld categories proceed`() {
        val subjectId = "player-under-investigation-101"

        // Setup subject data across stores
        authAdapter.activeSessions[subjectId] = mutableSetOf("sess-1", "sess-2")
        authAdapter.credentials[subjectId] = "hash123"
        kycAdapter.documents[subjectId] = mutableListOf(KycStoreAdapter.KycDoc("doc-1", "passport.pdf"))

        // Place scoped hold ONLY on KYC_DOCUMENTS
        val hold = complianceService.placeHold(
            principal = policyMakerPrincipal,
            hold = ScopedLegalHoldRecord(
                tenantId = tenantId,
                holdReference = "HOLD-KYC-COURT-001",
                subjectId = subjectId,
                matterId = "MATTER-2026-99",
                jurisdiction = "MALTA",
                targetCategories = setOf(DataCategory.KYC_DOCUMENTS),
                reason = "Court subpoena requiring preservation of identity verification records",
                placedBy = policyMakerPrincipal.id,
            )
        )
        assertTrue(complianceService.isHeld(subjectId, DataCategory.KYC_DOCUMENTS))
        assertFalse(complianceService.isHeld(subjectId, DataCategory.SESSION_DATA))

        // Execute DSAR erasure request targeting both categories
        val result = dsarOrchestrator.executeDsar(
            principal = policyMakerPrincipal,
            command = ExecuteDsarCommand(
                tenantId = tenantId,
                subjectId = subjectId,
                requestedAction = PostRetentionAction.DELETE,
                categories = setOf(DataCategory.SESSION_DATA, DataCategory.KYC_DOCUMENTS),
                idempotencyKey = "idemp-hold-test-001",
                correlationId = "corr-1",
                causationId = "cause-1",
            )
        )

        // Overall status must be RESTRICTED_BY_HOLD
        assertEquals(OverallDsarStatus.RESTRICTED_BY_HOLD, result.overallStatus)

        // Verify per-store receipts
        val kycReceipt = result.receipts.find { it.dataCategory == DataCategory.KYC_DOCUMENTS }
        assertNotNull(kycReceipt)
        assertEquals(StoreActionStatus.HELD, kycReceipt.status)
        assertEquals(PostRetentionAction.HOLD, kycReceipt.executedAction)

        val authReceipt = result.receipts.find { it.dataCategory == DataCategory.SESSION_DATA }
        assertNotNull(authReceipt)
        assertEquals(StoreActionStatus.COMPLETED, authReceipt.status)
        assertEquals(PostRetentionAction.DELETE, authReceipt.executedAction)

        // Verify non-readability on deleted data vs retention on held data
        val authQuery = authAdapter.queryData(tenantId, subjectId, DataCategory.SESSION_DATA)
        assertEquals(0, authQuery.recordCount) // deleted

        val kycQuery = kycAdapter.queryData(tenantId, subjectId, DataCategory.KYC_DOCUMENTS)
        assertEquals(1, kycQuery.recordCount) // preserved due to hold
    }

    @Test
    fun `test 3 - Legal Hold Release - Release does not auto-delete but permits subsequent erasure`() {
        val subjectId = "player-released-hold-202"
        kycAdapter.documents[subjectId] = mutableListOf(KycStoreAdapter.KycDoc("doc-2", "utility_bill.pdf"))

        val hold = complianceService.placeHold(
            principal = policyMakerPrincipal,
            hold = ScopedLegalHoldRecord(
                tenantId = tenantId,
                holdReference = "HOLD-RELEASE-TEST",
                subjectId = subjectId,
                matterId = "MATTER-CLOSED-01",
                reason = "Preservation order",
                placedBy = policyMakerPrincipal.id,
            )
        )
        assertTrue(complianceService.isHeld(subjectId, DataCategory.KYC_DOCUMENTS))

        // Release hold with audited justification
        val released = complianceService.releaseHold(
            principal = policyCheckerPrincipal,
            holdId = hold.holdId,
            justification = "Investigation closed; no regulatory proceedings initiated"
        )
        assertFalse(released.active)
        assertFalse(complianceService.isHeld(subjectId, DataCategory.KYC_DOCUMENTS))

        // Document must NOT have been auto-deleted immediately upon hold release
        val queryBeforeDsar = kycAdapter.queryData(tenantId, subjectId, DataCategory.KYC_DOCUMENTS)
        assertEquals(1, queryBeforeDsar.recordCount)

        // Subsequent DSAR erasure executes successfully
        val result = dsarOrchestrator.executeDsar(
            principal = policyMakerPrincipal,
            command = ExecuteDsarCommand(
                tenantId = tenantId,
                subjectId = subjectId,
                requestedAction = PostRetentionAction.DELETE,
                categories = setOf(DataCategory.KYC_DOCUMENTS),
                idempotencyKey = "idemp-post-release-01",
                correlationId = "corr-post-rel",
                causationId = "cause-post-rel",
            )
        )
        assertEquals(OverallDsarStatus.FULFILLED, result.overallStatus)
        val queryAfterDsar = kycAdapter.queryData(tenantId, subjectId, DataCategory.KYC_DOCUMENTS)
        assertEquals(0, queryAfterDsar.recordCount)
    }

    @Test
    fun `test 4 - Financial Ledger Integrity - Ledger balance preserved under statutory override or pseudonymization`() {
        val subjectId = "player-financial-ledger-303"

        // Seed double-entry ledger entries for player
        ledgerAdapter.ledgerEntries[subjectId] = mutableListOf(
            LedgerStoreAdapter.LedgerEntry(subjectId = subjectId, debitAmountCents = 10000, creditAmountCents = 0),
            LedgerStoreAdapter.LedgerEntry(subjectId = subjectId, debitAmountCents = 0, creditAmountCents = 10000),
        )

        // Execute DSAR erasure on financial ledger
        val result = dsarOrchestrator.executeDsar(
            principal = policyMakerPrincipal,
            command = ExecuteDsarCommand(
                tenantId = tenantId,
                subjectId = subjectId,
                requestedAction = PostRetentionAction.DELETE,
                categories = setOf(DataCategory.FINANCIAL_LEDGER),
                idempotencyKey = "idemp-ledger-001",
                correlationId = "corr-ledger",
                causationId = "cause-ledger",
            )
        )

        // Financial ledger retention overrides destructive deletion
        assertEquals(OverallDsarStatus.COMPLETED_WITH_RETENTION, result.overallStatus)
        val ledgerReceipt = result.receipts.find { it.dataCategory == DataCategory.FINANCIAL_LEDGER }
        assertNotNull(ledgerReceipt)
        assertEquals(StoreActionStatus.STATUTORY_OVERRIDE, ledgerReceipt.status)
        assertEquals(PostRetentionAction.RETAIN, ledgerReceipt.executedAction)

        // Verify ledger entries are completely intact
        val query = ledgerAdapter.queryData(tenantId, subjectId, DataCategory.FINANCIAL_LEDGER)
        assertEquals(2, query.recordCount)
    }

    @Test
    fun `test 5 - Responsible Gaming Self-Exclusion Protection - Self-exclusion cannot be erased to evade restriction`() {
        val subjectId = "player-rg-self-excluded-404"
        rgAdapter.activeExclusions[subjectId] = true
        rgAdapter.limits[subjectId] = "DAILY_DEPOSIT_50"

        val result = dsarOrchestrator.executeDsar(
            principal = policyMakerPrincipal,
            command = ExecuteDsarCommand(
                tenantId = tenantId,
                subjectId = subjectId,
                requestedAction = PostRetentionAction.DELETE,
                categories = setOf(DataCategory.RESPONSIBLE_GAMING_RECORDS),
                idempotencyKey = "idemp-rg-001",
                correlationId = "corr-rg",
                causationId = "cause-rg",
            )
        )

        assertEquals(OverallDsarStatus.COMPLETED_WITH_RETENTION, result.overallStatus)
        val rgReceipt = result.receipts.find { it.dataCategory == DataCategory.RESPONSIBLE_GAMING_RECORDS }
        assertNotNull(rgReceipt)
        assertEquals(StoreActionStatus.STATUTORY_OVERRIDE, rgReceipt.status)
        assertEquals(PostRetentionAction.RETAIN, rgReceipt.executedAction)

        // Self-exclusion remains active!
        assertTrue(rgAdapter.activeExclusions[subjectId] == true)
    }

    @Test
    fun `test 6 - Notification Suppression Tombstone - Marketing suppression retained upon erasure`() {
        val subjectId = "player-suppression-505"

        val result = dsarOrchestrator.executeDsar(
            principal = policyMakerPrincipal,
            command = ExecuteDsarCommand(
                tenantId = tenantId,
                subjectId = subjectId,
                requestedAction = PostRetentionAction.DELETE,
                categories = setOf(DataCategory.NOTIFICATION_SUPPRESSION),
                idempotencyKey = "idemp-suppress-001",
                correlationId = "corr-sup",
                causationId = "cause-sup",
            )
        )

        // Suppression is retained as tombstone
        val supReceipt = result.receipts.find { it.dataCategory == DataCategory.NOTIFICATION_SUPPRESSION }
        assertNotNull(supReceipt)
        assertEquals(StoreActionStatus.STATUTORY_OVERRIDE, supReceipt.status)
        assertEquals(PostRetentionAction.RETAIN, supReceipt.executedAction)

        // Subsequent marketing check confirms subject is suppressed
        val query = suppressionAdapter.queryData(tenantId, subjectId, DataCategory.NOTIFICATION_SUPPRESSION)
        assertEquals(1, query.recordCount)
        assertTrue(suppressionAdapter.suppressedSubjects[subjectId] == true)
    }

    @Test
    fun `test 7 - External Privacy Provider - Transient failure causes RETRYABLE_FAILURE and successful retry`() {
        val subjectId = "player-external-606"

        // Simulate transient network 503 on external provider
        externalProviderAdapter.transientFailureSimulated = true

        val result = dsarOrchestrator.executeDsar(
            principal = policyMakerPrincipal,
            command = ExecuteDsarCommand(
                tenantId = tenantId,
                subjectId = subjectId,
                requestedAction = PostRetentionAction.DELETE,
                categories = setOf(DataCategory.OPERATIONAL_TELEMETRY),
                idempotencyKey = "idemp-ext-fail-001",
                correlationId = "corr-ext",
                causationId = "cause-ext",
            )
        )

        assertEquals(OverallDsarStatus.FAILED_PARTIAL, result.overallStatus)
        val extReceipt = result.receipts.find { it.dataCategory == DataCategory.OPERATIONAL_TELEMETRY }
        assertNotNull(extReceipt)
        assertEquals(StoreActionStatus.RETRYABLE_FAILURE, extReceipt.status)

        // Recover transient network issue and trigger retry
        externalProviderAdapter.transientFailureSimulated = false
        val retriedResult = dsarOrchestrator.retryDsar(policyMakerPrincipal, result.dsarId)

        assertEquals(OverallDsarStatus.FULFILLED, retriedResult.overallStatus)
        val retriedReceipt = retriedResult.receipts.find { it.dataCategory == DataCategory.OPERATIONAL_TELEMETRY }
        assertNotNull(retriedReceipt)
        assertEquals(StoreActionStatus.COMPLETED, retriedReceipt.status)
    }

    @Test
    fun `test 8 - External Privacy Provider - Manual workflow records MANUAL_ACTION_REQUIRED until confirmed`() {
        val subjectId = "player-manual-707"

        val manualConfig = ExternalPrivacyProviderConfig(
            providerId = "provider-crm-legacy",
            providerType = "CRM",
            endpointUrl = "https://legacy-crm.portal",
            encryptedApiKey = byteArrayOf(10, 11),
            iv = byteArrayOf(12, 13),
            supportsAutomatedErasure = false, // Manual portal ticket required
        )
        val manualAdapter = ExternalPrivacyProviderAdapter(manualConfig)

        val manualOrchestrator = DsarOrchestrationService(
            rbacPolicy = rbacPolicy,
            complianceService = complianceService,
            adapters = listOf(manualAdapter),
            clock = clock,
            auditSink = { auditEvents.add(it) },
        )

        val result = manualOrchestrator.executeDsar(
            principal = policyMakerPrincipal,
            command = ExecuteDsarCommand(
                tenantId = tenantId,
                subjectId = subjectId,
                requestedAction = PostRetentionAction.DELETE,
                categories = setOf(DataCategory.OPERATIONAL_TELEMETRY),
                idempotencyKey = "idemp-manual-001",
                correlationId = "corr-man",
                causationId = "cause-man",
            )
        )

        assertEquals(OverallDsarStatus.FAILED_PARTIAL, result.overallStatus)
        val receipt = result.receipts.first()
        assertEquals(StoreActionStatus.MANUAL_ACTION_REQUIRED, receipt.status)

        // Admin performs manual action in vendor portal and confirms
        val confirmedResult = manualOrchestrator.confirmManualAction(
            principal = policyMakerPrincipal,
            dsarId = result.dsarId,
            receiptId = receipt.receiptId,
            notes = "Completed erasure in CRM portal, ticket reference CRM-TICKET-88992"
        )

        assertEquals(OverallDsarStatus.FULFILLED, confirmedResult.overallStatus)
        val confirmedReceipt = confirmedResult.receipts.first()
        assertEquals(StoreActionStatus.COMPLETED, confirmedReceipt.status)
        assertEquals(policyMakerPrincipal.id, confirmedReceipt.manualConfirmationBy)
        assertTrue(confirmedReceipt.manualConfirmationNotes!!.contains("CRM-TICKET-88992"))
    }

    @Test
    fun `test 9 - Idempotency - Duplicate DSAR command returns existing execution result without duplicate side-effects`() {
        val subjectId = "player-idempotent-808"
        authAdapter.activeSessions[subjectId] = mutableSetOf("sess-idemp-1")

        val cmd = ExecuteDsarCommand(
            tenantId = tenantId,
            subjectId = subjectId,
            requestedAction = PostRetentionAction.DELETE,
            categories = setOf(DataCategory.SESSION_DATA),
            idempotencyKey = "idemp-key-unique-999",
            correlationId = "corr-idemp",
            causationId = "cause-idemp",
        )

        val first = dsarOrchestrator.executeDsar(policyMakerPrincipal, cmd)
        val second = dsarOrchestrator.executeDsar(policyMakerPrincipal, cmd)

        assertEquals(first.dsarId, second.dsarId)
        assertEquals(first.overallStatus, second.overallStatus)
        assertEquals(first.receipts.size, second.receipts.size)
    }

    @Test
    fun `test 10 - RBAC Permission Enforcement - Unauthorized principals are denied`() {
        // Support role lacks CREATE_PRIVACY_POLICY
        assertFailsWith<SecurityException> {
            complianceService.createPolicy(
                principal = supportPrincipal,
                config = RetentionPolicyConfig(
                    dataCategory = DataCategory.SUPPORT_CASES,
                    purpose = "Support Ticket Archival",
                    policyReference = "POL-SUP-01",
                    retentionDuration = 30,
                    createdBy = supportPrincipal.id,
                )
            )
        }

        // Support role lacks EXECUTE_DSAR
        assertFailsWith<SecurityException> {
            dsarOrchestrator.executeDsar(
                principal = supportPrincipal,
                command = ExecuteDsarCommand(
                    tenantId = tenantId,
                    subjectId = "subject-unauth",
                    idempotencyKey = "idemp-unauth",
                    correlationId = "corr",
                    causationId = "cause",
                )
            )
        }

        // Auditor can view policies and receipts but cannot execute DSAR
        val policies = complianceService.listPolicies(auditorPrincipal)
        assertNotNull(policies)

        assertFailsWith<SecurityException> {
            dsarOrchestrator.executeDsar(
                principal = auditorPrincipal,
                command = ExecuteDsarCommand(
                    tenantId = tenantId,
                    subjectId = "subject-auditor-exec",
                    idempotencyKey = "idemp-aud-exec",
                    correlationId = "corr",
                    causationId = "cause",
                )
            )
        }
    }
}
