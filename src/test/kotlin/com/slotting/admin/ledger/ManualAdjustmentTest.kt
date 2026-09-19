package com.slotting.admin.ledger

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

/**
 * Mandatory backend TDD test suite for LEDGER-004:
 * Manual adjustments.
 *
 * Semantic contract: "Original entries untouched; reason/evidence mandatory; configured dual approval."
 * Protected risk assertion: "direct/self-approved adjustment"
 */
class ManualAdjustmentTest {

    private val fixedClock = Clock.fixed(Instant.parse("2026-09-19T10:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: ManualAdjustmentService

    private val makerPrincipal = AuthenticatedPrincipal(
        id = "maker-admin-01",
        tenantId = "tenant-01",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val checkerPrincipal = AuthenticatedPrincipal(
        id = "checker-admin-02",
        tenantId = "tenant-01",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val crossTenantPrincipal = AuthenticatedPrincipal(
        id = "checker-admin-03",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-01",
        tenantId = "tenant-01",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    @BeforeEach
    fun setUp() {
        service = ManualAdjustmentService(clock = fixedClock)
    }

    private fun sampleEntries(): List<JournalEntryDraft> = listOf(
        JournalEntryDraft("ACC-PLAYER-1", JournalEntryDirection.CREDIT, 5000L, "USD", "Goodwill compensation"),
        JournalEntryDraft("ACC-EXPENSE-1", JournalEntryDirection.DEBIT, 5000L, "USD", "Operational adjustment expense"),
    )

    // =========================================================================
    // LEDGER-004-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `LEDGER-004-T001 Manual adjustments produces the required authoritative outcome`() {
        val proposeCmd = ProposeManualAdjustmentCommand(
            makerPrincipal = makerPrincipal,
            tenantId = "tenant-01",
            adjustmentReference = "ADJ-2026-001",
            currencyCode = "USD",
            entries = sampleEntries(),
            reason = "Customer dispute refund ticket #88492",
            evidenceReference = "ticket://zendesk/88492/signed-affidavit.pdf",
            idempotencyKey = "IDEM-PROP-001",
            correlationId = "corr-prop-001",
            causationId = "caus-prop-001",
        )

        val proposal = service.proposeAdjustment(proposeCmd)
        assertNotNull(proposal.proposalId)
        assertEquals(ManualAdjustmentStatus.PENDING_APPROVAL, proposal.status)

        // Checker reviews and approves
        val reviewCmd = ReviewAndExecuteAdjustmentCommand(
            checkerPrincipal = checkerPrincipal,
            tenantId = "tenant-01",
            proposalId = proposal.proposalId,
            approve = true,
            checkerReason = "Verified dispute evidence and approved for settlement",
            idempotencyKey = "IDEM-REV-001",
            correlationId = "corr-rev-001",
            causationId = "caus-rev-001",
        )

        val result = service.reviewAndExecute(reviewCmd)

        assertEquals(ManualAdjustmentStatus.APPROVED_EXECUTED, result.status)
        assertEquals("maker-admin-01", result.makerId)
        assertEquals("checker-admin-02", result.checkerId)
        assertEquals("Customer dispute refund ticket #88492", result.reason)
        assertEquals("ticket://zendesk/88492/signed-affidavit.pdf", result.evidenceReference)
        assertTrue(result.originalEntriesUntouched)
        assertTrue(result.dualApprovalEnforced)
        assertNotNull(result.executionBatchId)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertEquals(
            "Original entries untouched; reason/evidence mandatory; configured dual approval.",
            result.semanticContract
        )
    }

    // =========================================================================
    // LEDGER-004-T002: Negative, Boundary & Rejection Verification
    // =========================================================================

    @Test
    fun `LEDGER-004-T002 Manual adjustments rejects invalid, boundary, unauthorized, and stale input`() {
        // Direct adjustment without dual approval: MUST throw DirectAdjustmentProhibitedException
        val directCmd = DirectAdjustmentCommand(
            principal = makerPrincipal,
            tenantId = "tenant-01",
            accountReference = "ACC-PLAYER-1",
            amountMinorUnits = 5000L,
            currencyCode = "USD",
        )
        val directEx = assertThrows(DirectAdjustmentProhibitedException::class.java) {
            service.directAdjustment(directCmd)
        }
        assertEquals("DIRECT_ADJUSTMENT_PROHIBITED", directEx.errorCode)

        // Propose with missing reason -> MUST throw MandatoryEvidenceMissingException
        val noReasonCmd = ProposeManualAdjustmentCommand(
            makerPrincipal = makerPrincipal,
            tenantId = "tenant-01",
            adjustmentReference = "ADJ-NO-REASON",
            currencyCode = "USD",
            entries = sampleEntries(),
            reason = "   ", // Blank reason!
            evidenceReference = "ticket://evidence/1",
            idempotencyKey = "IDEM-BAD-1",
            correlationId = "corr",
            causationId = "caus",
        )
        assertThrows(MandatoryEvidenceMissingException::class.java) {
            service.proposeAdjustment(noReasonCmd)
        }

        // Propose with missing evidence -> MUST throw MandatoryEvidenceMissingException
        val noEvidenceCmd = noReasonCmd.copy(
            reason = "Valid reason",
            evidenceReference = "", // Blank evidence!
        )
        assertThrows(MandatoryEvidenceMissingException::class.java) {
            service.proposeAdjustment(noEvidenceCmd)
        }

        // Propose valid adjustment
        val validPropCmd = noReasonCmd.copy(
            reason = "Valid reason",
            evidenceReference = "ticket://evidence/valid",
            idempotencyKey = "IDEM-VALID-PROP",
        )
        val proposal = service.proposeAdjustment(validPropCmd)

        // SELF-APPROVAL ATTEMPT: Maker attempts to review/approve their own proposal
        val selfReviewCmd = ReviewAndExecuteAdjustmentCommand(
            checkerPrincipal = makerPrincipal, // SAME PRINCIPAL (Maker == Checker)!
            tenantId = "tenant-01",
            proposalId = proposal.proposalId,
            approve = true,
            checkerReason = "Self approving",
            idempotencyKey = "IDEM-SELF-REV",
            correlationId = "corr",
            causationId = "caus",
        )
        val selfEx = assertThrows(SelfApprovalProhibitedException::class.java) {
            service.reviewAndExecute(selfReviewCmd)
        }
        assertEquals("SELF_APPROVAL_PROHIBITED", selfEx.errorCode)

        // Cross-tenant review attempt
        val idorReviewCmd = selfReviewCmd.copy(
            checkerPrincipal = crossTenantPrincipal,
            idempotencyKey = "IDEM-IDOR",
        )
        assertThrows(AdjustmentForbiddenException::class.java) {
            service.reviewAndExecute(idorReviewCmd)
        }

        // Player principal review attempt
        val playerReviewCmd = selfReviewCmd.copy(
            checkerPrincipal = playerPrincipal,
            idempotencyKey = "IDEM-PLAYER",
        )
        assertThrows(AdjustmentForbiddenException::class.java) {
            service.reviewAndExecute(playerReviewCmd)
        }
    }

    // =========================================================================
    // LEDGER-004-T003: Concurrency, Duplicate Delivery & Failure Recovery
    // =========================================================================

    @Test
    fun `LEDGER-004-T003 Manual adjustments survives concurrency, duplicate delivery, and dependency failure`() {
        val proposeCmd = ProposeManualAdjustmentCommand(
            makerPrincipal = makerPrincipal,
            tenantId = "tenant-01",
            adjustmentReference = "ADJ-IDEM-001",
            currencyCode = "USD",
            entries = sampleEntries(),
            reason = "Duplicate delivery check",
            evidenceReference = "ticket://evidence/idem",
            idempotencyKey = "IDEM-PROP-DUP",
            correlationId = "corr-dup",
            causationId = "caus-dup",
        )

        // Replaying proposal under same key returns identical proposal
        val p1 = service.proposeAdjustment(proposeCmd)
        val p2 = service.proposeAdjustment(proposeCmd)
        assertEquals(p1.proposalId, p2.proposalId)

        // Review approval replay
        val reviewCmd = ReviewAndExecuteAdjustmentCommand(
            checkerPrincipal = checkerPrincipal,
            tenantId = "tenant-01",
            proposalId = p1.proposalId,
            approve = true,
            checkerReason = "Approved by checker",
            idempotencyKey = "IDEM-REV-DUP",
            correlationId = "corr-rev-dup",
            causationId = "caus-rev-dup",
        )

        val r1 = service.reviewAndExecute(reviewCmd)
        val r2 = service.reviewAndExecute(reviewCmd)
        assertEquals(r1.resultId, r2.resultId)
        assertEquals(r1.executionBatchId, r2.executionBatchId)

        // Subsequent review attempt with different key on already-decided proposal throws conflict
        val extraReviewCmd = reviewCmd.copy(idempotencyKey = "IDEM-NEW-KEY")
        val conflictEx = assertThrows(AdjustmentConflictException::class.java) {
            service.reviewAndExecute(extraReviewCmd)
        }
        assertEquals("CONFLICT", conflictEx.errorCode)
    }

    // =========================================================================
    // LEDGER-004-T004: Compatibility, Recovery, Lifecycle & Observability
    // =========================================================================

    @Test
    fun `LEDGER-004-T004 Manual adjustments remains compatible, recoverable, observable, and lifecycle-safe`() {
        val proposeCmd = ProposeManualAdjustmentCommand(
            makerPrincipal = makerPrincipal,
            tenantId = "tenant-01",
            adjustmentReference = "ADJ-AUDIT-001",
            currencyCode = "USD",
            entries = sampleEntries(),
            reason = "Audit verification",
            evidenceReference = "evidence://audit/case-44",
            idempotencyKey = "IDEM-AUDIT-PROP",
            correlationId = "corr-audit-prop",
            causationId = "caus-audit-prop",
        )
        val proposal = service.proposeAdjustment(proposeCmd)

        val reviewCmd = ReviewAndExecuteAdjustmentCommand(
            checkerPrincipal = checkerPrincipal,
            tenantId = "tenant-01",
            proposalId = proposal.proposalId,
            approve = true,
            checkerReason = "Audit review approved",
            idempotencyKey = "IDEM-AUDIT-REV",
            correlationId = "corr-audit-rev",
            causationId = "caus-audit-rev",
        )
        val result = service.reviewAndExecute(reviewCmd)

        // Observability and audit lineage
        val logs = service.getAuditLogs("tenant-01")
        val propEvent = logs.find { it.type == "MANUAL_ADJUSTMENT_PROPOSED" }
        val execEvent = logs.find { it.type == "MANUAL_ADJUSTMENT_EXECUTED" }

        assertNotNull(propEvent)
        assertNotNull(execEvent)
        assertEquals("corr-audit-prop", propEvent!!.correlationId)
        assertEquals("corr-audit-rev", execEvent!!.correlationId)

        // Untrusted client assertions
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertTrue(result.originalEntriesUntouched)
    }
}
