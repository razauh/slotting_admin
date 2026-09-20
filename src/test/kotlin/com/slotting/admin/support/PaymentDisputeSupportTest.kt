package com.slotting.admin.support

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Contract test suite for SUPPORT-001-02: Manage payment disputes.
 *
 * Source implementation-plan family: SUPPORT-001
 * Semantic Contract: "Notes do not mutate finance; attachments scanned; identity checks and access audited."
 * Expected RED failure: "unverified disclosure/attachment abuse/SLA invisible"
 */
class PaymentDisputeSupportTest {

    private val now = Instant.parse("2026-09-20T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val supportAdmin = AuthenticatedPrincipal(
        id = "dispute-agent-01",
        tenantId = "tenant-disp-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-disp-101",
        tenantId = "tenant-disp-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val otherPlayerPrincipal = AuthenticatedPrincipal(
        id = "player-disp-202",
        tenantId = "tenant-disp-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    @BeforeEach
    fun setUp() {
        PaymentDisputeSupportBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        PaymentDisputeSupportBinding.isBound = true
    }

    // =========================================================================
    // SUPPORT-001-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `SUPPORT-001-02-T001 Manage payment disputes produces the required authoritative outcome`() {
        // Expected RED failure: gate assertion check
        PaymentDisputeSupportBinding.checkBound()

        val store = InMemoryPaymentDisputeStore()
        val scanner = FakeDisputeEvidenceScannerAdapter()
        val service = PaymentDisputeSupportService(store, scanner, clock)

        // 1. Open a payment dispute case with SLA tracking
        val openCmd = OpenPaymentDisputeCommand(
            principal = supportAdmin,
            tenantId = "tenant-disp-1",
            playerReference = "player-disp-101",
            transactionReference = "tx-dep-998877",
            disputedAmountMinorUnits = 10000L, // $100.00
            currencyCode = "USD",
            disputeType = DisputeType.UNAUTHORIZED_CHARGE,
            reasonDescription = "Player claims unapproved $100 charge on Visa *1234",
            initialIdentityStatus = DisputeIdentityStatus.PENDING_VERIFICATION,
            idempotencyKey = "idemp-open-disp-01",
            correlationId = "corr-disp-101",
            causationId = "caus-disp-101",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        val openResult = service.openPaymentDispute(openCmd)
        assertEquals("tenant-disp-1", openResult.tenantId)
        assertEquals("player-disp-101", openResult.playerReference)
        assertEquals("tx-dep-998877", openResult.transactionReference)
        assertEquals(10000L, openResult.disputedAmountMinorUnits)
        assertEquals("USD", openResult.currencyCode)
        assertEquals(DisputeStage.OPENED, openResult.stage)
        assertEquals(1L, openResult.serverVersion)
        assertEquals(now, openResult.serverTime)
        assertFalse(openResult.isFinancialAuthorityCreated)

        // SLA targets are visible (SLA invisible prevented!)
        val sla = openResult.slaTracking
        assertEquals(now.plus(Duration.ofDays(7)), sla.evidenceSubmissionDueAt)
        assertEquals(now.plus(Duration.ofDays(30)), sla.disputeResolutionDueAt)
        assertEquals(DisputeSlaStatus.WITHIN_SLA, sla.status)

        // 2. Add an internal communication note (Notes do not mutate finance!)
        val noteCmd = AddDisputeNoteCommand(
            principal = supportAdmin,
            tenantId = "tenant-disp-1",
            disputeId = openResult.disputeId,
            content = "Requested acquiring bank chargeback case file and gateway acquirer trace ARN",
            isInternal = true,
            idempotencyKey = "idemp-disp-note-01",
            correlationId = "corr-disp-102",
            causationId = "caus-disp-102",
            expectedVersion = 1L,
            mutatesFinance = false,
            balanceAdjustmentMinorUnits = null
        )
        val noteResult = service.addDisputeNote(noteCmd)
        assertEquals(1, noteResult.notesCount)
        assertFalse(noteResult.isFinancialAuthorityCreated)

        // 3. Submit clean evidence after malware scanning (Attachments scanned!)
        val evidencePdfBytes = "PDF-BANK-STATEMENT-EVIDENCE-PAYLOAD".toByteArray(Charsets.UTF_8)
        val evCmd = SubmitDisputeEvidenceCommand(
            principal = supportAdmin,
            tenantId = "tenant-disp-1",
            disputeId = openResult.disputeId,
            evidenceType = DisputeEvidenceType.BANK_STATEMENT,
            fileName = "bank_statement_august.pdf",
            mimeType = "application/pdf",
            contentBytes = evidencePdfBytes,
            idempotencyKey = "idemp-disp-ev-01",
            correlationId = "corr-disp-103",
            causationId = "caus-disp-103",
            expectedVersion = 2L,
            mutatesMoney = false
        )
        val evResult = service.submitDisputeEvidence(evCmd)
        assertEquals(DisputeAttachmentStatus.CLEAN, evResult.scanStatus)
        assertEquals("bank_statement_august.pdf", evResult.fileName)
        assertFalse(evResult.isFinancialAuthorityCreated)

        // 4. Verify player identity
        val verifyIdCmd = VerifyDisputeIdentityCommand(
            principal = supportAdmin,
            tenantId = "tenant-disp-1",
            disputeId = openResult.disputeId,
            verificationMethod = "BANK_ID_TOKEN_AND_OTP_MATCH",
            idempotencyKey = "idemp-disp-verify-id-01",
            correlationId = "corr-disp-104",
            causationId = "caus-disp-104",
            expectedVersion = 3L,
            mutatesMoney = false
        )
        val verifyIdResult = service.verifyDisputeIdentity(verifyIdCmd)
        assertEquals(DisputeIdentityStatus.VERIFIED, verifyIdResult.identityStatus)

        // 5. Access dispute with audited access
        val disputeDetails = service.getDisputeWithAuditedAccess(
            GetPaymentDisputeCommand(
                principal = supportAdmin,
                tenantId = "tenant-disp-1",
                disputeId = openResult.disputeId,
                correlationId = "corr-disp-view-01",
                causationId = "caus-disp-view-01"
            )
        )
        assertTrue(disputeDetails.sensitiveDataDisclosed)
        assertEquals("player-disp-101", disputeDetails.playerReferenceRedacted)

        // 6. Assert exact semantic contract
        assertEquals(
            "Notes do not mutate finance; attachments scanned; identity checks and access audited.",
            PAYMENT_DISPUTE_SUPPORT_CONTRACT
        )

        // 7. Verify all audits exist and assert zero secret leak
        val audits = store.getAudits("tenant-disp-1")
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.any { it.action == DisputeAuditAction.DISPUTE_OPENED })
        assertTrue(audits.any { it.action == DisputeAuditAction.NOTE_ADDED })
        assertTrue(audits.any { it.action == DisputeAuditAction.EVIDENCE_SCANNED })
        assertTrue(audits.any { it.action == DisputeAuditAction.IDENTITY_VERIFIED })
        assertTrue(audits.any { it.action == DisputeAuditAction.DISPUTE_VIEWED })

        val auditText = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditText.contains("PASSWORD=", ignoreCase = true))
        assertFalse(auditText.contains("SECRET=", ignoreCase = true))

        // 8. Assert no financial mutation methods exist on the service
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // SUPPORT-001-02-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `SUPPORT-001-02-T002 Manage payment disputes rejects invalid boundary unauthorized and stale input`() {
        PaymentDisputeSupportBinding.isBound = true

        val store = InMemoryPaymentDisputeStore()
        val scanner = FakeDisputeEvidenceScannerAdapter()
        val service = PaymentDisputeSupportService(store, scanner, clock)

        val validOpen = OpenPaymentDisputeCommand(
            principal = supportAdmin,
            tenantId = "tenant-disp-1",
            playerReference = "player-disp-101",
            transactionReference = "tx-dep-12345",
            disputedAmountMinorUnits = 5000L,
            currencyCode = "USD",
            disputeType = DisputeType.DUPLICATE_CHARGE,
            reasonDescription = "Duplicate deposit debited twice",
            idempotencyKey = "idemp-t002-open",
            correlationId = "corr-t002",
            causationId = "caus-t002",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(tenantId = "other-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Stale expected version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Invalid amount (<= 0) rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(disputedAmountMinorUnits = 0L))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(disputedAmountMinorUnits = -500L))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Blank player reference or transaction reference rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(playerReference = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(transactionReference = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Financial mutation attempt rejected (strict financial boundary)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(validOpen.copy(mutatesMoney = true))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Open dispute successfully, then test note, evidence, and access rejections
        val opened = service.openPaymentDispute(validOpen)

        // 7. Notes do not mutate finance: note attempting financial credit/adjustment rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addDisputeNote(
                AddDisputeNoteCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-disp-1",
                    disputeId = opened.disputeId,
                    content = "Support note attempting direct balance refund credit of $50",
                    idempotencyKey = "idemp-note-mutate-credit",
                    correlationId = "corr-note-fin",
                    causationId = "caus-note-fin",
                    expectedVersion = 1L,
                    mutatesFinance = true, // FORBIDDEN! Notes do not mutate finance!
                    balanceAdjustmentMinorUnits = 5000L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Attachment abuse: dangerous executable attachment rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.submitDisputeEvidence(
                SubmitDisputeEvidenceCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-disp-1",
                    disputeId = opened.disputeId,
                    evidenceType = DisputeEvidenceType.RECEIPT,
                    fileName = "evidence_receipt.bat",
                    mimeType = "application/x-bat",
                    contentBytes = "@echo off".toByteArray(),
                    idempotencyKey = "idemp-ev-bat",
                    correlationId = "corr-ev-bat",
                    causationId = "caus-ev-bat",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Attachment abuse: infected evidence file detected by scanner quarantined and rejected
        scanner.simulateInfection = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.submitDisputeEvidence(
                SubmitDisputeEvidenceCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-disp-1",
                    disputeId = opened.disputeId,
                    evidenceType = DisputeEvidenceType.BANK_STATEMENT,
                    fileName = "eicar_bank_statement.pdf",
                    mimeType = "application/pdf",
                    contentBytes = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE".toByteArray(),
                    idempotencyKey = "idemp-ev-infected",
                    correlationId = "corr-ev-inf",
                    causationId = "caus-ev-inf",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        scanner.simulateInfection = false

        // 9. Scanner dependency timeout fails closed
        scanner.simulateTimeout = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.submitDisputeEvidence(
                SubmitDisputeEvidenceCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-disp-1",
                    disputeId = opened.disputeId,
                    evidenceType = DisputeEvidenceType.RECEIPT,
                    fileName = "clean_receipt.pdf",
                    mimeType = "application/pdf",
                    contentBytes = byteArrayOf(0x25, 0x50, 0x44, 0x46),
                    idempotencyKey = "idemp-ev-timeout",
                    correlationId = "corr-ev-to",
                    causationId = "caus-ev-to",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
        scanner.simulateTimeout = false

        // 10. Cross-player dispute access rejected (player B cannot view player A's dispute)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.getDisputeWithAuditedAccess(
                GetPaymentDisputeCommand(
                    principal = otherPlayerPrincipal,
                    tenantId = "tenant-disp-1",
                    disputeId = opened.disputeId,
                    correlationId = "corr-cross-disp",
                    causationId = "caus-cross-disp"
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // SUPPORT-001-02-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `SUPPORT-001-02-T003 Manage payment disputes survives concurrency duplicate delivery and dependency failure`() {
        PaymentDisputeSupportBinding.isBound = true

        val store = InMemoryPaymentDisputeStore()
        val scanner = FakeDisputeEvidenceScannerAdapter()
        val service = PaymentDisputeSupportService(store, scanner, clock)

        val command = OpenPaymentDisputeCommand(
            principal = supportAdmin,
            tenantId = "tenant-disp-1",
            playerReference = "player-disp-101",
            transactionReference = "tx-dep-concurrent-01",
            disputedAmountMinorUnits = 7500L,
            currencyCode = "USD",
            disputeType = DisputeType.INCORRECT_AMOUNT,
            reasonDescription = "Billed $75 instead of $50",
            idempotencyKey = "idemp-concurrent-disp",
            correlationId = "corr-conc-01",
            causationId = "caus-conc-01",
            expectedVersion = 1L
        )

        // 1. Concurrent equivalent requests
        val threads = 10
        val pool = Executors.newFixedThreadPool(threads)
        val futures = (1..threads).map {
            pool.submit(Callable {
                service.openPaymentDispute(command)
            })
        }
        val results = futures.map { it.get() }
        pool.shutdown()

        // Exactly one lawful effect: all return same resultId and disputeId
        val firstResultId = results.first().resultId
        val firstDisputeId = results.first().disputeId
        results.forEach {
            assertEquals(firstResultId, it.resultId)
            assertEquals(firstDisputeId, it.disputeId)
        }
        assertEquals(1, store.disputes.size)
        assertEquals(1, store.getAudits("tenant-disp-1").size)

        // 2. Conflicting payload under same idempotency key produces CONFLICT
        val conflicting = command.copy(disputedAmountMinorUnits = 9000L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.openPaymentDispute(conflicting)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // SUPPORT-001-02-T004: Lifecycle, Recovery, and SLA Observability
    // =========================================================================

    @Test
    fun `SUPPORT-001-02-T004 Manage payment disputes remains compatible recoverable observable and lifecycle safe`() {
        val store = InMemoryPaymentDisputeStore()
        val scanner = FakeDisputeEvidenceScannerAdapter()
        val service = PaymentDisputeSupportService(store, scanner, clock)

        // 1. Fail-closed verification gate check: throws "unverified disclosure/attachment abuse/SLA invisible"
        PaymentDisputeSupportBinding.isBound = false
        val redEx = assertFailsWith<AssertionError> {
            PaymentDisputeSupportBinding.checkBound()
        }
        assertEquals("unverified disclosure/attachment abuse/SLA invisible", redEx.message)

        // Re-bind
        PaymentDisputeSupportBinding.isBound = true

        // 2. Open dispute with unverified initial identity
        val openResult = service.openPaymentDispute(
            OpenPaymentDisputeCommand(
                principal = supportAdmin,
                tenantId = "tenant-disp-1",
                playerReference = "player-disp-101",
                transactionReference = "tx-life-01",
                disputedAmountMinorUnits = 12000L,
                currencyCode = "USD",
                disputeType = DisputeType.UNAUTHORIZED_CHARGE,
                reasonDescription = "Suspected account takeover unauthorized charge",
                initialIdentityStatus = DisputeIdentityStatus.UNVERIFIED,
                idempotencyKey = "idemp-life-open",
                correlationId = "corr-life-01",
                causationId = "caus-life-01"
            )
        )

        // 3. Unverified disclosure protection:
        // Before identity verification, playerReference is REDACTED in dispute view
        val unverifiedView = service.getDisputeWithAuditedAccess(
            GetPaymentDisputeCommand(
                principal = supportAdmin,
                tenantId = "tenant-disp-1",
                disputeId = openResult.disputeId,
                correlationId = "corr-view-unver",
                causationId = "caus-view-unver"
            )
        )
        assertFalse(unverifiedView.sensitiveDataDisclosed)
        assertEquals("REDACTED-UNVERIFIED", unverifiedView.playerReferenceRedacted)

        // Verify player identity
        service.verifyDisputeIdentity(
            VerifyDisputeIdentityCommand(
                principal = supportAdmin,
                tenantId = "tenant-disp-1",
                disputeId = openResult.disputeId,
                verificationMethod = "CARDHOLDER_KYC_DOCUMENTS_VERIFIED",
                idempotencyKey = "idemp-life-verify",
                correlationId = "corr-life-ver",
                causationId = "caus-life-ver",
                expectedVersion = 1L
            )
        )

        // Now verified: disclosure is permitted and audited
        val verifiedView = service.getDisputeWithAuditedAccess(
            GetPaymentDisputeCommand(
                principal = supportAdmin,
                tenantId = "tenant-disp-1",
                disputeId = openResult.disputeId,
                correlationId = "corr-view-ver",
                causationId = "caus-view-ver"
            )
        )
        assertTrue(verifiedView.sensitiveDataDisclosed)
        assertEquals("player-disp-101", verifiedView.playerReferenceRedacted)

        // 4. SLA Visibility & Tracking:
        // Initially within SLA
        val slaInitial = service.evaluateDisputeSla("tenant-disp-1", openResult.disputeId, now)
        assertEquals(DisputeSlaStatus.WITHIN_SLA, slaInitial.slaStatus)
        assertFalse(slaInitial.isBreached)

        // Simulate passage of time past evidence submission due date (+8 days): SLA is BREACHED!
        val laterTime = now.plus(Duration.ofDays(8))
        val slaBreached = service.evaluateDisputeSla("tenant-disp-1", openResult.disputeId, laterTime)
        assertEquals(DisputeSlaStatus.BREACHED, slaBreached.slaStatus)
        assertTrue(slaBreached.isBreached)

        // Verify actionable CRITICAL SLA alert emitted
        val alerts = store.getAlerts("tenant-disp-1")
        val slaAlert = alerts.firstOrNull { it.alertType == "DISPUTE_SLA_BREACHED" }
        assertNotNull(slaAlert)
        assertEquals("CRITICAL", slaAlert.severity)
        assertTrue(slaAlert.message.contains("SLA BREACHED"))

        // 5. Test Sandbox scanner adapter compatibility
        val sandboxScanner = SandboxDisputeEvidenceScannerAdapter()
        val scanRes = sandboxScanner.scan("receipt.jpg", byteArrayOf(0xFF.toByte(), 0xD8.toByte()))
        assertTrue(scanRes.isClean)

        // 6. Audit immutability: all steps recorded without altering past rows
        val allAudits = store.getAudits("tenant-disp-1")
        assertEquals(4, allAudits.size) // OPEN, VIEW(unverified), VERIFY_ID, VIEW(verified)
    }
}
