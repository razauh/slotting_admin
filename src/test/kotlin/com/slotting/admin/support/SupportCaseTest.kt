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
 * Contract test suite for SUPPORT-001-01: Manage verified support cases and SLA.
 *
 * Source implementation-plan family: SUPPORT-001
 * Semantic Contract: "Notes do not mutate finance; attachments scanned; identity checks and access audited."
 * Expected RED failure: "unverified disclosure/attachment abuse/SLA invisible"
 */
class SupportCaseTest {

    private val now = Instant.parse("2026-09-20T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val supportAdmin = AuthenticatedPrincipal(
        id = "agent-support-01",
        tenantId = "tenant-supp-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-user-777",
        tenantId = "tenant-supp-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val otherPlayerPrincipal = AuthenticatedPrincipal(
        id = "player-user-888",
        tenantId = "tenant-supp-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    @BeforeEach
    fun setUp() {
        SupportCaseBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        SupportCaseBinding.isBound = true
    }

    // =========================================================================
    // SUPPORT-001-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `SUPPORT-001-01-T001 Manage verified support cases and SLA produces the required authoritative outcome`() {
        // Expected RED failure: gate assertion
        SupportCaseBinding.checkBound()

        val store = InMemorySupportCaseStore()
        val scanner = FakeAttachmentScannerAdapter()
        val service = SupportCaseService(store, scanner, clock)

        // 1. Create a support case with SLA tracking
        val createCmd = CreateSupportCaseCommand(
            principal = supportAdmin,
            tenantId = "tenant-supp-1",
            playerReference = "player-user-777",
            category = CaseCategory.PAYMENT_DISPUTE,
            priority = CasePriority.CRITICAL, // 1h response SLA, 4h resolution SLA
            subject = "Deposit confirmation delayed for round 1024",
            description = "Player reports $50 deposit not credited immediately",
            initialIdentityStatus = IdentityVerificationStatus.PENDING_VERIFICATION,
            idempotencyKey = "idemp-create-case-01",
            correlationId = "corr-supp-101",
            causationId = "caus-supp-101",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        val caseResult = service.createSupportCase(createCmd)
        assertEquals("tenant-supp-1", caseResult.tenantId)
        assertEquals("player-user-777", caseResult.playerReference)
        assertEquals(CaseCategory.PAYMENT_DISPUTE, caseResult.category)
        assertEquals(CasePriority.CRITICAL, caseResult.priority)
        assertEquals(CaseStatus.NEW, caseResult.status)
        assertEquals(1L, caseResult.serverVersion)
        assertEquals(now, caseResult.serverTime)
        assertFalse(caseResult.isFinancialAuthorityCreated)

        // SLA targets are explicitly calculated and visible (SLA invisible prevented!)
        val sla = caseResult.slaTracking
        assertEquals(now.plus(Duration.ofHours(1)), sla.firstResponseDueAt)
        assertEquals(now.plus(Duration.ofHours(4)), sla.resolutionDueAt)
        assertEquals(SlaStatus.WITHIN_SLA, sla.status)

        // 2. Add an internal communication note (Notes do not mutate finance!)
        val noteCmd = AddCaseNoteCommand(
            principal = supportAdmin,
            tenantId = "tenant-supp-1",
            caseId = caseResult.caseId,
            content = "Investigated provider callback logs: settlement confirmation pending at payment gateway",
            isInternal = true,
            idempotencyKey = "idemp-note-01",
            correlationId = "corr-supp-102",
            causationId = "caus-supp-102",
            expectedVersion = 1L,
            mutatesFinance = false,
            balanceAdjustmentMinorUnits = null
        )
        val noteResult = service.addCaseNote(noteCmd)
        assertEquals(1, noteResult.notesCount)
        assertFalse(noteResult.isFinancialAuthorityCreated)

        // 3. Add clean attachment after malware scanning (Attachments scanned!)
        val attachmentBytes = "RECEIPT-PAYMENT-REF-99998888".toByteArray(Charsets.UTF_8)
        val attCmd = AddCaseAttachmentCommand(
            principal = supportAdmin,
            tenantId = "tenant-supp-1",
            caseId = caseResult.caseId,
            fileName = "deposit_receipt.pdf",
            mimeType = "application/pdf",
            contentBytes = attachmentBytes,
            idempotencyKey = "idemp-att-01",
            correlationId = "corr-supp-103",
            causationId = "caus-supp-103",
            expectedVersion = 2L,
            mutatesMoney = false
        )
        val attResult = service.addCaseAttachment(attCmd)
        assertEquals(AttachmentScanStatus.CLEAN, attResult.scanStatus)
        assertEquals("deposit_receipt.pdf", attResult.fileName)
        assertFalse(attResult.isFinancialAuthorityCreated)

        // 4. Verify player identity
        val verifyIdCmd = VerifyPlayerIdentityCommand(
            principal = supportAdmin,
            tenantId = "tenant-supp-1",
            caseId = caseResult.caseId,
            verificationMethod = "MFA_CHALLENGE_AND_ACCOUNT_MATCH",
            idempotencyKey = "idemp-verify-id-01",
            correlationId = "corr-supp-104",
            causationId = "caus-supp-104",
            expectedVersion = 3L,
            mutatesMoney = false
        )
        val verifyIdResult = service.verifyPlayerIdentity(verifyIdCmd)
        assertEquals(IdentityVerificationStatus.VERIFIED, verifyIdResult.identityStatus)

        // 5. Access case with audited access
        val caseDetails = service.getCaseWithAuditedAccess(
            GetSupportCaseCommand(
                principal = supportAdmin,
                tenantId = "tenant-supp-1",
                caseId = caseResult.caseId,
                correlationId = "corr-view-01",
                causationId = "caus-view-01"
            )
        )
        assertTrue(caseDetails.sensitiveDataDisclosed)
        assertEquals("player-user-777", caseDetails.playerReferenceRedacted)

        // 6. Assert exact semantic contract
        assertEquals(
            "Notes do not mutate finance; attachments scanned; identity checks and access audited.",
            SUPPORT_CASE_CONTRACT
        )

        // 7. Verify all audits exist and assert zero secret leak
        val audits = store.getAudits("tenant-supp-1")
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.any { it.action == CaseAuditAction.CASE_CREATED })
        assertTrue(audits.any { it.action == CaseAuditAction.NOTE_ADDED })
        assertTrue(audits.any { it.action == CaseAuditAction.ATTACHMENT_SCANNED })
        assertTrue(audits.any { it.action == CaseAuditAction.IDENTITY_VERIFIED })
        assertTrue(audits.any { it.action == CaseAuditAction.CASE_VIEWED })

        val auditText = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditText.contains("PASSWORD=", ignoreCase = true))
        assertFalse(auditText.contains("SECRET=", ignoreCase = true))

        // 8. Assert no financial mutation methods exist
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // SUPPORT-001-01-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `SUPPORT-001-01-T002 Manage verified support cases and SLA rejects invalid boundary unauthorized and stale input`() {
        SupportCaseBinding.isBound = true

        val store = InMemorySupportCaseStore()
        val scanner = FakeAttachmentScannerAdapter()
        val service = SupportCaseService(store, scanner, clock)

        val validCreate = CreateSupportCaseCommand(
            principal = supportAdmin,
            tenantId = "tenant-supp-1",
            playerReference = "player-user-777",
            category = CaseCategory.TECHNICAL_GAMEPLAY,
            priority = CasePriority.NORMAL,
            subject = "Game disconnection issue",
            description = "Connection dropped during spin",
            idempotencyKey = "idemp-t002-create",
            correlationId = "corr-t002",
            causationId = "caus-t002",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createSupportCase(validCreate.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createSupportCase(validCreate.copy(tenantId = "other-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Stale expected version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createSupportCase(validCreate.copy(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Blank player reference or subject rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createSupportCase(validCreate.copy(playerReference = "  "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createSupportCase(validCreate.copy(subject = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Financial mutation attempt rejected (strict financial boundary)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createSupportCase(validCreate.copy(mutatesMoney = true))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Create the case successfully, then test note, attachment, and access rejections
        val created = service.createSupportCase(validCreate)

        // 6. Notes do not mutate finance: note attempting financial adjustment rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addCaseNote(
                AddCaseNoteCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-supp-1",
                    caseId = created.caseId,
                    content = "Attempting to grant $10 balance credit via support note",
                    idempotencyKey = "idemp-note-fin-mutate",
                    correlationId = "corr-note-fin",
                    causationId = "caus-note-fin",
                    expectedVersion = 1L,
                    mutatesFinance = true, // FORBIDDEN! Notes do not mutate finance!
                    balanceAdjustmentMinorUnits = 1000L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Attachment abuse: dangerous executable attachment rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addCaseAttachment(
                AddCaseAttachmentCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-supp-1",
                    caseId = created.caseId,
                    fileName = "malicious_payload.exe",
                    mimeType = "application/x-msdownload",
                    contentBytes = byteArrayOf(0x4D, 0x5A), // MZ DOS header
                    idempotencyKey = "idemp-att-exe",
                    correlationId = "corr-att-exe",
                    causationId = "caus-att-exe",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Attachment abuse: infected file detected by scanner quarantined and rejected
        scanner.simulateInfection = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addCaseAttachment(
                AddCaseAttachmentCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-supp-1",
                    caseId = created.caseId,
                    fileName = "eicar_virus_test.txt",
                    mimeType = "text/plain",
                    contentBytes = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*".toByteArray(),
                    idempotencyKey = "idemp-att-infected",
                    correlationId = "corr-att-inf",
                    causationId = "caus-att-inf",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        scanner.simulateInfection = false

        // 8. Scanner dependency timeout fails closed
        scanner.simulateTimeout = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addCaseAttachment(
                AddCaseAttachmentCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-supp-1",
                    caseId = created.caseId,
                    fileName = "document.pdf",
                    mimeType = "application/pdf",
                    contentBytes = byteArrayOf(0x25, 0x50, 0x44, 0x46),
                    idempotencyKey = "idemp-att-timeout",
                    correlationId = "corr-att-to",
                    causationId = "caus-att-to",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
        scanner.simulateTimeout = false

        // 9. Cross-player case access rejected (player B cannot view player A's case)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.getCaseWithAuditedAccess(
                GetSupportCaseCommand(
                    principal = otherPlayerPrincipal,
                    tenantId = "tenant-supp-1",
                    caseId = created.caseId,
                    correlationId = "corr-unauth-access",
                    causationId = "caus-unauth-access"
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // SUPPORT-001-01-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `SUPPORT-001-01-T003 Manage verified support cases and SLA survives concurrency duplicate delivery and dependency failure`() {
        SupportCaseBinding.isBound = true

        val store = InMemorySupportCaseStore()
        val scanner = FakeAttachmentScannerAdapter()
        val service = SupportCaseService(store, scanner, clock)

        val command = CreateSupportCaseCommand(
            principal = supportAdmin,
            tenantId = "tenant-supp-1",
            playerReference = "player-user-777",
            category = CaseCategory.ACCOUNT_ACCESS,
            priority = CasePriority.HIGH,
            subject = "Password reset and MFA challenge",
            description = "Player lost MFA device",
            idempotencyKey = "idemp-concurrent-case",
            correlationId = "corr-conc-01",
            causationId = "caus-conc-01",
            expectedVersion = 1L
        )

        // 1. Concurrent equivalent requests
        val threads = 10
        val pool = Executors.newFixedThreadPool(threads)
        val futures = (1..threads).map {
            pool.submit(Callable {
                service.createSupportCase(command)
            })
        }
        val results = futures.map { it.get() }
        pool.shutdown()

        // Exactly one lawful effect: all return same resultId and caseId
        val firstResultId = results.first().resultId
        val firstCaseId = results.first().caseId
        results.forEach {
            assertEquals(firstResultId, it.resultId)
            assertEquals(firstCaseId, it.caseId)
        }
        assertEquals(1, store.cases.size)
        assertEquals(1, store.getAudits("tenant-supp-1").size)

        // 2. Conflicting payload under same idempotency key produces CONFLICT
        val conflicting = command.copy(priority = CasePriority.CRITICAL)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.createSupportCase(conflicting)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // SUPPORT-001-01-T004: Lifecycle, Recovery, and SLA Observability
    // =========================================================================

    @Test
    fun `SUPPORT-001-01-T004 Manage verified support cases and SLA remains compatible recoverable observable and lifecycle safe`() {
        val store = InMemorySupportCaseStore()
        val scanner = FakeAttachmentScannerAdapter()
        val service = SupportCaseService(store, scanner, clock)

        // 1. Fail-closed verification gate check: throws "unverified disclosure/attachment abuse/SLA invisible"
        SupportCaseBinding.isBound = false
        val redEx = assertFailsWith<AssertionError> {
            SupportCaseBinding.checkBound()
        }
        assertEquals("unverified disclosure/attachment abuse/SLA invisible", redEx.message)

        // Re-bind
        SupportCaseBinding.isBound = true

        // 2. Create case with CRITICAL priority (first response due: 1h, resolution due: 4h)
        val createResult = service.createSupportCase(
            CreateSupportCaseCommand(
                principal = supportAdmin,
                tenantId = "tenant-supp-1",
                playerReference = "player-user-777",
                category = CaseCategory.PAYMENT_DISPUTE,
                priority = CasePriority.CRITICAL,
                subject = "Unauthorized withdrawal reported",
                description = "Urgent player report of withdrawal anomaly",
                initialIdentityStatus = IdentityVerificationStatus.UNVERIFIED,
                idempotencyKey = "idemp-life-01",
                correlationId = "corr-life-01",
                causationId = "caus-life-01"
            )
        )

        // 3. Unverified disclosure protection:
        // Before identity verification, playerReference is REDACTED to prevent unverified disclosure
        val unverifiedView = service.getCaseWithAuditedAccess(
            GetSupportCaseCommand(
                principal = supportAdmin,
                tenantId = "tenant-supp-1",
                caseId = createResult.caseId,
                correlationId = "corr-view-unver",
                causationId = "caus-view-unver"
            )
        )
        assertFalse(unverifiedView.sensitiveDataDisclosed)
        assertEquals("REDACTED-UNVERIFIED", unverifiedView.playerReferenceRedacted)

        // Now verify identity
        service.verifyPlayerIdentity(
            VerifyPlayerIdentityCommand(
                principal = supportAdmin,
                tenantId = "tenant-supp-1",
                caseId = createResult.caseId,
                verificationMethod = "BIOMETRIC_AND_SMS_OTP",
                idempotencyKey = "idemp-life-verify",
                correlationId = "corr-life-ver",
                causationId = "caus-life-ver",
                expectedVersion = 1L
            )
        )

        // Now verified: disclosure is permitted and audited
        val verifiedView = service.getCaseWithAuditedAccess(
            GetSupportCaseCommand(
                principal = supportAdmin,
                tenantId = "tenant-supp-1",
                caseId = createResult.caseId,
                correlationId = "corr-view-ver",
                causationId = "caus-view-ver"
            )
        )
        assertTrue(verifiedView.sensitiveDataDisclosed)
        assertEquals("player-user-777", verifiedView.playerReferenceRedacted)

        // 4. SLA Visibility & Tracking:
        // Initially within SLA
        val slaInitial = service.evaluateCaseSla("tenant-supp-1", createResult.caseId, now)
        assertEquals(SlaStatus.WITHIN_SLA, slaInitial.slaStatus)
        assertFalse(slaInitial.isBreached)

        // Simulate passage of time past first response deadline (+2 hours): SLA is BREACHED!
        val laterTime = now.plus(Duration.ofHours(2))
        val slaBreached = service.evaluateCaseSla("tenant-supp-1", createResult.caseId, laterTime)
        assertEquals(SlaStatus.BREACHED, slaBreached.slaStatus)
        assertTrue(slaBreached.isBreached)

        // Verify actionable CRITICAL SLA alert emitted
        val alerts = store.getAlerts("tenant-supp-1")
        val slaAlert = alerts.firstOrNull { it.alertType == "CASE_SLA_BREACHED" }
        assertNotNull(slaAlert)
        assertEquals("CRITICAL", slaAlert.severity)
        assertTrue(slaAlert.message.contains("SLA BREACHED"))

        // 5. Test Sandbox scanner adapter compatibility
        val sandboxScanner = SandboxAttachmentScannerAdapter()
        val scanRes = sandboxScanner.scan("file.png", byteArrayOf(0x01, 0x02))
        assertTrue(scanRes.isClean)

        // 6. Audit immutability: all steps recorded without altering past rows
        val allAudits = store.getAudits("tenant-supp-1")
        assertEquals(4, allAudits.size) // CREATE, VIEW(unverified), VERIFY_ID, VIEW(verified)
    }
}
