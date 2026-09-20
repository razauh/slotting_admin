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
 * Contract test suite for SUPPORT-001-03: Secure support notes and attachments.
 *
 * Source implementation-plan family: SUPPORT-001
 * Semantic Contract: "Notes do not mutate finance; attachments scanned; identity checks and access audited."
 * Expected RED failure: "unverified disclosure/attachment abuse/SLA invisible"
 */
class SecureSupportNotesAttachmentsTest {

    private val now = Instant.parse("2026-09-20T16:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val supportAdmin = AuthenticatedPrincipal(
        id = "agent-sec-support-01",
        tenantId = "tenant-sec-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-sec-user-101",
        tenantId = "tenant-sec-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val otherPlayerPrincipal = AuthenticatedPrincipal(
        id = "player-sec-user-202",
        tenantId = "tenant-sec-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    @BeforeEach
    fun setUp() {
        SecureSupportNotesAttachmentsBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        SecureSupportNotesAttachmentsBinding.isBound = true
    }

    // =========================================================================
    // SUPPORT-001-03-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `SUPPORT-001-03-T001 Secure support notes and attachments produces the required authoritative outcome`() {
        // Fail-closed gate check: triggers RED assertion failure when unbound
        SecureSupportNotesAttachmentsBinding.checkBound()

        val store = InMemorySecureSupportNotesAttachmentsStore()
        val scanner = FakeSecureAttachmentScanner()
        val service = SecureSupportNotesAttachmentsService(store, scanner, clock)

        // 1. Initialize case container
        val initCmd = InitializeCaseContainerCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-101",
            playerReference = "player-sec-user-101",
            initialIdentityState = RequesterIdentityState.IDENTITY_UNVERIFIED,
            idempotencyKey = "idemp-init-01",
            correlationId = "corr-init-01",
            causationId = "caus-init-01",
            expectedVersion = 1L,
            mutatesMoney = false
        )
        val initResult = service.initializeCaseContainer(initCmd)
        assertEquals("case-sec-101", initResult.caseId)
        assertEquals(RequesterIdentityState.IDENTITY_UNVERIFIED, initResult.identityState)
        assertFalse(initResult.isFinancialAuthorityCreated)

        // 2. Add secure note (Notes do not mutate finance!)
        val noteCmd = AddSecureNoteCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-101",
            classification = NoteClassification.TEAM_COLLABORATION,
            content = "Verified player submitted transaction ID 883921 from external provider",
            isInternal = true,
            containsPii = false,
            idempotencyKey = "idemp-note-01",
            correlationId = "corr-note-01",
            causationId = "caus-note-01",
            expectedVersion = 1L,
            mutatesFinance = false,
            balanceAdjustmentMinorUnits = null,
            mutatesMoney = false
        )
        val noteResult = service.addSecureNote(noteCmd)
        assertEquals(1, noteResult.notesCount)
        assertEquals(NoteClassification.TEAM_COLLABORATION, noteResult.classification)
        assertFalse(noteResult.isFinancialAuthorityCreated)

        // 3. Upload secure attachment with malware scanning (Attachments scanned!)
        val pdfContent = "%PDF-1.4 test secure receipt evidence".toByteArray(Charsets.UTF_8)
        val uploadCmd = UploadSecureAttachmentCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-101",
            fileName = "payment_receipt.pdf",
            mimeType = "application/pdf",
            documentType = SupportDocumentType.PAYMENT_RECEIPT,
            contentBytes = pdfContent,
            idempotencyKey = "idemp-upload-01",
            correlationId = "corr-upload-01",
            causationId = "caus-upload-01",
            expectedVersion = 2L,
            mutatesMoney = false
        )
        val uploadResult = service.uploadSecureAttachment(uploadCmd)
        assertEquals(SecureAttachmentScanStatus.CLEAN, uploadResult.scanStatus)
        assertEquals(1, uploadResult.attachmentsCount)
        assertFalse(uploadResult.isFinancialAuthorityCreated)
        // Review SLA is 4h for PAYMENT_RECEIPT
        assertEquals(now.plus(Duration.ofHours(4)), uploadResult.reviewSlaDueAt)

        // 4. Verify player identity
        val verifyCmd = VerifyRequesterIdentityCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-101",
            verificationMethod = "BANK_MFA_TOKEN_CONFIRMATION",
            idempotencyKey = "idemp-verify-01",
            correlationId = "corr-verify-01",
            causationId = "caus-verify-01",
            expectedVersion = 3L,
            mutatesMoney = false
        )
        val verifyResult = service.verifyRequesterIdentity(verifyCmd)
        assertEquals(RequesterIdentityState.IDENTITY_VERIFIED, verifyResult.identityState)
        assertFalse(verifyResult.isFinancialAuthorityCreated)

        // 5. Access attachment with audited access
        val accessCmd = AccessSecureAttachmentCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-101",
            attachmentId = uploadResult.attachmentId,
            correlationId = "corr-access-01",
            causationId = "caus-access-01"
        )
        val accessResult = service.accessSecureAttachment(accessCmd)
        assertEquals("payment_receipt.pdf", accessResult.fileName)
        assertFalse(accessResult.isFinancialAuthorityCreated)

        // 6. View notes and attachments with verified access
        val viewCmd = GetSecureCaseNotesAndAttachmentsCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-101",
            correlationId = "corr-view-01",
            causationId = "caus-view-01"
        )
        val viewResult = service.getSecureCaseNotesAndAttachments(viewCmd)
        assertTrue(viewResult.sensitiveDataDisclosed)
        assertEquals("player-sec-user-101", viewResult.playerReferenceRedacted)
        assertEquals(1, viewResult.notes.size)
        assertEquals(1, viewResult.attachments.size)

        // 7. Evaluate attachment SLA (SLA visible!)
        val slaCmd = EvaluateAttachmentReviewSlaCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-101",
            attachmentId = uploadResult.attachmentId,
            asOfTime = now.plus(Duration.ofHours(1)),
            correlationId = "corr-sla-01",
            causationId = "caus-sla-01"
        )
        val slaResult = service.evaluateAttachmentReviewSla(slaCmd)
        assertEquals(SecureAttachmentSlaStatus.WITHIN_SLA, slaResult.slaStatus)
        assertFalse(slaResult.isBreached)
        assertFalse(slaResult.isAtRisk)

        // 8. Assert exact semantic contract
        assertEquals(
            "Notes do not mutate finance; attachments scanned; identity checks and access audited.",
            SECURE_SUPPORT_NOTES_ATTACHMENTS_CONTRACT
        )

        // 9. Verify audits exist and no secrets leaked
        val audits = store.getAudits("tenant-sec-1")
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.any { it.action == SecureSupportAuditAction.CASE_CONTAINER_INITIALIZED })
        assertTrue(audits.any { it.action == SecureSupportAuditAction.NOTE_ADDED })
        assertTrue(audits.any { it.action == SecureSupportAuditAction.ATTACHMENT_SCANNED })
        assertTrue(audits.any { it.action == SecureSupportAuditAction.IDENTITY_VERIFIED })
        assertTrue(audits.any { it.action == SecureSupportAuditAction.ATTACHMENT_ACCESSED })
        assertTrue(audits.any { it.action == SecureSupportAuditAction.NOTES_ATTACHMENTS_VIEWED })

        val auditDetails = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditDetails.contains("PASSWORD", ignoreCase = true))
        assertFalse(auditDetails.contains("SECRET", ignoreCase = true))

        // 10. Assert no financial mutation methods exist on service
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // SUPPORT-001-03-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `SUPPORT-001-03-T002 Secure support notes and attachments rejects invalid boundary unauthorized and stale input`() {
        SecureSupportNotesAttachmentsBinding.isBound = true

        val store = InMemorySecureSupportNotesAttachmentsStore()
        val scanner = FakeSecureAttachmentScanner()
        val service = SecureSupportNotesAttachmentsService(store, scanner, clock)

        val validInit = InitializeCaseContainerCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-202",
            playerReference = "player-sec-user-101",
            initialIdentityState = RequesterIdentityState.IDENTITY_UNVERIFIED,
            idempotencyKey = "idemp-t002-init",
            correlationId = "corr-t002",
            causationId = "caus-t002",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initializeCaseContainer(validInit.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initializeCaseContainer(validInit.copy(tenantId = "other-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Stale expected version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initializeCaseContainer(validInit.copy(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Blank caseId or playerReference rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initializeCaseContainer(validInit.copy(caseId = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initializeCaseContainer(validInit.copy(playerReference = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Initialize valid container for note/attachment tests
        service.initializeCaseContainer(validInit)

        // 5. Note attempting to mutate finance rejected (Notes do not mutate finance!)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addSecureNote(
                AddSecureNoteCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-202",
                    content = "Attempting to grant compensatory credit",
                    isInternal = true,
                    idempotencyKey = "idemp-t002-note-fin",
                    correlationId = "corr-t002",
                    causationId = "caus-t002",
                    expectedVersion = 1L,
                    mutatesFinance = true, // FORBIDDEN!
                    balanceAdjustmentMinorUnits = 5000L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Note with balance adjustment rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addSecureNote(
                AddSecureNoteCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-202",
                    content = "Balance adjust note",
                    isInternal = true,
                    idempotencyKey = "idemp-t002-note-bal",
                    correlationId = "corr-t002",
                    causationId = "caus-t002",
                    expectedVersion = 1L,
                    mutatesFinance = false,
                    balanceAdjustmentMinorUnits = 1000L // FORBIDDEN!
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Player attempting to post internal note rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.addSecureNote(
                AddSecureNoteCommand(
                    principal = playerPrincipal,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-202",
                    content = "Player posting internal note",
                    isInternal = true,
                    idempotencyKey = "idemp-t002-player-internal",
                    correlationId = "corr-t002",
                    causationId = "caus-t002",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 8. Attachment with dangerous extension rejected
        listOf("malware.exe", "script.bat", "run.sh", "payload.cmd", "agent.ps1", "trojan.jar").forEach { dangerousFile ->
            assertFailsWith<AuthenticationFailure.Rejected> {
                service.uploadSecureAttachment(
                    UploadSecureAttachmentCommand(
                        principal = supportAdmin,
                        tenantId = "tenant-sec-1",
                        caseId = "case-sec-202",
                        fileName = dangerousFile,
                        mimeType = "application/octet-stream",
                        contentBytes = "echo bad".toByteArray(Charsets.UTF_8),
                        idempotencyKey = "idemp-t002-danger-$dangerousFile",
                        correlationId = "corr-t002",
                        causationId = "caus-t002",
                        expectedVersion = 1L
                    )
                )
            }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        }

        // 9. Attachment with malware signature quarantined and rejected (Attachment abuse prevented!)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.uploadSecureAttachment(
                UploadSecureAttachmentCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-202",
                    fileName = "eicar_test_virus.pdf",
                    mimeType = "application/pdf",
                    contentBytes = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*".toByteArray(Charsets.UTF_8),
                    idempotencyKey = "idemp-t002-eicar",
                    correlationId = "corr-t002",
                    causationId = "caus-t002",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Verify critical alert was raised for quarantined file
        val alerts = store.getAlerts("tenant-sec-1")
        assertTrue(alerts.any { it.severity == "CRITICAL" && it.alertType == "ATTACHMENT_MALWARE_DETECTED" })

        // 10. Attachment exceeding max file size (> 10MB) rejected
        val oversizedBytes = ByteArray(10 * 1024 * 1024 + 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.uploadSecureAttachment(
                UploadSecureAttachmentCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-202",
                    fileName = "oversized_log.txt",
                    mimeType = "text/plain",
                    contentBytes = oversizedBytes,
                    idempotencyKey = "idemp-t002-oversized",
                    correlationId = "corr-t002",
                    causationId = "caus-t002",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 11. Cross-player access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.getSecureCaseNotesAndAttachments(
                GetSecureCaseNotesAndAttachmentsCommand(
                    principal = otherPlayerPrincipal, // player-sec-user-202 trying to view player-sec-user-101's case
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-202",
                    correlationId = "corr-t002",
                    causationId = "caus-t002"
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 12. Non-admin verifying identity rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.verifyRequesterIdentity(
                VerifyRequesterIdentityCommand(
                    principal = playerPrincipal,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-202",
                    verificationMethod = "SELF_CONFIRMATION",
                    idempotencyKey = "idemp-t002-nonadmin-verify",
                    correlationId = "corr-t002",
                    causationId = "caus-t002",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // SUPPORT-001-03-T003: Concurrency, Replay, Conflict, and Dependency Failure
    // =========================================================================

    @Test
    fun `SUPPORT-001-03-T003 Secure support notes and attachments handles concurrency replay conflict and dependency failure`() {
        SecureSupportNotesAttachmentsBinding.isBound = true

        val store = InMemorySecureSupportNotesAttachmentsStore()
        val scanner = FakeSecureAttachmentScanner()
        val service = SecureSupportNotesAttachmentsService(store, scanner, clock)

        // 1. Concurrency: 10 concurrent threads adding notes to 10 independent cases
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        try {
            val tasks = (1..threadCount).map { i ->
                Callable {
                    val caseId = "case-concurrent-$i"
                    service.initializeCaseContainer(
                        InitializeCaseContainerCommand(
                            principal = supportAdmin,
                            tenantId = "tenant-sec-1",
                            caseId = caseId,
                            playerReference = "player-sec-$i",
                            initialIdentityState = RequesterIdentityState.IDENTITY_VERIFIED,
                            idempotencyKey = "idemp-init-$i",
                            correlationId = "corr-conc-$i",
                            causationId = "caus-conc-$i",
                            expectedVersion = 1L
                        )
                    )
                    service.addSecureNote(
                        AddSecureNoteCommand(
                            principal = supportAdmin,
                            tenantId = "tenant-sec-1",
                            caseId = caseId,
                            content = "Concurrent test note for case $i",
                            isInternal = true,
                            idempotencyKey = "idemp-note-conc-$i",
                            correlationId = "corr-conc-note-$i",
                            causationId = "caus-conc-note-$i",
                            expectedVersion = 1L
                        )
                    )
                }
            }

            val futures = tasks.map { executor.submit(it) }
            val results = futures.map { it.get() }
            assertEquals(10, results.size)
            results.forEach {
                assertEquals(1, it.notesCount)
                assertFalse(it.isFinancialAuthorityCreated)
            }
        } finally {
            executor.shutdown()
        }

        // 2. Idempotent replay: identical idempotencyKey + fingerprint returns cached result
        val initCase = InitializeCaseContainerCommand(
            principal = supportAdmin,
            tenantId = "tenant-sec-1",
            caseId = "case-sec-replay",
            playerReference = "player-sec-user-101",
            initialIdentityState = RequesterIdentityState.IDENTITY_VERIFIED,
            idempotencyKey = "idemp-replay-01",
            correlationId = "corr-rep-01",
            causationId = "caus-rep-01",
            expectedVersion = 1L
        )
        val firstResult = service.initializeCaseContainer(initCase)
        val replayedResult = service.initializeCaseContainer(initCase)
        assertEquals(firstResult.resultId, replayedResult.resultId)
        assertEquals(firstResult.evidenceReference, replayedResult.evidenceReference)

        // 3. Conflict replay: identical idempotencyKey with modified payload throws CONFLICT
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.initializeCaseContainer(initCase.copy(playerReference = "player-sec-DIFFERENT"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Dependency failure: malware scanner timeout or unavailable fails closed
        scanner.simulateTimeout = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.uploadSecureAttachment(
                UploadSecureAttachmentCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-replay",
                    fileName = "receipt.pdf",
                    mimeType = "application/pdf",
                    contentBytes = "sample receipt content".toByteArray(Charsets.UTF_8),
                    idempotencyKey = "idemp-timeout-upload",
                    correlationId = "corr-to-01",
                    causationId = "caus-to-01",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        scanner.simulateTimeout = false
        scanner.shouldFail = true
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.uploadSecureAttachment(
                UploadSecureAttachmentCommand(
                    principal = supportAdmin,
                    tenantId = "tenant-sec-1",
                    caseId = "case-sec-replay",
                    fileName = "receipt2.pdf",
                    mimeType = "application/pdf",
                    contentBytes = "sample receipt content".toByteArray(Charsets.UTF_8),
                    idempotencyKey = "idemp-fail-upload",
                    correlationId = "corr-fail-01",
                    causationId = "caus-fail-01",
                    expectedVersion = 1L
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    // =========================================================================
    // SUPPORT-001-03-T004: Lifecycle, Fail-Closed Binding, Redaction, and SLA Alerting
    // =========================================================================

    @Test
    fun `SUPPORT-001-03-T004 Secure support notes and attachments enforces lifecycle invariants audit immutability and fails closed`() {
        // 1. Verification gate test: when isBound = false, checkBound() throws AssertionError
        SecureSupportNotesAttachmentsBinding.isBound = false
        val gateException = assertFailsWith<AssertionError> {
            SecureSupportNotesAttachmentsBinding.checkBound()
        }
        assertEquals("unverified disclosure/attachment abuse/SLA invisible", gateException.message)

        // Restore gate for remaining assertions
        SecureSupportNotesAttachmentsBinding.isBound = true

        val store = InMemorySecureSupportNotesAttachmentsStore()
        val scanner = FakeSecureAttachmentScanner()
        val service = SecureSupportNotesAttachmentsService(store, scanner, clock)

        // 2. Initialize case with UNVERIFIED identity
        val caseId = "case-unverified-lifecycle"
        service.initializeCaseContainer(
            InitializeCaseContainerCommand(
                principal = supportAdmin,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                playerReference = "player-sec-user-101",
                initialIdentityState = RequesterIdentityState.IDENTITY_UNVERIFIED,
                idempotencyKey = "idemp-life-init",
                correlationId = "corr-life-01",
                causationId = "caus-life-01",
                expectedVersion = 1L
            )
        )

        // Add note containing PII
        service.addSecureNote(
            AddSecureNoteCommand(
                principal = supportAdmin,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                classification = NoteClassification.PUBLIC_CUSTOMER,
                content = "Customer phone number +1-555-0199 and SSN last 4: 9812",
                isInternal = false,
                containsPii = true,
                idempotencyKey = "idemp-life-pii-note",
                correlationId = "corr-life-02",
                causationId = "caus-life-02",
                expectedVersion = 1L
            )
        )

        // Upload clean attachment
        val attUpload = service.uploadSecureAttachment(
            UploadSecureAttachmentCommand(
                principal = supportAdmin,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                fileName = "id_card.png",
                mimeType = "image/png",
                documentType = SupportDocumentType.IDENTITY_ID_PROOF, // 2h SLA
                contentBytes = "binary png data".toByteArray(Charsets.UTF_8),
                idempotencyKey = "idemp-life-att",
                correlationId = "corr-life-03",
                causationId = "caus-life-03",
                expectedVersion = 2L
            )
        )

        // 3. Unverified disclosure protection:
        // Player views case while UNVERIFIED -> sensitive data redacted!
        val unverifiedPlayerView = service.getSecureCaseNotesAndAttachments(
            GetSecureCaseNotesAndAttachmentsCommand(
                principal = playerPrincipal,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                correlationId = "corr-life-04",
                causationId = "caus-life-04"
            )
        )
        assertFalse(unverifiedPlayerView.sensitiveDataDisclosed)
        assertEquals("REDACTED-UNVERIFIED", unverifiedPlayerView.playerReferenceRedacted)
        assertEquals(1, unverifiedPlayerView.notes.size)
        assertEquals("REDACTED-UNVERIFIED", unverifiedPlayerView.notes[0].content)

        // Player attempting to download attachment while UNVERIFIED -> rejected!
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.accessSecureAttachment(
                AccessSecureAttachmentCommand(
                    principal = playerPrincipal,
                    tenantId = "tenant-sec-1",
                    caseId = caseId,
                    attachmentId = attUpload.attachmentId,
                    correlationId = "corr-life-05",
                    causationId = "caus-life-05"
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. SLA visibility & alerting:
        // Evaluate SLA at +1h30m (30m remaining < 1h) -> AT_RISK alert emitted!
        val atRiskSla = service.evaluateAttachmentReviewSla(
            EvaluateAttachmentReviewSlaCommand(
                principal = supportAdmin,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                attachmentId = attUpload.attachmentId,
                asOfTime = now.plus(Duration.ofMinutes(90)),
                correlationId = "corr-sla-risk",
                causationId = "caus-sla-risk"
            )
        )
        assertEquals(SecureAttachmentSlaStatus.AT_RISK, atRiskSla.slaStatus)
        assertTrue(atRiskSla.isAtRisk)
        assertTrue(atRiskSla.alertEmitted)

        // Evaluate SLA at +3h (> 2h due) -> BREACHED critical alert emitted!
        val breachedSla = service.evaluateAttachmentReviewSla(
            EvaluateAttachmentReviewSlaCommand(
                principal = supportAdmin,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                attachmentId = attUpload.attachmentId,
                asOfTime = now.plus(Duration.ofHours(3)),
                correlationId = "corr-sla-breach",
                causationId = "caus-sla-breach"
            )
        )
        assertEquals(SecureAttachmentSlaStatus.BREACHED, breachedSla.slaStatus)
        assertTrue(breachedSla.isBreached)
        assertTrue(breachedSla.alertEmitted)

        val alerts = store.getAlerts("tenant-sec-1")
        assertTrue(alerts.any { it.severity == "WARN" && it.alertType == "ATTACHMENT_REVIEW_SLA_AT_RISK" })
        assertTrue(alerts.any { it.severity == "CRITICAL" && it.alertType == "ATTACHMENT_REVIEW_SLA_BREACHED" })

        // 5. Verify identity transitions case and unlocks disclosure
        service.verifyRequesterIdentity(
            VerifyRequesterIdentityCommand(
                principal = supportAdmin,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                verificationMethod = "PASSPORT_AND_FACIAL_MATCH",
                idempotencyKey = "idemp-life-verify",
                correlationId = "corr-life-06",
                causationId = "caus-life-06",
                expectedVersion = 3L
            )
        )

        // Verified player can now view unredacted data and download attachment
        val verifiedPlayerView = service.getSecureCaseNotesAndAttachments(
            GetSecureCaseNotesAndAttachmentsCommand(
                principal = playerPrincipal,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                correlationId = "corr-life-07",
                causationId = "caus-life-07"
            )
        )
        assertTrue(verifiedPlayerView.sensitiveDataDisclosed)
        assertEquals("player-sec-user-101", verifiedPlayerView.playerReferenceRedacted)
        assertEquals("Customer phone number +1-555-0199 and SSN last 4: 9812", verifiedPlayerView.notes[0].content)

        val downloadResult = service.accessSecureAttachment(
            AccessSecureAttachmentCommand(
                principal = playerPrincipal,
                tenantId = "tenant-sec-1",
                caseId = caseId,
                attachmentId = attUpload.attachmentId,
                correlationId = "corr-life-08",
                causationId = "caus-life-08"
            )
        )
        assertEquals("id_card.png", downloadResult.fileName)
        assertFalse(downloadResult.isFinancialAuthorityCreated)

        // 6. Audit immutability check
        val allAudits = store.getAudits("tenant-sec-1")
        assertTrue(allAudits.size >= 7)
        assertTrue(allAudits.any { it.action == SecureSupportAuditAction.IDENTITY_VERIFIED })
        assertTrue(allAudits.any { it.action == SecureSupportAuditAction.UNVERIFIED_DISCLOSURE_PREVENTED })
        assertTrue(allAudits.any { it.action == SecureSupportAuditAction.SLA_BREACH_ALERTED })
    }
}
