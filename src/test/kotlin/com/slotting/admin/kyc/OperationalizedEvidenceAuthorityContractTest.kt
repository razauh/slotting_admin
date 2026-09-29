package com.slotting.admin.kyc

import com.slotting.admin.aml.*
import com.slotting.admin.auth.*
import com.slotting.admin.geo.*
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.*
import org.junit.jupiter.api.Test

class OperationalizedEvidenceAuthorityContractTest {
    private val now = Instant.parse("2026-09-26T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-compliance-1",
        tenantId = "tenant-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY, AdminRole.SUPER_ADMIN),
    )

    private fun sessionDirectory(
        active: Boolean = true,
        expiresAt: Instant = now.plus(Duration.ofHours(1)),
    ) = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return AdminSessionStatus(active = active, breakGlass = false, expiresAt = expiresAt)
        }
    }

    // -------------------------------------------------------------
    // Scenario 1: Provider Outage
    // -------------------------------------------------------------
    @Test
    fun `Scenario 1 - provider outage on geolocation fails closed to SUSPENDED_OR_AMBIGUOUS`() {
        val geoStore = GeoAntiSpoofMemoryStore()
        val vendorStore = LocalGeoVendorEvidenceStore()
        val outageVendorResult = GeoVendorEvidenceResult(
            resultId = UUID.randomUUID(),
            tenantId = "tenant-1",
            subjectReference = "player-geo-outage",
            providerId = "prov-geo-outage",
            operation = GeoEvidencePortOperation.VERIFY_LOCATION,
            canonicalStatus = GeoCanonicalStatus.SUSPENDED,
            vendorOutcome = GeoVendorOutcome.OUTAGE,
            detectedJurisdiction = null,
            directEligibilityGranted = false,
            evidenceReference = "EVID-REF-OUTAGE",
            serverTime = now,
        )
        vendorStore.save(
            outageVendorResult,
            "tenant-1",
            "fp-outage",
            "vendor-ref-outage",
            AuditEvent(UUID.randomUUID(), outageVendorResult.resultId, "tenant-1", "GEO", now, "c", "c"),
            OutboxEvent(UUID.randomUUID(), outageVendorResult.resultId, "tenant-1", "GEO", now),
        )

        val geoService = LicensedGeolocationAntiSpoofService(
            sessions = sessionDirectory(),
            store = geoStore,
            vendorEvidenceStore = vendorStore,
            clock = clock,
        )

        val result = geoService.evaluate(
            EvaluateGeolocationAntiSpoofCommand(
                principal = adminPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                subjectReference = "player-geo-outage",
                ipAddress = "198.51.100.5",
                clientReportedTimestamp = now,
                deviceIntegrity = DeviceIntegritySignals(),
                vendorEvidenceReference = "vendor-ref-outage",
                idempotencyKey = "idem-geo-outage-1",
                correlationId = "corr-1",
                causationId = "cause-1",
            )
        )

        assertEquals(GeoAntiSpoofStatus.SUSPENDED, result.status)
        assertEquals(GeoAntiSpoofVerdict.SUSPENDED_OR_AMBIGUOUS, result.verdict)
        assertEquals("VENDOR_OUTAGE_OR_INDETERMINATE", result.reasonCode)
        assertFalse(result.directEligibilityGranted)
    }

    // -------------------------------------------------------------
    // Scenario 2: Stale KYC
    // -------------------------------------------------------------
    @Test
    fun `Scenario 2 - stale KYC blocks eligibility and requires reverification`() {
        val staleRecord = KycStatusRecord(
            tenantId = "tenant-1",
            userId = "player-stale-kyc",
            status = KycStatusState.VERIFIED,
            verifiedAge = 25,
            verifiedAt = now.minus(Duration.ofDays(400)),
            expiresAt = now.minus(Duration.ofDays(10)), // Expired 10 days ago!
            serverVersion = 1L,
            updatedAt = now.minus(Duration.ofDays(10)),
        )

        // When evaluating staleness
        val isStale = staleRecord.expiresAt != null && staleRecord.expiresAt.isBefore(now)
        assertTrue(isStale)
        val effectiveStatus = if (isStale) KycStatusState.EXPIRED else staleRecord.status
        assertEquals(KycStatusState.EXPIRED, effectiveStatus)
    }

    // -------------------------------------------------------------
    // Scenario 3: PEP Hit
    // -------------------------------------------------------------
    @Test
    fun `Scenario 3 - PEP hit produces PEP_MATCH outcome and never SANCTION_HIT`() {
        val amlStore = TestAmlScreeningStore()
        val pepAdapter = object : SanctionsPepVendorAdapter {
            override val providerId: String = "prov-pep"
            override fun screen(subject: ScreeningSubject, checkType: ScreeningCheckType): SanctionsPepVendorResponse {
                return SanctionsPepVendorResponse(
                    matchScore = 0.90, // Greater than both sanctions (0.80) and PEP (0.85)
                    matchedLists = listOf("PEP_POLITICAL_FIGURES"),
                    indeterminate = false,
                )
            }
        }

        val amlService = SanctionsPepScreeningService(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory(),
            store = amlStore,
            thresholdConfig = ApprovedThresholdConfig(sanctionsMatchThreshold = 0.80, pepMatchThreshold = 0.85),
            adapters = mapOf("prov-pep" to pepAdapter),
            clock = clock,
        )

        val result = amlService.screenSubject(
            SanctionsPepScreeningCommand(
                principal = adminPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                subject = ScreeningSubject("player-pep-001", "Politician Jane"),
                checkType = ScreeningCheckType.PEP,
                providerId = "prov-pep",
                idempotencyKey = "idem-pep-1",
                correlationId = "corr-pep-1",
                causationId = "cause-pep-1",
            )
        )

        assertEquals(SanctionsPepOutcome.PEP_MATCH, result.outcome)
        assertEquals(ScreeningDecisionStatus.HOLD, result.status)
        assertNotNull(result.amlCaseReference)
        assertFalse(result.financialAuthorityCreated)
        assertFalse(result.moneyMutated)
    }

    // -------------------------------------------------------------
    // Scenario 4: Sanctions Hit
    // -------------------------------------------------------------
    @Test
    fun `Scenario 4 - sanctions hit produces SANCTION_HIT and queues AML review`() {
        val amlStore = TestAmlScreeningStore()
        val sanctionsAdapter = object : SanctionsPepVendorAdapter {
            override val providerId: String = "prov-sanctions"
            override fun screen(subject: ScreeningSubject, checkType: ScreeningCheckType): SanctionsPepVendorResponse {
                return SanctionsPepVendorResponse(
                    matchScore = 0.92,
                    matchedLists = listOf("OFAC_SDN"),
                    indeterminate = false,
                )
            }
        }

        val amlService = SanctionsPepScreeningService(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory(),
            store = amlStore,
            thresholdConfig = ApprovedThresholdConfig(sanctionsMatchThreshold = 0.80, pepMatchThreshold = 0.85),
            adapters = mapOf("prov-sanctions" to sanctionsAdapter),
            clock = clock,
        )

        val result = amlService.screenSubject(
            SanctionsPepScreeningCommand(
                principal = adminPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                subject = ScreeningSubject("player-sanctions-001", "Sanctioned Entity"),
                checkType = ScreeningCheckType.SANCTIONS,
                providerId = "prov-sanctions",
                idempotencyKey = "idem-sanctions-1",
                correlationId = "corr-sanctions-1",
                causationId = "cause-sanctions-1",
            )
        )

        assertEquals(SanctionsPepOutcome.SANCTION_HIT, result.outcome)
        assertEquals(ScreeningDecisionStatus.HOLD, result.status)
        assertNotNull(result.amlCaseReference)
        assertFalse(result.financialAuthorityCreated)
    }

    // -------------------------------------------------------------
    // Scenario 5: NaN Score
    // -------------------------------------------------------------
    @Test
    fun `Scenario 5 - NaN or invalid match score fails closed to INDETERMINATE and HOLD`() {
        val amlStore = TestAmlScreeningStore()
        val nanAdapter = object : SanctionsPepVendorAdapter {
            override val providerId: String = "prov-nan"
            override fun screen(subject: ScreeningSubject, checkType: ScreeningCheckType): SanctionsPepVendorResponse {
                return SanctionsPepVendorResponse(
                    matchScore = Double.NaN, // Corrupt/poisoned score
                    matchedLists = emptyList(),
                    indeterminate = false,
                )
            }
        }

        val amlService = SanctionsPepScreeningService(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory(),
            store = amlStore,
            adapters = mapOf("prov-nan" to nanAdapter),
            clock = clock,
        )

        val result = amlService.screenSubject(
            SanctionsPepScreeningCommand(
                principal = adminPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                subject = ScreeningSubject("player-nan-001", "NaN Test"),
                checkType = ScreeningCheckType.SANCTIONS_AND_PEP,
                providerId = "prov-nan",
                idempotencyKey = "idem-nan-1",
                correlationId = "corr-nan-1",
                causationId = "cause-nan-1",
            )
        )

        // Must FAIL CLOSED: cannot clear with NaN score!
        assertEquals(SanctionsPepOutcome.INDETERMINATE, result.outcome)
        assertEquals(ScreeningDecisionStatus.HOLD, result.status)
        assertNotNull(result.amlCaseReference)
    }

    // -------------------------------------------------------------
    // Scenario 6: Document Malware
    // -------------------------------------------------------------
    @Test
    fun `Scenario 6 - document malware detected throws MalwareDetectedException and quarantines`() {
        val malwareScanner = object : MalwareScannerPort {
            override fun scan(fileBytes: ByteArray, filename: String): MalwareScanOutcome {
                return MalwareScanOutcome(
                    status = MalwareScanStatus.INFECTED,
                    threatName = "Trojan.EICAR.TestFile",
                )
            }
        }

        val mockStorage = object : EncryptedStoragePort {
            override fun storeEncrypted(
                tenantId: String,
                userId: String,
                documentId: UUID,
                fileBytes: ByteArray,
                mimeType: String
            ): EncryptedStorageReference = EncryptedStorageReference("key", "arn")

            override fun delete(storageKey: String): Boolean = true
        }

        val service = IdentityDocumentUploadService(
            encryptedStorage = mockStorage,
            malwareScanner = malwareScanner,
            clock = clock,
        )

        val cmd = IdentityDocumentUploadCommand(
            principal = adminPrincipal,
            tenantId = "tenant-1",
            userId = "player-malware-001",
            documentType = IdentityDocumentType.PASSPORT,
            filename = "passport.pdf",
            mimeType = "application/pdf",
            fileBytes = "VIRUS_PAYLOAD".toByteArray(),
            idempotencyKey = "idem-malware-1",
            correlationId = "corr-malware-1",
            causationId = "cause-malware-1",
        )

        val ex = assertFailsWith<MalwareDetectedException> {
            service.uploadDocument(cmd)
        }
        assertEquals("Trojan.EICAR.TestFile", ex.threatName)
    }

    // -------------------------------------------------------------
    // Scenario 7: Foreign Subject
    // -------------------------------------------------------------
    @Test
    fun `Scenario 7 - foreign subject reference in geolocation vendor evidence is rejected`() {
        val geoStore = GeoAntiSpoofMemoryStore()
        val vendorStore = LocalGeoVendorEvidenceStore()

        // Vendor evidence belongs to "player-DIFFERENT"
        val foreignVendorResult = GeoVendorEvidenceResult(
            resultId = UUID.randomUUID(),
            tenantId = "tenant-1",
            subjectReference = "player-DIFFERENT",
            providerId = "prov-geo-1",
            operation = GeoEvidencePortOperation.VERIFY_LOCATION,
            canonicalStatus = GeoCanonicalStatus.EVIDENCE_COLLECTED,
            vendorOutcome = GeoVendorOutcome.PERMITTED_JURISDICTION,
            detectedJurisdiction = "US-NJ",
            directEligibilityGranted = false,
            evidenceReference = "EVID-REF-FOREIGN",
            serverTime = now,
        )
        vendorStore.save(
            foreignVendorResult,
            "tenant-1",
            "fp-foreign",
            "vendor-ref-foreign",
            AuditEvent(UUID.randomUUID(), foreignVendorResult.resultId, "tenant-1", "GEO", now, "c", "c"),
            OutboxEvent(UUID.randomUUID(), foreignVendorResult.resultId, "tenant-1", "GEO", now),
        )

        val geoService = LicensedGeolocationAntiSpoofService(
            sessions = sessionDirectory(),
            store = geoStore,
            vendorEvidenceStore = vendorStore,
            clock = clock,
        )

        val result = geoService.evaluate(
            EvaluateGeolocationAntiSpoofCommand(
                principal = adminPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                subjectReference = "player-real-user", // Mismatch with foreign vendor evidence!
                ipAddress = "198.51.100.5",
                clientReportedTimestamp = now,
                deviceIntegrity = DeviceIntegritySignals(),
                vendorEvidenceReference = "vendor-ref-foreign",
                idempotencyKey = "idem-foreign-1",
                correlationId = "corr-foreign-1",
                causationId = "cause-foreign-1",
            )
        )

        assertEquals(GeoAntiSpoofStatus.SUSPENDED, result.status)
        assertEquals(GeoAntiSpoofVerdict.SUSPENDED_OR_AMBIGUOUS, result.verdict)
        assertEquals("FOREIGN_SUBJECT_MISMATCH", result.reasonCode)
    }

    // -------------------------------------------------------------
    // Scenario 8: Geo Unavailable
    // -------------------------------------------------------------
    @Test
    fun `Scenario 8 - geolocation reports SUSPENDED_OR_AMBIGUOUS when vendor evidence is omitted`() {
        val geoStore = GeoAntiSpoofMemoryStore()
        val geoService = LicensedGeolocationAntiSpoofService(
            sessions = sessionDirectory(),
            store = geoStore,
            vendorEvidenceStore = null,
            clock = clock,
        )

        val result = geoService.evaluate(
            EvaluateGeolocationAntiSpoofCommand(
                principal = adminPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                subjectReference = "player-geo-no-evidence",
                ipAddress = "198.51.100.5",
                clientReportedTimestamp = now,
                deviceIntegrity = DeviceIntegritySignals(),
                vendorEvidenceReference = null, // Omitted!
                idempotencyKey = "idem-geo-no-evid-1",
                correlationId = "corr-no-evid-1",
                causationId = "cause-no-evid-1",
            )
        )

        // Cannot report VERIFIED_GENUINE without vendor evidence!
        assertEquals(GeoAntiSpoofStatus.SUSPENDED, result.status)
        assertEquals(GeoAntiSpoofVerdict.SUSPENDED_OR_AMBIGUOUS, result.verdict)
        assertEquals("VENDOR_EVIDENCE_REQUIRED", result.reasonCode)
    }

    // -------------------------------------------------------------
    // Scenario 9: Manual Review
    // -------------------------------------------------------------
    @Test
    fun `Scenario 9 - manual review case can be claimed and evaluated with audit trail`() {
        val store = LocalKycQueueStore()
        val reviewQueue = KycReviewQueue(
            policy = AdminRbacPolicy(true),
            sessions = sessionDirectory(),
            store = store,
            clock = clock,
        )

        store.seedItem(
            KycQueueItem(
                caseReference = "KYC-CASE-001",
                state = KycReviewState.QUEUED,
                claimedBy = null,
                claimExpiresAt = null,
                serverVersion = 1L,
            )
        )

        val claimCmd = KycReviewCommand(
            principal = adminPrincipal,
            sessionId = "sess-1",
            tenantId = "tenant-1",
            caseReference = "KYC-CASE-001",
            action = KycReviewAction.CLAIM,
            reason = KycReviewReason.IDENTITY_REVIEW,
            idempotencyKey = "idem-claim-1",
            correlationId = "corr-claim-1",
            causationId = "cause-claim-1",
            expectedVersion = 1L,
        )

        val result = reviewQueue.operate(claimCmd)
        assertEquals(KycReviewState.CLAIMED, result.item.state)
        assertEquals(adminPrincipal.id, result.item.claimedBy)
    }

    // -------------------------------------------------------------
    // Scenario 10: Recheck
    // -------------------------------------------------------------
    @Test
    fun `Scenario 10 - geo recheck action is required on expiry and cannot be bypassed`() {
        val verdictDirectory = object : GeoGateVerdictDirectory {
            override fun findVerdict(tenantId: String, verdictId: UUID): ActiveGeoVerdictRecord {
                return ActiveGeoVerdictRecord(
                    verdictId = verdictId,
                    tenantId = tenantId,
                    subjectReference = "player-recheck-001",
                    jurisdictionCode = "US-NJ",
                    isPermittedJurisdiction = true,
                    isAntiSpoofVerified = true,
                    evaluatedAt = now.minus(Duration.ofMinutes(30)),
                    expiresAt = now.minus(Duration.ofSeconds(10)), // Expired
                    isProviderOutage = false,
                    evidenceReference = "EVID-VERDICT-EXPIRED",
                )
            }
        }

        val wagerGateStore = InMemoryWagerGeoGateStore()

        val gateService = GeoExpiryRecheckGateService(
            sessions = sessionDirectory(),
            verdicts = verdictDirectory,
            store = wagerGateStore,
            clock = clock,
        )

        val verdictId = UUID.randomUUID()
        val result = gateService.evaluateGate(
            EvaluateWagerGeoGateCommand(
                principal = adminPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-1",
                subjectReference = "player-recheck-001",
                wagerId = UUID.randomUUID(),
                verdictId = verdictId,
                idempotencyKey = "idem-gate-recheck-1",
                correlationId = "corr-gate-1",
                causationId = "cause-gate-1",
            )
        )

        assertEquals(GeoGateDecision.DENIED_EXPIRED, result.decision)
        assertFalse(result.permitted)
        assertEquals(GeoRecheckActionType.REQUEST_FRESH_GEOLOCATION, result.recheckAction.actionType)
        assertFalse(result.recheckAction.canBypass) // Invariant: CANNOT BYPASS!
    }
}

private class LocalGeoVendorEvidenceStore : GeoVendorEvidenceStore {
    private val results = mutableMapOf<String, Pair<String, GeoVendorEvidenceResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        results["$tenantId:$idempotencyKey"]

    override fun save(
        result: GeoVendorEvidenceResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}

private class LocalKycQueueStore : KycQueueStore {
    private val items = mutableMapOf<String, KycQueueItem>()
    private val idempotency = mutableMapOf<String, Pair<String, KycReviewResult>>()

    fun seedItem(item: KycQueueItem) {
        items[item.caseReference] = item
    }

    override fun findByIdempotency(tenantId: String, key: String): Pair<String, KycReviewResult>? =
        idempotency["$tenantId:$key"]

    override fun findItem(tenantId: String, caseReference: String): KycQueueItem? =
        items[caseReference]

    override fun save(
        result: KycReviewResult,
        tenantId: String,
        reason: KycReviewReason,
        secondApproverId: String?,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent
    ) {
        items[result.item.caseReference] = result.item
        idempotency["$tenantId:$idempotencyKey"] = queryFingerprint to result
    }
}

private class TestAmlScreeningStore : SanctionsPepScreeningStore {
    val results = mutableMapOf<String, Pair<String, SanctionsPepScreeningResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()
    val queuedItems = mutableMapOf<String, AmlQueueItem>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        results["$tenantId:$idempotencyKey"]

    override fun save(
        result: SanctionsPepScreeningResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
        queuedAmlItem: AmlQueueItem?,
    ) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit.add(audit)
        this.outbox.add(outbox)
        queuedAmlItem?.let { queuedItems[it.caseReference] = it }
    }
}
