package com.slotting.admin.observability

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.secret.AesGcmEnvelopeEncryptor
import com.slotting.admin.secret.LocalDevMasterKeyProvider
import com.slotting.admin.secret.ProductionSecurityException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class OperationalObservabilityContractTest {

    private lateinit var clock: Clock
    private lateinit var store: ObservabilitySettingsStore
    private lateinit var sessions: FakeAdminSessionDirectory
    private lateinit var rbacPolicy: AdminRbacPolicy
    private lateinit var encryptor: AesGcmEnvelopeEncryptor
    private lateinit var settingsService: ObservabilitySettingsService

    private val tenantId = "tenant-observability-01"
    private val sessionId = "session-sec-01"

    private val securityAdmin = AuthenticatedPrincipal(
        id = "admin-sec",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private val auditor = AuthenticatedPrincipal(
        id = "auditor-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val support = AuthenticatedPrincipal(
        id = "support-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    @BeforeEach
    fun setUp() {
        clock = Clock.fixed(Instant.parse("2026-09-26T12:00:00Z"), ZoneOffset.UTC)
        store = ObservabilitySettingsStore()
        sessions = FakeAdminSessionDirectory()
        rbacPolicy = AdminRbacPolicy(dualControlRequired = false)
        encryptor = AesGcmEnvelopeEncryptor(LocalDevMasterKeyProvider(), environment = "TEST")

        // Register active sessions
        sessions.registerSession(
            tenantId,
            securityAdmin.id,
            sessionId,
            com.slotting.admin.auth.AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = Instant.parse("2026-09-26T14:00:00Z"),
                mfaVerified = true,
            )
        )
        sessions.registerSession(
            tenantId,
            auditor.id,
            "session-audit",
            com.slotting.admin.auth.AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = Instant.parse("2026-09-26T14:00:00Z"),
                mfaVerified = true,
            )
        )
        sessions.registerSession(
            tenantId,
            support.id,
            "session-support",
            com.slotting.admin.auth.AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = Instant.parse("2026-09-26T14:00:00Z"),
                mfaVerified = true,
            )
        )

        settingsService = ObservabilitySettingsService(
            store = store,
            sessions = sessions,
            rbacPolicy = rbacPolicy,
            encryptor = encryptor,
            clock = clock,
            environment = "TEST",
            allowLocalDevEndpoints = true
        )
    }

    @Test
    fun test01_rbacAuthorization_viewAndEditObservabilitySettings() {
        // Auditor can VIEW
        val view = settingsService.getSiemSettings(auditor, tenantId, "session-audit")
        assertNotNull(view)
        assertEquals(ObservabilityReadinessState.NOT_CONFIGURED, view.readiness)

        // Support cannot VIEW
        assertThrows(AuthenticationFailure.Rejected::class.java) {
            settingsService.getSiemSettings(support, tenantId, "session-support")
        }

        // Auditor cannot EDIT
        assertThrows(AuthenticationFailure.Rejected::class.java) {
            settingsService.updateSiemSettings(
                auditor,
                UpdateSiemConfigCommand(
                    tenantId = tenantId,
                    sessionId = "session-audit",
                    providerType = SiemProviderType.OPENSEARCH,
                    enabled = true,
                    endpointUrl = "https://opensearch.example.com",
                    expectedVersion = 0L,
                    correlationId = "corr-01",
                    causationId = "cause-01"
                )
            )
        }

        // SecurityAdmin can EDIT
        val updated = settingsService.updateSiemSettings(
            securityAdmin,
            UpdateSiemConfigCommand(
                tenantId = tenantId,
                sessionId = sessionId,
                providerType = SiemProviderType.OPENSEARCH,
                enabled = true,
                endpointUrl = "https://opensearch.example.com",
                expectedVersion = 0L,
                correlationId = "corr-01",
                causationId = "cause-01"
            )
        )
        assertEquals(ObservabilityReadinessState.CONFIGURED, updated.readiness)
        assertEquals(1L, updated.configVersion)
    }

    @Test
    fun test02_writeOnlySecrets_neverReturnedInViewAndCanBePreservedOrReplaced() {
        // 1. Initial save with secret
        val saved = settingsService.updateSiemSettings(
            securityAdmin,
            UpdateSiemConfigCommand(
                tenantId = tenantId,
                sessionId = sessionId,
                providerType = SiemProviderType.OPENSEARCH,
                enabled = true,
                endpointUrl = "https://opensearch.example.com",
                replaceAuthSecret = "SecretApiKey123!",
                expectedVersion = 0L,
                correlationId = "corr-02",
                causationId = "cause-02"
            )
        )
        assertTrue(saved.secretStatus.configured)

        // 2. View settings: secret is NOT returned in plaintext or masked string
        val view = settingsService.getSiemSettings(securityAdmin, tenantId, sessionId)
        assertTrue(view.secretStatus.configured)

        // 3. Update without secret preserves existing encrypted secret
        val preserved = settingsService.updateSiemSettings(
            securityAdmin,
            UpdateSiemConfigCommand(
                tenantId = tenantId,
                sessionId = sessionId,
                providerType = SiemProviderType.OPENSEARCH,
                enabled = true,
                endpointUrl = "https://opensearch-cluster2.example.com",
                replaceAuthSecret = null,
                clearAuthSecret = false,
                expectedVersion = 1L,
                correlationId = "corr-03",
                causationId = "cause-03"
            )
        )
        assertTrue(preserved.secretStatus.configured)
        assertEquals("https://opensearch-cluster2.example.com", preserved.endpointUrl)

        val rawConfig = store.getSiemConfig(tenantId)!!
        assertNotNull(rawConfig.encryptedAuthSecret)
        val decrypted = settingsService.decryptSiemSecret(tenantId, rawConfig.encryptedAuthSecret!!)
        assertEquals("SecretApiKey123!", decrypted)

        // 4. Clear secret removes it
        val cleared = settingsService.updateSiemSettings(
            securityAdmin,
            UpdateSiemConfigCommand(
                tenantId = tenantId,
                sessionId = sessionId,
                providerType = SiemProviderType.OPENSEARCH,
                enabled = true,
                endpointUrl = "https://opensearch-cluster2.example.com",
                replaceAuthSecret = null,
                clearAuthSecret = true,
                expectedVersion = 2L,
                correlationId = "corr-04",
                causationId = "cause-04"
            )
        )
        assertFalse(cleared.secretStatus.configured)
    }

    @Test
    fun test03_ssrfProtection_rejectsCloudMetadataAndProhibitedProtocols() {
        val prodSettingsService = ObservabilitySettingsService(
            store = store,
            sessions = sessions,
            rbacPolicy = rbacPolicy,
            encryptor = encryptor,
            clock = clock,
            environment = "PRODUCTION",
            allowLocalDevEndpoints = false
        )

        // Cloud metadata rejected
        assertThrows(ObservabilitySsrfException::class.java) {
            prodSettingsService.updateSiemSettings(
                securityAdmin,
                UpdateSiemConfigCommand(
                    tenantId = tenantId,
                    sessionId = sessionId,
                    providerType = SiemProviderType.GENERIC_HTTPS,
                    endpointUrl = "http://169.254.169.254/latest/meta-data",
                    expectedVersion = 0L,
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // Loopback rejected in PRODUCTION
        assertThrows(ObservabilitySsrfException::class.java) {
            prodSettingsService.updateSiemSettings(
                securityAdmin,
                UpdateSiemConfigCommand(
                    tenantId = tenantId,
                    sessionId = sessionId,
                    providerType = SiemProviderType.GENERIC_HTTPS,
                    endpointUrl = "https://127.0.0.1:9200",
                    expectedVersion = 0L,
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // Plain HTTP rejected in PRODUCTION
        assertThrows(ObservabilitySsrfException::class.java) {
            prodSettingsService.updateSiemSettings(
                securityAdmin,
                UpdateSiemConfigCommand(
                    tenantId = tenantId,
                    sessionId = sessionId,
                    providerType = SiemProviderType.GENERIC_HTTPS,
                    endpointUrl = "http://insecure-siem.example.com",
                    expectedVersion = 0L,
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
    }

    @Test
    fun test04_productionSafety_rejectsSyntheticAdaptersInProduction() {
        assertThrows(ProductionSecurityException::class.java) {
            TruthfulObservabilityService(
                settingsService = settingsService,
                siemTransport = SyntheticSiemAdapter(),
                pagingTransport = AlertmanagerPagingAdapter { _, _, _ -> HttpResponse(200, "ok") },
                environment = "PRODUCTION"
            )
        }

        assertThrows(ProductionSecurityException::class.java) {
            TruthfulObservabilityService(
                settingsService = settingsService,
                siemTransport = OpenSearchSiemAdapter { _, _, _ -> HttpResponse(200, "ok") },
                pagingTransport = SyntheticPagingAdapter(),
                environment = "PRODUCTION"
            )
        }
    }

    @Test
    fun test05_structuredRedaction_sanitizesNestedMapsListsHeadersAndQueryStrings() {
        val payload = mapOf(
            "user" to mapOf(
                "id" to "usr-123",
                "email" to "player@example.com",
                "auth" to mapOf(
                    "password" to "SuperSecretP@ssword",
                    "pinCode" to "1234",
                    "mfa_token" to "882910"
                )
            ),
            "cardDetails" to mapOf(
                "cardNumber" to "4111111111111111",
                "cvv" to "999"
            ),
            "headers" to listOf(
                "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID",
                "Host: api.slotting.internal"
            ),
            "url" to "https://api.slotting.internal/callback?token=secretTokenVal&status=ok"
        )

        val redacted = StructuredRedactionEngine.redactMap(payload)

        // Nested map assertions
        val userMap = redacted["user"] as Map<*, *>
        assertEquals("usr-123", userMap["id"])
        assertEquals("[REDACTED_EMAIL]", userMap["email"])
        val authMap = userMap["auth"] as Map<*, *>
        assertEquals("[REDACTED_SECRET]", authMap["password"])
        assertEquals("[REDACTED_SECRET]", authMap["pinCode"])
        assertEquals("[REDACTED_SECRET]", authMap["mfa_token"])

        // Card details assertions
        val cardMap = redacted["cardDetails"] as Map<*, *>
        assertEquals("[REDACTED_SECRET]", cardMap["cardNumber"])
        assertEquals("[REDACTED_SECRET]", cardMap["cvv"])

        // Header and query token redaction
        val headersList = redacted["headers"] as List<*>
        assertEquals("Authorization: [REDACTED_HEADER]", headersList[0])
        assertEquals("Host: api.slotting.internal", headersList[1])

        val urlString = redacted["url"] as String
        assertTrue(urlString.contains("token=[REDACTED_SECRET]"))
        assertFalse(urlString.contains("secretTokenVal"))
    }

    @Test
    fun test06_siemTruthfulDelivery_timeoutOrConnectionErrorRemainsPendingOrRetryable() {
        var callCount = 0
        val failingHttpClient: HttpCall = { _, _, _ ->
            callCount++
            throw java.net.SocketTimeoutException("Read timed out to OpenSearch cluster")
        }

        val openSearchAdapter = OpenSearchSiemAdapter(failingHttpClient)
        val service = TruthfulObservabilityService(
            settingsService = settingsService,
            siemTransport = openSearchAdapter,
            environment = "TEST"
        )

        val record = service.dispatchSecurityEvent(
            tenantId = tenantId,
            category = SiemEventCategory.AUTH_FAILURE,
            severity = SiemEventSeverity.CRITICAL,
            action = "BRUTE_FORCE_ATTACK",
            targetResource = "/api/v1/auth/login",
            sourceIp = "10.0.0.99",
            rawPayload = mapOf("attempts" to 20),
            correlationId = "corr-siem-06",
            causationId = "cause-siem-06"
        )

        // Never marked FORWARDED upon local creation
        assertEquals(SiemForwardStatus.PENDING_FORWARD, record.forwardStatus)
        assertNull(record.siemReceiptId)

        val config = SiemConfigRecord(
            tenantId = tenantId,
            providerType = SiemProviderType.OPENSEARCH,
            endpointUrl = "https://opensearch.example.com",
            updatedAt = clock.instant()
        )

        // Process outbox with network failure
        val results = service.processSiemOutbox(config, "token")
        assertEquals(1, results.size)
        assertEquals(SiemDispatchStatus.FAILED_RETRYABLE, results[0].status)
        assertTrue(results[0].retryable)
        assertNull(results[0].externalReceiptId)
    }

    @Test
    fun test07_siemDlq_exceededRetriesTransitionsToDlqWithAuditedReplay() {
        val failingHttpClient: HttpCall = { _, _, _ ->
            HttpResponse(503, "Cluster unavailable")
        }

        val service = TruthfulObservabilityService(
            settingsService = settingsService,
            siemTransport = OpenSearchSiemAdapter(failingHttpClient),
            environment = "TEST",
            maxRetries = 2
        )

        val record = service.dispatchSecurityEvent(
            tenantId = tenantId,
            category = SiemEventCategory.PRIVILEGE_ESCALATION,
            severity = SiemEventSeverity.CRITICAL,
            action = "UNAUTHORIZED_ADMIN_ELEVATION",
            targetResource = "/api/v1/admin/users",
            sourceIp = "10.0.0.50",
            rawPayload = mapOf("role" to "SUPER_ADMIN"),
            correlationId = "corr-dlq-01",
            causationId = "cause-dlq-01"
        )

        val config = SiemConfigRecord(
            tenantId = tenantId,
            providerType = SiemProviderType.OPENSEARCH,
            endpointUrl = "https://opensearch.example.com",
            updatedAt = clock.instant()
        )

        // Attempt 1 -> FAILED_RETRYABLE (retryCount = 1)
        val res1 = service.processSiemOutbox(config, "secret")
        assertEquals(SiemDispatchStatus.FAILED_RETRYABLE, res1[0].status)
        assertEquals(0, service.getDlqRecords(tenantId).size)

        // Attempt 2 -> Reaches maxRetries (2) -> Enters DLQ
        val res2 = service.processSiemOutbox(config, "secret")
        assertEquals(SiemDispatchStatus.FAILED_RETRYABLE, res2[0].status)

        val dlqRecords = service.getDlqRecords(tenantId)
        assertEquals(1, dlqRecords.size)
        assertEquals(record.eventId, dlqRecords[0].eventId)
        assertEquals("corr-dlq-01", dlqRecords[0].correlationId)
        assertNull(dlqRecords[0].replayedAt)

        // Replay DLQ
        val replayed = service.replaySiemDlq(dlqRecords[0].dlqId)
        assertTrue(replayed)
        assertNotNull(service.getDlqRecords(tenantId)[0].replayedAt)
    }

    @Test
    fun test08_pagingTruthfulDispatch_deliversToEndpointWithoutFakingHumanAck() {
        var dispatchedPayload = ""
        val mockGoAlertClient: HttpCall = { _, _, body ->
            dispatchedPayload = body
            HttpResponse(200, """{"id":"goalert-123"}""")
        }

        val service = TruthfulObservabilityService(
            settingsService = settingsService,
            pagingTransport = GoAlertPagingAdapter(mockGoAlertClient),
            environment = "TEST"
        )

        val pagingConfig = PagingConfigRecord(
            tenantId = tenantId,
            providerType = PagingProviderType.GOALERT,
            enabled = true,
            endpointUrl = "https://goalert.example.com/api/v1/webhooks",
            updatedAt = clock.instant()
        )

        val routingPolicy = AlertRoutingPolicyConfig(
            tenantId = tenantId,
            updatedAt = clock.instant()
        )

        val (incident, newlyPaged) = service.triggerOperationalAlert(
            tenantId = tenantId,
            incidentType = OperationalIncidentType.LEDGER_IMBALANCE,
            affectedResource = "ledger:account:1001",
            title = "Ledger account 1001 is imbalanced by $500",
            description = "Debit total does not match credit total after batch settlement",
            correlationId = "corr-ledger-01",
            causationId = "cause-ledger-01",
            config = pagingConfig,
            decryptedSecret = "goalert-secret",
            routingPolicy = routingPolicy
        )

        assertTrue(newlyPaged)
        assertEquals(PagingIncidentStatus.PAGING_TRIGGERED, incident.status)
        assertTrue(dispatchedPayload.contains("finance-critical"))
        assertTrue(dispatchedPayload.contains("/runbooks/ledger-imbalance.md"))

        // Does NOT manufacture human acknowledgement
        val activeIncidents = service.getActiveIncidents()
        assertEquals(1, activeIncidents.size)
        assertEquals(HumanIncidentStatus.TRIGGERED, activeIncidents[0].humanStatus)

        // Human explicitly acknowledges incident
        service.acknowledgeIncidentByHuman(activeIncidents[0].deduplicationKey)
        assertEquals(HumanIncidentStatus.ACKNOWLEDGED_BY_HUMAN, service.getActiveIncidents()[0].humanStatus)
    }

    @Test
    fun test09_alertDeduplicationAndStormProtection_repeatedEventsDoNotTriggerDuplicatePaging() {
        var pageCount = 0
        val countingClient: HttpCall = { _, _, _ ->
            pageCount++
            HttpResponse(200, "OK")
        }

        val service = TruthfulObservabilityService(
            settingsService = settingsService,
            pagingTransport = AlertmanagerPagingAdapter(countingClient),
            environment = "TEST"
        )

        val pagingConfig = PagingConfigRecord(
            tenantId = tenantId,
            providerType = PagingProviderType.ALERTMANAGER,
            enabled = true,
            endpointUrl = "https://alertmanager.example.com",
            updatedAt = clock.instant()
        )

        val routingPolicy = AlertRoutingPolicyConfig(tenantId = tenantId, updatedAt = clock.instant())

        // 1st incident occurrence -> Pages
        val (_, paged1) = service.triggerOperationalAlert(
            tenantId = tenantId,
            incidentType = OperationalIncidentType.PROVIDER_OUTAGE,
            affectedResource = "provider:stripe:us-east",
            title = "Stripe webhook outage",
            description = "Connection timeout after 3 retries",
            correlationId = "corr-storm-01",
            causationId = "cause-storm-01",
            config = pagingConfig,
            decryptedSecret = null,
            routingPolicy = routingPolicy
        )
        assertTrue(paged1)
        assertEquals(1, pageCount)

        // 2nd occurrence of identical issue -> Deduplicated, count incremented, NO new page
        val (_, paged2) = service.triggerOperationalAlert(
            tenantId = tenantId,
            incidentType = OperationalIncidentType.PROVIDER_OUTAGE,
            affectedResource = "provider:stripe:us-east",
            title = "Stripe webhook outage",
            description = "Connection timeout after 3 retries",
            correlationId = "corr-storm-02",
            causationId = "cause-storm-02",
            config = pagingConfig,
            decryptedSecret = null,
            routingPolicy = routingPolicy
        )
        assertFalse(paged2)
        assertEquals(1, pageCount) // Still 1 page, alert storm prevented!
        assertEquals(2, service.getActiveIncidents()[0].occurrenceCount.get())

        // Resolve incident -> clears dedup entry
        service.resolveIncident(service.getActiveIncidents()[0].deduplicationKey)
        assertEquals(0, service.getActiveIncidents().size)

        // Reoccurrence after resolution -> triggers new page
        val (_, paged3) = service.triggerOperationalAlert(
            tenantId = tenantId,
            incidentType = OperationalIncidentType.PROVIDER_OUTAGE,
            affectedResource = "provider:stripe:us-east",
            title = "Stripe webhook outage",
            description = "Connection timeout after 3 retries",
            correlationId = "corr-storm-03",
            causationId = "cause-storm-03",
            config = pagingConfig,
            decryptedSecret = null,
            routingPolicy = routingPolicy
        )
        assertTrue(paged3)
        assertEquals(2, pageCount)
    }

    @Test
    fun test10_highValueScenarios_ledgerPayoutWorkerAuthAttackMappings() {
        val policy = AlertRoutingPolicyConfig.defaultRoutingRules()

        // 1. Ledger Imbalance
        val ledgerRule = policy[OperationalIncidentType.LEDGER_IMBALANCE]!!
        assertEquals(IncidentSeverity.CRITICAL, ledgerRule.severity)
        assertEquals("finance-critical", ledgerRule.targetServiceOrTier)
        assertTrue(ledgerRule.requiresPaging)

        // 2. Ambiguous Payout
        val payoutRule = policy[OperationalIncidentType.AMBIGUOUS_PAYOUT]!!
        assertEquals(IncidentSeverity.CRITICAL, payoutRule.severity)
        assertEquals("payouts-critical", payoutRule.targetServiceOrTier)
        assertTrue(payoutRule.requiresPaging)

        // 3. Stuck Worker
        val workerRule = policy[OperationalIncidentType.STUCK_WORKER]!!
        assertEquals(IncidentSeverity.HIGH, workerRule.severity)
        assertEquals("infra-high", workerRule.targetServiceOrTier)
        assertTrue(workerRule.requiresPaging)

        // 4. Auth Attack
        val authRule = policy[OperationalIncidentType.AUTH_ATTACK]!!
        assertEquals(IncidentSeverity.CRITICAL, authRule.severity)
        assertEquals("security-critical", authRule.targetServiceOrTier)
        assertTrue(authRule.requiresPaging)

        // 5. PIN / MFA failure: Security event, but does not wake up on-call unless threshold attack
        val pinRule = policy[OperationalIncidentType.PIN_FAILURE]!!
        assertEquals(IncidentSeverity.HIGH, pinRule.severity)
        assertFalse(pinRule.requiresPaging)
    }

    private class FakeAdminSessionDirectory : AdminSessionDirectory {
        private val sessions = mutableMapOf<String, com.slotting.admin.auth.AdminSessionStatus>()

        fun registerSession(tenantId: String, principalId: String, sessionId: String, status: com.slotting.admin.auth.AdminSessionStatus) {
            sessions["$tenantId:$principalId:$sessionId"] = status
        }

        override fun find(tenantId: String, principalId: String, sessionId: String): com.slotting.admin.auth.AdminSessionStatus? {
            return sessions["$tenantId:$principalId:$sessionId"]
        }
    }
}
