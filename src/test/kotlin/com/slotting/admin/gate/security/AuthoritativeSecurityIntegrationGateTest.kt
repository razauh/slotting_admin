package com.slotting.admin.gate.security

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthoritativeSecurityIntegrationGateTest {
    private var now = Instant.parse("2026-09-21T08:00:00Z")
    private val clock: Clock get() = Clock.fixed(now, ZoneOffset.UTC)

    private val tenantId = "tenant-sec-gate-test"
    private val adminOperatorPrincipal = AuthenticatedPrincipal(
        id = "admin-sec-gate-op-01",
        tenantId = tenantId,
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT, AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-sec-01",
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "foreign-admin-sec-99",
        tenantId = "tenant-other",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var evidenceStore: InMemorySecurityGateEvidenceStore
    private lateinit var alertSink: InMemorySecurityGateAlertSink
    private lateinit var observability: InMemorySecurityGateObservability
    private lateinit var service: AuthoritativeSecurityIntegrationGateService

    private fun createValidManifest(): SecurityArtifactManifest {
        return SecurityArtifactManifest(
            commitHash = "794dbc16dc6b882f3102574f241fee436e9d9987",
            artifactDigest = "sha256:sec4b8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a",
            configurationVersion = "sec-cfg-v1.0",
            environment = "production-candidate",
            owner = "infosec-security-team",
            reviewer = "ciso-security-lead",
            signedAt = now.minusSeconds(3600),
            expiry = now.plusSeconds(86400)
        )
    }

    @BeforeEach
    fun setUp() {
        AuthoritativeSecurityIntegrationGateBinding.checkBound()
        evidenceStore = InMemorySecurityGateEvidenceStore()
        alertSink = InMemorySecurityGateAlertSink()
        observability = InMemorySecurityGateObservability()

        service = AuthoritativeSecurityIntegrationGateService(
            evidenceStore = evidenceStore,
            alertSink = alertSink,
            observability = observability,
            clock = object : Clock() {
                override fun getZone(): ZoneOffset = ZoneOffset.UTC
                override fun withZone(zone: java.time.ZoneId?): Clock = this
                override fun instant(): Instant = now
            }
        )
    }

    @AfterEach
    fun tearDown() {
    }

    // =========================================================================
    // GATE-SECURITY-001-T001 — Expired, malformed, wrong-audience, and revoked tokens fail; concurrent refresh has one winner
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T001 — Expired, malformed, wrong-audience, and revoked tokens fail, concurrent refresh has one winner`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T001_TOKEN_EXPIRY_MALFORMED_CONCURRENT_REFRESH),
            correlationId = "corr-sec-001",
            causationId = "caus-sec-001"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T001_TOKEN_EXPIRY_MALFORMED_CONCURRENT_REFRESH]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("concurrent refresh yielded exactly 1 winner"))
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)
    }

    // =========================================================================
    // GATE-SECURITY-001-T002 — Refresh-token reuse and logout reuse revoke the family and alert
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T002 — Refresh-token reuse and logout reuse revoke the family and alert`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T002_REFRESH_TOKEN_LOGOUT_REUSE_REVOCATION),
            correlationId = "corr-sec-002",
            causationId = "caus-sec-002"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T002_REFRESH_TOKEN_LOGOUT_REUSE_REVOCATION]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("revoked immediately"))

        // Verify that security alert was emitted for token reuse detection
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("Token family reuse attack detected") })
    }

    // =========================================================================
    // GATE-SECURITY-001-T003 — Lock, suspension, closure, and self-exclusion immediately deny protected commands
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T003 — Lock, suspension, closure, and self-exclusion immediately deny protected commands`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T003_ACCOUNT_STATE_RESTRICTION_DENIAL),
            correlationId = "corr-sec-003",
            causationId = "caus-sec-003"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T003_ACCOUNT_STATE_RESTRICTION_DENIAL]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("All protected commands denied across LOCKED, SUSPENDED, CLOSED, and SELF_EXCLUDED"))
        assertFalse(report.hasFinancialAuthorityImpact)
    }

    // =========================================================================
    // GATE-SECURITY-001-T004 — IDOR, role bypass, maker-checker collision, and player-admin token confusion fail
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T004 — IDOR, role bypass, maker-checker collision, and player-admin token confusion fail`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T004_IDOR_ROLE_BYPASS_MAKER_CHECKER_COLLISION),
            correlationId = "corr-sec-004",
            causationId = "caus-sec-004"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T004_IDOR_ROLE_BYPASS_MAKER_CHECKER_COLLISION]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("IDOR, role bypass, maker-checker dual-control collision, and token confusion rejected"))
    }

    // =========================================================================
    // GATE-SECURITY-001-T005 — Spoofed, replayed, stale, and reordered payment or game callbacks make no mutation
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T005 — Spoofed, replayed, stale, and reordered payment or game callbacks make no mutation`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T005_CALLBACK_SPOOF_REPLAY_NO_MUTATION),
            correlationId = "corr-sec-005",
            causationId = "caus-sec-005"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T005_CALLBACK_SPOOF_REPLAY_NO_MUTATION]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("0 mutations"))
        assertFalse(report.hasFinancialAuthorityImpact)
    }

    // =========================================================================
    // GATE-SECURITY-001-T006 — Manipulated Android eligibility, balance, location, time, and integrity input grants nothing
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T006 — Manipulated Android eligibility, balance, location, time, and integrity input grants nothing`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T006_MANIPULATED_CLIENT_INPUT_GRANTS_NOTHING),
            correlationId = "corr-sec-006",
            causationId = "caus-sec-006"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T006_MANIPULATED_CLIENT_INPUT_GRANTS_NOTHING]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("Manipulated client balance, eligibility, location, clock, and integrity input completely disregarded"))
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)
    }

    // =========================================================================
    // GATE-SECURITY-001-T007 — Owned HTTPS App Links enforce PKCE, state, nonce, and one-time replay protection
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T007 — Owned HTTPS App Links enforce PKCE, state, nonce, and one-time replay protection`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T007_HTTPS_APP_LINKS_PKCE_NONCE_REPLAY),
            correlationId = "corr-sec-007",
            causationId = "caus-sec-007"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T007_HTTPS_APP_LINKS_PKCE_NONCE_REPLAY]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("PKCE SHA-256 code challenge"))
    }

    // =========================================================================
    // GATE-SECURITY-001-T008 — WebView, exported components, intents, clipboard, screenshots, notifications, and logs meet policy
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T008 — WebView, exported components, intents, clipboard, screenshots, notifications, and logs meet policy`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T008_CLIENT_HARDENING_POLICY_ENFORCEMENT),
            correlationId = "corr-sec-008",
            causationId = "caus-sec-008"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T008_CLIENT_HARDENING_POLICY_ENFORCEMENT]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("All client hardening policies verified"))
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)
    }

    // =========================================================================
    // GATE-SECURITY-001-T009 — Secrets, tokens, PII, and documents never enter artifacts, telemetry, crashes, or SBOM
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T009 — Secrets, tokens, PII, and documents never enter artifacts, telemetry, crashes, or SBOM`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T009_SECRETS_PII_LEAK_PREVENTION),
            correlationId = "corr-sec-009",
            causationId = "caus-sec-009"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T009_SECRETS_PII_LEAK_PREVENTION]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("0 private keys, 0 secrets, 0 unmasked PII found"))
    }

    // =========================================================================
    // GATE-SECURITY-001-T010 — Pin, certificate, and key rotation plus KMS, WAF, rate-limit, and break-glass failures alert safely
    // =========================================================================
    @Test
    fun `GATE-SECURITY-001-T010 — Pin, certificate, and key rotation plus KMS, WAF, rate-limit, and break-glass failures alert safely`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = setOf(SecurityScenarioId.T010_ROTATION_INFRA_FAILURES_SAFE_ALERT),
            correlationId = "corr-sec-010",
            causationId = "caus-sec-010"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        val scenarioResult = report.scenarioResults[SecurityScenarioId.T010_ROTATION_INFRA_FAILURES_SAFE_ALERT]
        assertNotNull(scenarioResult)
        assertEquals(SecurityScenarioStatus.PASS, scenarioResult.status)
        assertTrue(scenarioResult.details.contains("Certificate/pin rotation verified"))

        // Check alert emitted for break glass
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("Break-glass privileged access invoked") })
    }

    // =========================================================================
    // Comprehensive Multi-Scenario Evaluation & Security Boundaries
    // =========================================================================
    @Test
    fun `Comprehensive Security Gate Evaluation with all 10 scenarios produces authoritative GO`() {
        val manifest = createValidManifest()
        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = SecurityScenarioId.values().toSet(),
            correlationId = "corr-sec-all",
            causationId = "caus-sec-all"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.GO, report.decision)
        assertEquals(10, report.scenarioResults.size)
        assertTrue(report.scenarioResults.values.all { it.status == SecurityScenarioStatus.PASS })
        assertEquals(SECURITY_INTEGRATION_GATE_CONTRACT, report.semanticContract)
        assertFalse(report.hasFinancialAuthorityImpact)
        assertFalse(report.hasAndroidDbImpact)
        assertFalse(report.hasAndroidLifecycleClaim)

        // Verify report persisted in evidence store
        val stored = evidenceStore.findLatestReport(tenantId)
        assertNotNull(stored)
        assertEquals(report.reportId, stored.reportId)
    }

    @Test
    fun `Injected failure in security scenario produces deterministic NO-GO and emits alert`() {
        val manifest = createValidManifest()
        service.scenarioFaults[SecurityScenarioId.T004_IDOR_ROLE_BYPASS_MAKER_CHECKER_COLLISION] = "Injected IDOR vulnerability defect"

        val cmd = EvaluateSecurityGateCommand(
            principal = adminOperatorPrincipal,
            tenantId = tenantId,
            manifest = manifest,
            selectedScenarios = SecurityScenarioId.values().toSet(),
            correlationId = "corr-sec-fault",
            causationId = "caus-sec-fault"
        )

        val report = service.evaluateGate(cmd)

        assertEquals(SecurityGateDecision.NO_GO, report.decision)
        val failedScenario = report.scenarioResults[SecurityScenarioId.T004_IDOR_ROLE_BYPASS_MAKER_CHECKER_COLLISION]
        assertNotNull(failedScenario)
        assertEquals(SecurityScenarioStatus.FAIL, failedScenario.status)

        // Verify alert emitted for NO-GO
        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("GATE-SECURITY-001 evaluation resulted in NO-GO") })
    }

    @Test
    fun `Unauthenticated or player principal is rejected with UnauthorizedSecurityGateException`() {
        val manifest = createValidManifest()

        // Null principal
        assertFailsWith<UnauthorizedSecurityGateException> {
            service.evaluateGate(
                EvaluateSecurityGateCommand(
                    principal = null,
                    tenantId = tenantId,
                    manifest = manifest,
                    correlationId = "corr-sec-null",
                    causationId = "caus-sec-null"
                )
            )
        }

        // Player principal
        assertFailsWith<UnauthorizedSecurityGateException> {
            service.evaluateGate(
                EvaluateSecurityGateCommand(
                    principal = playerPrincipal,
                    tenantId = tenantId,
                    manifest = manifest,
                    correlationId = "corr-sec-player",
                    causationId = "caus-sec-player"
                )
            )
        }

        // Foreign admin principal
        assertFailsWith<UnauthorizedSecurityGateException> {
            service.evaluateGate(
                EvaluateSecurityGateCommand(
                    principal = foreignAdminPrincipal,
                    tenantId = tenantId,
                    manifest = manifest,
                    correlationId = "corr-sec-foreign",
                    causationId = "caus-sec-foreign"
                )
            )
        }
    }

    @Test
    fun `Expired manifest throws InvalidSecurityGateManifestException and emits alert`() {
        val expiredManifest = createValidManifest().copy(
            expiry = now.minusSeconds(10)
        )

        assertFailsWith<InvalidSecurityGateManifestException> {
            service.evaluateGate(
                EvaluateSecurityGateCommand(
                    principal = adminOperatorPrincipal,
                    tenantId = tenantId,
                    manifest = expiredManifest,
                    correlationId = "corr-sec-expired",
                    causationId = "caus-sec-expired"
                )
            )
        }

        val alerts = alertSink.getAlerts()
        assertTrue(alerts.any { it.message.contains("manifest is invalid or expired") })
    }
}
