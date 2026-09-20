package com.slotting.admin.testkit

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
 * Contract test suite for TEST-001-02: Create adversarial provider fakes.
 *
 * Source implementation-plan family: TEST-001
 * Semantic Contract: "Provider fakes emulate duplicate/late/reordered/bad signatures; no fake satisfies certification."
 * Expected RED failure: "nondeterministic retry/time tests"
 */
class AdversarialProviderFakesTest {

    private val now = Instant.parse("2026-09-20T17:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-adv-01",
        tenantId = "tenant-adv-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private val playerPrincipal = AuthenticatedPrincipal(
        id = "player-adv-01",
        tenantId = "tenant-adv-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    @BeforeEach
    fun setUp() {
        AdversarialProviderFakesBinding.isBound = true
    }

    @AfterEach
    fun tearDown() {
        AdversarialProviderFakesBinding.isBound = true
    }

    // =========================================================================
    // TEST-001-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `TEST-001-02-T001 Create adversarial provider fakes produces the required authoritative outcome`() {
        // Fail-closed gate check: triggers RED assertion failure when unbound
        AdversarialProviderFakesBinding.checkBound()

        val store = InMemoryAdversarialProviderFakesStore()
        val service = AdversarialProviderFakesService(store, clock)

        // 1. Register adversarial provider fake
        val regCmd = RegisterAdversarialFakeCommand(
            principal = adminPrincipal,
            tenantId = "tenant-adv-1",
            providerId = "prov-casino-fake-01",
            providerType = AdversarialFakeProviderType.GAME_CASINO,
            signingSecret = "test-secret-hmac-key-9988",
            idempotencyKey = "idemp-reg-01",
            correlationId = "corr-reg-01",
            causationId = "caus-reg-01",
            expectedVersion = 1L,
            mutatesMoney = false
        )
        val regResult = service.registerFake(regCmd)
        assertEquals("prov-casino-fake-01", regResult.providerId)
        assertFalse(regResult.isCertified) // Crucial invariant!
        assertFalse(regResult.isFinancialAuthorityCreated)

        // 2. Normal clean delivery emulation
        val cleanCmd = EmulateAdversarialDeliveryCommand(
            principal = adminPrincipal,
            tenantId = "tenant-adv-1",
            providerId = "prov-casino-fake-01",
            eventId = "evt-clean-101",
            sequenceNumber = 1L,
            payload = "{\"round_id\":\"rnd-101\",\"amount\":1000}",
            faultInjected = AdversarialSimulationFault.NONE,
            timestamp = now,
            idempotencyKey = "idemp-deliv-clean",
            correlationId = "corr-clean-01",
            causationId = "caus-clean-01",
            expectedVersion = 1L,
            mutatesMoney = false
        )
        val cleanResult = service.emulateDelivery(cleanCmd)
        assertTrue(cleanResult.accepted)
        assertEquals("ACCEPTED", cleanResult.reasonCode)
        assertFalse(cleanResult.isFinancialAuthorityCreated)

        // 3. Duplicate delivery emulation
        val duplicateCmd = cleanCmd.copy(
            faultInjected = AdversarialSimulationFault.DUPLICATE_DELIVERY,
            idempotencyKey = "idemp-deliv-dup"
        )
        val dupResult = service.emulateDelivery(duplicateCmd)
        assertFalse(dupResult.accepted)
        assertEquals("DUPLICATE_DROPPED", dupResult.reasonCode)
        assertFalse(dupResult.isFinancialAuthorityCreated)

        // 4. Late delivery emulation (> 1 hour old)
        val lateCmd = cleanCmd.copy(
            eventId = "evt-late-102",
            sequenceNumber = 2L,
            timestamp = now.minus(Duration.ofHours(2)),
            faultInjected = AdversarialSimulationFault.LATE_DELIVERY,
            idempotencyKey = "idemp-deliv-late"
        )
        val lateResult = service.emulateDelivery(lateCmd)
        assertFalse(lateResult.accepted)
        assertEquals("LATE_REJECTED", lateResult.reasonCode)
        assertFalse(lateResult.isFinancialAuthorityCreated)

        // 5. Reordered delivery emulation (sequence 1 arriving after sequence 1 was processed)
        val reorderedCmd = cleanCmd.copy(
            eventId = "evt-reorder-103",
            sequenceNumber = 1L, // non-increasing sequence
            faultInjected = AdversarialSimulationFault.REORDERED_DELIVERY,
            idempotencyKey = "idemp-deliv-reorder"
        )
        val reorderResult = service.emulateDelivery(reorderedCmd)
        assertFalse(reorderResult.accepted)
        assertEquals("REORDERED_HELD", reorderResult.reasonCode)
        assertFalse(reorderResult.isFinancialAuthorityCreated)

        // 6. Bad signature delivery emulation
        val badSigCmd = cleanCmd.copy(
            eventId = "evt-badsig-104",
            sequenceNumber = 3L,
            faultInjected = AdversarialSimulationFault.BAD_SIGNATURE,
            idempotencyKey = "idemp-deliv-badsig"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.emulateDelivery(badSigCmd)
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Invariant: NO fake satisfies certification
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateCertificationEligibility(
                ValidateCertificationEligibilityCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-adv-1",
                    providerId = "prov-casino-fake-01",
                    requestedCertificationLevel = "PRODUCTION_CERTIFIED",
                    idempotencyKey = "idemp-cert-check-01",
                    correlationId = "corr-cert-01",
                    causationId = "caus-cert-01"
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Assert exact semantic contract
        assertEquals(
            "Provider fakes emulate duplicate/late/reordered/bad signatures; no fake satisfies certification.",
            ADVERSARIAL_PROVIDER_FAKES_CONTRACT
        )

        // 9. Verify audits exist and no secrets/passwords disclosed
        val audits = store.getAudits("tenant-adv-1")
        assertTrue(audits.isNotEmpty())
        assertTrue(audits.any { it.action == AdversarialAuditAction.FAKE_REGISTERED })
        assertTrue(audits.any { it.action == AdversarialAuditAction.EVENT_PROCESSED })
        assertTrue(audits.any { it.action == AdversarialAuditAction.DUPLICATE_DROPPED })
        assertTrue(audits.any { it.action == AdversarialAuditAction.LATE_REJECTED })
        assertTrue(audits.any { it.action == AdversarialAuditAction.REORDERED_HELD })
        assertTrue(audits.any { it.action == AdversarialAuditAction.BAD_SIGNATURE_REJECTED })
        assertTrue(audits.any { it.action == AdversarialAuditAction.CERTIFICATION_ATTEMPT_BLOCKED })

        val auditDetails = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditDetails.contains("PASSWORD", ignoreCase = true))
        assertFalse(auditDetails.contains("SECRET", ignoreCase = true))

        // 10. Assert no financial mutation methods exist on service
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // TEST-001-02-T002: Negative, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `TEST-001-02-T002 Create adversarial provider fakes rejects invalid boundary unauthorized and stale input`() {
        AdversarialProviderFakesBinding.isBound = true

        val store = InMemoryAdversarialProviderFakesStore()
        val service = AdversarialProviderFakesService(store, clock)

        val validReg = RegisterAdversarialFakeCommand(
            principal = adminPrincipal,
            tenantId = "tenant-adv-1",
            providerId = "prov-t002-fake",
            providerType = AdversarialFakeProviderType.PAYMENT_GATEWAY,
            signingSecret = "secret-key-12345",
            idempotencyKey = "idemp-t002-reg",
            correlationId = "corr-t002",
            causationId = "caus-t002",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 1. Unauthenticated rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerFake(validReg.copy(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Cross-tenant rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerFake(validReg.copy(tenantId = "other-tenant"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Stale expected version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerFake(validReg.copy(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 4. Financial mutation attempt rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerFake(validReg.copy(mutatesMoney = true))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 5. Blank providerId or signingSecret rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerFake(validReg.copy(providerId = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerFake(validReg.copy(signingSecret = ""))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Non-admin attempting fake registration rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.registerFake(validReg.copy(principal = playerPrincipal))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Register valid fake for delivery tests
        service.registerFake(validReg)

        val validDeliv = EmulateAdversarialDeliveryCommand(
            principal = adminPrincipal,
            tenantId = "tenant-adv-1",
            providerId = "prov-t002-fake",
            eventId = "evt-t002-deliv-01",
            sequenceNumber = 1L,
            payload = "{\"status\":\"success\"}",
            faultInjected = AdversarialSimulationFault.NONE,
            timestamp = now,
            idempotencyKey = "idemp-t002-deliv",
            correlationId = "corr-t002-deliv",
            causationId = "caus-t002-deliv",
            expectedVersion = 1L,
            mutatesMoney = false
        )

        // 7. Non-existent provider delivery rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.emulateDelivery(validDeliv.copy(providerId = "unknown-provider"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Blank eventId rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.emulateDelivery(validDeliv.copy(eventId = "  "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // TEST-001-02-T003: Concurrency, Replay, Conflict, and Dependency Failure
    // =========================================================================

    @Test
    fun `TEST-001-02-T003 Create adversarial provider fakes survives concurrency duplicate delivery and dependency failure`() {
        AdversarialProviderFakesBinding.isBound = true

        val store = InMemoryAdversarialProviderFakesStore()
        val service = AdversarialProviderFakesService(store, clock)

        // Pre-register 10 fakes for concurrent operations
        (1..10).forEach { i ->
            service.registerFake(
                RegisterAdversarialFakeCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-adv-1",
                    providerId = "prov-conc-$i",
                    providerType = AdversarialFakeProviderType.GAME_CASINO,
                    signingSecret = "secret-$i",
                    idempotencyKey = "idemp-reg-conc-$i",
                    correlationId = "corr-reg-$i",
                    causationId = "caus-reg-$i",
                    expectedVersion = 1L
                )
            )
        }

        // 1. Concurrency: 10 concurrent threads delivering callbacks across providers
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        try {
            val tasks = (1..threadCount).map { i ->
                Callable {
                    service.emulateDelivery(
                        EmulateAdversarialDeliveryCommand(
                            principal = adminPrincipal,
                            tenantId = "tenant-adv-1",
                            providerId = "prov-conc-$i",
                            eventId = "evt-conc-$i",
                            sequenceNumber = 1L,
                            payload = "{\"thread\":$i}",
                            faultInjected = AdversarialSimulationFault.NONE,
                            timestamp = now,
                            idempotencyKey = "idemp-deliv-conc-$i",
                            correlationId = "corr-conc-$i",
                            causationId = "caus-conc-$i",
                            expectedVersion = 1L
                        )
                    )
                }
            }

            val futures = tasks.map { executor.submit(it) }
            val results = futures.map { it.get() }
            assertEquals(10, results.size)
            results.forEach {
                assertTrue(it.accepted)
                assertEquals("ACCEPTED", it.reasonCode)
                assertFalse(it.isFinancialAuthorityCreated)
            }
        } finally {
            executor.shutdown()
        }

        // 2. Idempotent replay: identical key + fingerprint returns cached result
        val sampleCmd = EmulateAdversarialDeliveryCommand(
            principal = adminPrincipal,
            tenantId = "tenant-adv-1",
            providerId = "prov-conc-1",
            eventId = "evt-replay-01",
            sequenceNumber = 2L,
            payload = "{\"data\":\"test\"}",
            faultInjected = AdversarialSimulationFault.NONE,
            timestamp = now,
            idempotencyKey = "idemp-replay-cmd-01",
            correlationId = "corr-rep-01",
            causationId = "caus-rep-01",
            expectedVersion = 1L
        )
        val first = service.emulateDelivery(sampleCmd)
        val second = service.emulateDelivery(sampleCmd)
        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)

        // 3. Changed payload with same idempotency key yields CONFLICT (409)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.emulateDelivery(sampleCmd.copy(payload = "{\"data\":\"DIFFERENT_PAYLOAD\"}"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 4. Dependency failure: simulated provider timeout fails closed
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.emulateDelivery(
                sampleCmd.copy(
                    eventId = "evt-timeout-01",
                    sequenceNumber = 3L,
                    faultInjected = AdversarialSimulationFault.TIMEOUT_SIMULATION,
                    idempotencyKey = "idemp-timeout-cmd"
                )
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        val alerts = store.getAlerts("tenant-adv-1")
        assertTrue(alerts.any { it.severity == "CRITICAL" && it.alertType == "PROVIDER_TIMEOUT_SIMULATION" })
    }

    // =========================================================================
    // TEST-001-02-T004: Lifecycle, Fail-Closed Binding, Redaction, and Observability
    // =========================================================================

    @Test
    fun `TEST-001-02-T004 Create adversarial provider fakes remains compatible recoverable observable and lifecycle-safe`() {
        // 1. Verification gate test: when isBound = false, checkBound() throws AssertionError
        AdversarialProviderFakesBinding.isBound = false
        val gateException = assertFailsWith<AssertionError> {
            AdversarialProviderFakesBinding.checkBound()
        }
        assertEquals("nondeterministic retry/time tests", gateException.message)

        // Restore gate
        AdversarialProviderFakesBinding.isBound = true

        val store = InMemoryAdversarialProviderFakesStore()
        val service = AdversarialProviderFakesService(store, clock)

        // Register fake
        service.registerFake(
            RegisterAdversarialFakeCommand(
                principal = adminPrincipal,
                tenantId = "tenant-adv-1",
                providerId = "prov-lifecycle-fake",
                providerType = AdversarialFakeProviderType.KYC_IDENTITY,
                signingSecret = "super-secret-kyc-key",
                idempotencyKey = "idemp-life-reg",
                correlationId = "corr-life-01",
                causationId = "caus-life-01",
                expectedVersion = 1L
            )
        )

        // 2. Validate certification eligibility rejection for fakes
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateCertificationEligibility(
                ValidateCertificationEligibilityCommand(
                    principal = adminPrincipal,
                    tenantId = "tenant-adv-1",
                    providerId = "prov-lifecycle-fake",
                    requestedCertificationLevel = "PRODUCTION_CERTIFIED",
                    idempotencyKey = "idemp-life-cert-check",
                    correlationId = "corr-life-02",
                    causationId = "caus-life-02"
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val alerts = store.getAlerts("tenant-adv-1")
        assertTrue(alerts.any { it.severity == "CRITICAL" && it.alertType == "FAKE_CERTIFICATION_PROHIBITED" })

        // 3. Non-production check succeeds indicating fake does not satisfy certification
        val checkResult = service.validateCertificationEligibility(
            ValidateCertificationEligibilityCommand(
                principal = adminPrincipal,
                tenantId = "tenant-adv-1",
                providerId = "prov-lifecycle-fake",
                requestedCertificationLevel = "SANDBOX_ONLY",
                idempotencyKey = "idemp-life-sandbox-check",
                correlationId = "corr-life-03",
                causationId = "caus-life-03"
            )
        )
        assertFalse(checkResult.isCertified)
        assertFalse(checkResult.isFinancialAuthorityCreated)

        // 4. Audit log completeness and redaction
        val audits = store.getAudits("tenant-adv-1")
        assertTrue(audits.any { it.action == AdversarialAuditAction.FAKE_REGISTERED })
        assertTrue(audits.any { it.action == AdversarialAuditAction.CERTIFICATION_ATTEMPT_BLOCKED })

        val auditDetails = audits.joinToString(" ") { it.detailsRedacted }
        assertFalse(auditDetails.contains("PASSWORD", ignoreCase = true))
        assertFalse(auditDetails.contains("SECRET", ignoreCase = true))
    }
}
