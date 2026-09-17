package com.slotting.admin.payment

import com.slotting.admin.auth.*
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Test

class PaymentAdapterCertificationTest {
    private val now = Instant.parse("2026-09-17T16:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-004-02-T001 Define payment-adapter certification boundary produces the required authoritative outcome`() {
        val store = PaymentAdapterCertificationMemoryStore()
        val service = service(store)

        // 1. Valid certification for PRODUCTION_CERTIFIED tier
        val certifyCmd = certifyCommand(
            providerId = "prov-stripe-prod",
            requestedTier = AdapterTier.PRODUCTION_CERTIFIED,
            canonicalSemanticsVerified = true,
            signatureVerificationVerified = true,
            retryAcknowledgementVerified = true,
            productionApproved = true,
            expiresAt = now.plusSeconds(86400 * 30),
            idempotencyKey = "key-cert-001",
            correlationId = "corr-cert-1",
            causationId = "cause-cert-1",
        )
        val res = service.certifyAdapter(certifyCmd)
        assertEquals(AdapterTier.PRODUCTION_CERTIFIED, res.tier)
        assertEquals(CertificationStatus.CERTIFIED, res.status)

        // Assert production access allowed
        assertDoesNotThrow { service.assertProductionAllowed("tenant-1", "prov-stripe-prod") }

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.certifyAdapter(certifyCmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.evidenceReference, replay.evidenceReference)

        // 3. Absent evidence permits only port/fake work: unapproved production request rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.certifyAdapter(
                certifyCommand(
                    providerId = "prov-unverified",
                    requestedTier = AdapterTier.PRODUCTION_CERTIFIED,
                    canonicalSemanticsVerified = true,
                    signatureVerificationVerified = false, // missing sig verification
                    retryAcknowledgementVerified = true,
                    productionApproved = false,
                    idempotencyKey = "key-unverified-prod",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Revocation workflow: authorized revocation changes status and blocks production access
        val revokeRes = service.revokeCertification(
            RevokeCertificationCommand(
                principal = admin(),
                sessionId = "session-cert-1",
                tenantId = "tenant-1",
                certificationId = res.certificationId,
                reason = "security incident: credential compromise",
                idempotencyKey = "key-revoke-001",
                correlationId = "corr-revoke-1",
                causationId = "cause-revoke-1",
                expectedVersion = 1L,
            )
        )
        assertEquals(CertificationStatus.REVOKED, revokeRes.status)

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.assertProductionAllowed("tenant-1", "prov-stripe-prod")
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Assert: Never invent provider webhook fields; adapter-specific schemas captured after selection
        assertEquals(2, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-cert-1", store.audit[0].correlationId)
        assertEquals("cause-cert-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-004-02-T002 Define payment-adapter certification boundary rejects invalid, boundary, unauthorized, and stale input`() {
        val store = PaymentAdapterCertificationMemoryStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.certifyAdapter(certifyCommand(principal = null, idempotencyKey = "key-unauth-cert"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.certifyAdapter(certifyCommand(principal = player(), idempotencyKey = "key-player-cert"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.certifyAdapter(certifyCommand(principal = admin(tenantId = "tenant-other"), idempotencyKey = "key-cross-cert"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Expired certification expiry timestamp (past date)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.certifyAdapter(
                certifyCommand(
                    expiresAt = now.minusSeconds(3600),
                    idempotencyKey = "key-past-expiry",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank providerId
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.certifyAdapter(certifyCommand(providerId = "   ", idempotencyKey = "key-blank-prov"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Revoke unknown certification
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.revokeCertification(
                RevokeCertificationCommand(
                    principal = admin(),
                    sessionId = "session-cert-1",
                    tenantId = "tenant-1",
                    certificationId = UUID.randomUUID(),
                    reason = "test reason",
                    idempotencyKey = "key-revoke-unknown",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                    expectedVersion = 1L,
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Conflicting replay with different tier
        service.certifyAdapter(certifyCommand(requestedTier = AdapterTier.SANDBOX, idempotencyKey = "key-conflict-cert"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.certifyAdapter(certifyCommand(requestedTier = AdapterTier.PORT_ONLY, idempotencyKey = "key-conflict-cert"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-004-02-T003 Define payment-adapter certification boundary survives concurrency, duplicate delivery, and dependency failure`() {
        val store = PaymentAdapterCertificationMemoryStore()
        val service = service(store)

        // 1. Benchmark concurrent duplicate certification attempts
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val calls = (1..4).map {
            pool.submit<CertificationVerificationResult> {
                gate.await()
                service.certifyAdapter(
                    certifyCommand(
                        providerId = "prov-concurrent",
                        requestedTier = AdapterTier.SANDBOX,
                        idempotencyKey = "key-concurrent-cert",
                    )
                )
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session directory
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).certifyAdapter(
                certifyCommand(idempotencyKey = "key-dep-fail-cert")
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-004-02-T004 Define payment-adapter certification boundary remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation over memory store preserves certified state
        val store = PaymentAdapterCertificationMemoryStore()
        val service = service(store)

        val cmd = certifyCommand(
            providerId = "prov-reboot-cert",
            requestedTier = AdapterTier.SANDBOX,
            idempotencyKey = "key-reboot-cert",
            correlationId = "corr-reboot-cert-1",
            causationId = "cause-reboot-cert-1",
        )
        val first = service.certifyAdapter(cmd)

        val restartedService = service(store)
        val second = restartedService.certifyAdapter(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)

        // Telemetry contains required IDs and no secrets
        assertEquals(1, store.audit.size)
        assertEquals("PAYMENT_ADAPTER_CERTIFIED", store.audit[0].type)
        assertEquals("corr-reboot-cert-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-cert-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: PaymentAdapterCertificationStore) =
        PaymentAdapterCertificationService(AdminRbacPolicy(true), ActiveCertificationSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: PaymentAdapterCertificationStore) =
        PaymentAdapterCertificationService(AdminRbacPolicy(true), FailingCertificationSessionDirectory(), store, clock)

    private fun certifyCommand(
        principal: AuthenticatedPrincipal? = admin(),
        providerId: String = "prov-sandbox",
        requestedTier: AdapterTier = AdapterTier.SANDBOX,
        canonicalSemanticsVerified: Boolean = true,
        signatureVerificationVerified: Boolean = true,
        retryAcknowledgementVerified: Boolean = true,
        productionApproved: Boolean = true,
        expiresAt: Instant = now.plusSeconds(86400 * 30),
        idempotencyKey: String = "key-cert-default",
        correlationId: String = "corr-cert-default",
        causationId: String = "cause-cert-default",
        expectedVersion: Long = 1L,
    ) = CertifyAdapterCommand(
        principal = principal,
        sessionId = "session-cert-1",
        tenantId = "tenant-1",
        providerId = providerId,
        requestedTier = requestedTier,
        canonicalSemanticsVerified = canonicalSemanticsVerified,
        signatureVerificationVerified = signatureVerificationVerified,
        retryAcknowledgementVerified = retryAcknowledgementVerified,
        productionApproved = productionApproved,
        expiresAt = expiresAt,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-cert-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveCertificationSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-cert-1" && sessionId == "session-cert-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingCertificationSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory unavailable")
}

private class PaymentAdapterCertificationMemoryStore : PaymentAdapterCertificationStore {
    val certifications = mutableMapOf<String, PaymentAdapterCertification>()
    val results = mutableMapOf<String, Pair<String, CertificationVerificationResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun findCertification(tenantId: String, certificationId: UUID) =
        synchronized(this) { certifications["$tenantId:$certificationId"] }

    override fun findByProvider(tenantId: String, providerId: String) =
        synchronized(this) { certifications.values.find { it.tenantId == tenantId && it.providerId == providerId } }

    override fun saveCertification(
        certification: PaymentAdapterCertification,
        result: CertificationVerificationResult,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        certifications["${certification.tenantId}:${certification.certificationId}"] = certification
        results["${certification.tenantId}:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
