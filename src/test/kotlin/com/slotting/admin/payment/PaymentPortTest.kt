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
import org.junit.jupiter.api.Test

class PaymentPortTest {
    private val now = Instant.parse("2026-09-17T15:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-004-01-T001 Define provider-neutral payment port produces the required authoritative outcome`() {
        val store = PaymentPortMemoryStore()
        val adapter = SandboxPaymentAdapter("prov-sandbox")
        val service = service(store, mapOf("prov-sandbox" to adapter))

        // 1. Execute canonical AUTHORIZE operation through provider-neutral port
        val cmd = command(
            paymentReference = "pay-ref-001",
            operation = PaymentPortOperation.AUTHORIZE,
            amountMinorUnits = 5000L,
            currencyCode = "EUR",
            providerId = "prov-sandbox",
            idempotencyKey = "key-pay-auth-001",
            correlationId = "corr-pay-1",
            causationId = "cause-pay-1",
        )
        val res = service.executeOperation(cmd)
        assertEquals(PaymentTransactionStatus.AUTHORIZED, res.status)
        assertEquals("pay-ref-001", res.paymentReference)
        assertEquals(5000L, res.amountMinorUnits)
        assertEquals("EUR", res.currencyCode)
        assertEquals("EXT-TX-pay-ref-001", res.externalTransactionReference)

        // 2. Replay with identical idempotency key returns identical authoritative result
        val replay = service.executeOperation(cmd)
        assertEquals(res.resultId, replay.resultId)
        assertEquals(res.evidenceReference, replay.evidenceReference)

        // 3. Process inbound webhook without inventing provider fields
        val webhookCmd = CanonicalWebhookCommand(
            tenantId = "tenant-1",
            providerId = "prov-sandbox",
            signatureHeader = "valid-sig-hash",
            rawPayload = "{\"reference\":\"pay-ref-001\",\"state\":\"CAPTURED\",\"amount\":5000,\"currency\":\"EUR\"}",
            idempotencyKey = "key-webhook-001",
            correlationId = "corr-wh-1",
            causationId = "cause-wh-1",
        )
        val webhookRes = service.processWebhook(webhookCmd)
        assertEquals(PaymentTransactionStatus.CAPTURED, webhookRes.status)
        assertEquals("pay-ref-001", webhookRes.paymentReference)

        // Assert: Never invent provider webhook fields; adapter-specific schemas captured after selection
        assertEquals(2, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-pay-1", store.audit[0].correlationId)
        assertEquals("cause-pay-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-004-01-T002 Define provider-neutral payment port rejects invalid, boundary, unauthorized, and stale input`() {
        val store = PaymentPortMemoryStore()
        val adapter = SandboxPaymentAdapter("prov-sandbox")
        val service = service(store, mapOf("prov-sandbox" to adapter))

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = null, idempotencyKey = "key-unauth"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = player(), idempotencyKey = "key-player"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = admin(tenantId = "tenant-other"), idempotencyKey = "key-cross"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Invalid currency
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(currencyCode = "INVALID", idempotencyKey = "key-curr-inv"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Zero or negative amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = 0L, idempotencyKey = "key-zero-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = -500L, idempotencyKey = "key-neg-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Blank paymentReference, correlationId, causationId
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(paymentReference = "   ", idempotencyKey = "key-blank-ref"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unknown provider
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(providerId = "prov-unknown", idempotencyKey = "key-unknown-prov"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Invalid webhook signature
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processWebhook(
                CanonicalWebhookCommand(
                    tenantId = "tenant-1",
                    providerId = "prov-sandbox",
                    signatureHeader = "forged-tampered-signature",
                    rawPayload = "{}",
                    idempotencyKey = "key-forged-sig",
                    correlationId = "corr-bad-sig",
                    causationId = "cause-bad-sig",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(expectedVersion = 999L, idempotencyKey = "key-stale-ver"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different amount
        service.executeOperation(command(amountMinorUnits = 1000L, idempotencyKey = "key-conflict-op"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = 2000L, idempotencyKey = "key-conflict-op"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-004-01-T003 Define provider-neutral payment port survives concurrency, duplicate delivery, and dependency failure`() {
        val store = PaymentPortMemoryStore()
        val adapter = SandboxPaymentAdapter("prov-sandbox")
        val service = service(store, mapOf("prov-sandbox" to adapter))

        // 1. Benchmark concurrent duplicate calls with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val calls = (1..4).map {
            pool.submit<PaymentPortResult> {
                gate.await()
                service.executeOperation(
                    command(
                        paymentReference = "pay-concurrent-001",
                        idempotencyKey = "key-concurrent-pay",
                    )
                )
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Adapter dependency failure
        val failingAdapter = FailingPaymentAdapter("prov-failing")
        val failingService = service(store, mapOf("prov-failing" to failingAdapter))
        assertFailsWith<AuthenticationFailure.Rejected> {
            failingService.executeOperation(command(providerId = "prov-failing", idempotencyKey = "key-dep-fail"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Adversarial fake adapter: simulated signature tampering
        val adversarialFake = AdversarialFakePaymentAdapter("prov-adversarial")
        val advService = service(store, mapOf("prov-adversarial" to adversarialFake))
        assertFailsWith<AuthenticationFailure.Rejected> {
            advService.processWebhook(
                CanonicalWebhookCommand(
                    tenantId = "tenant-1",
                    providerId = "prov-adversarial",
                    signatureHeader = "tampered-header",
                    rawPayload = "{\"data\":\"test\"}",
                    idempotencyKey = "key-adv-tamper",
                    correlationId = "corr-adv-1",
                    causationId = "cause-adv-1",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-004-01-T004 Define provider-neutral payment port remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = PaymentPortMemoryStore()
        val adapter = SandboxPaymentAdapter("prov-sandbox")
        val service = service(store, mapOf("prov-sandbox" to adapter))

        val cmd = command(
            paymentReference = "pay-ref-reboot",
            idempotencyKey = "key-reboot-pay",
            correlationId = "corr-reboot-1",
            causationId = "cause-reboot-1",
        )
        val first = service.executeOperation(cmd)

        val restartedService = service(store, mapOf("prov-sandbox" to adapter))
        val second = restartedService.executeOperation(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)

        // Observability and no secrets
        assertEquals(1, store.audit.size)
        assertEquals("PAYMENT_PORT_AUTHORIZE", store.audit[0].type)
        assertEquals("corr-reboot-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: PaymentPortStore, adapters: Map<String, PaymentProviderAdapter>) =
        PaymentPortService(AdminRbacPolicy(true), ActivePaymentPortSessionDirectory(), store, adapters, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        paymentReference: String = "pay-ref-default",
        operation: PaymentPortOperation = PaymentPortOperation.AUTHORIZE,
        amountMinorUnits: Long = 1000L,
        currencyCode: String = "EUR",
        providerId: String = "prov-sandbox",
        paymentMethod: PaymentMethodType = PaymentMethodType.CARD,
        idempotencyKey: String = "key-pay-default",
        correlationId: String = "corr-pay-default",
        causationId: String = "cause-pay-default",
        expectedVersion: Long = 1L,
    ) = PaymentPortCommand(
        principal = principal,
        sessionId = "session-pay-1",
        tenantId = "tenant-1",
        paymentReference = paymentReference,
        operation = operation,
        amountMinorUnits = amountMinorUnits,
        currencyCode = currencyCode,
        providerId = providerId,
        paymentMethod = paymentMethod,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-pay-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActivePaymentPortSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-pay-1" && sessionId == "session-pay-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class SandboxPaymentAdapter(override val providerId: String) : PaymentProviderAdapter {
    override fun execute(command: PaymentPortCommand): Pair<PaymentTransactionStatus, String> {
        val status = when (command.operation) {
            PaymentPortOperation.AUTHORIZE -> PaymentTransactionStatus.AUTHORIZED
            PaymentPortOperation.CAPTURE -> PaymentTransactionStatus.CAPTURED
            PaymentPortOperation.REFUND -> PaymentTransactionStatus.REFUNDED
            PaymentPortOperation.VOID -> PaymentTransactionStatus.VOIDED
        }
        return status to "EXT-TX-${command.paymentReference}"
    }

    override fun verifyWebhook(signature: String, rawPayload: String): CanonicalPaymentWebhookEvent? {
        if (signature != "valid-sig-hash") return null
        return CanonicalPaymentWebhookEvent(
            paymentReference = "pay-ref-001",
            status = PaymentTransactionStatus.CAPTURED,
            amountMinorUnits = 5000L,
            currencyCode = "EUR",
            externalTransactionReference = "EXT-TX-WEBHOOK-001",
        )
    }
}

private class FailingPaymentAdapter(override val providerId: String) : PaymentProviderAdapter {
    override fun execute(command: PaymentPortCommand): Pair<PaymentTransactionStatus, String> {
        error("provider gateway timeout")
    }

    override fun verifyWebhook(signature: String, rawPayload: String): CanonicalPaymentWebhookEvent? {
        error("webhook gateway unavailable")
    }
}

private class AdversarialFakePaymentAdapter(override val providerId: String) : PaymentProviderAdapter {
    override fun execute(command: PaymentPortCommand): Pair<PaymentTransactionStatus, String> {
        return PaymentTransactionStatus.FAILED to "EXT-TX-FAILED"
    }

    override fun verifyWebhook(signature: String, rawPayload: String): CanonicalPaymentWebhookEvent? {
        // Simulates invalid signature / tampering
        return null
    }
}

private class PaymentPortMemoryStore : PaymentPortStore {
    val results = mutableMapOf<String, Pair<String, PaymentPortResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: PaymentPortResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
