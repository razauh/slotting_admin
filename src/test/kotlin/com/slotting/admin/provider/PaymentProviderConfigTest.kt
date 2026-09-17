package com.slotting.admin.provider

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class PaymentProviderConfigTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-005-01-T001 Manage approved payment-provider configuration produces authoritative outcome`() {
        val store = ProviderMemoryStore()
        val service = service(store)

        // 1. Register approved provider with secret
        val registered = service.operate(
            command(
                action = PaymentProviderConfigAction.REGISTER,
                apiKeySecret = "sk_live_supersecret_12345",
            )
        )
        // Assert: No secret values displayed
        assertFalse(registered.provider.toString().contains("supersecret"))
        assertEquals("****2345", registered.provider.maskedSecretPreview)
        assertEquals(PaymentProviderStatus.ENABLED, registered.provider.status)
        assertEquals("https://api.provider.test/v1", registered.provider.endpointUrl)

        // 2. Disable provider correlating to incident
        val disabled = service.operate(
            command(
                action = PaymentProviderConfigAction.DISABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "INC-1002",
                idempotencyKey = "key-disable",
            )
        )
        assertEquals(PaymentProviderStatus.DISABLED, disabled.provider.status)
        assertEquals("INC-1002", disabled.provider.incidentReference)

        // 3. Disable is reversible: re-enable correlating to resolution
        val reEnabled = service.operate(
            command(
                action = PaymentProviderConfigAction.ENABLE,
                expectedVersion = disabled.provider.serverVersion,
                incidentReference = "INC-1002-RESOLVED",
                idempotencyKey = "key-enable",
            )
        )
        assertEquals(PaymentProviderStatus.ENABLED, reEnabled.provider.status)
        assertEquals("INC-1002-RESOLVED", reEnabled.provider.incidentReference)

        // Verify audit and outbox
        assertEquals(3, store.audit.size)
        assertEquals(3, store.outbox.size)
        assertEquals("PROVIDER_CONFIG_REGISTER", store.audit[0].type)
        assertEquals("PROVIDER_CONFIG_DISABLE", store.audit[1].type)
        assertEquals("PROVIDER_CONFIG_ENABLE", store.audit[2].type)
        assertEquals("corr-1", store.audit[0].correlationId)
        assertEquals("cause-1", store.audit[0].causationId)
    }

    @Test
    fun `ADMIN-005-01-T002 Manage approved payment-provider configuration rejects invalid boundary unauthorized and stale input`() {
        val store = ProviderMemoryStore()
        val service = service(store)

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = null)) }
            .also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = player())) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(principal = admin(tenantId = "tenant-other"))) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unsafe enable/input validations
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(providerId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(endpointUrl = "not-a-url")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(sessionId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unknown provider on disable
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = PaymentProviderConfigAction.DISABLE, providerId = "unknown-prov"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        val registered = service.operate(command(action = PaymentProviderConfigAction.REGISTER))

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = PaymentProviderConfigAction.DISABLE, expectedVersion = 99))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Unsafe enable: enabling without incident reference
        val disabled = service.operate(
            command(
                action = PaymentProviderConfigAction.DISABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "INC-1",
                idempotencyKey = "dis-1",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = PaymentProviderConfigAction.ENABLE,
                    expectedVersion = disabled.provider.serverVersion,
                    incidentReference = null,
                    idempotencyKey = "en-fail",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `ADMIN-005-01-T003 Manage approved payment-provider configuration survives concurrency duplicate delivery and dependency failure`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<PaymentProviderConfigResult> {
                gate.await()
                service.operate(command(action = PaymentProviderConfigAction.REGISTER, idempotencyKey = "race-reg"))
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }
        pool.shutdown()

        assertEquals(2, outcomes.count { it.isSuccess })
        assertEquals(1, outcomes.mapNotNull { it.getOrNull() }.distinctBy { it.resultId }.size)
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)

        // Conflicting replay with different payload
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = PaymentProviderConfigAction.REGISTER,
                    displayName = "Conflicting Name",
                    idempotencyKey = "race-reg",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = PaymentProviderConfigAction.DISABLE, expectedVersion = 0, idempotencyKey = "stale-dis"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(command(action = PaymentProviderConfigAction.DISABLE, expectedVersion = 1, idempotencyKey = "dep-dis"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-005-01-T004 Manage approved payment-provider configuration remains compatible recoverable observable and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V11__payment_provider_config.sql").readText()
        assertTrue(migration.contains("admin_payment_provider_config"))
        assertTrue(migration.contains("admin_payment_provider_config_result"))
        assertTrue(migration.contains("masked_secret"))
        assertTrue(migration.contains("secret_hash"))
        assertTrue(migration.contains("incident_reference"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: ProviderMemoryStore) =
        PaymentProviderConfigService(AdminRbacPolicy(true), ActiveProviderSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: ProviderMemoryStore) =
        PaymentProviderConfigService(AdminRbacPolicy(true), FailingProviderSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        providerId: String = "stripe-v1",
        action: PaymentProviderConfigAction = PaymentProviderConfigAction.REGISTER,
        displayName: String = "Stripe Gateway",
        endpointUrl: String = "https://api.provider.test/v1",
        apiKeySecret: String? = "sec_12345",
        incidentReference: String? = null,
        expectedVersion: Long = 0L,
        idempotencyKey: String = "key-${action.name}",
        sessionId: String = "session-1",
        correlationId: String = "corr-1",
        causationId: String = "cause-1",
    ) = PaymentProviderConfigCommand(
        principal,
        sessionId,
        "tenant-1",
        providerId,
        action,
        displayName,
        endpointUrl,
        apiKeySecret,
        incidentReference,
        idempotencyKey,
        correlationId,
        causationId,
        expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveProviderSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingProviderSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class ProviderMemoryStore : PaymentProviderConfigStore {
    val items = mutableMapOf<String, PaymentProviderConfig>()
    val results = mutableMapOf<String, Pair<String, PaymentProviderConfigResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findProvider(tenantId: String, providerId: String) = synchronized(this) { items["$tenantId:$providerId"] }
    override fun save(
        result: PaymentProviderConfigResult,
        tenantId: String,
        secretHash: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) = synchronized(this) {
        items["$tenantId:${result.provider.providerId}"] = result.provider
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
        this.audit += audit
        this.outbox += outbox
    }
}
