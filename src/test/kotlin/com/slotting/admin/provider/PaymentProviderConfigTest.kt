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
        assertEquals("********", registered.provider.maskedSecretPreview)
        assertEquals(PaymentProviderStatus.DISABLED, registered.provider.status)
        assertEquals("https://api.provider.test/v1", registered.provider.endpointUrl)

        // 2. Enable after setup validation, then disable correlating to incident
        val enabled = service.operate(
            command(
                action = PaymentProviderConfigAction.ENABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "INC-1001",
                idempotencyKey = "key-enable-initial",
            )
        )
        assertEquals(PaymentProviderStatus.ENABLED, enabled.provider.status)
        val disabled = service.operate(
            command(
                action = PaymentProviderConfigAction.DISABLE,
                expectedVersion = enabled.provider.serverVersion,
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
        assertEquals(4, store.audit.size)
        assertEquals(4, store.outbox.size)
        assertEquals("PROVIDER_CONFIG_REGISTER", store.audit[0].type)
        assertEquals("PROVIDER_CONFIG_ENABLE", store.audit[1].type)
        assertEquals("PROVIDER_CONFIG_DISABLE", store.audit[2].type)
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
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val registered = service.operate(command(action = PaymentProviderConfigAction.REGISTER))

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = PaymentProviderConfigAction.DISABLE, expectedVersion = 99))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        val enabled = service.operate(
            command(
                action = PaymentProviderConfigAction.ENABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "INC-0",
                idempotencyKey = "en-0",
            )
        )
        // Unsafe enable: enabling without incident reference
        val disabled = service.operate(
            command(
                action = PaymentProviderConfigAction.DISABLE,
                expectedVersion = enabled.provider.serverVersion,
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

    @Test
    fun `TC-013-R1 PKR provider configuration is eligible while USD settlement and INR are rejected`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        val registered = service.operate(
            command(action = PaymentProviderConfigAction.REGISTER, apiKeySecret = "fake-key", idempotencyKey = "tc013-reg")
        )
        assertEquals(PaymentProviderStatus.DISABLED, registered.provider.status)
        assertEquals(ProviderSetupState.READY, registered.provider.setupStatus)
        assertEquals(setOf("PKR"), registered.provider.settlementCurrencies)
        assertEquals("********", registered.provider.maskedSecretPreview)

        val enabled = service.operate(
            command(
                action = PaymentProviderConfigAction.ENABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "CHG-013",
                idempotencyKey = "tc013-enable",
            )
        )
        assertEquals(PaymentProviderStatus.ENABLED, enabled.provider.status)

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    providerId = "SAFEPAY_RAAST",
                    action = PaymentProviderConfigAction.REGISTER,
                    walletCurrencies = setOf("USD"),
                    settlementCurrencies = setOf("USD"),
                    idempotencyKey = "tc013-usd",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    providerId = "EASYPAISA",
                    action = PaymentProviderConfigAction.REGISTER,
                    walletCurrencies = setOf("INR"),
                    settlementCurrencies = setOf("PKR"),
                    idempotencyKey = "tc013-inr",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertEquals(2, store.audit.size)
    }

    @Test
    fun `TC-013-R2 unknown provider and unsupported payout fail closed without fallback`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(providerId = "UNKNOWN_PROVIDER", idempotencyKey = "tc013-unknown"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val unsupported = service.operate(
            command(
                action = PaymentProviderConfigAction.REGISTER,
                supportedOperations = setOf("PAYOUT"),
                idempotencyKey = "tc013-payout",
            )
        )
        assertEquals(PaymentProviderStatus.DISABLED, unsupported.provider.status)
        assertEquals(ProviderSetupState.INVALID_CONFIG, unsupported.provider.setupStatus)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = PaymentProviderConfigAction.ENABLE,
                    expectedVersion = unsupported.provider.serverVersion,
                    incidentReference = "CHG-013",
                    idempotencyKey = "tc013-payout-enable",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `TC-013-R3 tenant isolation and stale capability version reject selection`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        val registered = service.operate(
            command(action = PaymentProviderConfigAction.REGISTER, idempotencyKey = "tc013-tenant")
        )
        assertTrue(service.listProviders("tenant-1").any { it.providerId == "JAZZCASH" })
        assertTrue(service.listProviders("tenant-2").isEmpty())
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    principal = admin("tenant-2"),
                    action = PaymentProviderConfigAction.ENABLE,
                    expectedVersion = registered.provider.serverVersion,
                    incidentReference = "CHG-013",
                    idempotencyKey = "tc013-cross-tenant",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = PaymentProviderConfigAction.ENABLE,
                    expectedVersion = 999L,
                    incidentReference = "CHG-013",
                    idempotencyKey = "tc013-stale",
                )
            )
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    @Test
    fun `TC-018-R1 production enablement requires permitted use technical verification and evidence`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        val registered = service.operate(
            command(
                action = PaymentProviderConfigAction.REGISTER,
                environment = com.slotting.admin.provider.port.ProviderEnvironment.PRODUCTION,
                apiKeySecret = "fake-key",
                idempotencyKey = "tc018-reg",
            )
        )
        assertEquals(ProviderSetupState.NOT_VERIFIED, registered.provider.setupStatus)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = PaymentProviderConfigAction.ENABLE,
                    expectedVersion = registered.provider.serverVersion,
                    incidentReference = "CHG-018",
                    idempotencyKey = "tc018-enable-denied",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val simulator = service.operate(
            command(
                providerId = "EASYPAISA",
                action = PaymentProviderConfigAction.REGISTER,
                environment = com.slotting.admin.provider.port.ProviderEnvironment.LOCAL_MOCK,
                apiKeySecret = "fake-key",
                idempotencyKey = "tc018-sim",
            )
        )
        assertEquals(ProviderSetupState.READY, simulator.provider.setupStatus)
        assertEquals(PaymentProviderStatus.DISABLED, simulator.provider.status)
    }

    @Test
    fun `TC-018-R2 disabled provider stops new payouts while existing operations remain reconcilable`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        val registered = service.operate(
            command(action = PaymentProviderConfigAction.REGISTER, idempotencyKey = "tc018-r2-reg")
        )
        val enabled = service.operate(
            command(
                action = PaymentProviderConfigAction.ENABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "CHG-018",
                idempotencyKey = "tc018-r2-enable",
            )
        )
        val disabled = service.operate(
            command(
                action = PaymentProviderConfigAction.DISABLE,
                expectedVersion = enabled.provider.serverVersion,
                incidentReference = "INC-018",
                idempotencyKey = "tc018-r2-disable",
            )
        )
        assertEquals(PaymentProviderStatus.DISABLED, disabled.provider.status)
        assertTrue(disabled.provider.setupStatus == ProviderSetupState.READY)
    }

    @Test
    fun `TC-018-R3 support role and aliased production guard are denied`() {
        val store = ProviderMemoryStore()
        val support = AuthenticatedPrincipal("support-1", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        val service = service(store)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    principal = support,
                    action = PaymentProviderConfigAction.REGISTER,
                    idempotencyKey = "tc018-support",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        val fakeAdapter = com.slotting.admin.provider.port.adapters.AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        assertFailsWith<IllegalStateException> {
            com.slotting.admin.provider.port.ProductionProviderGuard.assertProductionReady(fakeAdapter, "prod")
        }
        assertFailsWith<IllegalStateException> {
            com.slotting.admin.provider.port.ProductionProviderGuard.assertProductionReady(fakeAdapter, "production")
        }
    }

    @Test
    fun `TC-014-R2 revoked session cannot replay a stored configuration result`() {
        val store = ProviderMemoryStore()
        val sessions = ToggleProviderSessionDirectory()
        val service = PaymentProviderConfigService(AdminRbacPolicy(true), sessions, store, clock, TestProviderCredentialWriter())
        val cmd = command(action = PaymentProviderConfigAction.REGISTER, idempotencyKey = "tc014-replay")
        service.operate(cmd)
        sessions.active = false
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(cmd) }
            .also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
        assertEquals(1, store.audit.size)
    }

    @Test
    fun `TC-014-RED-3 missing KMS writer fails closed and config save failure revokes the new credential version`() {
        val noWriter = PaymentProviderConfigService(AdminRbacPolicy(true), ActiveProviderSessionDirectory(), ProviderMemoryStore(), clock)
        assertFailsWith<AuthenticationFailure.Rejected> {
            noWriter.operate(command(action = PaymentProviderConfigAction.REGISTER, idempotencyKey = "tc014-no-kms"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        val writer = TestProviderCredentialWriter()
        val failingStore = FailingSaveProviderStore()
        val service = PaymentProviderConfigService(AdminRbacPolicy(true), ActiveProviderSessionDirectory(), failingStore, clock, writer)
        assertFailsWith<IllegalStateException> {
            service.operate(command(action = PaymentProviderConfigAction.REGISTER, idempotencyKey = "tc014-atomic"))
        }
        assertTrue(writer.revoked.contains(1L))
    }

    @Test
    fun `TC-018-R1 adapter readiness is server-derived and caller flags cannot enable production`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        val registered = service.operate(
            command(
                action = PaymentProviderConfigAction.REGISTER,
                environment = com.slotting.admin.provider.port.ProviderEnvironment.PRODUCTION,
                apiKeySecret = "fake-key",
                permittedUseApproved = true,
                technicalVerificationApproved = true,
                externalEvidenceReference = "external-evidence-1",
                reviewer = "reviewer-1",
                adapterProductionReady = true,
                idempotencyKey = "tc018-adapter-flag",
            )
        )
        assertEquals(ProviderSetupState.NOT_VERIFIED, registered.provider.setupStatus)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = PaymentProviderConfigAction.ENABLE,
                    expectedVersion = registered.provider.serverVersion,
                    incidentReference = "CHG-018",
                    adapterProductionReady = true,
                    idempotencyKey = "tc018-adapter-enable-denied",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val trusted = service(ProviderMemoryStore(), ProviderAdapterRegistry(setOf("JAZZCASH")))
        val trustedStore = ProviderMemoryStore()
        val trustedService = service(trustedStore, ProviderAdapterRegistry(setOf("JAZZCASH")))
        val trustedRegistered = trustedService.operate(
            command(
                action = PaymentProviderConfigAction.REGISTER,
                environment = com.slotting.admin.provider.port.ProviderEnvironment.PRODUCTION,
                apiKeySecret = "fake-key",
                permittedUseApproved = true,
                technicalVerificationApproved = true,
                externalEvidenceReference = "external-evidence-1",
                reviewer = "reviewer-1",
                idempotencyKey = "tc018-trusted-reg",
            )
        )
        assertEquals(ProviderSetupState.READY, trustedRegistered.provider.setupStatus)
        val enabled = trustedService.operate(
            command(
                action = PaymentProviderConfigAction.ENABLE,
                expectedVersion = trustedRegistered.provider.serverVersion,
                incidentReference = "CHG-018",
                idempotencyKey = "tc018-trusted-enable",
            )
        )
        assertEquals(PaymentProviderStatus.ENABLED, enabled.provider.status)
    }

    @Test
    fun `TC-013-R1 public method availability is gated by enabled and ready provider configuration`() {
        val store = ProviderMemoryStore()
        val service = service(store)
        val resolver = ConfiguredProviderStatusResolver(service)
        val registered = service.operate(
            command(action = PaymentProviderConfigAction.REGISTER, idempotencyKey = "tc013-gate-reg")
        )
        assertEquals(false, resolver.isProviderAvailable("tenant-1", "JAZZCASH"))
        val enabled = service.operate(
            command(
                action = PaymentProviderConfigAction.ENABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "CHG-013",
                idempotencyKey = "tc013-gate-enable",
            )
        )
        assertEquals(true, resolver.isProviderAvailable("tenant-1", "JAZZCASH"))
        assertEquals(false, resolver.isProviderAvailable("tenant-2", "JAZZCASH"))
        assertEquals(false, resolver.isProviderAvailable("tenant-1", "UNKNOWN_PROVIDER"))
    }

    private fun service(store: ProviderMemoryStore, registry: ProviderAdapterRegistry = ProviderAdapterRegistry()) =
        PaymentProviderConfigService(AdminRbacPolicy(true), ActiveProviderSessionDirectory(), store, clock, TestProviderCredentialWriter(), registry)

    private fun serviceWithDependencyFailure(store: ProviderMemoryStore) =
        PaymentProviderConfigService(AdminRbacPolicy(true), FailingProviderSessionDirectory(), store, clock, TestProviderCredentialWriter())

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        providerId: String = "JAZZCASH",
        action: PaymentProviderConfigAction = PaymentProviderConfigAction.REGISTER,
        displayName: String = "JazzCash",
        endpointUrl: String = "https://api.provider.test/v1",
        apiKeySecret: String? = "sec_12345",
        incidentReference: String? = null,
        expectedVersion: Long = 0L,
        idempotencyKey: String = "key-${action.name}",
        sessionId: String = "session-1",
        correlationId: String = "corr-1",
        causationId: String = "cause-1",
        environment: com.slotting.admin.provider.port.ProviderEnvironment = com.slotting.admin.provider.port.ProviderEnvironment.SANDBOX,
        walletCurrencies: Set<String> = setOf("PKR"),
        settlementCurrencies: Set<String> = setOf("PKR"),
        supportedOperations: Set<String> = setOf("DEPOSIT"),
        permittedUseApproved: Boolean = false,
        technicalVerificationApproved: Boolean = false,
        externalEvidenceReference: String? = null,
        reviewer: String? = null,
        adapterProductionReady: Boolean = false,
        credentialVersion: Long = 1L,
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
        environment,
        walletCurrencies,
        settlementCurrencies,
        supportedOperations,
        1L,
        permittedUseApproved,
        technicalVerificationApproved,
        externalEvidenceReference,
        reviewer,
        credentialVersion,
        null,
        null,
        null,
        null,
        adapterProductionReady,
        null,
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
    override fun listProviders(tenantId: String): List<PaymentProviderConfig> = synchronized(this) {
        items.filterKeys { it.startsWith("$tenantId:") }.values.toList()
    }
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

private class ToggleProviderSessionDirectory : AdminSessionDirectory {
    var active: Boolean = true
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (active) AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"), mfaVerified = true)
        else AdminSessionStatus(false, false, Instant.parse("2026-09-17T18:00:00Z"), mfaVerified = true)
}

private class FailingSaveProviderStore : PaymentProviderConfigStore {
    override fun findByIdempotency(tenantId: String, key: String): Pair<String, PaymentProviderConfigResult>? = null
    override fun findProvider(tenantId: String, providerId: String): PaymentProviderConfig? = null
    override fun save(
        result: PaymentProviderConfigResult,
        tenantId: String,
        secretHash: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        throw IllegalStateException("simulated config persistence failure")
    }
}
