package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.*
import org.junit.jupiter.api.Test

class GameProviderConfigTest {
    private val now = Instant.parse("2026-09-17T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADMIN-005-02-T001 Manage approved game-provider configuration produces the required authoritative outcome`() {
        val store = GameProviderMemoryStore()
        val service = service(store)

        // 1. Register approved game provider with secret
        val registered = service.operate(
            command(
                action = GameProviderConfigAction.REGISTER,
                providerId = "pragmatic-play",
                displayName = "Pragmatic Play RGS",
                apiKeySecret = "game_sec_live_987654321",
            )
        )
        // Assert: No secret values displayed; masked secret preview
        assertFalse(registered.provider.toString().contains("987654321"))
        assertEquals("****4321", registered.provider.maskedSecretPreview)
        assertEquals(GameProviderStatus.ENABLED, registered.provider.status)
        assertEquals("https://api.gameprovider.test/rgs", registered.provider.endpointUrl)

        // 2. Disable provider correlating to incident
        val disabled = service.operate(
            command(
                action = GameProviderConfigAction.DISABLE,
                providerId = "pragmatic-play",
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "INC-RGS-501",
                idempotencyKey = "key-disable-game-prov",
            )
        )
        assertEquals(GameProviderStatus.DISABLED, disabled.provider.status)
        assertEquals("INC-RGS-501", disabled.provider.incidentReference)

        // 3. Disable is reversible: re-enable correlating to resolution
        val reEnabled = service.operate(
            command(
                action = GameProviderConfigAction.ENABLE,
                providerId = "pragmatic-play",
                expectedVersion = disabled.provider.serverVersion,
                incidentReference = "INC-RGS-501-RESOLVED",
                idempotencyKey = "key-enable-game-prov",
            )
        )
        assertEquals(GameProviderStatus.ENABLED, reEnabled.provider.status)
        assertEquals("INC-RGS-501-RESOLVED", reEnabled.provider.incidentReference)

        // Verify audit and outbox
        assertEquals(3, store.audit.size)
        assertEquals(3, store.outbox.size)
        assertEquals("GAME_PROVIDER_CONFIG_REGISTER", store.audit[0].type)
        assertEquals("GAME_PROVIDER_CONFIG_DISABLE", store.audit[1].type)
        assertEquals("GAME_PROVIDER_CONFIG_ENABLE", store.audit[2].type)
        assertEquals("corr-gp-1", store.audit[0].correlationId)
        assertEquals("cause-gp-1", store.audit[0].causationId)
    }

    @Test
    fun `ADMIN-005-02-T002 Manage approved game-provider configuration rejects invalid, boundary, unauthorized, and stale input`() {
        val store = GameProviderMemoryStore()
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
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(endpointUrl = "invalid-url")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }
        assertFailsWith<AuthenticationFailure.Rejected> { service.operate(command(sessionId = "")) }
            .also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Unknown provider on disable
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = GameProviderConfigAction.DISABLE, providerId = "unknown-gp"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        val registered = service.operate(command(action = GameProviderConfigAction.REGISTER))

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = GameProviderConfigAction.DISABLE, expectedVersion = 99))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Unsafe enable: enabling without incident reference
        val disabled = service.operate(
            command(
                action = GameProviderConfigAction.DISABLE,
                expectedVersion = registered.provider.serverVersion,
                incidentReference = "INC-RGS-1",
                idempotencyKey = "dis-gp-1",
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(
                command(
                    action = GameProviderConfigAction.ENABLE,
                    expectedVersion = disabled.provider.serverVersion,
                    incidentReference = null,
                    idempotencyKey = "en-gp-fail",
                )
            )
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    @Test
    fun `ADMIN-005-02-T003 Manage approved game-provider configuration survives concurrency, duplicate delivery, and dependency failure`() {
        val store = GameProviderMemoryStore()
        val service = service(store)
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val calls = (1..2).map {
            pool.submit<GameProviderConfigResult> {
                gate.await()
                service.operate(command(action = GameProviderConfigAction.REGISTER, idempotencyKey = "race-reg-gp"))
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
                    action = GameProviderConfigAction.REGISTER,
                    displayName = "Conflicting Game Provider",
                    idempotencyKey = "race-reg-gp",
                )
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // Stale version rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(command(action = GameProviderConfigAction.DISABLE, expectedVersion = 0, idempotencyKey = "stale-dis-gp"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Dependency failure
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store).operate(command(action = GameProviderConfigAction.DISABLE, expectedVersion = 1, idempotencyKey = "dep-dis-gp"))
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }
    }

    @Test
    fun `ADMIN-005-02-T004 Manage approved game-provider configuration remains compatible, recoverable, observable, and lifecycle-safe`() {
        val migration = java.io.File("src/main/resources/db/migration/V12__game_provider_config.sql").readText()
        assertTrue(migration.contains("admin_game_provider_config"))
        assertTrue(migration.contains("admin_game_provider_config_result"))
        assertTrue(migration.contains("masked_secret"))
        assertTrue(migration.contains("secret_hash"))
        assertTrue(migration.contains("incident_reference"))
        assertTrue(migration.contains("foreign key"))
        assertTrue(!migration.contains("update admin_"))
    }

    private fun service(store: GameProviderMemoryStore) =
        GameProviderConfigService(AdminRbacPolicy(true), ActiveGameProviderSessionDirectory(), store, clock)

    private fun serviceWithDependencyFailure(store: GameProviderMemoryStore) =
        GameProviderConfigService(AdminRbacPolicy(true), FailingGameProviderSessionDirectory(), store, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        providerId: String = "pragmatic-play",
        action: GameProviderConfigAction = GameProviderConfigAction.REGISTER,
        displayName: String = "Pragmatic Play RGS",
        endpointUrl: String = "https://api.gameprovider.test/rgs",
        apiKeySecret: String? = "sec_rgs_12345",
        incidentReference: String? = null,
        expectedVersion: Long = 0L,
        idempotencyKey: String = "key-gp-${action.name}",
        sessionId: String = "session-gp-1",
        correlationId: String = "corr-gp-1",
        causationId: String = "cause-gp-1",
    ) = GameProviderConfigCommand(
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

private class ActiveGameProviderSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-1" && sessionId == "session-gp-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingGameProviderSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session dependency unavailable")
}

private class GameProviderMemoryStore : GameProviderConfigStore {
    val items = mutableMapOf<String, GameProviderConfig>()
    val results = mutableMapOf<String, Pair<String, GameProviderConfigResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String) = synchronized(this) { results["$tenantId:$key"] }
    override fun findProvider(tenantId: String, providerId: String) = synchronized(this) { items["$tenantId:$providerId"] }
    override fun save(
        result: GameProviderConfigResult,
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
