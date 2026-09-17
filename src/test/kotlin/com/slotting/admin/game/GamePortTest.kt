package com.slotting.admin.game

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

class GamePortTest {
    private val now = Instant.parse("2026-09-17T17:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun `ADR-005-01-T001 Define provider-neutral game port produces the required authoritative outcome`() {
        val store = GamePortMemoryStore()
        val adapter = AviatorCompatibilityAdapter("prov-aviator")
        val service = service(store, mapOf("prov-aviator" to adapter))

        // 1. Initiate game round through canonical game port
        val startCmd = command(
            roundReference = "round-aviator-001",
            operation = GameOperationType.START_ROUND,
            amountMinorUnits = 1000L,
            idempotencyKey = "key-game-start-001",
            correlationId = "corr-game-1",
            causationId = "cause-game-1",
        )
        val startRes = service.executeOperation(startCmd)
        assertEquals(GameRoundStatus.INITIATED, startRes.status)
        assertFalse(startRes.directSettlementPermitted) // Settlement authority retained by backend, not port

        // 2. Process Aviator callback: treated as compatibility input, not authority
        val callbackCmd = GameCallbackCommand(
            tenantId = "tenant-1",
            providerId = "prov-aviator",
            roundReference = "round-aviator-001",
            aviatorPayload = AviatorCompatibilityPayload(
                roundId = "round-aviator-001",
                crashPoint = 2.45,
                cashOutMultiplier = 2.10,
                signature = "valid-aviator-sig",
                rawJson = "{\"roundId\":\"round-aviator-001\",\"crashPoint\":2.45,\"cashOut\":2.10}",
            ),
            idempotencyKey = "key-cb-001",
            correlationId = "corr-cb-1",
            causationId = "cause-cb-1",
        )
        val cbRes = service.processCallback(callbackCmd)
        assertEquals(GameRoundStatus.PENDING_SETTLEMENT, cbRes.status)
        assertFalse(cbRes.directSettlementPermitted) // Callbacks CANNOT settle directly!
        assertEquals(2.10, cbRes.normalizedMultiplier)

        // 3. Replay with same idempotency key returns identical result
        val cbReplay = service.processCallback(callbackCmd)
        assertEquals(cbRes.resultId, cbReplay.resultId)
        assertEquals(cbRes.evidenceReference, cbReplay.evidenceReference)

        // Assert: Preserve existing Aviator contracts as compatibility input, not authority
        assertEquals(2, store.audit.size)
        assertFalse(store.audit[0].type.contains("secret"))
        assertEquals("corr-game-1", store.audit[0].correlationId)
        assertEquals("cause-game-1", store.audit[0].causationId)
    }

    @Test
    fun `ADR-005-01-T002 Define provider-neutral game port rejects invalid, boundary, unauthorized, and stale input`() {
        val store = GamePortMemoryStore()
        val adapter = AviatorCompatibilityAdapter("prov-aviator")
        val service = service(store, mapOf("prov-aviator" to adapter))

        // Unauthenticated
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = null, idempotencyKey = "key-unauth-game"))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Non-admin player
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = player(), idempotencyKey = "key-player-game"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Cross-tenant
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(principal = admin(tenantId = "tenant-other"), idempotencyKey = "key-cross-game"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Direct settlement attempt rejected: callback/caller cannot settle directly
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(
                command(
                    operation = GameOperationType.DIRECT_SETTLE,
                    idempotencyKey = "key-direct-settle-attempt",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Invalid currency
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(currencyCode = "INVALID", idempotencyKey = "key-bad-curr"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Zero amount
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = 0L, idempotencyKey = "key-zero-amt"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid Aviator signature in callback
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.processCallback(
                GameCallbackCommand(
                    tenantId = "tenant-1",
                    providerId = "prov-aviator",
                    roundReference = "round-1",
                    aviatorPayload = AviatorCompatibilityPayload(
                        roundId = "round-1",
                        signature = "forged-signature",
                        rawJson = "{}",
                    ),
                    idempotencyKey = "key-forged-cb",
                    correlationId = "corr-1",
                    causationId = "cause-1",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Stale expected version
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(expectedVersion = 999L, idempotencyKey = "key-stale-game"))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // Conflicting replay with different amount
        service.executeOperation(command(amountMinorUnits = 1000L, idempotencyKey = "key-conflict-game"))
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.executeOperation(command(amountMinorUnits = 2000L, idempotencyKey = "key-conflict-game"))
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `ADR-005-01-T003 Define provider-neutral game port survives concurrency, duplicate delivery, and dependency failure`() {
        val store = GamePortMemoryStore()
        val adapter = AviatorCompatibilityAdapter("prov-aviator")
        val service = service(store, mapOf("prov-aviator" to adapter))

        // 1. Benchmark concurrent duplicate calls with identical idempotency key
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(4)
        val calls = (1..4).map {
            pool.submit<GamePortResult> {
                gate.await()
                service.executeOperation(
                    command(
                        roundReference = "round-concurrent-001",
                        idempotencyKey = "key-concurrent-game",
                    )
                )
            }
        }
        gate.countDown()
        val outcomes = calls.map { runCatching { it.get() } }

        assertEquals(4, outcomes.count { it.isSuccess })
        val distinctResultIds = outcomes.mapNotNull { it.getOrNull()?.resultId }.toSet()
        assertEquals(1, distinctResultIds.size)

        // 2. Dependency failure on session lookup
        assertFailsWith<AuthenticationFailure.Rejected> {
            serviceWithDependencyFailure(store, mapOf("prov-aviator" to adapter)).executeOperation(
                command(idempotencyKey = "key-dep-fail-game")
            )
        }.also { assertEquals(AuthErrorCode.DEPENDENCY_UNAVAILABLE, it.code) }

        // 3. Adversarial fake adapter simulating signature tampering
        val advFake = AdversarialGameAdapter("prov-adv")
        val advService = service(store, mapOf("prov-adv" to advFake))
        assertFailsWith<AuthenticationFailure.Rejected> {
            advService.processCallback(
                GameCallbackCommand(
                    tenantId = "tenant-1",
                    providerId = "prov-adv",
                    roundReference = "round-adv-1",
                    aviatorPayload = AviatorCompatibilityPayload(
                        roundId = "round-adv-1",
                        signature = "tampered-sig",
                        rawJson = "{}",
                    ),
                    idempotencyKey = "key-adv-cb",
                    correlationId = "corr-adv-1",
                    causationId = "cause-adv-1",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        pool.shutdown()
    }

    @Test
    fun `ADR-005-01-T004 Define provider-neutral game port remains compatible, recoverable, observable, and lifecycle-safe`() {
        // Assert: no unapproved persistence or migration introduced
        val migrationDir = File("src/main/resources/db/migration")
        val sqlFiles = migrationDir.listFiles { _, name -> name.endsWith(".sql") } ?: emptyArray()
        assertTrue(sqlFiles.isNotEmpty())
        val migrationVersions = sqlFiles.map { it.name.substringBefore("__") }
        assertTrue(!migrationVersions.contains("V17"))

        // Assert: restart/recreation preserves consistency
        val store = GamePortMemoryStore()
        val adapter = AviatorCompatibilityAdapter("prov-aviator")
        val service = service(store, mapOf("prov-aviator" to adapter))

        val cmd = command(
            roundReference = "round-reboot-game",
            idempotencyKey = "key-reboot-game",
            correlationId = "corr-reboot-game-1",
            causationId = "cause-reboot-game-1",
        )
        val first = service.executeOperation(cmd)

        val restartedService = service(store, mapOf("prov-aviator" to adapter))
        val second = restartedService.executeOperation(cmd)

        assertEquals(first.resultId, second.resultId)
        assertEquals(first.evidenceReference, second.evidenceReference)

        // Observability check
        assertEquals(1, store.audit.size)
        assertEquals("GAME_PORT_START_ROUND", store.audit[0].type)
        assertEquals("corr-reboot-game-1", store.audit[0].correlationId)
        assertEquals("cause-reboot-game-1", store.audit[0].causationId)
        assertFalse(store.audit[0].type.contains("secret"))
    }

    private fun service(store: GamePortStore, adapters: Map<String, GameProviderAdapter>) =
        GamePortService(AdminRbacPolicy(true), ActiveGameSessionDirectory(), store, adapters, clock)

    private fun serviceWithDependencyFailure(store: GamePortStore, adapters: Map<String, GameProviderAdapter>) =
        GamePortService(AdminRbacPolicy(true), FailingGameSessionDirectory(), store, adapters, clock)

    private fun command(
        principal: AuthenticatedPrincipal? = admin(),
        roundReference: String = "round-default",
        gameId: String = "game-aviator-1",
        providerId: String = "prov-aviator",
        playerId: String = "player-1",
        operation: GameOperationType = GameOperationType.START_ROUND,
        amountMinorUnits: Long = 1000L,
        currencyCode: String = "EUR",
        idempotencyKey: String = "key-game-default",
        correlationId: String = "corr-game-default",
        causationId: String = "cause-game-default",
        expectedVersion: Long = 1L,
    ) = GameProviderPortCommand(
        principal = principal,
        sessionId = "session-game-1",
        tenantId = "tenant-1",
        gameId = gameId,
        providerId = providerId,
        roundReference = roundReference,
        playerId = playerId,
        operation = operation,
        amountMinorUnits = amountMinorUnits,
        currencyCode = currencyCode,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    private fun admin(tenantId: String = "tenant-1") =
        AuthenticatedPrincipal("admin-game-1", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SUPER_ADMIN))

    private fun player() =
        AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
}

private class ActiveGameSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String) =
        if (tenantId == "tenant-1" && principalId == "admin-game-1" && sessionId == "session-game-1")
            AdminSessionStatus(true, false, Instant.parse("2026-09-17T18:00:00Z"))
        else null
}

private class FailingGameSessionDirectory : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        error("session directory unavailable")
}

private class AviatorCompatibilityAdapter(override val providerId: String) : GameProviderAdapter {
    override fun normalizeCallback(payload: AviatorCompatibilityPayload): NormalizedGameEvent? {
        if (payload.signature != "valid-aviator-sig") return null
        return NormalizedGameEvent(
            roundReference = payload.roundId,
            status = GameRoundStatus.PENDING_SETTLEMENT,
            multiplier = payload.cashOutMultiplier ?: payload.crashPoint,
            externalReference = "AVIATOR-${payload.roundId}",
        )
    }
}

private class AdversarialGameAdapter(override val providerId: String) : GameProviderAdapter {
    override fun normalizeCallback(payload: AviatorCompatibilityPayload): NormalizedGameEvent? {
        // Tampered signature or invalid payload
        return null
    }
}

private class GamePortMemoryStore : GamePortStore {
    val results = mutableMapOf<String, Pair<String, GamePortResult>>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, idempotencyKey: String) =
        synchronized(this) { results["$tenantId:$idempotencyKey"] }

    override fun save(
        result: GamePortResult,
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
