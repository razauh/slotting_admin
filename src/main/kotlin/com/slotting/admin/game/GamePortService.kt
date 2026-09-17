package com.slotting.admin.game

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class GameOperationType {
    START_ROUND,
    RECORD_BET,
    CASH_OUT_INTENT,
    PROCESS_CALLBACK,
    DIRECT_SETTLE, // Disallowed: callback can settle directly risk
}

enum class GameRoundStatus {
    INITIATED,
    ACTIVE,
    PENDING_SETTLEMENT,
    SETTLED,
    VOIDED,
    REJECTED,
}

data class GameProviderPortCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val gameId: String,
    val providerId: String,
    val roundReference: String,
    val playerId: String,
    val operation: GameOperationType,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class AviatorCompatibilityPayload(
    val roundId: String,
    val crashPoint: Double? = null,
    val cashOutMultiplier: Double? = null,
    val signature: String,
    val rawJson: String,
)

data class GameCallbackCommand(
    val tenantId: String,
    val providerId: String,
    val roundReference: String,
    val aviatorPayload: AviatorCompatibilityPayload,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class GamePortResult(
    val resultId: UUID,
    val roundReference: String,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val status: GameRoundStatus,
    val directSettlementPermitted: Boolean,
    val normalizedMultiplier: Double?,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class NormalizedGameEvent(
    val roundReference: String,
    val status: GameRoundStatus,
    val multiplier: Double?,
    val externalReference: String,
)

interface GameProviderAdapter {
    val providerId: String
    fun normalizeCallback(payload: AviatorCompatibilityPayload): NormalizedGameEvent?
}

interface GamePortStore {
    fun findByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GamePortResult>?
    fun save(
        result: GamePortResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class GamePortService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: GamePortStore,
    private val adapters: Map<String, GameProviderAdapter>,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun executeOperation(command: GameProviderPortCommand): GamePortResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Direct settlement is strictly prohibited; callbacks cannot settle directly
        if (command.operation == GameOperationType.DIRECT_SETTLE) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!command.currencyCode.matches(Regex("^[A-Z]{3}$")) ||
            command.amountMinorUnits <= 0L ||
            command.roundReference.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val fp = fingerprintCommand(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        if (!adapters.containsKey(command.providerId)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GAME-EVID-$resultId"

        val status = when (command.operation) {
            GameOperationType.START_ROUND -> GameRoundStatus.INITIATED
            GameOperationType.RECORD_BET -> GameRoundStatus.ACTIVE
            GameOperationType.CASH_OUT_INTENT -> GameRoundStatus.PENDING_SETTLEMENT
            GameOperationType.PROCESS_CALLBACK -> GameRoundStatus.PENDING_SETTLEMENT
            GameOperationType.DIRECT_SETTLE -> throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val result = GamePortResult(
            resultId = resultId,
            roundReference = command.roundReference,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            status = status,
            directSettlementPermitted = false,
            normalizedMultiplier = null,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_PORT_${command.operation.name}",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_PORT_${command.operation.name}",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    @Synchronized
    fun processCallback(command: GameCallbackCommand): GamePortResult {
        if (command.providerId.isBlank() || command.correlationId.isBlank() ||
            command.causationId.isBlank() || command.roundReference.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val fp = fingerprintCallback(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val adapter = adapters[command.providerId]
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val normalizedEvent = try {
            adapter.normalizeCallback(command.aviatorPayload)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val now = clock.instant()
        val resultId = UUID.randomUUID()
        val evidenceRef = "GAME-CB-$resultId"

        val result = GamePortResult(
            resultId = resultId,
            roundReference = command.roundReference,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = "game-aviator",
            status = normalizedEvent.status,
            directSettlementPermitted = false, // Callbacks CANNOT settle directly
            normalizedMultiplier = normalizedEvent.multiplier,
            serverTime = now,
            evidenceReference = evidenceRef,
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_CALLBACK_PROCESSED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_CALLBACK_PROCESSED",
            createdAt = now,
        )

        store.save(result, command.tenantId, fp, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprintCommand(cmd: GameProviderPortCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.roundReference}:${cmd.operation}:${cmd.amountMinorUnits}:${cmd.currencyCode}:${cmd.providerId}:${cmd.gameId}:${cmd.expectedVersion}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintCallback(cmd: GameCallbackCommand): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.roundReference}:${cmd.aviatorPayload.signature}:${cmd.aviatorPayload.rawJson}"
        return digest.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
