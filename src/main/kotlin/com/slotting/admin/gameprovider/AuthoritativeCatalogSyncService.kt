package com.slotting.admin.gameprovider

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * Fail-closed verification gate for GAME-002-01.
 * Throws expected RED failure until contract bindings and invariant protections are verified.
 */
object AuthoritativeCatalogSyncBinding {
    @Volatile
    var isBound: Boolean = false

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("disabled/unlicensed game launches")
        }
    }
}

enum class GameEnablementStatus {
    ENABLED,
    DISABLED_BY_OPERATOR,
    DISABLED_BY_JURISDICTION,
    DISABLED_STALE_SYNC,
    DISABLED_WITHDRAWN,
}

data class ProviderCatalogGameDto(
    val gameId: String,
    val gameTitle: String,
    val gameType: CasinoProviderType,
    val supportedJurisdictions: Set<String>,
    val rtpPercent: Double,
    val minBetMinorUnits: Long,
    val maxBetMinorUnits: Long,
    val initialEnablement: GameEnablementStatus = GameEnablementStatus.ENABLED,
)

data class CatalogGameEntry(
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val gameTitle: String,
    val gameType: CasinoProviderType,
    val supportedJurisdictions: Set<String>,
    val rtpPercent: Double,
    val minBetMinorUnits: Long,
    val maxBetMinorUnits: Long,
    val enablementStatus: GameEnablementStatus,
    val lastSynchronizedAt: Instant,
    val staleSyncThresholdSeconds: Long = 86400L,
    val version: Long = 1L,
)

data class SynchronizeProviderCatalogCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val games: List<ProviderCatalogGameDto>,
    val syncTimestamp: Instant,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class UpdateGameEnablementCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val newStatus: GameEnablementStatus,
    val reason: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class AuthorizeGameLaunchCommand(
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val playerId: String,
    val jurisdictionCode: String,
    val currencyCode: String,
    val requestedBetMinorUnits: Long,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class CatalogSyncResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val totalSynchronized: Int,
    val enabledCount: Int,
    val disabledCount: Int,
    val staleCount: Int,
    val syncTimestamp: Instant,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class GameEnablementResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val previousStatus: GameEnablementStatus,
    val newStatus: GameEnablementStatus,
    val serverTime: Instant,
    val evidenceReference: String,
)

data class GameLaunchAuthorizationResult(
    val resultId: UUID,
    val tenantId: String,
    val providerId: String,
    val gameId: String,
    val playerId: String,
    val jurisdictionCode: String,
    val authorized: Boolean,
    val launchToken: String?,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface AuthoritativeCatalogStore {
    fun findGame(tenantId: String, providerId: String, gameId: String): CatalogGameEntry?
    fun listGames(tenantId: String, providerId: String): List<CatalogGameEntry>
    fun saveGame(game: CatalogGameEntry)
    fun findSyncByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, CatalogSyncResult>?
    fun saveSync(
        result: CatalogSyncResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findEnablementByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameEnablementResult>?
    fun saveEnablement(
        result: GameEnablementResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
    fun findLaunchByIdempotency(tenantId: String, idempotencyKey: String): Pair<String, GameLaunchAuthorizationResult>?
    fun saveLaunch(
        result: GameLaunchAuthorizationResult,
        tenantId: String,
        idempotencyKey: String,
        fingerprint: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class AuthoritativeCatalogSyncService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val contractStore: CanonicalCasinoProviderContractStore,
    private val store: AuthoritativeCatalogStore,
    private val clock: Clock = Clock.systemUTC(),
    private val defaultStaleThresholdSeconds: Long = 86400L,
) {
    private val secureRandom = SecureRandom()

    @Synchronized
    fun synchronizeCatalog(command: SynchronizeProviderCatalogCommand): CatalogSyncResult {
        AuthoritativeCatalogSyncBinding.checkBound()

        // 1. Validation
        if (command.providerId.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.games.isEmpty()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // Validate each game
        for (g in command.games) {
            if (g.gameId.isBlank() ||
                g.gameTitle.isBlank() ||
                g.supportedJurisdictions.isEmpty() ||
                g.minBetMinorUnits < 0 ||
                g.maxBetMinorUnits < g.minBetMinorUnits ||
                g.rtpPercent <= 0.0 ||
                g.rtpPercent > 100.0
            ) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
            }
        }

        // 2. Authentication & Principal check
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 3. Idempotency check
        val fp = fingerprintSync(command)
        store.findSyncByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 4. Session authorization
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // Schema presence check
        contractStore.findSchema(command.tenantId, command.providerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        val now = clock.instant()
        var enabledCount = 0
        var disabledCount = 0

        for (g in command.games) {
            val existing = store.findGame(command.tenantId, command.providerId, g.gameId)
            // Preserve operator disablement if previously disabled by operator, else use sync status
            val status = if (existing != null && existing.enablementStatus == GameEnablementStatus.DISABLED_BY_OPERATOR) {
                GameEnablementStatus.DISABLED_BY_OPERATOR
            } else {
                g.initialEnablement
            }

            if (status == GameEnablementStatus.ENABLED) {
                enabledCount++
            } else {
                disabledCount++
            }

            val entry = CatalogGameEntry(
                tenantId = command.tenantId,
                providerId = command.providerId,
                gameId = g.gameId,
                gameTitle = g.gameTitle,
                gameType = g.gameType,
                supportedJurisdictions = g.supportedJurisdictions,
                rtpPercent = g.rtpPercent,
                minBetMinorUnits = g.minBetMinorUnits,
                maxBetMinorUnits = g.maxBetMinorUnits,
                enablementStatus = status,
                lastSynchronizedAt = command.syncTimestamp,
                staleSyncThresholdSeconds = defaultStaleThresholdSeconds,
                version = (existing?.version ?: 0L) + 1L,
            )
            store.saveGame(entry)
        }

        val resultId = UUID.randomUUID()
        val result = CatalogSyncResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            totalSynchronized = command.games.size,
            enabledCount = enabledCount,
            disabledCount = disabledCount,
            staleCount = 0,
            syncTimestamp = command.syncTimestamp,
            serverTime = now,
            evidenceReference = "EVID-CATALOG-SYNC-${command.tenantId}-${command.providerId}-$resultId",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_CATALOG_SYNCHRONIZED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_CATALOG_SYNCHRONIZED",
            createdAt = now,
        )

        store.saveSync(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun updateGameEnablement(command: UpdateGameEnablementCommand): GameEnablementResult {
        AuthoritativeCatalogSyncBinding.checkBound()

        if (command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.sessionId.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.reason.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val fp = fingerprintEnablement(command)
        store.findEnablementByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)

        if (!session.active || session.expiresAt.isBefore(clock.instant())) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
            !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT)
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val existing = store.findGame(command.tenantId, command.providerId, command.gameId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (command.expectedVersion != existing.version + 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        val now = clock.instant()
        val previous = existing.enablementStatus
        val updated = existing.copy(
            enablementStatus = command.newStatus,
            version = existing.version + 1L,
        )
        store.saveGame(updated)

        val resultId = UUID.randomUUID()
        val result = GameEnablementResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            previousStatus = previous,
            newStatus = command.newStatus,
            serverTime = now,
            evidenceReference = "EVID-GAME-ENABLEMENT-${command.tenantId}-${command.gameId}-v${updated.version}",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_ENABLEMENT_UPDATED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_ENABLEMENT_UPDATED",
            createdAt = now,
        )

        store.saveEnablement(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    @Synchronized
    fun authorizeGameLaunch(command: AuthorizeGameLaunchCommand): GameLaunchAuthorizationResult {
        AuthoritativeCatalogSyncBinding.checkBound()

        // 1. Input validation & financial sanity
        if (command.tenantId.isBlank() ||
            command.providerId.isBlank() ||
            command.gameId.isBlank() ||
            command.playerId.isBlank() ||
            command.jurisdictionCode.isBlank() ||
            command.correlationId.isBlank() ||
            command.causationId.isBlank() ||
            command.requestedBetMinorUnits < 0 ||
            !command.currencyCode.matches(Regex("[A-Z]{3}"))
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        if (command.expectedVersion != 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }

        // 2. Idempotency check
        val fp = fingerprintLaunch(command)
        store.findLaunchByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedFp, cachedResult) ->
            if (cachedFp != fp) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return cachedResult
        }

        // 3. Find game in catalog
        val game = try {
            store.findGame(command.tenantId, command.providerId, command.gameId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        } ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        val now = clock.instant()

        // 4. Stale sync check (Semantic contract: Stale sync disables affected launch)
        val syncAgeSeconds = now.epochSecond - game.lastSynchronizedAt.epochSecond
        val isStale = syncAgeSeconds > game.staleSyncThresholdSeconds

        if (isStale) {
            // Automatically mark game as disabled due to stale sync
            if (game.enablementStatus != GameEnablementStatus.DISABLED_STALE_SYNC) {
                val staleGame = game.copy(
                    enablementStatus = GameEnablementStatus.DISABLED_STALE_SYNC,
                    version = game.version + 1L,
                )
                store.saveGame(staleGame)
            }

            // Stale sync audit event
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "GAME_LAUNCH_REJECTED_STALE_SYNC",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = "GAME_LAUNCH_REJECTED_STALE_SYNC",
                createdAt = now,
            )
            store.saveLaunch(
                GameLaunchAuthorizationResult(
                    resultId = audit.resultId,
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    gameId = command.gameId,
                    playerId = command.playerId,
                    jurisdictionCode = command.jurisdictionCode,
                    authorized = false,
                    launchToken = null,
                    serverTime = now,
                    evidenceReference = "EVID-LAUNCH-STALE-${command.tenantId}-${command.gameId}",
                ),
                command.tenantId,
                command.idempotencyKey,
                fp,
                audit,
                outbox,
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 5. Operator / General Enablement check (Prevent disabled game launches)
        if (game.enablementStatus != GameEnablementStatus.ENABLED) {
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "GAME_LAUNCH_REJECTED_DISABLED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = "GAME_LAUNCH_REJECTED_DISABLED",
                createdAt = now,
            )
            store.saveLaunch(
                GameLaunchAuthorizationResult(
                    resultId = audit.resultId,
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    gameId = command.gameId,
                    playerId = command.playerId,
                    jurisdictionCode = command.jurisdictionCode,
                    authorized = false,
                    launchToken = null,
                    serverTime = now,
                    evidenceReference = "EVID-LAUNCH-DISABLED-${command.tenantId}-${command.gameId}",
                ),
                command.tenantId,
                command.idempotencyKey,
                fp,
                audit,
                outbox,
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 6. Jurisdiction license check (Prevent unlicensed game launches)
        if (command.jurisdictionCode !in game.supportedJurisdictions) {
            val audit = AuditEvent(
                eventId = UUID.randomUUID(),
                resultId = UUID.randomUUID(),
                tenantId = command.tenantId,
                type = "GAME_LAUNCH_REJECTED_UNLICENSED",
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
            val outbox = OutboxEvent(
                eventId = UUID.randomUUID(),
                resultId = audit.resultId,
                tenantId = command.tenantId,
                type = "GAME_LAUNCH_REJECTED_UNLICENSED",
                createdAt = now,
            )
            store.saveLaunch(
                GameLaunchAuthorizationResult(
                    resultId = audit.resultId,
                    tenantId = command.tenantId,
                    providerId = command.providerId,
                    gameId = command.gameId,
                    playerId = command.playerId,
                    jurisdictionCode = command.jurisdictionCode,
                    authorized = false,
                    launchToken = null,
                    serverTime = now,
                    evidenceReference = "EVID-LAUNCH-UNLICENSED-${command.tenantId}-${command.gameId}-${command.jurisdictionCode}",
                ),
                command.tenantId,
                command.idempotencyKey,
                fp,
                audit,
                outbox,
            )
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // 7. Bet minor units boundary check
        if (command.requestedBetMinorUnits < game.minBetMinorUnits ||
            command.requestedBetMinorUnits > game.maxBetMinorUnits
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        // 8. Launch authorization granted
        val resultId = UUID.randomUUID()
        val tokenBytes = ByteArray(32)
        secureRandom.nextBytes(tokenBytes)
        val launchToken = "LAUNCH-${Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes)}"

        val result = GameLaunchAuthorizationResult(
            resultId = resultId,
            tenantId = command.tenantId,
            providerId = command.providerId,
            gameId = command.gameId,
            playerId = command.playerId,
            jurisdictionCode = command.jurisdictionCode,
            authorized = true,
            launchToken = launchToken,
            serverTime = now,
            evidenceReference = "EVID-GAME-LAUNCH-${command.tenantId}-${command.gameId}-$resultId",
        )

        val audit = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_AUTHORIZED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )

        val outbox = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "GAME_LAUNCH_AUTHORIZED",
            createdAt = now,
        )

        store.saveLaunch(result, command.tenantId, command.idempotencyKey, fp, audit, outbox)
        return result
    }

    private fun fingerprintSync(cmd: SynchronizeProviderCatalogCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val gamesDigest = cmd.games.joinToString(";") { "${it.gameId}:${it.minBetMinorUnits}:${it.maxBetMinorUnits}" }
        val raw = "${cmd.tenantId}:${cmd.providerId}:$gamesDigest:${cmd.syncTimestamp.epochSecond}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintEnablement(cmd: UpdateGameEnablementCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.gameId}:${cmd.newStatus}:${cmd.expectedVersion}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    private fun fingerprintLaunch(cmd: AuthorizeGameLaunchCommand): String {
        val md = MessageDigest.getInstance("SHA-256")
        val raw = "${cmd.tenantId}:${cmd.providerId}:${cmd.gameId}:${cmd.playerId}:${cmd.jurisdictionCode}:${cmd.requestedBetMinorUnits}:${cmd.currencyCode}"
        return md.digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
