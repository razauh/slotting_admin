package com.slotting.admin.identity

import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import java.time.Clock
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Gate to enforce AUTH-002-03: Implement session revocation and device inventory.
 * Semantic contract: "Reuse revokes family and alerts; Android Keystore remains refresh-token store."
 */
object SessionDeviceRevocationBinding {
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("expired/malformed/revoked, simultaneous refresh, reuse and logout reuse")
        }
    }
}

enum class DeviceSessionStatus {
    ACTIVE,
    REVOKED,
    EXPIRED
}

data class DeviceMetadata(
    val deviceId: String,
    val deviceModel: String,
    val osVersion: String,
    val clientIp: String,
    val userAgent: String
)

data class DeviceSessionRecord(
    val sessionId: UUID,
    val familyId: UUID,
    val tenantId: String,
    val playerId: UUID,
    val deviceMetadata: DeviceMetadata,
    var status: DeviceSessionStatus,
    var revocationReason: TokenRevocationReason? = null,
    val createdAt: Instant,
    var lastSeenAt: Instant,
    var revokedAt: Instant? = null
)

data class DeviceInventoryItem(
    val sessionId: UUID,
    val familyId: UUID,
    val deviceId: String,
    val deviceModel: String,
    val osVersion: String,
    val clientIp: String,
    val status: DeviceSessionStatus,
    val createdAt: Instant,
    val lastSeenAt: Instant
)

data class CreateDeviceSessionCommand(
    val tenantId: String,
    val playerId: UUID,
    val familyId: UUID,
    val deviceMetadata: DeviceMetadata,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class RevokeDeviceSessionCommand(
    val tenantId: String,
    val playerId: UUID,
    val sessionId: UUID,
    val reason: TokenRevocationReason,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class RevokeAllSessionsCommand(
    val tenantId: String,
    val playerId: UUID,
    val exceptSessionId: UUID? = null,
    val reason: TokenRevocationReason,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L
)

data class DeviceSessionResult(
    val resultId: UUID,
    val sessionId: UUID,
    val familyId: UUID,
    val playerId: UUID,
    val status: DeviceSessionStatus,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

data class RevokeAllSessionsResult(
    val resultId: UUID,
    val playerId: UUID,
    val revokedCount: Int,
    val activeCount: Int,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val auditEvent: AuditEvent,
    val outboxEvent: OutboxEvent
)

interface DeviceInventoryStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>?
    fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any)
    fun saveSession(session: DeviceSessionRecord)
    fun findSession(tenantId: String, sessionId: UUID): DeviceSessionRecord?
    fun findSessionsByPlayer(tenantId: String, playerId: UUID): List<DeviceSessionRecord>
    fun findSessionByFamily(tenantId: String, familyId: UUID): DeviceSessionRecord?
}

class InMemoryDeviceInventoryStore : DeviceInventoryStore {
    val idempotency = ConcurrentHashMap<String, Pair<Any, Any>>()
    val sessions = ConcurrentHashMap<UUID, DeviceSessionRecord>()
    val audit = mutableListOf<AuditEvent>()
    val outbox = mutableListOf<OutboxEvent>()

    override fun findByIdempotency(tenantId: String, key: String): Pair<Any, Any>? =
        idempotency["$tenantId:$key"]

    override fun saveIdempotency(tenantId: String, key: String, command: Any, result: Any) {
        idempotency["$tenantId:$key"] = Pair(command, result)
        when (result) {
            is DeviceSessionResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
            is RevokeAllSessionsResult -> {
                audit.add(result.auditEvent)
                outbox.add(result.outboxEvent)
            }
        }
    }

    override fun saveSession(session: DeviceSessionRecord) {
        sessions[session.sessionId] = session
    }

    override fun findSession(tenantId: String, sessionId: UUID): DeviceSessionRecord? =
        sessions[sessionId]?.takeIf { it.tenantId == tenantId }

    override fun findSessionsByPlayer(tenantId: String, playerId: UUID): List<DeviceSessionRecord> =
        sessions.values.filter { it.tenantId == tenantId && it.playerId == playerId }

    override fun findSessionByFamily(tenantId: String, familyId: UUID): DeviceSessionRecord? =
        sessions.values.firstOrNull { it.tenantId == tenantId && it.familyId == familyId }
}

class SessionDeviceInventoryService(
    private val registrationStore: PlayerRegistrationStore,
    private val tokenSecurityStore: TokenSecurityStore,
    private val deviceStore: DeviceInventoryStore,
    private val alertSink: TokenSecurityAlertSink,
    private val clock: Clock = Clock.systemUTC()
) {

    private fun validateHeaders(
        tenantId: String,
        correlationId: String,
        causationId: String,
        idempotencyKey: String,
        expectedVersion: Long
    ) {
        if (tenantId.isBlank() || correlationId.isBlank() || causationId.isBlank() || idempotencyKey.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }
        if (expectedVersion < 1L) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
        }
    }

    fun createDeviceSession(command: CreateDeviceSessionCommand): DeviceSessionResult = synchronized(deviceStore) {
        SessionDeviceRevocationBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        if (command.deviceMetadata.deviceId.isBlank() ||
            command.deviceMetadata.deviceModel.isBlank() ||
            command.deviceMetadata.clientIp.isBlank()
        ) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        deviceStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is DeviceSessionResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        // Verify player exists
        val player = registrationStore.findById(command.tenantId, command.playerId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (player.status == PlayerAccountStatus.SUSPENDED) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        // Verify token family exists and is active
        val family = tokenSecurityStore.findFamily(command.tenantId, command.familyId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        if (family.isRevoked) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        val sessionId = UUID.randomUUID()
        val session = DeviceSessionRecord(
            sessionId = sessionId,
            familyId = command.familyId,
            tenantId = command.tenantId,
            playerId = command.playerId,
            deviceMetadata = command.deviceMetadata,
            status = DeviceSessionStatus.ACTIVE,
            createdAt = now,
            lastSeenAt = now
        )
        deviceStore.saveSession(session)

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEVICE_SESSION_REGISTERED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEVICE_SESSION_REGISTERED",
            createdAt = now
        )

        val result = DeviceSessionResult(
            resultId = resultId,
            sessionId = sessionId,
            familyId = command.familyId,
            playerId = command.playerId,
            status = DeviceSessionStatus.ACTIVE,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-device-session-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        deviceStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun listDeviceInventory(tenantId: String, playerId: UUID): List<DeviceInventoryItem> {
        SessionDeviceRevocationBinding.checkBound()

        if (tenantId.isBlank()) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val sessions = deviceStore.findSessionsByPlayer(tenantId, playerId)
        return sessions.map { session ->
            DeviceInventoryItem(
                sessionId = session.sessionId,
                familyId = session.familyId,
                deviceId = session.deviceMetadata.deviceId,
                deviceModel = session.deviceMetadata.deviceModel,
                osVersion = session.deviceMetadata.osVersion,
                clientIp = session.deviceMetadata.clientIp,
                status = session.status,
                createdAt = session.createdAt,
                lastSeenAt = session.lastSeenAt
            )
        }
    }

    fun revokeDeviceSession(command: RevokeDeviceSessionCommand): DeviceSessionResult = synchronized(deviceStore) {
        SessionDeviceRevocationBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        deviceStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is DeviceSessionResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val session = deviceStore.findSession(command.tenantId, command.sessionId)
            ?: throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)

        // Strict ownership check (cross-owner protection)
        if (session.playerId != command.playerId || session.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val now = clock.instant()
        session.status = DeviceSessionStatus.REVOKED
        session.revocationReason = command.reason
        session.revokedAt = now
        deviceStore.saveSession(session)

        // Authoritatively revoke the associated token family in TokenSecurityStore
        tokenSecurityStore.revokeEntireFamily(command.tenantId, session.familyId, command.reason, now)

        // Emit security alert if revoked due to policy or compromise
        if (command.reason == TokenRevocationReason.SECURITY_POLICY ||
            command.reason == TokenRevocationReason.ROTATED_REUSE_DETECTED
        ) {
            alertSink.sendSecurityAlert(
                tenantId = command.tenantId,
                playerId = command.playerId,
                familyId = session.familyId,
                reason = "DEVICE_SESSION_SECURITY_REVOCATION",
                details = "Device session ${session.sessionId} (device: ${session.deviceMetadata.deviceId}) revoked: ${command.reason}"
            )
        }

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEVICE_SESSION_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "DEVICE_SESSION_REVOKED",
            createdAt = now
        )

        val result = DeviceSessionResult(
            resultId = resultId,
            sessionId = session.sessionId,
            familyId = session.familyId,
            playerId = session.playerId,
            status = DeviceSessionStatus.REVOKED,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-device-revoked-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        deviceStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }

    fun revokeAllSessions(command: RevokeAllSessionsCommand): RevokeAllSessionsResult = synchronized(deviceStore) {
        SessionDeviceRevocationBinding.checkBound()

        validateHeaders(
            command.tenantId,
            command.correlationId,
            command.causationId,
            command.idempotencyKey,
            command.expectedVersion
        )

        deviceStore.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { (cachedCmd, cachedResult) ->
            if (cachedCmd == command && cachedResult is RevokeAllSessionsResult) {
                return cachedResult
            } else {
                throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            }
        }

        val now = clock.instant()
        val sessions = deviceStore.findSessionsByPlayer(command.tenantId, command.playerId)
        var revokedCount = 0
        var activeCount = 0

        for (s in sessions) {
            if (command.exceptSessionId != null && s.sessionId == command.exceptSessionId) {
                if (s.status == DeviceSessionStatus.ACTIVE) {
                    activeCount++
                }
            } else {
                if (s.status == DeviceSessionStatus.ACTIVE) {
                    s.status = DeviceSessionStatus.REVOKED
                    s.revocationReason = command.reason
                    s.revokedAt = now
                    deviceStore.saveSession(s)
                    tokenSecurityStore.revokeEntireFamily(command.tenantId, s.familyId, command.reason, now)
                    revokedCount++
                }
            }
        }

        alertSink.sendSecurityAlert(
            tenantId = command.tenantId,
            playerId = command.playerId,
            familyId = UUID.randomUUID(),
            reason = "ALL_SESSIONS_REVOKED",
            details = "Revoked $revokedCount sessions for player ${command.playerId}, reason: ${command.reason}"
        )

        val resultId = UUID.randomUUID()
        val auditEvent = AuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ALL_SESSIONS_REVOKED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId
        )
        val outboxEvent = OutboxEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "ALL_SESSIONS_REVOKED",
            createdAt = now
        )

        val result = RevokeAllSessionsResult(
            resultId = resultId,
            playerId = command.playerId,
            revokedCount = revokedCount,
            activeCount = activeCount,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "ev-all-sessions-revoked-$resultId",
            auditEvent = auditEvent,
            outboxEvent = outboxEvent
        )

        deviceStore.saveIdempotency(command.tenantId, command.idempotencyKey, command, result)
        return result
    }
}
