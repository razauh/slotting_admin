package com.slotting.admin.notification

import com.slotting.admin.auth.AuthenticatedPrincipal
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for NOTIFY-002-02:
 * "opted-out/excluded user marketed"
 */
object DeviceTokenLifecycleBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("opted-out/excluded user marketed")
        }
    }
}

enum class DevicePlatform {
    ANDROID,
    IOS,
    WEB,
}

enum class DeviceTokenState {
    ACTIVE,
    STALE,
    REVOKED,
    UNREGISTERED,
}

data class RegisterDeviceTokenCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val userId: String,
    val deviceId: String,
    val platform: DevicePlatform,
    val tokenValue: String,
    val appVersion: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long = 1L,
)

data class DeviceTokenRecord(
    val tokenId: UUID = UUID.randomUUID(),
    val tenantId: String,
    val userId: String,
    val deviceId: String,
    val platform: DevicePlatform,
    val tokenValue: String,
    var tokenState: DeviceTokenState = DeviceTokenState.ACTIVE,
    var appVersion: String,
    val registeredAt: Instant,
    var lastSeenAt: Instant,
    var updatedAt: Instant,
    val evidenceReference: String,
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class DeviceTokenLifecycleResult(
    val tokenId: UUID,
    val tenantId: String,
    val userId: String,
    val deviceId: String,
    val tokenState: DeviceTokenState,
    val action: String,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String = "Mandatory legal/security notices separately approved; stale tokens removed safely.",
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

data class DeviceTokenAuditEvent(
    val eventId: UUID,
    val tokenId: UUID,
    val tenantId: String,
    val userId: String,
    val deviceId: String,
    val eventType: String,
    val tokenState: DeviceTokenState,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

sealed class DeviceTokenLifecycleException(message: String) : RuntimeException(message) {
    class Unauthorized(message: String) : DeviceTokenLifecycleException(message)
    class Forbidden(message: String) : DeviceTokenLifecycleException(message)
    class Invalid(message: String) : DeviceTokenLifecycleException(message)
    class Conflict(message: String) : DeviceTokenLifecycleException(message)
    class NotFound(message: String) : DeviceTokenLifecycleException(message)
}

class DeviceTokenLifecycleService(
    private val clock: Clock = Clock.systemUTC(),
) {
    // tenantId -> tokenId -> DeviceTokenRecord
    private val tokenStore = ConcurrentHashMap<String, ConcurrentHashMap<UUID, DeviceTokenRecord>>()
    // tenantId:tokenValue -> tokenId
    private val tokenIndex = ConcurrentHashMap<String, UUID>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, DeviceTokenLifecycleResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<DeviceTokenAuditEvent>>()

    @Synchronized
    fun registerDeviceToken(command: RegisterDeviceTokenCommand): DeviceTokenLifecycleResult {
        DeviceTokenLifecycleBinding.checkBound()

        // 1. Authentication and Authorization
        val principal = command.principal
            ?: throw DeviceTokenLifecycleException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != command.tenantId) {
            throw DeviceTokenLifecycleException.Forbidden(
                "Cross-tenant access forbidden: principal ${principal.tenantId} != request ${command.tenantId}"
            )
        }

        // 2. Input validation
        if (command.idempotencyKey.isBlank()) {
            throw DeviceTokenLifecycleException.Invalid("Idempotency key cannot be blank")
        }
        if (command.userId.isBlank()) {
            throw DeviceTokenLifecycleException.Invalid("User ID cannot be blank")
        }
        if (command.deviceId.isBlank()) {
            throw DeviceTokenLifecycleException.Invalid("Device ID cannot be blank")
        }
        if (command.tokenValue.length < 16) {
            throw DeviceTokenLifecycleException.Invalid("Token value must be at least 16 characters")
        }
        if (command.appVersion.isBlank()) {
            throw DeviceTokenLifecycleException.Invalid("App version cannot be blank")
        }
        if (command.expectedVersion < 1L) {
            throw DeviceTokenLifecycleException.Invalid("Expected version must be >= 1")
        }

        // 3. Replay / Idempotency check
        val idemKey = "${command.tenantId}:${command.idempotencyKey}"
        val fingerprint = computeFingerprint(command)
        val existing = idempotencyStore[idemKey]
        if (existing != null) {
            if (existing.first == fingerprint) {
                return existing.second
            } else {
                throw DeviceTokenLifecycleException.Conflict(
                    "Conflicting payload for idempotency key: ${command.idempotencyKey}"
                )
            }
        }

        val now = Instant.now(clock)
        val tenantTokens = tokenStore.computeIfAbsent(command.tenantId) { ConcurrentHashMap() }

        // Token rotation: deactivate existing active tokens for the same (userId, deviceId)
        for (record in tenantTokens.values) {
            if (record.userId == command.userId && record.deviceId == command.deviceId && record.tokenState == DeviceTokenState.ACTIVE) {
                record.tokenState = DeviceTokenState.REVOKED
                record.updatedAt = now
                auditLogs.computeIfAbsent(command.tenantId) { mutableListOf() }.add(
                    DeviceTokenAuditEvent(
                        eventId = UUID.randomUUID(),
                        tokenId = record.tokenId,
                        tenantId = command.tenantId,
                        userId = command.userId,
                        deviceId = command.deviceId,
                        eventType = "DEVICE_TOKEN_ROTATED_REVOKED",
                        tokenState = DeviceTokenState.REVOKED,
                        occurredAt = now,
                        correlationId = command.correlationId,
                        causationId = command.causationId,
                    )
                )
            }
        }

        val tokenId = UUID.randomUUID()
        val evidenceRef = "device:token:$tokenId"
        val record = DeviceTokenRecord(
            tokenId = tokenId,
            tenantId = command.tenantId,
            userId = command.userId,
            deviceId = command.deviceId,
            platform = command.platform,
            tokenValue = command.tokenValue,
            tokenState = DeviceTokenState.ACTIVE,
            appVersion = command.appVersion,
            registeredAt = now,
            lastSeenAt = now,
            updatedAt = now,
            evidenceReference = evidenceRef,
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        tenantTokens[tokenId] = record
        tokenIndex["${command.tenantId}:${command.tokenValue}"] = tokenId

        val result = DeviceTokenLifecycleResult(
            tokenId = tokenId,
            tenantId = command.tenantId,
            userId = command.userId,
            deviceId = command.deviceId,
            tokenState = DeviceTokenState.ACTIVE,
            action = "REGISTERED",
            serverTime = now,
            serverVersion = command.expectedVersion,
            evidenceReference = evidenceRef,
            semanticContract = "Mandatory legal/security notices separately approved; stale tokens removed safely.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        auditLogs.computeIfAbsent(command.tenantId) { mutableListOf() }.add(
            DeviceTokenAuditEvent(
                eventId = UUID.randomUUID(),
                tokenId = tokenId,
                tenantId = command.tenantId,
                userId = command.userId,
                deviceId = command.deviceId,
                eventType = "DEVICE_TOKEN_REGISTERED",
                tokenState = DeviceTokenState.ACTIVE,
                occurredAt = now,
                correlationId = command.correlationId,
                causationId = command.causationId,
            )
        )

        idempotencyStore[idemKey] = fingerprint to result
        return result
    }

    @Synchronized
    fun markTokenStale(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        tokenValue: String,
        reason: String
    ): DeviceTokenLifecycleResult {
        DeviceTokenLifecycleBinding.checkBound()

        if (principal == null) {
            throw DeviceTokenLifecycleException.Unauthorized("Principal is unauthenticated")
        }
        if (principal.tenantId != tenantId) {
            throw DeviceTokenLifecycleException.Forbidden("Cross-tenant access forbidden")
        }

        val tokenId = tokenIndex["$tenantId:$tokenValue"]
            ?: throw DeviceTokenLifecycleException.NotFound("Token not found for value: $tokenValue")
        val record = tokenStore[tenantId]?.get(tokenId)
            ?: throw DeviceTokenLifecycleException.NotFound("Token record not found: $tokenId")

        val now = Instant.now(clock)
        record.tokenState = DeviceTokenState.STALE
        record.updatedAt = now

        auditLogs.computeIfAbsent(tenantId) { mutableListOf() }.add(
            DeviceTokenAuditEvent(
                eventId = UUID.randomUUID(),
                tokenId = tokenId,
                tenantId = tenantId,
                userId = record.userId,
                deviceId = record.deviceId,
                eventType = "DEVICE_TOKEN_MARKED_STALE: $reason",
                tokenState = DeviceTokenState.STALE,
                occurredAt = now,
                correlationId = "corr-stale-${UUID.randomUUID()}",
                causationId = "cause-stale-${UUID.randomUUID()}",
            )
        )

        return DeviceTokenLifecycleResult(
            tokenId = tokenId,
            tenantId = tenantId,
            userId = record.userId,
            deviceId = record.deviceId,
            tokenState = DeviceTokenState.STALE,
            action = "MARKED_STALE",
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = record.evidenceReference,
            semanticContract = "Mandatory legal/security notices separately approved; stale tokens removed safely.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )
    }

    @Synchronized
    fun revokeDeviceToken(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        tokenValue: String,
        reason: String
    ): DeviceTokenLifecycleResult {
        DeviceTokenLifecycleBinding.checkBound()

        if (principal == null) {
            throw DeviceTokenLifecycleException.Unauthorized("Principal is unauthenticated")
        }
        if (principal.tenantId != tenantId) {
            throw DeviceTokenLifecycleException.Forbidden("Cross-tenant access forbidden")
        }

        val tokenId = tokenIndex["$tenantId:$tokenValue"]
            ?: throw DeviceTokenLifecycleException.NotFound("Token not found for value: $tokenValue")
        val record = tokenStore[tenantId]?.get(tokenId)
            ?: throw DeviceTokenLifecycleException.NotFound("Token record not found: $tokenId")

        val now = Instant.now(clock)
        record.tokenState = DeviceTokenState.REVOKED
        record.updatedAt = now

        auditLogs.computeIfAbsent(tenantId) { mutableListOf() }.add(
            DeviceTokenAuditEvent(
                eventId = UUID.randomUUID(),
                tokenId = tokenId,
                tenantId = tenantId,
                userId = record.userId,
                deviceId = record.deviceId,
                eventType = "DEVICE_TOKEN_REVOKED: $reason",
                tokenState = DeviceTokenState.REVOKED,
                occurredAt = now,
                correlationId = "corr-revoke-${UUID.randomUUID()}",
                causationId = "cause-revoke-${UUID.randomUUID()}",
            )
        )

        return DeviceTokenLifecycleResult(
            tokenId = tokenId,
            tenantId = tenantId,
            userId = record.userId,
            deviceId = record.deviceId,
            tokenState = DeviceTokenState.REVOKED,
            action = "REVOKED",
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = record.evidenceReference,
            semanticContract = "Mandatory legal/security notices separately approved; stale tokens removed safely.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )
    }

    @Synchronized
    fun purgeStaleTokens(
        principal: AuthenticatedPrincipal?,
        tenantId: String,
        retentionThreshold: Instant
    ): Int {
        DeviceTokenLifecycleBinding.checkBound()

        if (principal == null) {
            throw DeviceTokenLifecycleException.Unauthorized("Principal is unauthenticated")
        }
        if (principal.tenantId != tenantId) {
            throw DeviceTokenLifecycleException.Forbidden("Cross-tenant access forbidden")
        }

        val tenantTokens = tokenStore[tenantId] ?: return 0
        var purgedCount = 0

        val toPurge = tenantTokens.values.filter {
            (it.tokenState == DeviceTokenState.STALE || it.tokenState == DeviceTokenState.REVOKED) &&
                it.updatedAt.isBefore(retentionThreshold)
        }

        for (record in toPurge) {
            tenantTokens.remove(record.tokenId)
            tokenIndex.remove("$tenantId:${record.tokenValue}")
            purgedCount++
        }

        val now = Instant.now(clock)
        auditLogs.computeIfAbsent(tenantId) { mutableListOf() }.add(
            DeviceTokenAuditEvent(
                eventId = UUID.randomUUID(),
                tokenId = UUID.randomUUID(),
                tenantId = tenantId,
                userId = "system",
                deviceId = "system",
                eventType = "STALE_TOKENS_PURGED: count=$purgedCount",
                tokenState = DeviceTokenState.UNREGISTERED,
                occurredAt = now,
                correlationId = "corr-purge-${UUID.randomUUID()}",
                causationId = "cause-purge-${UUID.randomUUID()}",
            )
        )

        return purgedCount
    }

    fun getActiveTokensForUser(tenantId: String, userId: String): List<DeviceTokenRecord> =
        tokenStore[tenantId]?.values?.filter { it.userId == userId && it.tokenState == DeviceTokenState.ACTIVE } ?: emptyList()

    fun getAuditLogs(tenantId: String): List<DeviceTokenAuditEvent> =
        auditLogs[tenantId]?.toList() ?: emptyList()

    private fun computeFingerprint(command: RegisterDeviceTokenCommand): String {
        val raw = listOf(
            command.tenantId,
            command.userId,
            command.deviceId,
            command.platform.name,
            command.tokenValue,
            command.appVersion,
            command.expectedVersion,
        ).joinToString("|")
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }
}
