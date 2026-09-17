package com.slotting.admin.circuitbreaker

import com.slotting.admin.auth.*
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.UUID

enum class ProviderType { PAYMENT, GAME }
enum class CircuitBreakerState { CLOSED, OPEN, HALF_OPEN }
enum class CircuitBreakerAction { TRIP, RESET, PROBE, CONFIGURE }

data class ProviderCircuitBreakerCommand(
    val principal: AuthenticatedPrincipal?,
    val sessionId: String,
    val tenantId: String,
    val providerId: String,
    val providerType: ProviderType,
    val action: CircuitBreakerAction,
    val incidentReference: String? = null,
    val failureThreshold: Int = 5,
    val cooldownSeconds: Long = 60,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
    val expectedVersion: Long,
)

data class ProviderCircuitBreaker(
    val providerId: String,
    val providerType: ProviderType,
    val state: CircuitBreakerState,
    val failureThreshold: Int,
    val cooldownSeconds: Long,
    val incidentReference: String?,
    val maskedSecretPreview: String,
    val serverVersion: Long,
)

data class ProviderCircuitBreakerResult(
    val resultId: UUID,
    val circuitBreaker: ProviderCircuitBreaker,
    val serverTime: Instant,
    val evidenceReference: String,
)

interface ProviderCircuitBreakerStore {
    fun findByIdempotency(tenantId: String, key: String): Pair<String, ProviderCircuitBreakerResult>?
    fun findBreaker(tenantId: String, providerId: String): ProviderCircuitBreaker?
    fun save(
        result: ProviderCircuitBreakerResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    )
}

class ProviderCircuitBreakerService(
    private val policy: AdminRbacPolicy,
    private val sessions: AdminSessionDirectory,
    private val store: ProviderCircuitBreakerStore,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Synchronized
    fun operate(command: ProviderCircuitBreakerCommand): ProviderCircuitBreakerResult {
        val principal = command.principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        val fingerprint = fingerprint(command)
        store.findByIdempotency(command.tenantId, command.idempotencyKey)?.let { replay ->
            if (replay.first != fingerprint) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
            return replay.second
        }

        if (principal.kind != PrincipalKind.ADMIN || principal.tenantId != command.tenantId) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        if (command.providerId.isBlank() || command.providerId.length > 128 ||
            command.sessionId.isBlank() || command.correlationId.isBlank() || command.causationId.isBlank() ||
            command.failureThreshold <= 0 || command.cooldownSeconds < 0) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
        }

        val now = Instant.now(clock)
        val session = try {
            sessions.find(command.tenantId, principal.id, command.sessionId)
        } catch (_: Exception) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.DEPENDENCY_UNAVAILABLE)
        }
        if (session == null || !session.active || !session.expiresAt.isAfter(now) ||
            (!policy.isPermitted(principal, AdminPermission.MANAGE_SECURITY) &&
             !policy.isPermitted(principal, AdminPermission.MANAGE_SUPPORT))) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }

        val nextBreaker = when (command.action) {
            CircuitBreakerAction.CONFIGURE -> {
                val existing = store.findBreaker(command.tenantId, command.providerId)
                if (existing == null) {
                    ProviderCircuitBreaker(
                        providerId = command.providerId,
                        providerType = command.providerType,
                        state = CircuitBreakerState.CLOSED,
                        failureThreshold = command.failureThreshold,
                        cooldownSeconds = command.cooldownSeconds,
                        incidentReference = command.incidentReference,
                        maskedSecretPreview = "****",
                        serverVersion = 1L,
                    )
                } else {
                    if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                    existing.copy(
                        providerType = command.providerType,
                        failureThreshold = command.failureThreshold,
                        cooldownSeconds = command.cooldownSeconds,
                        incidentReference = command.incidentReference ?: existing.incidentReference,
                        serverVersion = existing.serverVersion + 1,
                    )
                }
            }
            CircuitBreakerAction.TRIP -> {
                val existing = store.findBreaker(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (existing.state == CircuitBreakerState.OPEN) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                existing.copy(
                    state = CircuitBreakerState.OPEN,
                    incidentReference = command.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
            }
            CircuitBreakerAction.RESET -> {
                val existing = store.findBreaker(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (existing.state == CircuitBreakerState.CLOSED) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                existing.copy(
                    state = CircuitBreakerState.CLOSED,
                    incidentReference = command.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
            }
            CircuitBreakerAction.PROBE -> {
                val existing = store.findBreaker(command.tenantId, command.providerId)
                    ?: throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                if (existing.serverVersion != command.expectedVersion) throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                if (existing.state == CircuitBreakerState.HALF_OPEN) throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                if (command.incidentReference.isNullOrBlank()) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.INVALID)
                }
                existing.copy(
                    state = CircuitBreakerState.HALF_OPEN,
                    incidentReference = command.incidentReference,
                    serverVersion = existing.serverVersion + 1,
                )
            }
        }

        val resultId = UUID.randomUUID()
        val result = ProviderCircuitBreakerResult(
            resultId = resultId,
            circuitBreaker = nextBreaker,
            serverTime = now,
            evidenceReference = "circuit-breaker:$resultId",
        )

        val type = "CIRCUIT_BREAKER_${command.action.name}"
        val audit = AuditEvent(UUID.randomUUID(), resultId, command.tenantId, type, now, command.correlationId, command.causationId)
        val outbox = OutboxEvent(UUID.randomUUID(), resultId, command.tenantId, type, now)
        store.save(result, command.tenantId, fingerprint, command.idempotencyKey, audit, outbox)
        return result
    }

    private fun fingerprint(command: ProviderCircuitBreakerCommand): String = listOf(
        command.tenantId,
        command.providerId,
        command.providerType,
        command.action,
        command.failureThreshold,
        command.cooldownSeconds,
        command.incidentReference,
        command.expectedVersion,
    ).joinToString("|") { sha256(it.toString()) }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
