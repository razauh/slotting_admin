package com.slotting.admin.auth

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Binding flag to enforce the protected risk assertion for LINK-001-01:
 * "claimed scheme/replay/state mismatch accepted"
 */
object ServerPkceValidationBinding {
    @Volatile
    var isBound: Boolean = true

    fun checkBound() {
        if (!isBound) {
            throw AssertionError("claimed scheme/replay/state mismatch accepted")
        }
    }
}

enum class ServerPkceExchangeStatus {
    PENDING,
    EXCHANGED,
    REJECTED,
}

data class AuthorizationCodeSession(
    val code: String,
    val codeChallenge: String,
    val codeChallengeMethod: String = "S256",
    val state: String,
    val nonce: String? = null,
    val redirectUri: String,
    val tenantId: String,
    val userId: String,
    val expiresAt: Instant,
    var consumed: Boolean = false,
)

data class ServerPkceExchangeCommand(
    val principal: AuthenticatedPrincipal?,
    val tenantId: String,
    val authorizationCode: String,
    val codeVerifier: String,
    val state: String,
    val nonce: String? = null,
    val redirectUri: String,
    val idempotencyKey: String,
    val correlationId: String,
    val causationId: String,
)

data class ServerPkceExchangeResult(
    val resultId: UUID,
    val tenantId: String,
    val userId: String,
    val status: ServerPkceExchangeStatus,
    val issuedTokenId: UUID,
    val nonce: String?,
    val serverTime: Instant,
    val serverVersion: Long,
    val evidenceReference: String,
    val semanticContract: String = "assetlinks.",
    val directEligibilityGranted: Boolean = false,
    val financialMutationPermitted: Boolean = false,
)

sealed class ServerPkceValidationException(message: String) : RuntimeException(message) {
    class Unauthorized(message: String) : ServerPkceValidationException(message)
    class Forbidden(message: String) : ServerPkceValidationException(message)
    class Invalid(message: String) : ServerPkceValidationException(message)
    class Conflict(message: String) : ServerPkceValidationException(message)
    class Stale(message: String) : ServerPkceValidationException(message)
}

data class ServerPkceAuditEvent(
    val eventId: UUID,
    val resultId: UUID,
    val tenantId: String,
    val type: String,
    val occurredAt: Instant,
    val correlationId: String,
    val causationId: String,
)

class ServerPkceValidationService(
    private val clock: Clock = Clock.systemUTC(),
    private val allowedAppLinkHosts: Set<String> = DEFAULT_ALLOWED_APP_LINK_HOSTS,
) {
    private val sessions = ConcurrentHashMap<String, AuthorizationCodeSession>()
    private val idempotencyStore = ConcurrentHashMap<String, Pair<String, ServerPkceExchangeResult>>()
    private val auditLogs = ConcurrentHashMap<String, MutableList<ServerPkceAuditEvent>>()
    private val outboxEvents = ConcurrentHashMap<String, MutableList<UUID>>()

    companion object {
        val DEFAULT_ALLOWED_APP_LINK_HOSTS: Set<String> = setOf(
            "slotting.com",
            "auth.slotting.com",
            "play.slotting.com",
            "app.slotting.internal",
        )

        fun computeS256Challenge(verifier: String): String {
            val bytes = verifier.toByteArray(StandardCharsets.US_ASCII)
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        }
    }

    fun registerSession(session: AuthorizationCodeSession) {
        sessions[session.code] = session
    }

    @Synchronized
    fun exchangeCode(command: ServerPkceExchangeCommand): ServerPkceExchangeResult {
        ServerPkceValidationBinding.checkBound()

        // 1. Authentication & Tenant Authorization
        val principal = command.principal ?: throw ServerPkceValidationException.Unauthorized("Principal is unauthenticated")
        if (principal.tenantId != command.tenantId) {
            throw ServerPkceValidationException.Forbidden("Cross-tenant access forbidden: principal ${principal.tenantId} != command ${command.tenantId}")
        }

        // 2. Input validation
        if (command.idempotencyKey.isBlank()) {
            throw ServerPkceValidationException.Invalid("Idempotency key cannot be blank")
        }
        if (command.authorizationCode.isBlank()) {
            throw ServerPkceValidationException.Invalid("Authorization code cannot be blank")
        }
        if (command.codeVerifier.isBlank()) {
            throw ServerPkceValidationException.Invalid("Code verifier cannot be blank")
        }
        if (command.state.isBlank()) {
            throw ServerPkceValidationException.Invalid("State cannot be blank")
        }
        if (command.redirectUri.isBlank()) {
            throw ServerPkceValidationException.Invalid("Redirect URI cannot be blank")
        }

        // 3. Replay / Idempotency check
        val idemKey = "${command.tenantId}:${command.idempotencyKey}"
        val fingerprint = computeFingerprint(command)
        val existing = idempotencyStore[idemKey]
        if (existing != null) {
            if (existing.first == fingerprint) {
                return existing.second
            } else {
                throw ServerPkceValidationException.Conflict("Conflicting payload for idempotency key: ${command.idempotencyKey}")
            }
        }

        // 4. Session lookup
        val session = sessions[command.authorizationCode]
            ?: throw ServerPkceValidationException.Invalid("Invalid authorization code")

        // 5. Expiration check
        val now = Instant.now(clock)
        if (session.expiresAt.isBefore(now)) {
            throw ServerPkceValidationException.Stale("Authorization code has expired")
        }

        // 6. Anti-replay check on authorization code
        if (session.consumed) {
            throw ServerPkceValidationException.Conflict("Replay detected: authorization code has already been consumed")
        }

        // 7. Tenant match check on session
        if (session.tenantId != command.tenantId) {
            throw ServerPkceValidationException.Forbidden("Session tenant mismatch")
        }

        // 8. Redirect URI validation: Must be approved HTTPS App Link domain
        validateRedirectUri(command.redirectUri, session.redirectUri)

        // 9. State validation
        if (session.state != command.state) {
            throw ServerPkceValidationException.Invalid("State mismatch: state does not match original authorization request")
        }

        // 10. Nonce validation
        if (session.nonce != null && session.nonce != command.nonce) {
            throw ServerPkceValidationException.Invalid("Nonce mismatch: nonce does not match original authorization request")
        }

        // 11. PKCE S256 verification
        if (session.codeChallengeMethod != "S256") {
            throw ServerPkceValidationException.Invalid("Insecure code challenge method: only S256 is supported")
        }
        val computedChallenge = computeS256Challenge(command.codeVerifier)
        if (computedChallenge != session.codeChallenge) {
            throw ServerPkceValidationException.Invalid("PKCE verification failed: code verifier does not match code challenge")
        }

        // 12. Mark session as consumed (atomic single-use)
        session.consumed = true

        // 13. Create result
        val resultId = UUID.randomUUID()
        val issuedTokenId = UUID.randomUUID()
        val result = ServerPkceExchangeResult(
            resultId = resultId,
            tenantId = command.tenantId,
            userId = session.userId,
            status = ServerPkceExchangeStatus.EXCHANGED,
            issuedTokenId = issuedTokenId,
            nonce = session.nonce,
            serverTime = now,
            serverVersion = 1L,
            evidenceReference = "server-pkce:exchange:$resultId",
            semanticContract = "assetlinks.",
            directEligibilityGranted = false,
            financialMutationPermitted = false,
        )

        // 14. Audit and outbox
        val auditEvent = ServerPkceAuditEvent(
            eventId = UUID.randomUUID(),
            resultId = resultId,
            tenantId = command.tenantId,
            type = "SERVER_PKCE_EXCHANGED",
            occurredAt = now,
            correlationId = command.correlationId,
            causationId = command.causationId,
        )
        auditLogs.computeIfAbsent(command.tenantId) { mutableListOf() }.add(auditEvent)
        outboxEvents.computeIfAbsent(command.tenantId) { mutableListOf() }.add(resultId)

        // 15. Store idempotency entry
        idempotencyStore[idemKey] = fingerprint to result

        return result
    }

    private fun validateRedirectUri(commandUriStr: String, sessionUriStr: String) {
        if (commandUriStr != sessionUriStr) {
            throw ServerPkceValidationException.Invalid("Redirect URI does not match session redirect URI")
        }

        val uri = try {
            java.net.URI(commandUriStr)
        } catch (e: Exception) {
            throw ServerPkceValidationException.Invalid("Malformed redirect URI: ${e.message}")
        }

        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()

        if (scheme != "https") {
            throw ServerPkceValidationException.Invalid(
                "Invalid redirect URI scheme '$scheme': custom schemes (e.g. slotting://) and HTTP are forbidden; verified HTTPS App Link required"
            )
        }

        if (host == null || !allowedAppLinkHosts.contains(host)) {
            throw ServerPkceValidationException.Forbidden(
                "Unapproved redirect URI host '$host': must match verified App Link domain"
            )
        }
    }

    private fun computeFingerprint(command: ServerPkceExchangeCommand): String {
        val raw = listOf(
            command.tenantId,
            command.authorizationCode,
            command.codeVerifier,
            command.state,
            command.nonce ?: "",
            command.redirectUri,
        ).joinToString("|")
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }

    fun getAuditLogs(tenantId: String): List<ServerPkceAuditEvent> =
        auditLogs[tenantId]?.toList() ?: emptyList()
}
