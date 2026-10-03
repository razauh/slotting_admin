package com.slotting.admin.auth

import java.net.URI

enum class OAuthClientType {
    PUBLIC,
    CONFIDENTIAL
}

data class OAuthClient(
    val clientId: String,
    val clientType: OAuthClientType,
    val allowedGrantTypes: Set<String>,
    val allowedResponseTypes: Set<String>,
    val allowedRedirectUris: Set<String>,
    val allowedScopes: Set<String>,
    val requirePkce: Boolean = true,
    val requireS256: Boolean = true,
    val clientSecret: String? = null
)

sealed interface OAuthClientValidationResult {
    data class Valid(val client: OAuthClient) : OAuthClientValidationResult
    data class Invalid(val error: String, val errorDescription: String) : OAuthClientValidationResult
}

object OAuthClientRegistry {

    private val registeredClients = mutableMapOf<String, OAuthClient>()

    init {
        // Public Android client registration (RFC 8252, RFC 9700)
        registerClient(
            OAuthClient(
                clientId = "slotting-android",
                clientType = OAuthClientType.PUBLIC,
                allowedGrantTypes = setOf("authorization_code", "refresh_token"),
                allowedResponseTypes = setOf("code"),
                allowedRedirectUris = setOf(
                    "https://app.slotting.internal/auth/callback",
                    "https://auth.slotting.com/callback",
                    "https://play.slotting.com/callback",
                    "https://slotting.com/auth/callback"
                ),
                allowedScopes = setOf("openid", "profile", "wallet.read", "cashier.write", "gameplay"),
                requirePkce = true,
                requireS256 = true,
                clientSecret = null
            )
        )
    }

    fun registerClient(client: OAuthClient) {
        registeredClients[client.clientId] = client
    }

    fun findClient(clientId: String): OAuthClient? = registeredClients[clientId]

    fun validateAuthorizationRequest(
        clientId: String?,
        responseType: String?,
        redirectUri: String?,
        scopes: Set<String>?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ): OAuthClientValidationResult {
        if (clientId.isNullOrBlank()) {
            return OAuthClientValidationResult.Invalid("invalid_request", "Missing client_id parameter")
        }

        val client = findClient(clientId)
            ?: return OAuthClientValidationResult.Invalid("unauthorized_client", "Unknown or unregistered client_id: $clientId")

        if (responseType.isNullOrBlank()) {
            return OAuthClientValidationResult.Invalid("invalid_request", "Missing response_type parameter")
        }

        if (!client.allowedResponseTypes.contains(responseType)) {
            return OAuthClientValidationResult.Invalid("unsupported_response_type", "Client does not support response_type: $responseType")
        }

        if (redirectUri.isNullOrBlank()) {
            return OAuthClientValidationResult.Invalid("invalid_request", "Missing redirect_uri parameter")
        }

        val uriValidation = validateRedirectUri(redirectUri, client)
        if (uriValidation != null) {
            return uriValidation
        }

        if (scopes.isNullOrEmpty()) {
            return OAuthClientValidationResult.Invalid("invalid_scope", "Scope cannot be empty")
        }

        if (!scopes.contains("openid")) {
            return OAuthClientValidationResult.Invalid("invalid_scope", "Scope 'openid' is required for player authentication")
        }

        val unpermittedScopes = scopes - client.allowedScopes
        if (unpermittedScopes.isNotEmpty()) {
            return OAuthClientValidationResult.Invalid("invalid_scope", "Unregistered scope(s): ${unpermittedScopes.joinToString()}")
        }

        if (client.requirePkce) {
            if (codeChallenge.isNullOrBlank()) {
                return OAuthClientValidationResult.Invalid("invalid_request", "PKCE code_challenge is required for public client")
            }
            if (codeChallengeMethod.isNullOrBlank()) {
                return OAuthClientValidationResult.Invalid("invalid_request", "code_challenge_method is required")
            }
            if (client.requireS256 && codeChallengeMethod != "S256") {
                return OAuthClientValidationResult.Invalid("invalid_request", "code_challenge_method must be S256 (plain is rejected)")
            }
        }

        return OAuthClientValidationResult.Valid(client)
    }

    fun validateRedirectUri(redirectUri: String, client: OAuthClient): OAuthClientValidationResult.Invalid? {
        val uri = try {
            URI(redirectUri)
        } catch (e: Exception) {
            return OAuthClientValidationResult.Invalid("invalid_request", "Malformed redirect_uri: ${e.message}")
        }

        val scheme = uri.scheme?.lowercase()
        if (scheme != "https") {
            return OAuthClientValidationResult.Invalid("invalid_request", "Redirect URI scheme must be https; HTTP and custom schemes are rejected")
        }

        // Exact match validation: no wildcards, no path traversal, exact URI required
        val exactMatch = client.allowedRedirectUris.contains(redirectUri)
        if (!exactMatch) {
            return OAuthClientValidationResult.Invalid("invalid_request", "Redirect URI does not exactly match registered redirect URIs for client")
        }

        return null
    }

    fun validateRedirectUri(clientId: String, redirectUri: String): Boolean {
        val client = findClient(clientId) ?: return false
        return validateRedirectUri(redirectUri, client) == null
    }

    fun validateScope(clientId: String, scope: String): Boolean {
        val client = findClient(clientId) ?: return false
        val requested = scope.split(" ").filter { it.isNotBlank() }.toSet()
        return (requested - client.allowedScopes).isEmpty()
    }

    fun reset() {
        registeredClients.clear()
        registerClient(
            OAuthClient(
                clientId = "slotting-android",
                clientType = OAuthClientType.PUBLIC,
                allowedGrantTypes = setOf("authorization_code", "refresh_token"),
                allowedResponseTypes = setOf("code"),
                allowedRedirectUris = setOf(
                    "https://app.slotting.internal/auth/callback",
                    "https://auth.slotting.com/callback",
                    "https://play.slotting.com/callback",
                    "https://slotting.com/auth/callback"
                ),
                allowedScopes = setOf("openid", "profile", "wallet.read", "cashier.write", "gameplay"),
                requirePkce = true,
                requireS256 = true,
                clientSecret = null
            )
        )
    }
}
