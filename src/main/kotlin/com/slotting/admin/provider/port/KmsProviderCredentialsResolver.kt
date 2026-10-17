package com.slotting.admin.provider.port

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.secret.KmsBackendSecretsService
import java.time.Instant
import java.util.Base64
import org.springframework.jdbc.core.JdbcTemplate

data class EncryptedProviderCredentials(
    val tenantId: String,
    val providerId: String,
    val secretKeyAlias: String,
    val keyVersion: Int,
    val ciphertextBase64: String,
    val updatedAt: Instant,
)

interface EncryptedProviderCredentialsStore {
    fun find(tenantId: String, providerId: String): EncryptedProviderCredentials?
    fun save(credentials: EncryptedProviderCredentials)
}

class InMemoryEncryptedProviderCredentialsStore : EncryptedProviderCredentialsStore {
    private val entries = java.util.concurrent.ConcurrentHashMap<String, EncryptedProviderCredentials>()

    override fun find(tenantId: String, providerId: String): EncryptedProviderCredentials? =
        entries["$tenantId:$providerId"]

    override fun save(credentials: EncryptedProviderCredentials) {
        entries["${credentials.tenantId}:${credentials.providerId}"] = credentials
    }
}

class JdbcEncryptedProviderCredentialsStore(private val jdbc: JdbcTemplate) : EncryptedProviderCredentialsStore {
    override fun find(tenantId: String, providerId: String): EncryptedProviderCredentials? = jdbc.query(
        "select tenant_id, provider_id, secret_key_alias, key_version, ciphertext_base64, updated_at from admin_provider_credentials_kms where tenant_id = ? and provider_id = ?",
        { rs, _ ->
            EncryptedProviderCredentials(
                tenantId = rs.getString("tenant_id"),
                providerId = rs.getString("provider_id"),
                secretKeyAlias = rs.getString("secret_key_alias"),
                keyVersion = rs.getInt("key_version"),
                ciphertextBase64 = rs.getString("ciphertext_base64"),
                updatedAt = rs.getTimestamp("updated_at").toInstant(),
            )
        },
        tenantId,
        providerId,
    ).firstOrNull()

    override fun save(credentials: EncryptedProviderCredentials) {
        jdbc.update(
            "insert into admin_provider_credentials_kms(tenant_id, provider_id, secret_key_alias, key_version, ciphertext_base64, updated_at) values (?, ?, ?, ?, ?, ?) on conflict (tenant_id, provider_id) do update set secret_key_alias = excluded.secret_key_alias, key_version = excluded.key_version, ciphertext_base64 = excluded.ciphertext_base64, updated_at = excluded.updated_at",
            credentials.tenantId,
            credentials.providerId,
            credentials.secretKeyAlias,
            credentials.keyVersion,
            credentials.ciphertextBase64,
            credentials.updatedAt,
        )
    }
}

class KmsProviderCredentialsResolver(
    private val kms: KmsBackendSecretsService,
    private val store: EncryptedProviderCredentialsStore,
    private val objectMapper: ObjectMapper = ObjectMapper(),
) : ProviderCredentialsResolver {
    fun storeCredentials(
        tenantId: String,
        providerId: String,
        secretKeyAlias: String,
        credentials: ProviderCredentials,
        principal: AuthenticatedPrincipal,
        now: Instant = Instant.now(),
    ) {
        require(principal.kind == PrincipalKind.ADMIN && principal.tenantId == tenantId)
        require(principal.roles.any { it == AdminRole.SECURITY || it == AdminRole.SUPER_ADMIN })
        require(providerId.isNotBlank() && secretKeyAlias.isNotBlank())
        val encrypted = kms.encryptWithActiveKey(
            tenantId,
            secretKeyAlias,
            objectMapper.writeValueAsBytes(credentials),
            principal,
        )
        store.save(
            EncryptedProviderCredentials(
                tenantId = tenantId,
                providerId = providerId,
                secretKeyAlias = secretKeyAlias,
                keyVersion = encrypted.first,
                ciphertextBase64 = Base64.getEncoder().encodeToString(encrypted.second),
                updatedAt = now,
            )
        )
    }

    override fun resolveCredentials(tenantId: String, providerId: String): ProviderCredentials? {
        val entry = store.find(tenantId, providerId) ?: return null
        return try {
            val plaintext = kms.decryptWithKeyVersion(
                tenantId,
                entry.secretKeyAlias,
                entry.keyVersion,
                Base64.getDecoder().decode(entry.ciphertextBase64),
                AuthenticatedPrincipal(
                    id = "provider-credentials-runtime",
                    tenantId = tenantId,
                    kind = PrincipalKind.ADMIN,
                    roles = setOf(AdminRole.SECURITY),
                ),
            )
            objectMapper.readValue(plaintext, ProviderCredentials::class.java)
        } catch (_: Exception) {
            null
        }
    }
}
