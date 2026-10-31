package com.slotting.admin.provider.port

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
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

open class KmsProviderCredentialsResolver(
    private val kms: KmsBackendSecretsService,
    private val store: EncryptedProviderCredentialsStore,
    private val objectMapper: ObjectMapper = ObjectMapper(),
    private val versionedStore: VersionedProviderCredentialsStore? = null,
) : ProviderCredentialsResolver, ProviderCredentialWriter {
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

    override fun storeCredentialsVersioned(
        tenantId: String,
        providerId: String,
        secretKeyAlias: String,
        credentials: ProviderCredentials,
        principal: AuthenticatedPrincipal,
        credentialVersion: Long,
        now: Instant,
    ): VersionedEncryptedProviderCredentials {
        require(principal.kind == PrincipalKind.ADMIN && principal.tenantId == tenantId)
        require(principal.roles.any { it == AdminRole.SECURITY || it == AdminRole.SUPER_ADMIN })
        require(providerId.isNotBlank() && secretKeyAlias.isNotBlank() && credentialVersion > 0L)
        val versioned = versionedStore
            ?: throw IllegalStateException("Versioned provider credential storage is not configured")
        val encrypted = kms.encryptWithActiveKey(
            tenantId,
            secretKeyAlias,
            objectMapper.writeValueAsBytes(credentials),
            principal,
        )
        val isFirstVersion = versioned.findCurrent(tenantId, providerId) == null
        val record = VersionedEncryptedProviderCredentials(
            tenantId = tenantId,
            providerId = providerId,
            credentialVersion = credentialVersion,
            secretKeyAlias = secretKeyAlias,
            keyVersion = encrypted.first,
            ciphertextBase64 = Base64.getEncoder().encodeToString(encrypted.second),
            status = if (isFirstVersion) ProviderCredentialVersionStatus.ACTIVE else ProviderCredentialVersionStatus.RETIRED,
            createdAt = now,
            activatedAt = if (isFirstVersion) now else null,
            retiredAt = null,
        )
        if (!versioned.saveIfAbsent(record)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
        }
        return record
    }

    fun resolveCredentials(tenantId: String, providerId: String, credentialVersion: Long): ProviderCredentials? {
        val versioned = versionedStore ?: return resolveCredentials(tenantId, providerId)
        val entry = versioned.find(tenantId, providerId, credentialVersion) ?: return null
        if (entry.status == ProviderCredentialVersionStatus.REVOKED) return null
        return decrypt(entry)
    }

    fun resolveCurrentVersionedCredentials(tenantId: String, providerId: String): ProviderCredentials? {
        val versioned = versionedStore ?: return resolveCredentials(tenantId, providerId)
        val entry = versioned.findCurrent(tenantId, providerId) ?: return null
        if (entry.status == ProviderCredentialVersionStatus.REVOKED) return null
        return decrypt(entry)
    }

    override fun activateVersion(tenantId: String, providerId: String, credentialVersion: Long, now: Instant): Boolean {
        val versioned = versionedStore ?: return false
        val current = versioned.findCurrent(tenantId, providerId)
        if (current != null && current.credentialVersion != credentialVersion &&
            current.status == ProviderCredentialVersionStatus.ACTIVE) {
            versioned.compareAndSetStatus(
                tenantId, providerId, current.credentialVersion,
                ProviderCredentialVersionStatus.ACTIVE, ProviderCredentialVersionStatus.RETIRED, now,
            )
        }
        return versioned.compareAndSetStatus(
            tenantId, providerId, credentialVersion,
            ProviderCredentialVersionStatus.RETIRED, ProviderCredentialVersionStatus.ACTIVE, now,
        ) || versioned.find(tenantId, providerId, credentialVersion)?.status == ProviderCredentialVersionStatus.ACTIVE
    }

    override fun revokeVersion(tenantId: String, providerId: String, credentialVersion: Long, now: Instant): Boolean {
        val versioned = versionedStore ?: return false
        return versioned.compareAndSetStatus(
            tenantId, providerId, credentialVersion,
            ProviderCredentialVersionStatus.ACTIVE, ProviderCredentialVersionStatus.REVOKED, now,
        ) || versioned.compareAndSetStatus(
            tenantId, providerId, credentialVersion,
            ProviderCredentialVersionStatus.RETIRED, ProviderCredentialVersionStatus.REVOKED, now,
        )
    }

    fun listVersions(tenantId: String, providerId: String): List<VersionedEncryptedProviderCredentials> =
        versionedStore?.list(tenantId, providerId) ?: emptyList()

    private fun decrypt(entry: VersionedEncryptedProviderCredentials): ProviderCredentials? {
        return try {
            val plaintext = kms.decryptWithKeyVersion(
                entry.tenantId,
                entry.secretKeyAlias,
                entry.keyVersion,
                Base64.getDecoder().decode(entry.ciphertextBase64),
                AuthenticatedPrincipal(
                    id = "provider-credentials-runtime",
                    tenantId = entry.tenantId,
                    kind = PrincipalKind.ADMIN,
                    roles = setOf(AdminRole.SECURITY),
                ),
            )
            objectMapper.readValue(plaintext, ProviderCredentials::class.java)
        } catch (_: Exception) {
            null
        }
    }

    override fun resolveCredentials(tenantId: String, providerId: String): ProviderCredentials? {
        val versioned = versionedStore
        if (versioned != null) {
            val current = versioned.findCurrent(tenantId, providerId)
            if (current != null) return decrypt(current)
        }
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

enum class ProviderCredentialVersionStatus {
    ACTIVE,
    RETIRED,
    REVOKED,
}

data class VersionedEncryptedProviderCredentials(
    val tenantId: String,
    val providerId: String,
    val credentialVersion: Long,
    val secretKeyAlias: String,
    val keyVersion: Int,
    val ciphertextBase64: String,
    val status: ProviderCredentialVersionStatus,
    val createdAt: Instant,
    val activatedAt: Instant?,
    val retiredAt: Instant?,
)

interface ProviderCredentialWriter {
    fun storeCredentialsVersioned(
        tenantId: String,
        providerId: String,
        secretKeyAlias: String,
        credentials: ProviderCredentials,
        principal: AuthenticatedPrincipal,
        credentialVersion: Long,
        now: Instant = Instant.now(),
    ): VersionedEncryptedProviderCredentials
    fun activateVersion(tenantId: String, providerId: String, credentialVersion: Long, now: Instant = Instant.now()): Boolean
    fun revokeVersion(tenantId: String, providerId: String, credentialVersion: Long, now: Instant = Instant.now()): Boolean
}

interface VersionedProviderCredentialsStore {
    fun find(tenantId: String, providerId: String, credentialVersion: Long): VersionedEncryptedProviderCredentials?
    fun findCurrent(tenantId: String, providerId: String): VersionedEncryptedProviderCredentials?
    fun saveIfAbsent(credentials: VersionedEncryptedProviderCredentials): Boolean
    fun compareAndSetStatus(
        tenantId: String,
        providerId: String,
        credentialVersion: Long,
        expected: ProviderCredentialVersionStatus,
        next: ProviderCredentialVersionStatus,
        at: Instant,
    ): Boolean
    fun list(tenantId: String, providerId: String): List<VersionedEncryptedProviderCredentials>
}

class InMemoryVersionedProviderCredentialsStore : VersionedProviderCredentialsStore {
    private val entries = java.util.concurrent.ConcurrentHashMap<String, VersionedEncryptedProviderCredentials>()

    private fun key(tenantId: String, providerId: String, version: Long) = "$tenantId:$providerId:$version"

    @Synchronized
    override fun find(tenantId: String, providerId: String, credentialVersion: Long) =
        entries[key(tenantId, providerId, credentialVersion)]

    @Synchronized
    override fun findCurrent(tenantId: String, providerId: String): VersionedEncryptedProviderCredentials? =
        entries.values
            .filter { it.tenantId == tenantId && it.providerId == providerId && it.status != ProviderCredentialVersionStatus.REVOKED }
            .maxByOrNull { it.credentialVersion }

    @Synchronized
    override fun saveIfAbsent(credentials: VersionedEncryptedProviderCredentials): Boolean {
        val key = key(credentials.tenantId, credentials.providerId, credentials.credentialVersion)
        return entries.putIfAbsent(key, credentials) == null
    }

    @Synchronized
    override fun compareAndSetStatus(
        tenantId: String,
        providerId: String,
        credentialVersion: Long,
        expected: ProviderCredentialVersionStatus,
        next: ProviderCredentialVersionStatus,
        at: Instant,
    ): Boolean {
        val key = key(tenantId, providerId, credentialVersion)
        val existing = entries[key] ?: return false
        if (existing.status != expected) return false
        entries[key] = existing.copy(
            status = next,
            activatedAt = if (next == ProviderCredentialVersionStatus.ACTIVE) at else existing.activatedAt,
            retiredAt = if (next != ProviderCredentialVersionStatus.ACTIVE) at else existing.retiredAt,
        )
        return true
    }

    @Synchronized
    override fun list(tenantId: String, providerId: String) =
        entries.values.filter { it.tenantId == tenantId && it.providerId == providerId }
            .sortedBy { it.credentialVersion }
}

class JdbcVersionedProviderCredentialsStore(private val jdbc: JdbcTemplate) : VersionedProviderCredentialsStore {
    override fun find(tenantId: String, providerId: String, credentialVersion: Long): VersionedEncryptedProviderCredentials? =
        jdbc.query(
            "select * from admin_provider_credentials_kms_versions where tenant_id = ? and provider_id = ? and credential_version = ?",
            { rs, _ -> rs.toVersionedRecord() },
            tenantId,
            providerId,
            credentialVersion,
        ).firstOrNull()

    override fun findCurrent(tenantId: String, providerId: String): VersionedEncryptedProviderCredentials? =
        jdbc.query(
            "select * from admin_provider_credentials_kms_versions where tenant_id = ? and provider_id = ? and status <> 'REVOKED' order by credential_version desc limit 1",
            { rs, _ -> rs.toVersionedRecord() },
            tenantId,
            providerId,
        ).firstOrNull()

    override fun saveIfAbsent(credentials: VersionedEncryptedProviderCredentials): Boolean {
        val inserted = jdbc.update(
            """
            insert into admin_provider_credentials_kms_versions(
                tenant_id, provider_id, credential_version, secret_key_alias, key_version,
                ciphertext_base64, status, created_at, activated_at, retired_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (tenant_id, provider_id, credential_version) do nothing
            """.trimIndent(),
            credentials.tenantId,
            credentials.providerId,
            credentials.credentialVersion,
            credentials.secretKeyAlias,
            credentials.keyVersion,
            credentials.ciphertextBase64,
            credentials.status.name,
            java.sql.Timestamp.from(credentials.createdAt),
            credentials.activatedAt?.let(java.sql.Timestamp::from),
            credentials.retiredAt?.let(java.sql.Timestamp::from),
        )
        return inserted == 1
    }

    override fun compareAndSetStatus(
        tenantId: String,
        providerId: String,
        credentialVersion: Long,
        expected: ProviderCredentialVersionStatus,
        next: ProviderCredentialVersionStatus,
        at: Instant,
    ): Boolean {
        val updated = jdbc.update(
            """
            update admin_provider_credentials_kms_versions
            set status = ?, activated_at = case when ? = 'ACTIVE' then ? else activated_at end,
                retired_at = case when ? <> 'ACTIVE' then ? else retired_at end
            where tenant_id = ? and provider_id = ? and credential_version = ? and status = ?
            """.trimIndent(),
            next.name,
            next.name,
            java.sql.Timestamp.from(at),
            next.name,
            java.sql.Timestamp.from(at),
            tenantId,
            providerId,
            credentialVersion,
            expected.name,
        )
        return updated == 1
    }

    override fun list(tenantId: String, providerId: String) =
        jdbc.query(
            "select * from admin_provider_credentials_kms_versions where tenant_id = ? and provider_id = ? order by credential_version",
            { rs, _ -> rs.toVersionedRecord() },
            tenantId,
            providerId,
        )

    private fun java.sql.ResultSet.toVersionedRecord() = VersionedEncryptedProviderCredentials(
        tenantId = getString("tenant_id"),
        providerId = getString("provider_id"),
        credentialVersion = getLong("credential_version"),
        secretKeyAlias = getString("secret_key_alias"),
        keyVersion = getInt("key_version"),
        ciphertextBase64 = getString("ciphertext_base64"),
        status = ProviderCredentialVersionStatus.valueOf(getString("status")),
        createdAt = getTimestamp("created_at").toInstant(),
        activatedAt = getTimestamp("activated_at")?.toInstant(),
        retiredAt = getTimestamp("retired_at")?.toInstant(),
    )
}
