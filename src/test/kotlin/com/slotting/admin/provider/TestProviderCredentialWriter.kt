package com.slotting.admin.provider

import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.provider.port.ProviderCredentialWriter
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderCredentialVersionStatus
import com.slotting.admin.provider.port.VersionedEncryptedProviderCredentials
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class TestProviderCredentialWriter : ProviderCredentialWriter {
    val stored = ConcurrentHashMap<String, ProviderCredentials>()
    val revoked = ConcurrentHashMap.newKeySet<Long>()

    override fun storeCredentialsVersioned(
        tenantId: String,
        providerId: String,
        secretKeyAlias: String,
        credentials: ProviderCredentials,
        principal: AuthenticatedPrincipal,
        credentialVersion: Long,
        now: Instant,
    ): VersionedEncryptedProviderCredentials {
        stored["$tenantId:$providerId:$credentialVersion"] = credentials
        return VersionedEncryptedProviderCredentials(
            tenantId = tenantId,
            providerId = providerId,
            credentialVersion = credentialVersion,
            secretKeyAlias = secretKeyAlias,
            keyVersion = 1,
            ciphertextBase64 = "test-ciphertext",
            status = ProviderCredentialVersionStatus.ACTIVE,
            createdAt = now,
            activatedAt = now,
            retiredAt = null,
        )
    }

    override fun activateVersion(tenantId: String, providerId: String, credentialVersion: Long, now: Instant): Boolean = true

    override fun revokeVersion(tenantId: String, providerId: String, credentialVersion: Long, now: Instant): Boolean {
        revoked.add(credentialVersion)
        return true
    }
}
