package com.slotting.admin.provider.port

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.secret.BackendKeyAlgorithm
import com.slotting.admin.secret.BackendSecretStatus
import com.slotting.admin.secret.BackendSecretType
import com.slotting.admin.secret.BackendSecretEntry
import com.slotting.admin.secret.FakeKmsBackendProviderAdapter
import com.slotting.admin.secret.InMemoryKmsBackendSecretsStore
import com.slotting.admin.secret.KeyVersionMetadata
import com.slotting.admin.secret.KmsBackendSecretsService
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class KmsProviderCredentialsResolverTest {
    @Test
    fun `provider credentials are encrypted at rest and resolved through KMS`() {
        val now = Instant.parse("2026-10-14T00:00:00Z")
        val clock = Clock.fixed(now, ZoneOffset.UTC)
        val kmsProvider = FakeKmsBackendProviderAdapter()
        val key = kmsProvider.createKey("tenant-a", "payment-api", BackendKeyAlgorithm.AES_256_GCM)
        val kmsStore = InMemoryKmsBackendSecretsStore()
        kmsStore.saveSecret(
            BackendSecretEntry(
                secretId = "secret-1",
                tenantId = "tenant-a",
                secretKeyAlias = "payment-api",
                secretType = BackendSecretType.API_INTEGRATION_TOKEN,
                algorithm = BackendKeyAlgorithm.AES_256_GCM,
                activeVersion = 1,
                versions = mapOf(1 to KeyVersionMetadata(1, key.kmsKeyUri, key.digestSha256, BackendSecretStatus.ACTIVE, now)),
                overlapGracePeriodSeconds = 3600,
                createdAt = now,
                updatedAt = now,
            )
        )
        val resolver = KmsProviderCredentialsResolver(
            KmsBackendSecretsService(kmsStore, kmsProvider, clock),
            InMemoryEncryptedProviderCredentialsStore(),
        )
        val principal = AuthenticatedPrincipal(
            id = "security-admin",
            tenantId = "tenant-a",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
        val credentials = ProviderCredentials(apiKey = "secret-api-key", signingSecretOrKey = "signing-key")

        resolver.storeCredentials("tenant-a", "provider-a", "payment-api", credentials, principal, now)

        assertEquals(credentials, resolver.resolveCredentials("tenant-a", "provider-a"))
        assertNull(resolver.resolveCredentials("tenant-b", "provider-a"))
    }
}
