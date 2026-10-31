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
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

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

    private fun versionedResolver(
        store: VersionedProviderCredentialsStore = InMemoryVersionedProviderCredentialsStore(),
    ): Pair<KmsProviderCredentialsResolver, AuthenticatedPrincipal> {
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
            versionedStore = store,
        )
        return resolver to AuthenticatedPrincipal(
            id = "security-admin",
            tenantId = "tenant-a",
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SECURITY),
        )
    }

    @Test
    fun `TC-014-R1 versioned credential survives resolver restart and plaintext is not exposed in metadata`() {
        val store = InMemoryVersionedProviderCredentialsStore()
        val (resolver, principal) = versionedResolver(store)
        val credentials = ProviderCredentials(apiKey = "fake-api-key-only-in-backend", signingSecretOrKey = "fake-signing-key")
        resolver.storeCredentialsVersioned("tenant-a", "provider-a", "payment-api", credentials, principal, 1L)
        resolver.activateVersion("tenant-a", "provider-a", 1L)

        val restarted = versionedResolver(store).first
        assertEquals(credentials, restarted.resolveCredentials("tenant-a", "provider-a", 1L))
        assertEquals(credentials, restarted.resolveCurrentVersionedCredentials("tenant-a", "provider-a"))
        val metadata = restarted.listVersions("tenant-a", "provider-a").toString()
        assertTrue(!metadata.contains("fake-api-key-only-in-backend"))
        assertTrue(!metadata.contains("fake-signing-key"))
    }

    @Test
    fun `TC-016-R1 in-flight version one remains resolvable after version two activation`() {
        val store = InMemoryVersionedProviderCredentialsStore()
        val (resolver, principal) = versionedResolver(store)
        val v1 = ProviderCredentials(apiKey = "v1-key")
        val v2 = ProviderCredentials(apiKey = "v2-key")
        resolver.storeCredentialsVersioned("tenant-a", "provider-a", "payment-api", v1, principal, 1L)
        resolver.storeCredentialsVersioned("tenant-a", "provider-a", "payment-api", v2, principal, 2L)
        resolver.activateVersion("tenant-a", "provider-a", 2L)

        assertEquals(v1, resolver.resolveCredentials("tenant-a", "provider-a", 1L))
        assertEquals(v2, resolver.resolveCredentials("tenant-a", "provider-a", 2L))
        assertEquals(v2, resolver.resolveCurrentVersionedCredentials("tenant-a", "provider-a"))
        assertEquals(v2, versionedResolver(store).first.resolveCurrentVersionedCredentials("tenant-a", "provider-a"))
    }

    @Test
    fun `TC-016-R2 duplicate credential version is rejected without replacing the winner`() {
        val store = InMemoryVersionedProviderCredentialsStore()
        val (resolver, principal) = versionedResolver(store)
        resolver.storeCredentialsVersioned("tenant-a", "provider-a", "payment-api", ProviderCredentials(apiKey = "winner"), principal, 1L)
        assertFailsWith<com.slotting.admin.auth.AuthenticationFailure.Rejected> {
            resolver.storeCredentialsVersioned("tenant-a", "provider-a", "payment-api", ProviderCredentials(apiKey = "loser"), principal, 1L)
        }
        assertEquals("winner", resolver.resolveCredentials("tenant-a", "provider-a", 1L)?.apiKey)
    }

    @Test
    fun `TC-016-R3 revoked version fails closed and tenant isolation is preserved`() {
        val store = InMemoryVersionedProviderCredentialsStore()
        val (resolver, principal) = versionedResolver(store)
        resolver.storeCredentialsVersioned("tenant-a", "provider-a", "payment-api", ProviderCredentials(apiKey = "v1"), principal, 1L)
        resolver.storeCredentialsVersioned("tenant-a", "provider-a", "payment-api", ProviderCredentials(apiKey = "v2"), principal, 2L)
        resolver.activateVersion("tenant-a", "provider-a", 2L)
        resolver.revokeVersion("tenant-a", "provider-a", 1L)

        assertNull(resolver.resolveCredentials("tenant-a", "provider-a", 1L))
        assertNull(resolver.resolveCredentials("tenant-b", "provider-a", 2L))
        assertEquals("v2", resolver.resolveCurrentVersionedCredentials("tenant-a", "provider-a")?.apiKey)
        assertEquals("v2", versionedResolver(store).first.resolveCurrentVersionedCredentials("tenant-a", "provider-a")?.apiKey)
    }

    @Test
    fun `TC-014-R3 credential store failure leaves no plaintext record`() {
        val failingStore = object : VersionedProviderCredentialsStore by InMemoryVersionedProviderCredentialsStore() {
            override fun saveIfAbsent(credentials: VersionedEncryptedProviderCredentials): Boolean {
                throw IllegalStateException("simulated durable store failure")
            }
        }
        val (resolver, principal) = versionedResolver(failingStore)
        assertFailsWith<IllegalStateException> {
            resolver.storeCredentialsVersioned(
                "tenant-a", "provider-a", "payment-api",
                ProviderCredentials(apiKey = "must-not-persist"), principal, 1L,
            )
        }
        assertTrue(resolver.listVersions("tenant-a", "provider-a").isEmpty())
    }
}
