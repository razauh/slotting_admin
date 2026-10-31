package com.slotting.admin.provider

import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.JdbcVersionedProviderCredentialsStore
import com.slotting.admin.provider.port.KmsProviderCredentialsResolver
import com.slotting.admin.secret.BackendKeyAlgorithm
import com.slotting.admin.secret.BackendSecretEntry
import com.slotting.admin.secret.BackendSecretStatus
import com.slotting.admin.secret.BackendSecretType
import com.slotting.admin.secret.FakeKmsBackendProviderAdapter
import com.slotting.admin.secret.InMemoryKmsBackendSecretsStore
import com.slotting.admin.secret.KeyVersionMetadata
import com.slotting.admin.secret.KmsBackendSecretsService
import com.slotting.admin.provider.port.InMemoryEncryptedProviderCredentialsStore
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProviderConfigurationPostgresTest {
    companion object {
        private val schema = PostgresIntegrationSupport.createIsolatedSchema(
            "tc04_${UUID.randomUUID().toString().replace("-", "").take(12)}",
        )

        @JvmStatic
        @AfterAll
        fun close() {
            schema.close()
        }
    }

    private val now = Instant.parse("2026-10-31T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val admin = AuthenticatedPrincipal("admin-1", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))
    private val sessions = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String) =
            AdminSessionStatus(true, false, now.plusSeconds(3600), mfaVerified = true)
    }

    private fun migrate() {
        Flyway.configure()
            .dataSource(schema.dataSource)
            .locations("classpath:db/migration")
            .load()
            .migrate()
    }

    @Test
    fun `TC-013-RED-1 provider metadata persists with PKR capability and no plaintext secret`() {
        migrate()
        val store = JdbcPaymentProviderConfigStore(schema.jdbc)
        val service = PaymentProviderConfigService(AdminRbacPolicy(true), sessions, store, clock, TestProviderCredentialWriter())
        val command = PaymentProviderConfigCommand(
            principal = admin,
            sessionId = "session-1",
            tenantId = "tenant-1",
            providerId = "JAZZCASH",
            action = PaymentProviderConfigAction.REGISTER,
            displayName = "JazzCash",
            endpointUrl = "https://provider.example/v1",
            apiKeySecret = "fake-secret-not-for-storage",
            idempotencyKey = "idem-jdbc-1",
            correlationId = "corr-jdbc",
            causationId = "cause-jdbc",
            expectedVersion = 0L,
            environment = ProviderEnvironment.SANDBOX,
            walletCurrencies = setOf("PKR"),
            settlementCurrencies = setOf("PKR"),
            supportedOperations = setOf("DEPOSIT"),
            credentialVersion = 1L,
        )
        val result = service.operate(command)
        assertEquals(ProviderSetupState.READY, result.provider.setupStatus)
        assertEquals(PaymentProviderStatus.DISABLED, result.provider.status)

        val stored = service.listProviders("tenant-1").single()
        assertEquals("JAZZCASH", stored.providerId)
        assertEquals(setOf("PKR"), stored.walletCurrencies)
        assertEquals(setOf("PKR"), stored.settlementCurrencies)
        assertTrue(service.listProviders("tenant-2").isEmpty())
        val secretHash = schema.jdbc.queryForObject(
            "select secret_hash from admin_payment_provider_config where tenant_id = ? and provider_id = ?",
            String::class.java,
            "tenant-1",
            "JAZZCASH",
        )
        assertFalse(secretHash!!.contains("fake-secret-not-for-storage"))
        assertTrue(secretHash.isBlank())
    }

    @Test
    fun `TC-014-RED-1 versioned credential table is created by migration`() {
        migrate()
        val count = schema.jdbc.queryForObject(
            "select count(*) from information_schema.tables where table_schema = current_schema() and table_name = 'admin_provider_credentials_kms_versions'",
            Int::class.java,
        )
        assertEquals(1, count)
        val columns = schema.jdbc.queryForList(
            "select column_name from information_schema.columns where table_schema = current_schema() and table_name = 'admin_provider_credentials_kms_versions'",
            String::class.java,
        )
        assertTrue(columns.containsAll(listOf("credential_version", "ciphertext_base64", "status", "activated_at", "retired_at")))
    }

    @Test
    fun `TC-014-RED-1 JDBC versioned credentials survive resolver restart`() {
        migrate()
        val kmsProvider = FakeKmsBackendProviderAdapter()
        val key = kmsProvider.createKey("tenant-1", "payment-api", BackendKeyAlgorithm.AES_256_GCM)
        val kmsStore = InMemoryKmsBackendSecretsStore()
        kmsStore.saveSecret(
            BackendSecretEntry(
                secretId = "secret-jdbc",
                tenantId = "tenant-1",
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
        val kms = KmsBackendSecretsService(kmsStore, kmsProvider, clock)
        val store = JdbcVersionedProviderCredentialsStore(schema.jdbc)
        val resolver = KmsProviderCredentialsResolver(kms, InMemoryEncryptedProviderCredentialsStore(), versionedStore = store)
        val credentials = ProviderCredentials(apiKey = "jdbc-fake-key")
        resolver.storeCredentialsVersioned("tenant-1", "JAZZCASH", "payment-api", credentials, admin, 1L, now)
        resolver.activateVersion("tenant-1", "JAZZCASH", 1L, now)

        val restarted = KmsProviderCredentialsResolver(kms, InMemoryEncryptedProviderCredentialsStore(), versionedStore = JdbcVersionedProviderCredentialsStore(schema.jdbc))
        assertEquals(credentials, restarted.resolveCredentials("tenant-1", "JAZZCASH", 1L))
        assertEquals(credentials, restarted.resolveCurrentVersionedCredentials("tenant-1", "JAZZCASH"))
    }
}
