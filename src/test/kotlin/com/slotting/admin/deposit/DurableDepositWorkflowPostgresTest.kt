package com.slotting.admin.deposit

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostTransactionCommand
import com.slotting.admin.provider.InMemoryPaymentMethodStore
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import com.slotting.admin.provider.port.JdbcVersionedProviderCredentialsStore
import com.slotting.admin.provider.port.KmsProviderCredentialsResolver
import com.slotting.admin.provider.port.InMemoryEncryptedProviderCredentialsStore
import com.slotting.admin.secret.BackendKeyAlgorithm
import com.slotting.admin.secret.BackendSecretEntry
import com.slotting.admin.secret.BackendSecretStatus
import com.slotting.admin.secret.BackendSecretType
import com.slotting.admin.secret.FakeKmsBackendProviderAdapter
import com.slotting.admin.secret.InMemoryKmsBackendSecretsStore
import com.slotting.admin.secret.KeyVersionMetadata
import com.slotting.admin.secret.KmsBackendSecretsService
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class DurableDepositWorkflowPostgresTest {

    companion object {
        private val databaseUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
            ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        private val isolatedSchema = PostgresIntegrationSupport.createIsolatedSchema(
            "tc04_${UUID.randomUUID().toString().replace("-", "").take(12)}",
        )

        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            val separator = if (databaseUrl.contains('?')) '&' else '?'
            registry.add("spring.datasource.url") { "$databaseUrl${separator}currentSchema=${isolatedSchema.schemaName}" }
            registry.add("spring.datasource.username") { System.getenv("SLOTTING_ADMIN_DATABASE_USERNAME") ?: "ci_runner" }
            registry.add("spring.datasource.password") { System.getenv("SLOTTING_ADMIN_DATABASE_PASSWORD") ?: "ci_test_password_ephemeral" }
            registry.add("spring.flyway.enabled") { "true" }
            registry.add("spring.datasource.hikari.maximum-pool-size") { "12" }
        }

        @JvmStatic
        @AfterAll
        fun dropIsolatedSchema() {
            isolatedSchema.close()
        }
    }

    @Autowired
    private lateinit var jdbc: JdbcTemplate

    @Autowired
    private lateinit var txManager: PlatformTransactionManager

    private val now = Instant.parse("2026-10-30T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val credentials = ProviderCredentials(
        merchantId = "MERCHANT-01",
        apiKey = "api-key-test",
        signingSecretOrKey = "signing-secret-123",
    )
    private val config = ProviderConfiguration(
        providerId = "SAFEPAY_RAAST",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.api.test/v1",
    )
    private val adapter = SafepayRaastAdapter()

    private fun newStore() = JdbcDepositWorkflowStore(jdbc)

    private fun newLedger(): LedgerPostingService = LedgerPostingService(JdbcLedgerJournalStore(jdbc), clock = clock)

    private fun newService(
        store: DepositWorkflowStore = newStore(),
        ledger: LedgerPostingService = newLedger(),
    ) = DurableDepositWorkflowService(
        workflowStore = store,
        paymentMethodStore = InMemoryPaymentMethodStore(),
        sessions = object : com.slotting.admin.auth.AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) =
                com.slotting.admin.auth.AdminSessionStatus(
                    active = true,
                    breakGlass = false,
                    expiresAt = now.plusSeconds(3600),
                    mfaVerified = true,
                )
        },
        ledgerPostingService = ledger,
        providerPorts = mapOf("SAFEPAY_RAAST" to adapter),
        credentialsResolver = { _, _ -> credentials },
        configResolver = { _, _ -> config },
        clock = clock,
    )

    private fun seedIntent(
        tenantId: String,
        tracker: String,
        amount: Long = 50_000L,
        currency: String = "PKR",
        playerId: UUID = UUID.randomUUID(),
        credentialVersion: Long? = null,
    ): DepositIntentRecord {
        val intent = DepositIntentRecord(
            intentId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = playerId,
            methodId = "SAFEPAY",
            providerId = "SAFEPAY_RAAST",
            amountMinorUnits = amount,
            currencyCode = currency,
            status = DepositIntentStatus.PROVIDER_PENDING,
            idempotencyKey = "idem-${UUID.randomUUID()}",
            requestFingerprint = "fp-${UUID.randomUUID()}",
            providerReference = tracker,
            providerCredentialVersion = credentialVersion,
            expiresAt = now.plusSeconds(900),
            createdAt = now,
            updatedAt = now,
        )
        return newStore().saveIntent(intent)
    }

    private fun callback(
        tenantId: String,
        tracker: String,
        eventId: String,
        amount: Long = 50_000L,
        currency: String = "PKR",
        status: String = "paid",
        signature: String? = null,
        signingSecret: String = credentials.signingSecretOrKey!!,
    ): DepositCallbackCommand {
        val body = """{"data":{"token":"token_123","amount":$amount,"currency":"$currency","status":"$status","tracker":"$tracker"}}"""
        return DepositCallbackCommand(
            tenantId = tenantId,
            providerId = "SAFEPAY_RAAST",
            providerEventId = eventId,
            rawBody = body,
            headers = mapOf("x-sfpy-signature" to (signature ?: adapter.calculateHmacSha256(body, signingSecret))),
        )
    }

    private fun process(service: DurableDepositWorkflowService, command: DepositCallbackCommand): DepositCallbackResult {
        val tx = TransactionTemplate(txManager)
        return tx.execute { service.processCallback(command) }!!
    }

    private fun ledgerCount(intentId: UUID): Int = jdbc.queryForObject(
        "select count(*) from ledger_transaction where idempotency_key = ?",
        Int::class.java,
        "LEDGER-DEP-$intentId",
    ) ?: 0

    @Test
    fun `TC-011-R1 two service instances replay the same callback with one balanced credit`() {
        val tenantId = "tenant-tc011-${UUID.randomUUID()}"
        val tracker = "tracker-${UUID.randomUUID()}"
        val intent = seedIntent(tenantId, tracker)
        val command = callback(tenantId, tracker, "evt-${UUID.randomUUID()}")

        val first = newService()
        val second = newService()
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val results = java.util.Collections.synchronizedList(mutableListOf<Any>())
        try {
            val futures = listOf(first, second).map { service ->
                pool.submit {
                    start.await(5, TimeUnit.SECONDS)
                    try {
                        results.add(process(service, command))
                    } catch (e: Exception) {
                        results.add(e)
                    }
                }
            }
            start.countDown()
            futures.forEach { it.get(30, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }

        assertEquals(1, ledgerCount(intent.intentId))
        val stored = newStore().findIntent(tenantId, intent.intentId)
        assertEquals(DepositIntentStatus.SETTLED, stored?.status)
        assertNotNull(stored?.ledgerTransactionReference)
        val inboxStatus = jdbc.queryForObject(
            "select status from admin_deposit_inbox where tenant_id = ? and provider_event_id = ?",
            String::class.java,
            tenantId,
            command.providerEventId,
        )
        assertEquals("PROCESSED", inboxStatus)
        val balanced = jdbc.queryForObject(
            "select count(*) from ledger_transaction where idempotency_key = ? and total_debits_minor_units = total_credits_minor_units",
            Int::class.java,
            "LEDGER-DEP-${intent.intentId}",
        )
        assertEquals(1, balanced)
    }

    @Test
    fun `TC-011-R2 forged signature or changed amount and currency never mutates the ledger`() {
        val tenantId = "tenant-tc011-forged-${UUID.randomUUID()}"
        val tracker = "tracker-${UUID.randomUUID()}"
        val intent = seedIntent(tenantId, tracker)

        assertFailsWith<AuthenticationFailure.Rejected> {
            process(newService(), callback(tenantId, tracker, "evt-bad-sig-${UUID.randomUUID()}", signature = "invalid"))
        }
        assertEquals(0, ledgerCount(intent.intentId))

        val changedAmount = process(
            newService(),
            callback(tenantId, tracker, "evt-amount-${UUID.randomUUID()}", amount = 25_000L),
        )
        assertEquals(DepositIntentStatus.QUARANTINED, changedAmount.status)
        assertEquals(0, ledgerCount(intent.intentId))

        val changedCurrency = process(
            newService(),
            callback(tenantId, tracker, "evt-currency-${UUID.randomUUID()}", currency = "USD"),
        )
        assertEquals(DepositIntentStatus.QUARANTINED, changedCurrency.status)
        assertEquals(0, ledgerCount(intent.intentId))
    }

    @Test
    fun `TC-011-R3 failure before posting commit is recoverable and restart credits at most once`() {
        val tenantId = "tenant-tc011-recovery-${UUID.randomUUID()}"
        val tracker = "tracker-${UUID.randomUUID()}"
        val intent = seedIntent(tenantId, tracker)
        val command = callback(tenantId, tracker, "evt-recovery-${UUID.randomUUID()}")

        val failingLedger = object : LedgerPostingService(JdbcLedgerJournalStore(jdbc), clock = clock) {
            override fun postTransaction(command: PostTransactionCommand) =
                throw IllegalStateException("injected failure after inbox claim")
        }
        assertFailsWith<IllegalStateException> {
            process(newService(ledger = failingLedger), command)
        }
        assertEquals(0, ledgerCount(intent.intentId))
        assertEquals(DepositIntentStatus.PROVIDER_PENDING, newStore().findIntent(tenantId, intent.intentId)?.status)

        val recovered = process(newService(), command)
        assertEquals(DepositIntentStatus.SETTLED, recovered.status)
        assertEquals(1, ledgerCount(intent.intentId))

        val replay = process(newService(), command)
        assertEquals(DepositIntentStatus.SETTLED, replay.status)
        assertEquals(1, ledgerCount(intent.intentId))
    }

    @Test
    fun `TC-011-R4 late pending or failure callback cannot undo confirmed money`() {
        val tenantId = "tenant-tc011-reorder-${UUID.randomUUID()}"
        val tracker = "tracker-${UUID.randomUUID()}"
        val intent = seedIntent(tenantId, tracker)

        val success = process(newService(), callback(tenantId, tracker, "evt-success-${UUID.randomUUID()}"))
        assertEquals(DepositIntentStatus.SETTLED, success.status)
        assertEquals(1, ledgerCount(intent.intentId))

        val delayedFailure = process(
            newService(),
            callback(tenantId, tracker, "evt-late-failure-${UUID.randomUUID()}", status = "failed"),
        )
        assertEquals(DepositIntentStatus.SETTLED, delayedFailure.status)
        assertTrue(delayedFailure.alreadyProcessed)
        assertEquals(1, ledgerCount(intent.intentId))
        assertEquals(
            50_000L,
            JdbcLedgerJournalStore(jdbc).findBalance(tenantId, "PLAYER:${intent.playerId}", "PKR"),
        )
    }

    @Test
    fun `TC-016-RED-1 callback verifies only the credential version bound to the intent`() {
        val tenantId = "tenant-tc016-${UUID.randomUUID()}"
        val trackerV1 = "tracker-v1-${UUID.randomUUID()}"
        val trackerMismatch = "tracker-mismatch-${UUID.randomUUID()}"
        val kmsProvider = FakeKmsBackendProviderAdapter()
        val key = kmsProvider.createKey(tenantId, "payment-api", BackendKeyAlgorithm.AES_256_GCM)
        val kmsStore = InMemoryKmsBackendSecretsStore()
        kmsStore.saveSecret(
            BackendSecretEntry(
                secretId = "secret-${UUID.randomUUID()}",
                tenantId = tenantId,
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
        val versionedStore = JdbcVersionedProviderCredentialsStore(jdbc)
        val resolver = KmsProviderCredentialsResolver(kms, InMemoryEncryptedProviderCredentialsStore(), versionedStore = versionedStore)
        val admin = AuthenticatedPrincipal("security-admin", tenantId, PrincipalKind.ADMIN, setOf(AdminRole.SECURITY))
        resolver.storeCredentialsVersioned(tenantId, "SAFEPAY_RAAST", "payment-api", ProviderCredentials(signingSecretOrKey = "v1-signing-secret"), admin, 1L, now)
        resolver.activateVersion(tenantId, "SAFEPAY_RAAST", 1L, now)

        val intent = seedIntent(tenantId, trackerV1, credentialVersion = 1L)
        val serviceV1 = DurableDepositWorkflowService(
            workflowStore = newStore(),
            paymentMethodStore = InMemoryPaymentMethodStore(),
            sessions = object : com.slotting.admin.auth.AdminSessionDirectory {
                override fun find(tenantId: String, principalId: String, sessionId: String) =
                    com.slotting.admin.auth.AdminSessionStatus(true, false, now.plusSeconds(3600), mfaVerified = true)
            },
            ledgerPostingService = newLedger(),
            providerPorts = mapOf("SAFEPAY_RAAST" to adapter),
            credentialsResolver = resolver,
            configResolver = { _, _ -> config },
            clock = clock,
        )
        val settled = process(serviceV1, callback(tenantId, trackerV1, "evt-v1-${UUID.randomUUID()}", signingSecret = "v1-signing-secret"))
        assertEquals(DepositIntentStatus.SETTLED, settled.status)

        resolver.storeCredentialsVersioned(tenantId, "SAFEPAY_RAAST", "payment-api", ProviderCredentials(signingSecretOrKey = "v2-signing-secret"), admin, 2L, now)
        resolver.activateVersion(tenantId, "SAFEPAY_RAAST", 2L, now)
        val mismatchIntent = seedIntent(tenantId, trackerMismatch, credentialVersion = 1L)
        assertFailsWith<AuthenticationFailure.Rejected> {
            process(serviceV1, callback(tenantId, trackerMismatch, "evt-v2-${UUID.randomUUID()}", signingSecret = "v2-signing-secret"))
        }
        assertEquals(0, ledgerCount(mismatchIntent.intentId))
    }
}
