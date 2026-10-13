package com.slotting.admin.deposit

import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.gameprovider.AuthoritativeGameSnapshotAndEventService
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.provider.InMemoryPaymentMethodStore
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.AfterAll
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
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
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class DepositReplayProtectionContractTest {
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
            registry.add("spring.datasource.hikari.maximum-pool-size") { "40" }
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
    private lateinit var transactionManager: PlatformTransactionManager

    @MockBean
    private lateinit var snapshotAndEventService: AuthoritativeGameSnapshotAndEventService

    @Test
    fun sameEventAcrossTwoServiceInstancesSettlesOnceForThirtyTwoConcurrentDeliveries() {
        val tenantId = "tenant-tc12-${UUID.randomUUID()}"
        val intentId = UUID.randomUUID()
        val playerId = UUID.randomUUID()
        val eventId = "event-${UUID.randomUUID()}"
        val providerReference = "track-$intentId"
        val secret = "tc12-signing-secret"
        val now = Instant.parse("2026-10-12T10:00:00Z")
        val clock = Clock.fixed(now, ZoneOffset.UTC)
        val workflowStore = JdbcDepositWorkflowStore(jdbc)
        val ledgerStore = JdbcLedgerJournalStore(jdbc)
        val adapter = SafepayRaastAdapter()
        val credentials = ProviderCredentials(apiKey = "tc12-api-key", signingSecretOrKey = secret)
        val sessionDirectory = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) = null
        }
        val services = (0..1).map {
            DurableDepositWorkflowService(
                workflowStore = workflowStore,
                paymentMethodStore = InMemoryPaymentMethodStore(),
                sessions = sessionDirectory,
                ledgerPostingService = LedgerPostingService(ledgerStore, clock = clock),
                providerPorts = mapOf("SAFEPAY_RAAST" to adapter),
                credentialsResolver = { _, _ -> credentials },
                configResolver = { _, providerId ->
                    ProviderConfiguration(
                        providerId = providerId,
                        environment = ProviderEnvironment.SANDBOX,
                        baseUrl = "https://sandbox.safepay.example",
                    )
                },
                clock = clock,
            )
        }
        workflowStore.saveIntent(
            DepositIntentRecord(
                intentId = intentId,
                tenantId = tenantId,
                playerId = playerId,
                methodId = "SAFEPAY",
                providerId = "SAFEPAY_RAAST",
                amountMinorUnits = 50_000L,
                currencyCode = "PKR",
                status = DepositIntentStatus.PROVIDER_PENDING,
                idempotencyKey = "deposit-$intentId",
                requestFingerprint = "fingerprint-$intentId",
                providerReference = providerReference,
                expiresAt = now.plusSeconds(900),
                createdAt = now,
                updatedAt = now,
            )
        )

        val body = """{"data":{"tracker":"$providerReference","amount":50000,"currency":"PKR","status":"paid"}}"""
        val signature = adapter.calculateHmacSha256(body, secret)
        val command = DepositCallbackCommand(
            tenantId = tenantId,
            providerId = "SAFEPAY_RAAST",
            providerEventId = eventId,
            rawBody = body,
            headers = mapOf("x-sfpy-signature" to signature),
        )
        val workers = 32
        val gate = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(workers)
        val results = try {
            val futures = (0 until workers).map { index ->
                pool.submit<DepositCallbackResult> {
                    gate.await()
                    val service = services[index % services.size]
                    TransactionTemplate(transactionManager).execute {
                        service.processCallback(command)
                    } ?: error("Callback transaction returned no result")
                }
            }
            gate.countDown()
            futures.map { it.get(45, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
            pool.awaitTermination(5, TimeUnit.SECONDS)
        }

        assertEquals(1, results.count { !it.alreadyProcessed })
        assertEquals(31, results.count { it.alreadyProcessed })
        assertEquals(1, results.mapNotNull { it.ledgerTransactionReference }.distinct().size)
        assertEquals(DepositIntentStatus.SETTLED, workflowStore.findIntent(tenantId, intentId)?.status)
        assertEquals(1, jdbc.queryForObject(
            "SELECT count(*) FROM admin_deposit_inbox WHERE tenant_id = ? AND provider_id = ? AND provider_event_id = ? AND status = 'PROCESSED'",
            Int::class.java,
            tenantId,
            "SAFEPAY_RAAST",
            eventId,
        ))
        assertEquals(1, ledgerStore.findAllTransactionsForTenant(tenantId).size)
        val legs = ledgerStore.findAllLegsForTenant(tenantId)
        assertEquals(2, legs.size)
        assertEquals(50_000L, legs.sumOf { if (it.direction.name == "DEBIT") it.amountMinorUnits else 0L })
        assertEquals(50_000L, legs.sumOf { if (it.direction.name == "CREDIT") it.amountMinorUnits else 0L })
        assertTrue(legs.all { it.currencyCode == "PKR" })
    }
}
