package com.slotting.admin.withdrawal

import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.provider.port.PaymentProviderPort
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.ProviderOutcome
import com.slotting.admin.provider.port.ProviderPayoutCommand
import com.slotting.admin.provider.port.ProviderStatusQuery
import com.slotting.admin.provider.port.adapters.AdversarialTestPaymentAdapter
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class DurablePayoutDispatchPostgresTest {

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
    private lateinit var dispatchStore: JdbcPayoutDispatchStore

    @Autowired
    private lateinit var withdrawalStore: JdbcAuthoritativeWithdrawalStore

    private val now = Instant.parse("2026-10-30T14:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val config = ProviderConfiguration(
        providerId = "ADVERSARIAL_TEST",
        environment = ProviderEnvironment.SANDBOX,
        baseUrl = "https://sandbox.api.test/v1",
    )
    private val credentials = ProviderCredentials(merchantId = "MERCHANT-01", apiKey = "api-key-test")

    private fun ledger() = LedgerPostingService(JdbcLedgerJournalStore(jdbc), clock = clock)

    private fun service(port: PaymentProviderPort) = DurablePayoutDispatchService(
        dispatchStore = dispatchStore,
        withdrawalStore = withdrawalStore,
        ledgerPostingService = ledger(),
        providerPorts = mapOf("ADVERSARIAL_TEST" to port),
        credentialsResolver = { _, _ -> credentials },
        configResolver = { _, _ -> config },
        providerEnabled = { _, _ -> true },
        clock = clock,
    )

    private fun seedWallet(tenantId: String, ownerId: UUID, currency: String, balance: Long) {
        jdbc.update(
            "insert into wallet_projection(projection_id, tenant_id, owner_reference, currency_code, balance_minor_units) values (?, ?, ?, ?, ?)",
            UUID.randomUUID(),
            tenantId,
            ownerId.toString(),
            currency,
            balance,
        )
    }

    private fun request(
        tenantId: String,
        ownerId: UUID,
        gross: Long = 50_000L,
        net: Long = 47_500L,
        fee: Long = 2_500L,
        currency: String = "PKR",
    ): AuthoritativeWithdrawalRequest {
        val requestId = UUID.randomUUID()
        return AuthoritativeWithdrawalRequest(
            requestId = requestId,
            tenantId = tenantId,
            ownerId = ownerId,
            quoteId = UUID.randomUUID(),
            reservationId = UUID.randomUUID(),
            methodId = "BANK_PK",
            destinationId = UUID.randomUUID(),
            destinationReference = "PK36SCBL0000001123456701",
            grossAmountMinorUnits = gross,
            feeMinorUnits = fee,
            netPayoutAmountMinorUnits = net,
            currencyCode = currency,
            stepUpAssertionId = UUID.randomUUID(),
            immutableDigest = "digest-$requestId",
            status = WithdrawalRequestStatus.REQUESTED,
            reviewState = WithdrawalReviewState.APPROVED,
            dualControlReceiptId = UUID.randomUUID(),
            idempotencyKey = "req-idemp-$requestId",
            requestVersion = 2L,
            createdAt = now.minusSeconds(600),
            updatedAt = now.minusSeconds(300),
        )
    }

    private fun stage(service: DurablePayoutDispatchService, req: AuthoritativeWithdrawalRequest, key: String): PayoutDispatchIntentRecord {
        withdrawalStore.saveRequest(req)
        return service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = req.tenantId,
                requestId = req.requestId,
                providerId = "ADVERSARIAL_TEST",
                idempotencyKey = key,
            )
        )
    }

    private fun ledgerCount(intentId: UUID): Int = jdbc.queryForObject(
        "select count(*) from ledger_transaction where idempotency_key in (?, ?)",
        Int::class.java,
        "LEDGER-PAYOUT-SETTLE-$intentId",
        "LEDGER-PAYOUT-COMP-$intentId",
    ) ?: 0

    @Test
    fun `TC-012-R1 two workers cannot create a duplicate dispatch`() {
        val tenantId = "tenant-tc012-race-${UUID.randomUUID()}"
        val ownerId = UUID.randomUUID()
        seedWallet(tenantId, ownerId, "PKR", 100_000L)
        val req = request(tenantId, ownerId)
        val adapter = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        val service = service(adapter)
        val staged = stage(service, req, "stage-race-${UUID.randomUUID()}")

        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        val results = java.util.Collections.synchronizedList(mutableListOf<PayoutDispatchResult?>())
        try {
            val futures = listOf("worker-a", "worker-b").map { worker ->
                pool.submit {
                    start.await(5, TimeUnit.SECONDS)
                    results.add(service.dispatchNext(worker, Duration.ofMinutes(5)))
                }
            }
            start.countDown()
            futures.forEach { it.get(30, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }

        assertEquals(1, results.count { it != null })
        val stored = dispatchStore.findIntent(tenantId, staged.intentId)
        assertEquals(PayoutDispatchStatus.SUCCEEDED, stored?.status)
        assertEquals(1, ledgerCount(staged.intentId))
        assertEquals(1, jdbc.queryForObject(
            "select count(*) from admin_payout_dispatch_intent where tenant_id = ? and request_id = ?",
            Int::class.java,
            tenantId,
            req.requestId,
        ))
    }

    @Test
    fun `TC-012-R2 accepted timeout stays ambiguous and reconciliation uses the original provider key`() {
        val tenantId = "tenant-tc012-timeout-${UUID.randomUUID()}"
        val ownerId = UUID.randomUUID()
        seedWallet(tenantId, ownerId, "PKR", 100_000L)
        val req = request(tenantId, ownerId)
        val base = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        val payoutCalls = AtomicInteger(0)
        val queryCalls = AtomicInteger(0)
        val adapter = object : PaymentProviderPort by base {
            override fun payout(
                command: ProviderPayoutCommand,
                config: ProviderConfiguration,
                credentials: ProviderCredentials?,
            ): ProviderOutcome {
                payoutCalls.incrementAndGet()
                return ProviderOutcome.ambiguous(
                    operationId = command.operationId,
                    code = "TIMEOUT_AFTER_ACCEPTANCE",
                    reason = "Provider accepted but acknowledgement was lost",
                )
            }

            override fun queryStatus(
                query: ProviderStatusQuery,
                config: ProviderConfiguration,
                credentials: ProviderCredentials?,
            ): ProviderOutcome {
                queryCalls.incrementAndGet()
                return ProviderOutcome.verifiedSettlement(
                    operationId = query.operationId,
                    providerReference = "prov-payout-${query.operationId}",
                    amountMinorUnits = query.expectedAmountMinorUnits ?: 0L,
                    currency = query.expectedCurrency ?: "PKR",
                    evidence = mapOf("key" to query.idempotencyKey),
                )
            }
        }
        val service = service(adapter)
        val staged = stage(service, req, "stage-timeout-${UUID.randomUUID()}")

        val dispatch = service.dispatchNext("worker-timeout", Duration.ofMinutes(5))
        assertEquals(PayoutDispatchStatus.AMBIGUOUS_RECONCILING, dispatch?.status)
        assertEquals(1, payoutCalls.get())

        val reconciled = service.reconcilePayout(tenantId, staged.intentId, "operator-1")
        assertEquals(PayoutDispatchStatus.SUCCEEDED, reconciled.newStatus)
        assertEquals(1, queryCalls.get())
        assertEquals(1, payoutCalls.get())
        assertEquals(1, ledgerCount(staged.intentId))

        val replay = service.reconcilePayout(tenantId, staged.intentId, "operator-1")
        assertEquals("ALREADY_FINALIZED_SUCCESS", replay.actionTaken)
        assertEquals(1, ledgerCount(staged.intentId))
    }

    @Test
    fun `TC-012-R3 replaying the same final failure releases the reservation exactly once`() {
        val tenantId = "tenant-tc012-failure-${UUID.randomUUID()}"
        val ownerId = UUID.randomUUID()
        seedWallet(tenantId, ownerId, "PKR", 50_000L)
        val req = request(tenantId, ownerId)
        val base = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        val adapter = object : PaymentProviderPort by base {
            override fun payout(
                command: ProviderPayoutCommand,
                config: ProviderConfiguration,
                credentials: ProviderCredentials?,
            ): ProviderOutcome = ProviderOutcome.failed(
                operationId = command.operationId,
                code = "PROVIDER_DECLINED",
                reason = "Provider definitively declined the payout",
            )
        }
        val service = service(adapter)
        val staged = stage(service, req, "stage-failure-${UUID.randomUUID()}")

        val dispatch = service.dispatchNext("worker-failure", Duration.ofMinutes(5))
        assertEquals(PayoutDispatchStatus.FAILED_FINAL, dispatch?.status)
        assertEquals(100_000L, withdrawalStore.getAuthoritativeBalance(tenantId, ownerId, "PKR"))
        assertEquals(1, ledgerCount(staged.intentId))

        val replay = service.reconcilePayout(tenantId, staged.intentId, "operator-1")
        assertEquals("ALREADY_FINALIZED_FAILURE", replay.actionTaken)
        assertEquals(100_000L, withdrawalStore.getAuthoritativeBalance(tenantId, ownerId, "PKR"))
        assertEquals(1, ledgerCount(staged.intentId))
    }

    @Test
    fun `TC-012-R4 another tenant cannot reuse a known idempotency key or trigger a payout`() {
        val tenantId = "tenant-tc012-owner-${UUID.randomUUID()}"
        val otherTenant = "tenant-tc012-other-${UUID.randomUUID()}"
        val ownerId = UUID.randomUUID()
        seedWallet(tenantId, ownerId, "PKR", 100_000L)
        val req = request(tenantId, ownerId)
        val adapter = AdversarialTestPaymentAdapter("ADVERSARIAL_TEST")
        val service = service(adapter)
        val key = "stage-shared-${UUID.randomUUID()}"
        stage(service, req, key)

        val error = assertFailsWith<IllegalArgumentException> {
            service.stageDispatchIntent(
                StagePayoutDispatchCommand(
                    tenantId = otherTenant,
                    requestId = req.requestId,
                    providerId = "ADVERSARIAL_TEST",
                    idempotencyKey = key,
                )
            )
        }
        assertFalse(error.message!!.contains(req.requestId.toString()))
        assertFalse(error.message!!.contains(tenantId))
        assertEquals(0, jdbc.queryForObject(
            "select count(*) from admin_payout_dispatch_intent where tenant_id = ?",
            Int::class.java,
            otherTenant,
        ))
        assertEquals(0, ledgerCount(UUID.randomUUID()))
    }
}
