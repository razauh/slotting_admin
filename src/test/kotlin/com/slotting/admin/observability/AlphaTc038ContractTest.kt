package com.slotting.admin.observability

import com.slotting.admin.deposit.DepositCallbackCommand
import com.slotting.admin.deposit.DepositCallbackResult
import com.slotting.admin.deposit.DepositIntentStatus
import com.slotting.admin.deposit.DepositWorkflowStore
import com.slotting.admin.deposit.DurableDepositWorkflowService
import com.slotting.admin.deposit.JdbcDepositWorkflowStore
import com.slotting.admin.infra.PostgresIntegrationSupport
import com.slotting.admin.ledger.JdbcLedgerJournalStore
import com.slotting.admin.ledger.LedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import com.slotting.admin.ledger.PostingResult
import com.slotting.admin.provider.InMemoryPaymentMethodStore
import com.slotting.admin.provider.port.JdbcVersionedProviderCredentialsStore
import com.slotting.admin.provider.port.KmsProviderCredentialsResolver
import com.slotting.admin.provider.port.InMemoryEncryptedProviderCredentialsStore
import com.slotting.admin.provider.port.PaymentProviderPort
import com.slotting.admin.provider.port.ProviderCallbackPayload
import com.slotting.admin.provider.port.ProviderConfiguration
import com.slotting.admin.provider.port.ProviderCredentials
import com.slotting.admin.provider.port.ProviderEnvironment
import com.slotting.admin.provider.port.ProviderOutcome
import com.slotting.admin.provider.port.ProviderOutcomeStatus
import com.slotting.admin.provider.port.ProviderStatusQuery
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import com.slotting.admin.withdrawal.AuthoritativeWithdrawalRequest
import com.slotting.admin.withdrawal.JdbcAuthoritativeWithdrawalStore
import com.slotting.admin.withdrawal.JdbcPayoutDispatchStore
import com.slotting.admin.withdrawal.PayoutDispatchStatus
import com.slotting.admin.withdrawal.StagePayoutDispatchCommand
import com.slotting.admin.withdrawal.WithdrawalRequestStatus
import com.slotting.admin.withdrawal.WithdrawalReviewState
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.support.TransactionTemplate

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AlphaTc038ContractTest {
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

    private val now = Instant.parse("2026-10-31T14:00:00Z")
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

    private class FailingLedgerStore(
        private val delegate: LedgerJournalStore,
    ) : LedgerJournalStore by delegate {
        var failSaves: Int = 0
        override fun save(
            result: PostingResult,
            legs: List<com.slotting.admin.ledger.JournalEntryRecord>,
            payloadDigest: String,
            audit: com.slotting.admin.auth.AuditEvent,
            outbox: com.slotting.admin.auth.OutboxEvent,
        ) {
            if (failSaves > 0) {
                failSaves -= 1
                throw IllegalStateException("planned ledger failpoint")
            }
            delegate.save(result, legs, payloadDigest, audit, outbox)
        }
    }

    private class InquiryFakePort : PaymentProviderPort {
        var inquiryOutcome: ProviderOutcome? = null
        var payoutAccepted = false
        override val providerId = "SAFEPAY_RAAST"
        override val capabilities = com.slotting.admin.provider.port.ProviderAdapterCapabilities(
            supportsDeposit = true,
            supportsPayout = true,
            supportsStatusLookup = true,
            supportedCurrencies = setOf("PKR"),
        )
        override fun deposit(command: com.slotting.admin.provider.port.ProviderDepositCommand, config: ProviderConfiguration, credentials: ProviderCredentials?) =
            ProviderOutcome.pending(command.operationId, "tracker", "PENDING", null, emptyMap())

        override fun payout(command: com.slotting.admin.provider.port.ProviderPayoutCommand, config: ProviderConfiguration, credentials: ProviderCredentials?): ProviderOutcome {
            payoutAccepted = true
            return ProviderOutcome.accepted(command.operationId, "IB-${command.operationId}", "TRANSFER_PENDING", emptyMap())
        }

        override fun queryStatus(query: ProviderStatusQuery, config: ProviderConfiguration, credentials: ProviderCredentials?): ProviderOutcome =
            inquiryOutcome ?: ProviderOutcome.pending(query.operationId, query.providerReference, "PENDING", null, emptyMap())

        override fun cancel(command: com.slotting.admin.provider.port.ProviderCancelCommand, config: ProviderConfiguration, credentials: ProviderCredentials?) =
            ProviderOutcome.declined(command.operationId, "UNSUPPORTED_OPERATION", "not supported")

        override fun refund(command: com.slotting.admin.provider.port.ProviderRefundCommand, config: ProviderConfiguration, credentials: ProviderCredentials?) =
            ProviderOutcome.declined(command.operationId, "UNSUPPORTED_OPERATION", "not supported")

        override fun verifyCallback(callback: ProviderCallbackPayload, config: ProviderConfiguration, credentials: ProviderCredentials?) =
            com.slotting.admin.provider.port.CallbackVerificationResult(false, "UNSUPPORTED")
    }

    @Test
    fun `TC-038-R1 credited deposit and replayed callback produce one credit with distinguishable diagnostics that survive restart`() {
        val tenantId = "tenant-tc038-r1-${UUID.randomUUID()}"
        val intent = seedIntent(tenantId)
        val service = depositService(tenantId, JdbcDepositWorkflowStore(jdbc))
        val command = callback(tenantId, intent.providerReference!!, "evt-r1")

        val first = TransactionTemplate(txManager).execute { service.processCallback(command) }!!
        assertEquals(DepositIntentStatus.SETTLED, first.status)
        assertEquals(1, ledgerTransactionCount("LEDGER-DEP-${intent.intentId}"))

        val replay = TransactionTemplate(txManager).execute { service.processCallback(command) }!!
        assertTrue(replay.alreadyProcessed)
        assertEquals(1, ledgerTransactionCount("LEDGER-DEP-${intent.intentId}"))

        val diagnosticStore = JdbcDiagnosticEventStore(jdbc, clock)
        val events = financialEvents(tenantId, "corr-${intent.intentId}")
        assertEquals(1, events.count { it.second == "DEPOSIT_CREDITED" })
        assertEquals(1, events.count { it.second == "DEPOSIT_CALLBACK_REPLAYED" })

        val restartedStore = JdbcDepositWorkflowStore(jdbc)
        val persistedIntent = restartedStore.findIntent(tenantId, intent.intentId)
        assertNotNull(persistedIntent)
        assertEquals(DepositIntentStatus.SETTLED, persistedIntent.status)
        assertEquals(first.ledgerTransactionReference, persistedIntent.ledgerTransactionReference)
        val credited = events.single { it.second == "DEPOSIT_CREDITED" }
        assertEquals(persistedIntent.ledgerTransactionReference, credited.third)
        assertEquals(intent.intentId.toString(), credited.fourth)
        assertEquals(50_000L, credited.fifth)
        assertEquals("PKR", credited.sixth)
    }

    @Test
    fun `TC-038-R2 rolled back credit leaves no committed success audit and recovery projects without repeating the provider action`() {
        val tenantId = "tenant-tc038-r2-${UUID.randomUUID()}"
        val intent = seedIntent(tenantId)
        val failingLedgerStore = FailingLedgerStore(JdbcLedgerJournalStore(jdbc))
        val failingService = depositService(
            tenantId,
            JdbcDepositWorkflowStore(jdbc),
            LedgerPostingService(failingLedgerStore, clock = clock),
        )
        failingLedgerStore.failSaves = 1

        val rollback = kotlin.runCatching {
            TransactionTemplate(txManager).execute { failingService.processCallback(callback(tenantId, intent.providerReference!!, "evt-r2")) }
        }
        assertTrue(rollback.isFailure)
        assertEquals(0, ledgerTransactionCount("LEDGER-DEP-${intent.intentId}"))
        assertEquals(0, financialEvents(tenantId, "corr-${intent.intentId}").count { it.second == "DEPOSIT_CREDITED" })

        val recovered = TransactionTemplate(txManager).execute {
            depositService(tenantId, JdbcDepositWorkflowStore(jdbc)).processCallback(callback(tenantId, intent.providerReference!!, "evt-r2-recovery"))
        }!!
        assertEquals(DepositIntentStatus.SETTLED, recovered.status)
        assertEquals(1, ledgerTransactionCount("LEDGER-DEP-${intent.intentId}"))
        val events = financialEvents(tenantId, "corr-${intent.intentId}")
        assertEquals(1, events.count { it.second == "DEPOSIT_CREDITED" })
        assertEquals(recovered.ledgerTransactionReference, events.single { it.second == "DEPOSIT_CREDITED" }.third)
    }

    @Test
    fun `TC-038-R3 payout pending then inquiry confirmed shares dispatch identity and mismatch is flagged without finalization`() {
        val tenantId = "tenant-tc038-r3-${UUID.randomUUID()}"
        val ownerId = UUID.randomUUID()
        seedWallet(tenantId, ownerId)
        val port = InquiryFakePort()
        val service = payoutService(tenantId, port)
        val first = stagePayout(service, tenantId, ownerId, "stage-r3a")
        val second = stagePayout(service, tenantId, ownerId, "stage-r3b")

        val dispatch = service.dispatchNext("worker-tc038", java.time.Duration.ofMinutes(5))
        assertNotNull(dispatch)
        assertEquals(PayoutDispatchStatus.AMBIGUOUS_RECONCILING, dispatch.status)
        assertEquals("IB-${first.intentId}", dispatch.providerReference)
        assertEquals(
            1,
            financialEvents(tenantId, "corr-${first.intentId}").count { it.second == "PAYOUT_DISPATCHED" },
        )

        port.inquiryOutcome = ProviderOutcome.verifiedSettlement(
            operationId = first.intentId,
            providerReference = "IB-${first.intentId}",
            amountMinorUnits = first.netPayoutAmountMinorUnits,
            currency = first.currencyCode,
            evidence = mapOf("status" to "SETTLED"),
        )
        val reconciled = service.reconcilePayout(tenantId, first.intentId, "operator-tc038")
        assertEquals(PayoutDispatchStatus.SUCCEEDED, reconciled.newStatus)
        val confirmed = financialEvents(tenantId, "corr-${first.intentId}")
            .filter { it.second == "PAYOUT_RECONCILE_CONFIRMED" }
        assertEquals(1, confirmed.size)
        assertEquals(first.intentId.toString(), confirmed.single().fourth)

        port.inquiryOutcome = ProviderOutcome.verifiedSettlement(
            operationId = second.intentId,
            providerReference = "IB-${second.intentId}",
            amountMinorUnits = second.netPayoutAmountMinorUnits + 1L,
            currency = second.currencyCode,
            evidence = mapOf("status" to "SETTLED"),
        )
        val walletBefore = walletBalance(tenantId, second.ownerId)
        val mismatched = service.reconcilePayout(tenantId, second.intentId, "operator-tc038")
        assertEquals(PayoutDispatchStatus.AMBIGUOUS_RECONCILING, mismatched.newStatus)
        val mismatchEvents = financialEvents(tenantId, "corr-${second.intentId}")
            .filter { it.second == "PAYOUT_RECONCILE_MISMATCH" }
        assertEquals(1, mismatchEvents.size)
        assertEquals(0, ledgerTransactionCount("LEDGER-PAYOUT-SETTLE-${second.intentId}"))
        assertEquals(walletBefore, walletBalance(tenantId, second.ownerId))
        assertEquals(0, ledgerTransactionCount("LEDGER-PAYOUT-COMP-${second.intentId}"))
    }

    private fun walletBalance(tenantId: String, ownerId: UUID): Long = jdbc.queryForObject(
        "select coalesce(sum(balance_minor_units), 0) from wallet_projection where tenant_id = ? and owner_reference = ?",
        Long::class.java,
        tenantId,
        "PLAYER:$ownerId",
    ) ?: 0L

    private fun financialEvents(tenantId: String, correlationId: String): List<Sextuple<String, String, String?, String?, Long, String?>> =
        jdbc.query(
            """
            select event_id, event_type, payload_json->>'ledgerId' as ledger_ref,
                   payload_json->>'paymentId' as payment_id,
                   coalesce((payload_json->>'amountMinorUnits')::bigint, 0) as amount,
                   payload_json->>'currency' as currency
            from diagnostic_event
            where tenant_id = ? and correlation_id = ?
            order by occurred_at, event_id
            """.trimIndent(),
            { rs, _ ->
                Sextuple(
                    rs.getString("event_id"),
                    rs.getString("event_type"),
                    rs.getString("ledger_ref"),
                    rs.getString("payment_id"),
                    rs.getLong("amount"),
                    rs.getString("currency"),
                )
            },
            tenantId,
            correlationId,
        )

    data class Sextuple<A, B, C, D, E, F>(
        val first: A,
        val second: B,
        val third: C,
        val fourth: D,
        val fifth: E,
        val sixth: F,
    )

    private fun ledgerTransactionCount(idempotencyKey: String): Int = jdbc.queryForObject(
        "select count(*) from ledger_transaction where idempotency_key = ?",
        Int::class.java,
        idempotencyKey,
    ) ?: 0

    private fun depositService(
        tenantId: String,
        store: DepositWorkflowStore = JdbcDepositWorkflowStore(jdbc),
        ledger: LedgerPostingService = LedgerPostingService(JdbcLedgerJournalStore(jdbc), clock = clock),
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
        financialAudit = JdbcFinancialAuditProjector(JdbcDiagnosticEventStore(jdbc, clock), clock),
    )

    private fun payoutService(tenantId: String, port: PaymentProviderPort) = com.slotting.admin.withdrawal.DurablePayoutDispatchService(
        dispatchStore = JdbcPayoutDispatchStore(jdbc),
        withdrawalStore = JdbcAuthoritativeWithdrawalStore(jdbc),
        ledgerPostingService = LedgerPostingService(JdbcLedgerJournalStore(jdbc), clock = clock),
        providerPorts = mapOf("SAFEPAY_RAAST" to port),
        credentialsResolver = { _, _ -> credentials },
        configResolver = { _, _ -> config },
        providerEnabled = { _, _ -> true },
        clock = clock,
        financialAudit = JdbcFinancialAuditProjector(JdbcDiagnosticEventStore(jdbc, clock), clock),
    )

    private fun seedIntent(
        tenantId: String,
        amount: Long = 50_000L,
    ): com.slotting.admin.deposit.DepositIntentRecord {
        val intent = com.slotting.admin.deposit.DepositIntentRecord(
            intentId = UUID.randomUUID(),
            tenantId = tenantId,
            playerId = UUID.randomUUID(),
            methodId = "SAFEPAY",
            providerId = "SAFEPAY_RAAST",
            amountMinorUnits = amount,
            currencyCode = "PKR",
            status = DepositIntentStatus.PROVIDER_PENDING,
            idempotencyKey = "idem-${UUID.randomUUID()}",
            requestFingerprint = "fp-${UUID.randomUUID()}",
            providerReference = "track-${UUID.randomUUID()}",
            providerCredentialVersion = null,
            expiresAt = now.plusSeconds(900),
            createdAt = now,
            updatedAt = now,
        )
        return JdbcDepositWorkflowStore(jdbc).saveIntent(intent)
    }

    private fun callback(
        tenantId: String,
        tracker: String,
        eventId: String,
        amount: Long = 50_000L,
        currency: String = "PKR",
        status: String = "paid",
    ): DepositCallbackCommand {
        val body = """{"data":{"token":"token_123","amount":$amount,"currency":"$currency","status":"$status","tracker":"$tracker"}}"""
        return DepositCallbackCommand(
            tenantId = tenantId,
            providerId = "SAFEPAY_RAAST",
            providerEventId = eventId,
            rawBody = body,
            headers = mapOf("x-sfpy-signature" to adapter.calculateHmacSha256(body, credentials.signingSecretOrKey!!)),
        )
    }

    private fun seedWallet(tenantId: String, ownerId: UUID) {
        jdbc.update(
            "insert into wallet_projection(projection_id, tenant_id, owner_reference, currency_code, balance_minor_units) values (?, ?, ?, ?, ?)",
            UUID.randomUUID(),
            tenantId,
            "PLAYER:$ownerId",
            "PKR",
            100_000L,
        )
    }

    private fun stagePayout(
        service: com.slotting.admin.withdrawal.DurablePayoutDispatchService,
        tenantId: String,
        ownerId: UUID,
        key: String,
    ): com.slotting.admin.withdrawal.PayoutDispatchIntentRecord {
        val requestId = UUID.randomUUID()
        val request = AuthoritativeWithdrawalRequest(
            requestId = requestId,
            tenantId = tenantId,
            ownerId = ownerId,
            quoteId = UUID.randomUUID(),
            reservationId = UUID.randomUUID(),
            methodId = "BANK_PK",
            destinationId = UUID.randomUUID(),
            destinationReference = "PK36SCBL0000001123456701",
            grossAmountMinorUnits = 50_000L,
            feeMinorUnits = 2_500L,
            netPayoutAmountMinorUnits = 47_500L,
            currencyCode = "PKR",
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
        JdbcAuthoritativeWithdrawalStore(jdbc).saveRequest(request)
        return service.stageDispatchIntent(
            StagePayoutDispatchCommand(
                tenantId = tenantId,
                requestId = request.requestId,
                providerId = "SAFEPAY_RAAST",
                idempotencyKey = key,
            )
        )
    }
}
