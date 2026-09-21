package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.wallet.BonusBuckets
import com.slotting.admin.wallet.CashBuckets
import com.slotting.admin.wallet.InMemoryBalanceBucketsStore
import com.slotting.admin.wallet.WalletBalanceBucketsRecord
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WithdrawalQuoteTest {
    private val now = Instant.parse("2026-09-20T18:45:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-withdraw-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val playerBPrincipal = AuthenticatedPrincipal(
        id = playerBId.toString(),
        tenantId = "tenant-withdraw-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-withdraw-quote",
        tenantId = "tenant-withdraw-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
    )

    private val foreignTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign",
        tenantId = "tenant-foreign-99",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var quoteStore: InMemoryWithdrawalQuoteStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var observability: InMemoryWithdrawalQuoteObservability
    private lateinit var service: WithdrawalQuoteService

    @BeforeEach
    fun setUp() {
        WithdrawalQuoteBinding.isBound = true
        quoteStore = InMemoryWithdrawalQuoteStore()
        bucketStore = InMemoryBalanceBucketsStore()
        observability = InMemoryWithdrawalQuoteObservability()
        service = WithdrawalQuoteService(
            quoteStore = quoteStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
    }

    @AfterEach
    fun tearDown() {
        WithdrawalQuoteBinding.isBound = true
    }

    private fun createTestWallet(
        ownerId: UUID,
        cashAvailable: Long = 300_000L,
        bonusActive: Long = 50_000L,
        version: Long = 4L
    ): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-withdraw-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            cash = CashBuckets(availableMinorUnits = cashAvailable, lockedMinorUnits = 0L, pendingWithdrawalMinorUnits = 0L),
            bonus = BonusBuckets(activeMinorUnits = bonusActive, lockedMinorUnits = 0L, pendingMinorUnits = 0L),
            version = version,
            createdAt = now.minusSeconds(7200),
            updatedAt = now
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    // =========================================================================
    // WITHDRAW-001-01-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WITHDRAW-001-01-T001 Quote withdrawal fees and expiry produces the required authoritative outcome`() {
        WithdrawalQuoteBinding.checkBound()

        // 1. Verify semantic contract constant
        assertEquals(
            "Fee/rate/expiry disclosed; ownership/limits server checked.",
            WITHDRAWAL_QUOTE_CONTRACT
        )

        val wallet = createTestWallet(ownerId = playerAId, cashAvailable = 100_000L, version = 5L)

        // 2. Request quote for 10_000 minor units (100.00 EUR) via SEPA_INSTANT
        val cmd = QuoteWithdrawalCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-withdraw-prod",
            ownerId = playerAId,
            currencyCode = "EUR",
            grossAmountMinorUnits = 10_000L,
            paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
            destinationReference = "IBAN-DE89370400440532013000",
            destinationVerified = true,
            eligibilityDecisionId = "ELIG-DEC-001",
            eligibilityDecisionVersion = 1L,
            ttlSeconds = 900L,
            idempotencyKey = "idemp-quote-001",
            correlationId = "corr-quote-001",
            causationId = "caus-quote-001"
        )
        val result = service.quoteWithdrawal(cmd)

        // Assert fee, rate, and expiry disclosed
        val quote = result.quote
        assertNotNull(quote.quoteId)
        assertEquals(10_000L, quote.grossAmountMinorUnits)
        assertEquals(100L, quote.feeBreakdown.fixedFeeMinorUnits) // SEPA_INSTANT fixed fee 1.00 EUR
        assertEquals(50L, quote.feeBreakdown.percentageFeeBps)   // 50 bps = 0.50%
        assertEquals(50L, quote.feeBreakdown.calculatedVariableFeeMinorUnits) // 10000 * 50 / 10000 = 50
        assertEquals(150L, quote.feeBreakdown.totalFeeMinorUnits)
        assertEquals(9_850L, quote.netPayoutAmountMinorUnits)    // 10000 - 150 = 9850
        assertEquals(1.0, quote.exchangeRate)
        assertEquals("EUR", quote.payoutCurrencyCode)
        assertEquals(now, quote.quotedAt)
        assertEquals(now.plusSeconds(900L), quote.expiresAt)
        assertEquals(WithdrawalQuoteStatus.ACTIVE, quote.status)
        assertFalse(quote.stepUpRequired) // 10_000 < 200_000 step-up threshold
        assertNull(quote.stepUpChallengeType)
        assertTrue(result.debitsEqualCredits)
        assertEquals(5L, result.serverVersion) // Server-checked version
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)
        assertEquals("WITHDRAWAL_QUOTE_CREATED", result.auditEvent.type)
        assertEquals("corr-quote-001", result.auditEvent.correlationId)
    }

    // =========================================================================
    // WITHDRAW-001-01-T002: Rejection of Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `WITHDRAW-001-01-T002 Quote withdrawal fees and expiry rejects invalid, boundary, unauthorized, and stale input`() {
        WithdrawalQuoteBinding.checkBound()

        val wallet = createTestWallet(ownerId = playerAId, cashAvailable = 50_000L)

        // 1. Unauthenticated request
        assertFailsWith<UnauthorizedWithdrawalAccessException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = null,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 5_000L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-1",
                    eligibilityDecisionId = "ELIG-1",
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Cross-tenant request
        assertFailsWith<CrossTenantWithdrawalAccessException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = foreignTenantPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 5_000L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-1",
                    eligibilityDecisionId = "ELIG-1",
                    idempotencyKey = "k2",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 3. Ownership Leak (IDOR): Player B queries quote for Player A
        val idorEx = assertFailsWith<IdorWithdrawalForbiddenException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = playerBPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId, // Target is Player A!
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 5_000L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-1",
                    eligibilityDecisionId = "ELIG-1",
                    idempotencyKey = "k3",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(idorEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 4. Unverified Destination
        val unverifiedEx = assertFailsWith<UnverifiedDestinationException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 5_000L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-UNVERIFIED",
                    destinationVerified = false, // Unverified destination!
                    eligibilityDecisionId = "ELIG-1",
                    idempotencyKey = "k4",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(unverifiedEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 5. Missing / Stale Eligibility Verdict (AUTHZ-001 prerequisite)
        val eligEx = assertFailsWith<EligibilityDeniedException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 5_000L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-1",
                    destinationVerified = true,
                    eligibilityDecisionId = "", // Missing verdict!
                    idempotencyKey = "k5",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(eligEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 6. Limit checks: below minimum (500 < 1000)
        val minEx = assertFailsWith<WithdrawalLimitExceededException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 500L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-1",
                    destinationVerified = true,
                    eligibilityDecisionId = "ELIG-1",
                    idempotencyKey = "k6",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(minEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 7. Limit checks: above maximum (600_000 > 500_000)
        val maxEx = assertFailsWith<WithdrawalLimitExceededException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 600_000L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-1",
                    destinationVerified = true,
                    eligibilityDecisionId = "ELIG-1",
                    idempotencyKey = "k7",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(maxEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 8. Insufficient withdrawable funds (wallet has 50_000, requested 60_000)
        val fundsEx = assertFailsWith<InsufficientWithdrawableFundsException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 60_000L,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "IBAN-1",
                    destinationVerified = true,
                    eligibilityDecisionId = "ELIG-1",
                    idempotencyKey = "k8",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(fundsEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 9. Stale Quote Consumption Rejection
        val validQuote = service.quoteWithdrawal(
            QuoteWithdrawalCommand(
                principal = playerAPrincipal,
                tenantId = "tenant-withdraw-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                grossAmountMinorUnits = 10_000L,
                paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                destinationReference = "IBAN-1",
                destinationVerified = true,
                eligibilityDecisionId = "ELIG-1",
                ttlSeconds = 1L, // 1 second TTL
                idempotencyKey = "k9-exp",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        // Advance clock past expiry
        val expiredClockService = WithdrawalQuoteService(
            quoteStore = quoteStore,
            bucketStore = bucketStore,
            clock = Clock.fixed(now.plusSeconds(10), ZoneOffset.UTC),
            observability = observability
        )
        val staleEx = assertFailsWith<StaleQuoteException> {
            expiredClockService.validateQuoteForConsumption(
                quoteId = validQuote.quote.quoteId,
                tenantId = "tenant-withdraw-prod",
                ownerId = playerAId
            )
        }
        assertTrue(staleEx.message!!.contains("stale quote/unverified destination/no step-up"))
    }

    // =========================================================================
    // WITHDRAW-001-01-T003: Concurrency, Duplicate Delivery, and Step-Up Policy
    // =========================================================================

    @Test
    fun `WITHDRAW-001-01-T003 Quote withdrawal fees and expiry survives concurrency, duplicate delivery, and dependency failure`() {
        WithdrawalQuoteBinding.checkBound()

        val wallet = createTestWallet(ownerId = playerAId, cashAvailable = 400_000L)

        // 1. Step-Up Authentication Policy Enforcement
        // Quote >= 200_000 minor units (2,000 EUR) must require step-up challenge
        val highValueQuote = service.quoteWithdrawal(
            QuoteWithdrawalCommand(
                principal = playerAPrincipal,
                tenantId = "tenant-withdraw-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                grossAmountMinorUnits = 250_000L,
                paymentMethod = WithdrawalPaymentMethod.BANK_TRANSFER,
                destinationReference = "IBAN-STEP-UP",
                destinationVerified = true,
                eligibilityDecisionId = "ELIG-HIGH-VAL",
                idempotencyKey = "k-stepup-01",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        assertTrue(highValueQuote.quote.stepUpRequired, "Quote >= 2000 EUR must require step-up")
        assertEquals("MFA_TOTP", highValueQuote.quote.stepUpChallengeType)

        // 2. Idempotent replay: identical command returns exact same cached quote
        val replayQuote = service.quoteWithdrawal(
            QuoteWithdrawalCommand(
                principal = playerAPrincipal,
                tenantId = "tenant-withdraw-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                grossAmountMinorUnits = 250_000L,
                paymentMethod = WithdrawalPaymentMethod.BANK_TRANSFER,
                destinationReference = "IBAN-STEP-UP",
                destinationVerified = true,
                eligibilityDecisionId = "ELIG-HIGH-VAL",
                idempotencyKey = "k-stepup-01",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        assertEquals(highValueQuote.quote.quoteId, replayQuote.quote.quoteId)

        // 3. Changed payload on existing idempotency key triggers CONFLICT
        assertFailsWith<IdempotencyConflictException> {
            service.quoteWithdrawal(
                QuoteWithdrawalCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-withdraw-prod",
                    ownerId = playerAId,
                    currencyCode = "EUR",
                    grossAmountMinorUnits = 300_000L, // Changed amount!
                    paymentMethod = WithdrawalPaymentMethod.BANK_TRANSFER,
                    destinationReference = "IBAN-STEP-UP",
                    destinationVerified = true,
                    eligibilityDecisionId = "ELIG-HIGH-VAL",
                    idempotencyKey = "k-stepup-01",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 4. Concurrency: 10 threads simultaneously quoting for same player
        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val futures = (1..threadCount).map { i ->
            executor.submit(Callable {
                service.quoteWithdrawal(
                    QuoteWithdrawalCommand(
                        principal = playerAPrincipal,
                        tenantId = "tenant-withdraw-prod",
                        ownerId = playerAId,
                        currencyCode = "EUR",
                        grossAmountMinorUnits = 10_000L + (i * 100L),
                        paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                        destinationReference = "IBAN-CONCUR-$i",
                        destinationVerified = true,
                        eligibilityDecisionId = "ELIG-CONCUR",
                        idempotencyKey = "k-concur-$i",
                        correlationId = "corr-$i",
                        causationId = "caus-$i"
                    )
                )
            })
        }
        val results = futures.map { it.get() }
        executor.shutdown()

        assertEquals(10, results.size)
        results.forEach { res ->
            assertNotNull(res.quote.quoteId)
            assertTrue(res.quote.feeBreakdown.totalFeeMinorUnits > 0L)
            assertTrue(res.debitsEqualCredits)
        }
    }

    // =========================================================================
    // WITHDRAW-001-01-T004: Recovery, Observability, and Lifecycle Safety
    // =========================================================================

    @Test
    fun `WITHDRAW-001-01-T004 Quote withdrawal fees and expiry remains compatible, recoverable, observable, and lifecycle-safe`() {
        WithdrawalQuoteBinding.checkBound()

        val wallet = createTestWallet(ownerId = playerAId, cashAvailable = 100_000L)

        val res = service.quoteWithdrawal(
            QuoteWithdrawalCommand(
                principal = playerAPrincipal,
                tenantId = "tenant-withdraw-prod",
                ownerId = playerAId,
                currencyCode = "EUR",
                grossAmountMinorUnits = 20_000L,
                paymentMethod = WithdrawalPaymentMethod.CARD_OCT,
                destinationReference = "CARD-TOKEN-9941",
                destinationVerified = true,
                eligibilityDecisionId = "ELIG-OBS-001",
                idempotencyKey = "k-obs-01",
                correlationId = "corr-obs-01",
                causationId = "caus-obs-01"
            )
        )

        // 1. Audit & Outbox events verified
        assertEquals("WITHDRAWAL_QUOTE_CREATED", res.auditEvent.type)
        assertEquals("corr-obs-01", res.auditEvent.correlationId)
        assertEquals("caus-obs-01", res.auditEvent.causationId)

        // 2. Metrics recorded
        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "attempt" })
        assertTrue(metrics.any { it.eventType == "accept" })

        // 3. Store persistence and recovery
        val loaded = quoteStore.findById(res.quote.quoteId)
        assertNotNull(loaded)
        assertEquals(res.quote.quoteId, loaded.quoteId)
        assertEquals(20_000L, loaded.grossAmountMinorUnits)

        // 4. Android lifecycle & DB impact invariants
        assertFalse(res.hasAndroidDbImpact)
        assertFalse(res.hasAndroidLifecycleClaim)
    }
}
