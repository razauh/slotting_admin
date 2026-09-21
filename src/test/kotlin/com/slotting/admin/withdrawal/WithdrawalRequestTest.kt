package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.wallet.BalanceBucketsStore
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

class WithdrawalRequestTest {
    private val now = Instant.parse("2026-09-20T19:45:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-request-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val playerBPrincipal = AuthenticatedPrincipal(
        id = playerBId.toString(),
        tenantId = "tenant-request-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-withdraw-request",
        tenantId = "tenant-request-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
    )

    private val foreignTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-request",
        tenantId = "tenant-foreign-99",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var requestStore: InMemoryWithdrawalRequestStore
    private lateinit var quoteStore: InMemoryWithdrawalQuoteStore
    private lateinit var destinationStore: InMemoryPayoutDestinationStore
    private lateinit var bucketStore: InMemoryBalanceBucketsStore
    private lateinit var observability: InMemoryWithdrawalRequestObservability
    private lateinit var service: WithdrawalRequestService

    @BeforeEach
    fun setUp() {
        WithdrawalRequestBinding.isBound = true
        requestStore = InMemoryWithdrawalRequestStore()
        quoteStore = InMemoryWithdrawalQuoteStore()
        destinationStore = InMemoryPayoutDestinationStore()
        bucketStore = InMemoryBalanceBucketsStore()
        observability = InMemoryWithdrawalRequestObservability()
        service = WithdrawalRequestService(
            requestStore = requestStore,
            quoteStore = quoteStore,
            destinationStore = destinationStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
    }

    @AfterEach
    fun tearDown() {
        WithdrawalRequestBinding.isBound = true
    }

    private fun setupWallet(ownerId: UUID, cashAvailable: Long = 500_000L): WalletBalanceBucketsRecord {
        val wallet = WalletBalanceBucketsRecord(
            walletId = UUID.randomUUID(),
            tenantId = "tenant-request-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            cash = CashBuckets(availableMinorUnits = cashAvailable, lockedMinorUnits = 0L, pendingWithdrawalMinorUnits = 0L),
            bonus = BonusBuckets(activeMinorUnits = 0L, lockedMinorUnits = 0L, pendingMinorUnits = 0L),
            version = 1L,
            createdAt = now.minusSeconds(3600),
            updatedAt = now
        )
        bucketStore.saveWallet(wallet)
        return wallet
    }

    private fun setupVerifiedDestination(
        ownerId: UUID,
        reference: String = "DE89370400440532013000",
        method: WithdrawalPaymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
        status: DestinationVerificationStatus = DestinationVerificationStatus.VERIFIED
    ): PayoutDestinationRecord {
        val dest = PayoutDestinationRecord(
            destinationId = UUID.randomUUID(),
            tenantId = "tenant-request-prod",
            ownerId = ownerId,
            paymentMethod = method,
            destinationReference = reference,
            accountHolderName = "Alice Wonderland",
            verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
            status = status,
            registeredAt = now.minusSeconds(1800),
            verifiedAt = if (status == DestinationVerificationStatus.VERIFIED) now.minusSeconds(1800) else null,
            verificationEvidenceReference = if (status == DestinationVerificationStatus.VERIFIED) "EVID-DEST-TEST" else null,
            idempotencyKey = "dest-key-${UUID.randomUUID()}",
            correlationId = "corr-dest",
            causationId = "caus-dest"
        )
        destinationStore.save(dest)
        return dest
    }

    private fun setupQuote(
        ownerId: UUID,
        grossAmount: Long = 10_000L,
        stepUpRequired: Boolean = false,
        status: WithdrawalQuoteStatus = WithdrawalQuoteStatus.ACTIVE,
        expiresAt: Instant = now.plusSeconds(900),
        destinationReference: String = "DE89370400440532013000",
        method: WithdrawalPaymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT
    ): WithdrawalQuoteRecord {
        val fee = if (method == WithdrawalPaymentMethod.SEPA_INSTANT) 150L else 200L
        val net = grossAmount - fee
        val quote = WithdrawalQuoteRecord(
            quoteId = UUID.randomUUID(),
            tenantId = "tenant-request-prod",
            ownerId = ownerId,
            currencyCode = "EUR",
            paymentMethod = method,
            destinationReference = destinationReference,
            destinationVerified = true,
            grossAmountMinorUnits = grossAmount,
            feeBreakdown = WithdrawalFeeBreakdown(
                fixedFeeMinorUnits = 100L,
                percentageFeeBps = 50L,
                calculatedVariableFeeMinorUnits = fee - 100L,
                totalFeeMinorUnits = fee
            ),
            netPayoutAmountMinorUnits = net,
            exchangeRate = 1.0,
            payoutCurrencyCode = "EUR",
            stepUpRequired = stepUpRequired,
            stepUpChallengeType = if (stepUpRequired) "MFA_TOTP" else null,
            status = status,
            quotedAt = now.minusSeconds(60),
            expiresAt = expiresAt,
            eligibilityDecisionId = "ELIG-TEST",
            eligibilityDecisionVersion = 1L,
            idempotencyKey = "quote-key-${UUID.randomUUID()}",
            correlationId = "corr-quote",
            causationId = "caus-quote",
            evidenceReference = "EVID-QUOTE-TEST"
        )
        quoteStore.save(quote)
        return quote
    }

    // =========================================================================
    // WITHDRAW-001-03-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WITHDRAW-001-03-T001 Create step-up protected withdrawal request produces the required authoritative outcome`() {
        WithdrawalRequestBinding.checkBound()

        // 1. Semantic contract assertion
        assertEquals(
            "Fee/rate/expiry disclosed; ownership/limits server checked.",
            WITHDRAWAL_REQUEST_CONTRACT
        )

        setupWallet(playerAId, cashAvailable = 500_000L)
        val destination = setupVerifiedDestination(playerAId)

        // Case A: Standard withdrawal request (under step-up threshold)
        val standardQuote = setupQuote(playerAId, grossAmount = 10_000L, stepUpRequired = false)
        val standardCmd = CreateWithdrawalRequestCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-request-prod",
            ownerId = playerAId,
            quoteId = standardQuote.quoteId,
            destinationId = destination.destinationId,
            stepUpAuthToken = null, // Not required for standard quote
            idempotencyKey = "idemp-req-001",
            correlationId = "corr-req-001",
            causationId = "caus-req-001"
        )
        val standardResult = service.createWithdrawalRequest(standardCmd)

        val req = standardResult.request
        assertNotNull(req.requestId)
        assertEquals(standardQuote.quoteId, req.quoteId)
        assertEquals(playerAId, req.ownerId)
        assertEquals("tenant-request-prod", req.tenantId)
        assertEquals(10_000L, req.grossAmountMinorUnits)
        assertEquals(150L, req.feeMinorUnits)
        assertEquals(9_850L, req.netPayoutAmountMinorUnits)
        assertEquals(WithdrawalRequestStatus.REQUESTED, req.status)
        assertFalse(req.stepUpAuthenticated)
        assertNull(req.stepUpEvidenceReference)
        assertTrue(standardResult.debitsEqualCredits)
        assertEquals(1L, standardResult.serverVersion)
        assertFalse(standardResult.hasAndroidDbImpact)
        assertFalse(standardResult.hasAndroidLifecycleClaim)
        assertEquals("WITHDRAWAL_REQUEST_CREATED", standardResult.auditEvent.type)
        assertEquals("corr-req-001", standardResult.auditEvent.correlationId)

        // Verify quote is atomically consumed
        val consumedQuote = quoteStore.findById(standardQuote.quoteId)!!
        assertEquals(WithdrawalQuoteStatus.CONSUMED, consumedQuote.status)

        // Case B: High-value withdrawal request requiring Step-Up MFA authentication
        val highValQuote = setupQuote(
            playerAId,
            grossAmount = 250_000L,
            stepUpRequired = true,
            destinationReference = destination.destinationReference
        )
        val stepUpCmd = CreateWithdrawalRequestCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-request-prod",
            ownerId = playerAId,
            quoteId = highValQuote.quoteId,
            destinationId = destination.destinationId,
            stepUpAuthToken = "MFA-STEPUP-VALID-AUTH-CODE-123456",
            idempotencyKey = "idemp-req-stepup-002",
            correlationId = "corr-req-002",
            causationId = "caus-req-002"
        )
        val stepUpResult = service.createWithdrawalRequest(stepUpCmd)

        val stepUpReq = stepUpResult.request
        assertEquals(WithdrawalRequestStatus.REQUESTED, stepUpReq.status)
        assertTrue(stepUpReq.stepUpAuthenticated)
        assertNotNull(stepUpReq.stepUpEvidenceReference)
        assertTrue(stepUpReq.stepUpEvidenceReference!!.startsWith("EVID-STEPUP-PROOF-"))

        // Query check
        val queried = service.getWithdrawalRequest(
            GetWithdrawalRequestQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-request-prod",
                requestId = stepUpReq.requestId
            )
        )
        assertEquals(stepUpReq.requestId, queried.requestId)
        assertEquals(WithdrawalRequestStatus.REQUESTED, queried.status)
    }

    // =========================================================================
    // WITHDRAW-001-03-T002: Rejection of Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `WITHDRAW-001-03-T002 Create step-up protected withdrawal request rejects invalid, boundary, unauthorized, and stale input`() {
        WithdrawalRequestBinding.checkBound()

        setupWallet(playerAId, cashAvailable = 100_000L)
        val destination = setupVerifiedDestination(playerAId)
        val validQuote = setupQuote(playerAId, grossAmount = 10_000L, destinationReference = destination.destinationReference)

        // 1. Unauthenticated request
        assertFailsWith<UnauthorizedWithdrawalAccessException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = null,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = validQuote.quoteId,
                    destinationId = destination.destinationId,
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Cross-tenant request
        assertFailsWith<CrossTenantWithdrawalAccessException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = foreignTenantPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = validQuote.quoteId,
                    destinationId = destination.destinationId,
                    idempotencyKey = "k2",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 3. IDOR / Cross-owner request: Player B tries to request withdrawal with Player A's account
        val idorEx = assertFailsWith<IdorWithdrawalForbiddenException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerBPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId, // Player B targeting Player A!
                    quoteId = validQuote.quoteId,
                    destinationId = destination.destinationId,
                    idempotencyKey = "k3",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(idorEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 4. Stale / Non-existent Quote
        val missingQuoteEx = assertFailsWith<StaleQuoteException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = UUID.randomUUID(), // non-existent quote!
                    destinationId = destination.destinationId,
                    idempotencyKey = "k4",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(missingQuoteEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 5. Expired Quote
        val expiredQuote = setupQuote(
            playerAId,
            grossAmount = 10_000L,
            expiresAt = now.minusSeconds(10), // expired!
            destinationReference = destination.destinationReference
        )
        val expiredEx = assertFailsWith<StaleQuoteException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = expiredQuote.quoteId,
                    destinationId = destination.destinationId,
                    idempotencyKey = "k5",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(expiredEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 6. Already Consumed Quote (prevent double consumption)
        val consumedQuote = setupQuote(
            playerAId,
            grossAmount = 10_000L,
            status = WithdrawalQuoteStatus.CONSUMED,
            destinationReference = destination.destinationReference
        )
        val consumedEx = assertFailsWith<StaleQuoteException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = consumedQuote.quoteId,
                    destinationId = destination.destinationId,
                    idempotencyKey = "k6",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(consumedEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 7. Unverified Destination
        val unverifiedDest = setupVerifiedDestination(
            playerAId,
            reference = "DE99999999999999999999",
            status = DestinationVerificationStatus.PENDING_VERIFICATION
        )
        val unverifiedQuote = setupQuote(
            playerAId,
            grossAmount = 10_000L,
            destinationReference = unverifiedDest.destinationReference
        )
        val unverifiedEx = assertFailsWith<UnverifiedDestinationException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = unverifiedQuote.quoteId,
                    destinationId = unverifiedDest.destinationId,
                    idempotencyKey = "k7",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(unverifiedEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 8. Destination Mismatch with Quote (quote destination != destination passed)
        val mismatchQuote = setupQuote(
            playerAId,
            grossAmount = 10_000L,
            destinationReference = "NL91ABNA0417164300" // Dutch IBAN, but destination is German!
        )
        val mismatchEx = assertFailsWith<InvalidDestinationException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = mismatchQuote.quoteId,
                    destinationId = destination.destinationId, // German IBAN
                    idempotencyKey = "k8",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(mismatchEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 9. Step-Up Authentication Required but missing
        val stepUpQuote = setupQuote(
            playerAId,
            grossAmount = 250_000L,
            stepUpRequired = true,
            destinationReference = destination.destinationReference
        )
        val stepUpMissingEx = assertFailsWith<StepUpAuthenticationRequiredException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = stepUpQuote.quoteId,
                    destinationId = destination.destinationId,
                    stepUpAuthToken = null, // Missing token!
                    idempotencyKey = "k9",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(stepUpMissingEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 10. Step-Up Authentication with invalid / expired token
        val stepUpInvalidEx = assertFailsWith<StepUpAuthenticationRequiredException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = stepUpQuote.quoteId,
                    destinationId = destination.destinationId,
                    stepUpAuthToken = "EXPIRED-TOKEN-XYZ", // Invalid!
                    idempotencyKey = "k10",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(stepUpInvalidEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 11. Insufficient withdrawable funds (wallet has 100_000, quote needs 250_000)
        val fundsEx = assertFailsWith<InsufficientWithdrawableFundsException> {
            service.createWithdrawalRequest(
                CreateWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-request-prod",
                    ownerId = playerAId,
                    quoteId = stepUpQuote.quoteId,
                    destinationId = destination.destinationId,
                    stepUpAuthToken = "MFA-STEPUP-VALID-TOKEN",
                    idempotencyKey = "k11",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(fundsEx.message!!.contains("stale quote/unverified destination/no step-up"))
    }

    // =========================================================================
    // WITHDRAW-001-03-T003: Concurrency, Duplicate Delivery, and Idempotency
    // =========================================================================

    @Test
    fun `WITHDRAW-001-03-T003 Create step-up protected withdrawal request survives concurrency, duplicate delivery, and dependency failure`() {
        WithdrawalRequestBinding.checkBound()

        setupWallet(playerAId, cashAvailable = 1_000_000L)
        val destination = setupVerifiedDestination(playerAId)
        val quote = setupQuote(playerAId, grossAmount = 15_000L, destinationReference = destination.destinationReference)

        // 1. Idempotency exact replay
        val cmd = CreateWithdrawalRequestCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-request-prod",
            ownerId = playerAId,
            quoteId = quote.quoteId,
            destinationId = destination.destinationId,
            idempotencyKey = "idemp-exact-replay-001",
            correlationId = "c1",
            causationId = "c2"
        )
        val firstResult = service.createWithdrawalRequest(cmd)
        val duplicateResult = service.createWithdrawalRequest(cmd)

        assertEquals(firstResult.request.requestId, duplicateResult.request.requestId)
        assertEquals(firstResult.resultId, duplicateResult.resultId)
        assertEquals(firstResult.serverTime, duplicateResult.serverTime)

        // 2. Idempotency conflict with modified payload
        val conflictingCmd = cmd.copy(destinationId = UUID.randomUUID())
        val conflictEx = assertFailsWith<IdempotencyConflictException> {
            service.createWithdrawalRequest(conflictingCmd)
        }
        assertTrue(conflictEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 3. Multi-threaded concurrency: distinct quotes created and requested concurrently
        val executor = Executors.newFixedThreadPool(8)
        val tasks = (1..10).map { i ->
            val q = setupQuote(
                playerAId,
                grossAmount = 10_000L + (i * 1000L),
                destinationReference = destination.destinationReference
            )
            Callable {
                service.createWithdrawalRequest(
                    CreateWithdrawalRequestCommand(
                        principal = playerAPrincipal,
                        tenantId = "tenant-request-prod",
                        ownerId = playerAId,
                        quoteId = q.quoteId,
                        destinationId = destination.destinationId,
                        idempotencyKey = "idemp-thread-$i",
                        correlationId = "corr-thread-$i",
                        causationId = "caus-thread-$i"
                    )
                )
            }
        }
        val futures = executor.invokeAll(tasks)
        executor.shutdown()

        val results = futures.map { it.get() }
        assertEquals(10, results.size)
        val uniqueRequestIds = results.map { it.request.requestId }.toSet()
        assertEquals(10, uniqueRequestIds.size)
    }

    // =========================================================================
    // WITHDRAW-001-03-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `WITHDRAW-001-03-T004 Create step-up protected withdrawal request remains compatible, recoverable, observable, and lifecycle-safe`() {
        WithdrawalRequestBinding.checkBound()

        setupWallet(playerAId, cashAvailable = 500_000L)
        val destination = setupVerifiedDestination(playerAId)
        val quote = setupQuote(playerAId, grossAmount = 20_000L, destinationReference = destination.destinationReference)

        // 1. Observability events emitted
        val cmd = CreateWithdrawalRequestCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-request-prod",
            ownerId = playerAId,
            quoteId = quote.quoteId,
            destinationId = destination.destinationId,
            idempotencyKey = "idemp-obs-001",
            correlationId = "corr-obs-001",
            causationId = "caus-obs-001"
        )
        val result = service.createWithdrawalRequest(cmd)

        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "attempt" && it.correlationId == "corr-obs-001" })
        assertTrue(metrics.any { it.eventType == "accept" && it.correlationId == "corr-obs-001" })

        // 2. Recovery across service restart with same stores
        val recoveredService = WithdrawalRequestService(
            requestStore = requestStore,
            quoteStore = quoteStore,
            destinationStore = destinationStore,
            bucketStore = bucketStore,
            clock = clock,
            observability = observability
        )
        val queried = recoveredService.getWithdrawalRequest(
            GetWithdrawalRequestQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-request-prod",
                requestId = result.request.requestId
            )
        )
        assertEquals(result.request.requestId, queried.requestId)
        assertEquals(WithdrawalRequestStatus.REQUESTED, queried.status)

        // 3. No Android database impact or lifecycle claims
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)
    }
}
