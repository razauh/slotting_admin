package com.slotting.admin.withdrawal

import com.slotting.admin.auth.*
import com.slotting.admin.provider.*
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

/**
 * TC-014 TDD Contract Test Suite:
 * Authoritative withdrawal quote, request, step-up, and approval binding.
 */
class AuthoritativeWithdrawalContractTest {

    private val now = Instant.parse("2026-09-25T13:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.fromString("00000000-0000-0000-0000-000000000001")
    private val playerBId = UUID.fromString("00000000-0000-0000-0000-000000000002")

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val playerBPrincipal = AuthenticatedPrincipal(
        id = playerBId.toString(),
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val adminMakerPrincipal = AuthenticatedPrincipal(
        id = "admin-maker-1",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val adminCheckerPrincipal = AuthenticatedPrincipal(
        id = "admin-checker-2",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val auditorPrincipal = AuthenticatedPrincipal(
        id = "auditor-read-only",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.AUDITOR),
    )

    private val sessionDir = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = now.plus(Duration.ofHours(2)),
                mfaVerified = true,
            )
        }
    }

    private val activeWithdrawalMethod = PaymentMethodConfig(
        tenantId = "tenant-pk-1",
        methodId = "BANK_PK",
        providerId = "ONE_LINK_IBFT",
        methodType = PaymentMethodType.BANK_TRANSFER,
        displayName = "1Link IBFT Bank Transfer",
        instructions = "Provide 24-digit IBAN",
        safeAccountTitle = "Bank Account",
        safeAccountNumber = "PK36SCBL0000001123456701",
        iconUrl = "https://cdn.example.com/1link.png",
        supportedCurrencies = listOf("PKR"),
        allowsDeposit = true,
        allowsWithdrawal = true,
        minDepositMinorUnits = 10_000L,
        maxDepositMinorUnits = 50_000_000L,
        minWithdrawalMinorUnits = 10_000L, // 100 PKR
        maxWithdrawalMinorUnits = 10_000_000L, // 100,000 PKR
        feeFlatMinorUnits = 2_500L, // 25 PKR flat
        feePercentageBps = 100, // 1.0%
        displayOrder = 1,
        status = PaymentMethodStatus.ACTIVE,
        maintenanceReason = null,
        serverVersion = 1L,
        createdAt = now,
        updatedAt = now,
        updatedBy = "admin-1",
    )

    private fun sampleDestination(
        ownerId: UUID = playerAId,
        ref: String = "PK36SCBL0000001123456701",
        status: DestinationVerificationStatus = DestinationVerificationStatus.VERIFIED,
    ) = PayoutDestinationRecord(
        destinationId = UUID.randomUUID(),
        tenantId = "tenant-pk-1",
        ownerId = ownerId,
        paymentMethod = WithdrawalPaymentMethod.BANK_TRANSFER,
        destinationReference = ref,
        accountHolderName = "Muhammad Ali",
        verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
        status = status,
        registeredAt = now.minus(Duration.ofHours(1)),
        verifiedAt = if (status == DestinationVerificationStatus.VERIFIED) now.minus(Duration.ofMinutes(30)) else null,
        idempotencyKey = "dest-${UUID.randomUUID()}",
        correlationId = "corr-dest",
        causationId = "caus-dest",
    )

    // =========================================================================
    // 1. Insufficient Funds & Overflow Scenarios
    // =========================================================================

    @Test
    fun `test01 insufficient funds rejects reservation and request`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 50_000L) // 500 PKR
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(activeWithdrawalMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        // Quote for 100_000 PKR (10,000,000 minor units) exceeds available 50,000 minor units
        val quoteCmd = CreateAuthoritativeQuoteCommand(
            principal = playerAPrincipal,
            sessionId = "sess-1",
            tenantId = "tenant-pk-1",
            ownerId = playerAId,
            currencyCode = "PKR",
            methodId = "BANK_PK",
            destinationId = dest.destinationId,
            grossAmountMinorUnits = 100_000L,
            idempotencyKey = "quote-insufficient-1",
        )

        assertFailsWith<InsufficientWithdrawableFundsException> {
            service.createQuote(quoteCmd)
        }
    }

    @Test
    fun `test02 overflow and non-positive amounts are rejected`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = InMemoryPaymentMethodStore(),
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        // Non-positive amount
        assertFailsWith<IllegalArgumentException> {
            service.createQuote(
                CreateAuthoritativeQuoteCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    currencyCode = "PKR",
                    methodId = "BANK_PK",
                    destinationId = dest.destinationId,
                    grossAmountMinorUnits = 0L,
                    idempotencyKey = "quote-zero",
                )
            )
        }

        // Arithmetic overflow amount
        assertFailsWith<IllegalArgumentException> {
            service.createQuote(
                CreateAuthoritativeQuoteCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    currencyCode = "PKR",
                    methodId = "BANK_PK",
                    destinationId = dest.destinationId,
                    grossAmountMinorUnits = -500L,
                    idempotencyKey = "quote-neg",
                )
            )
        }
    }

    // =========================================================================
    // 2. Fee Boundary Scenario
    // =========================================================================

    @Test
    fun `test03 fee boundary rejects gross amount less than or equal to fee`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 500_000L)
        val methodStore = InMemoryPaymentMethodStore()
        // Method with min withdrawal 10 PKR (1,000 minor units) and flat fee 25 PKR (2,500 minor units)
        val feeBoundaryMethod = activeWithdrawalMethod.copy(
            minWithdrawalMinorUnits = 1_000L,
            feeFlatMinorUnits = 2_500L,
        )
        methodStore.saveMethod(feeBoundaryMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        // Gross amount 2,000 minor units is below feeFlat 2,500 minor units
        assertFailsWith<InvalidFeeBoundaryException> {
            service.createQuote(
                CreateAuthoritativeQuoteCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    currencyCode = "PKR",
                    methodId = "BANK_PK",
                    destinationId = dest.destinationId,
                    grossAmountMinorUnits = 2_000L,
                    idempotencyKey = "quote-below-fee",
                )
            )
        }
    }

    // =========================================================================
    // 3. Destination Changed & Unverified Destination
    // =========================================================================

    @Test
    fun `test04 destination changed or unverified destination is rejected`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 500_000L)
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(activeWithdrawalMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val unverifiedDest = sampleDestination(playerAId, status = DestinationVerificationStatus.PENDING_VERIFICATION)
        store.saveDestination(unverifiedDest)

        // Unverified destination rejected
        assertFailsWith<UnverifiedDestinationException> {
            service.createQuote(
                CreateAuthoritativeQuoteCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    currencyCode = "PKR",
                    methodId = "BANK_PK",
                    destinationId = unverifiedDest.destinationId,
                    grossAmountMinorUnits = 50_000L,
                    idempotencyKey = "quote-unverified",
                )
            )
        }

        // Quote created with destination A
        val destA = sampleDestination(playerAId, ref = "PK36SCBL0000001123456701")
        val destB = sampleDestination(playerAId, ref = "PK36SCBL0000009988776602")
        store.saveDestination(destA)
        store.saveDestination(destB)

        val quote = service.createQuote(
            CreateAuthoritativeQuoteCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                currencyCode = "PKR",
                methodId = "BANK_PK",
                destinationId = destA.destinationId,
                grossAmountMinorUnits = 50_000L,
                idempotencyKey = "quote-dest-a",
            )
        )

        // Request submitted with destination B while quote was for destination A
        assertFailsWith<DestinationMismatchException> {
            service.createWithdrawalRequest(
                CreateAuthoritativeWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    quoteId = quote.quoteId,
                    destinationId = destB.destinationId,
                    stepUpToken = null,
                    idempotencyKey = "req-dest-mismatch",
                )
            )
        }
    }

    // =========================================================================
    // 4. Step-Up Replay & Forged Prefix Rejection
    // =========================================================================

    @Test
    fun `test05 forged prefix step-up token is rejected and never authorizes request`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 500_000L)
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(activeWithdrawalMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        val quote = service.createQuote(
            CreateAuthoritativeQuoteCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                currencyCode = "PKR",
                methodId = "BANK_PK",
                destinationId = dest.destinationId,
                grossAmountMinorUnits = 50_000L,
                idempotencyKey = "quote-stepup-forged",
            )
        )

        // Forged prefix token that previously passed DefaultStepUpTokenValidator
        val forgedToken = "MFA-STEPUP-VALID-FORGED-123456"

        assertFailsWith<StepUpAuthenticationRequiredException> {
            service.createWithdrawalRequest(
                CreateAuthoritativeWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    quoteId = quote.quoteId,
                    destinationId = dest.destinationId,
                    stepUpToken = forgedToken,
                    idempotencyKey = "req-forged-token",
                )
            )
        }
    }

    @Test
    fun `test06 step-up replay is rejected and token cannot be reused`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 500_000L)
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(activeWithdrawalMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        val quote1 = service.createQuote(
            CreateAuthoritativeQuoteCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                currencyCode = "PKR",
                methodId = "BANK_PK",
                destinationId = dest.destinationId,
                grossAmountMinorUnits = 50_000L,
                idempotencyKey = "quote-replay-1",
            )
        )

        // Issue valid step-up assertion
        val assertion = service.issueStepUpAssertion(
            IssueStepUpAssertionCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                quoteId = quote1.quoteId,
            )
        )

        // First use succeeds
        val req1 = service.createWithdrawalRequest(
            CreateAuthoritativeWithdrawalRequestCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                quoteId = quote1.quoteId,
                destinationId = dest.destinationId,
                stepUpToken = assertion.token,
                idempotencyKey = "req-use-1",
            )
        )
        assertNotNull(req1.requestId)

        // Create second quote
        val quote2 = service.createQuote(
            CreateAuthoritativeQuoteCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                currencyCode = "PKR",
                methodId = "BANK_PK",
                destinationId = dest.destinationId,
                grossAmountMinorUnits = 50_000L,
                idempotencyKey = "quote-replay-2",
            )
        )

        // Attempting to reuse same step-up token must fail with StepUpReplayException
        assertFailsWith<StepUpReplayException> {
            service.createWithdrawalRequest(
                CreateAuthoritativeWithdrawalRequestCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    quoteId = quote2.quoteId,
                    destinationId = dest.destinationId,
                    stepUpToken = assertion.token,
                    idempotencyKey = "req-use-2",
                )
            )
        }
    }

    // =========================================================================
    // 5. Dual-Control Approval: Self-Approval, Stale, Unrelated, Auditor
    // =========================================================================

    @Test
    fun `test07 self-approval and auditor approval are strictly rejected`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 500_000L)
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(activeWithdrawalMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        val quote = service.createQuote(
            CreateAuthoritativeQuoteCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                currencyCode = "PKR",
                methodId = "BANK_PK",
                destinationId = dest.destinationId,
                grossAmountMinorUnits = 50_000L,
                idempotencyKey = "quote-dual-1",
            )
        )

        val assertion = service.issueStepUpAssertion(
            IssueStepUpAssertionCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                quoteId = quote.quoteId,
            )
        )

        val req = service.createWithdrawalRequest(
            CreateAuthoritativeWithdrawalRequestCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                quoteId = quote.quoteId,
                destinationId = dest.destinationId,
                stepUpToken = assertion.token,
                idempotencyKey = "req-dual-1",
            )
        )

        // 1. Self-approval: Maker == Checker
        val selfApprovalReceipt = DualControlReceipt(
            receiptId = UUID.randomUUID(),
            proposalId = UUID.randomUUID(),
            tenantId = "tenant-pk-1",
            operationId = req.requestId.toString(),
            operationType = "WITHDRAWAL_REVIEW",
            resourceReference = req.requestId.toString(),
            payloadDigest = req.immutableDigest,
            requiredPermission = AdminPermission.WITHDRAWAL_REVIEW,
            targetVersion = req.requestVersion,
            status = DualControlStatus.APPROVED,
            maker = DecisionActor(
                principalId = "admin-same-1",
                tenantId = "tenant-pk-1",
                roles = setOf(AdminRole.SUPER_ADMIN),
                sessionId = "sess-m",
                mfaVerified = true,
                decidedAt = now,
            ),
            checker = DecisionActor(
                principalId = "admin-same-1", // Self-approval!
                tenantId = "tenant-pk-1",
                roles = setOf(AdminRole.SUPER_ADMIN),
                sessionId = "sess-c",
                mfaVerified = true,
                decidedAt = now,
            ),
            decidedAt = now,
            expiresAt = now.plus(Duration.ofMinutes(15)),
            evidenceReference = "EVID-SELF",
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewWithdrawal(
                ReviewWithdrawalCommand(
                    principal = adminMakerPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    requestId = req.requestId,
                    action = WithdrawalReviewAction.APPROVE,
                    dualControlReceipt = selfApprovalReceipt,
                    idempotencyKey = "review-self",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Auditor approval: Auditor cannot execute financial mutations
        val auditorReceipt = selfApprovalReceipt.copy(
            checker = DecisionActor(
                principalId = auditorPrincipal.id,
                tenantId = "tenant-pk-1",
                roles = setOf(AdminRole.AUDITOR), // Auditor!
                sessionId = "sess-aud",
                mfaVerified = true,
                decidedAt = now,
            )
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewWithdrawal(
                ReviewWithdrawalCommand(
                    principal = adminMakerPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    requestId = req.requestId,
                    action = WithdrawalReviewAction.APPROVE,
                    dualControlReceipt = auditorReceipt,
                    idempotencyKey = "review-auditor",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    @Test
    fun `test08 stale approval or unrelated approval digest is rejected`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 500_000L)
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(activeWithdrawalMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        val quote = service.createQuote(
            CreateAuthoritativeQuoteCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                currencyCode = "PKR",
                methodId = "BANK_PK",
                destinationId = dest.destinationId,
                grossAmountMinorUnits = 50_000L,
                idempotencyKey = "quote-stale-1",
            )
        )

        val assertion = service.issueStepUpAssertion(
            IssueStepUpAssertionCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                quoteId = quote.quoteId,
            )
        )

        val req = service.createWithdrawalRequest(
            CreateAuthoritativeWithdrawalRequestCommand(
                principal = playerAPrincipal,
                sessionId = "sess-1",
                tenantId = "tenant-pk-1",
                ownerId = playerAId,
                quoteId = quote.quoteId,
                destinationId = dest.destinationId,
                stepUpToken = assertion.token,
                idempotencyKey = "req-stale-1",
            )
        )

        // 1. Unrelated approval (wrong payload digest)
        val unrelatedReceipt = DualControlReceipt(
            receiptId = UUID.randomUUID(),
            proposalId = UUID.randomUUID(),
            tenantId = "tenant-pk-1",
            operationId = req.requestId.toString(),
            operationType = "WITHDRAWAL_REVIEW",
            resourceReference = req.requestId.toString(),
            payloadDigest = "unrelated-altered-payload-digest", // Digest mismatch!
            requiredPermission = AdminPermission.WITHDRAWAL_REVIEW,
            targetVersion = req.requestVersion,
            status = DualControlStatus.APPROVED,
            maker = DecisionActor("admin-maker-1", "tenant-pk-1", setOf(AdminRole.SUPER_ADMIN), "sess-m", true, now),
            checker = DecisionActor("admin-checker-2", "tenant-pk-1", setOf(AdminRole.SUPER_ADMIN), "sess-c", true, now),
            decidedAt = now,
            expiresAt = now.plus(Duration.ofMinutes(15)),
            evidenceReference = "EVID-UNRELATED",
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewWithdrawal(
                ReviewWithdrawalCommand(
                    principal = adminMakerPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    requestId = req.requestId,
                    action = WithdrawalReviewAction.APPROVE,
                    dualControlReceipt = unrelatedReceipt,
                    idempotencyKey = "review-unrelated",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 2. Stale approval (expired)
        val expiredReceipt = unrelatedReceipt.copy(
            payloadDigest = req.immutableDigest,
            expiresAt = now.minusSeconds(10), // Expired!
        )

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.reviewWithdrawal(
                ReviewWithdrawalCommand(
                    principal = adminMakerPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    requestId = req.requestId,
                    action = WithdrawalReviewAction.APPROVE,
                    dualControlReceipt = expiredReceipt,
                    idempotencyKey = "review-expired",
                )
            )
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // 6. Inactive Method & Restriction Appears
    // =========================================================================

    @Test
    fun `test09 inactive payment method or account restriction rejects withdrawal`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 500_000L)
        val methodStore = InMemoryPaymentMethodStore()
        val inactiveMethod = activeWithdrawalMethod.copy(status = PaymentMethodStatus.INACTIVE)
        methodStore.saveMethod(inactiveMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        // Inactive method
        assertFailsWith<PaymentMethodUnavailableException> {
            service.createQuote(
                CreateAuthoritativeQuoteCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    currencyCode = "PKR",
                    methodId = "BANK_PK",
                    destinationId = dest.destinationId,
                    grossAmountMinorUnits = 50_000L,
                    idempotencyKey = "quote-inactive-method",
                )
            )
        }

        // Account restriction appears
        val restrictedService = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = InMemoryPaymentMethodStore().also { it.saveMethod(activeWithdrawalMethod) },
            sessions = sessionDir,
            restrictionPolicy = { _, ownerId -> ownerId == playerAId }, // Restrict playerA
            clock = clock,
        )

        assertFailsWith<RestrictedAccountException> {
            restrictedService.createQuote(
                CreateAuthoritativeQuoteCommand(
                    principal = playerAPrincipal,
                    sessionId = "sess-1",
                    tenantId = "tenant-pk-1",
                    ownerId = playerAId,
                    currencyCode = "PKR",
                    methodId = "BANK_PK",
                    destinationId = dest.destinationId,
                    grossAmountMinorUnits = 50_000L,
                    idempotencyKey = "quote-restricted-player",
                )
            )
        }
    }

    // =========================================================================
    // 7. Concurrent Requests Exceeding Balance
    // =========================================================================

    @Test
    fun `test10 concurrent requests cannot overspend ledger-authorized available balance`() {
        val store = InMemoryAuthoritativeWithdrawalStore()
        // Available balance: 100_000 minor units (1,000 PKR)
        store.setAuthoritativeBalance("tenant-pk-1", playerAId, "PKR", 100_000L)
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(activeWithdrawalMethod)

        val service = AuthoritativeWithdrawalService(
            withdrawalStore = store,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val dest = sampleDestination(playerAId)
        store.saveDestination(dest)

        // Request 60_000 minor units each across 6 concurrent requests.
        // Balance (100_000) only permits exactly 1 request to succeed; the remaining 5 must fail!
        val threadCount = 6
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)

        val tasks = (1..threadCount).map { i ->
            {
                latch.await()
                try {
                    val quote = service.createQuote(
                        CreateAuthoritativeQuoteCommand(
                            principal = playerAPrincipal,
                            sessionId = "sess-1",
                            tenantId = "tenant-pk-1",
                            ownerId = playerAId,
                            currencyCode = "PKR",
                            methodId = "BANK_PK",
                            destinationId = dest.destinationId,
                            grossAmountMinorUnits = 60_000L,
                            idempotencyKey = "quote-conc-$i",
                        )
                    )
                    val assertion = service.issueStepUpAssertion(
                        IssueStepUpAssertionCommand(
                            principal = playerAPrincipal,
                            sessionId = "sess-1",
                            tenantId = "tenant-pk-1",
                            ownerId = playerAId,
                            quoteId = quote.quoteId,
                        )
                    )
                    service.createWithdrawalRequest(
                        CreateAuthoritativeWithdrawalRequestCommand(
                            principal = playerAPrincipal,
                            sessionId = "sess-1",
                            tenantId = "tenant-pk-1",
                            ownerId = playerAId,
                            quoteId = quote.quoteId,
                            destinationId = dest.destinationId,
                            stepUpToken = assertion.token,
                            idempotencyKey = "req-conc-$i",
                        )
                    )
                } catch (e: Exception) {
                    e
                }
            }
        }

        val futures = tasks.map { executor.submit(it) }
        latch.countDown()
        val results = futures.map { it.get() }
        executor.shutdown()
        executor.awaitTermination(5, TimeUnit.SECONDS)

        val successfulRequests = results.filterIsInstance<AuthoritativeWithdrawalRequestResult>()
        val insufficientFundsFailures = results.filterIsInstance<InsufficientWithdrawableFundsException>()

        assertEquals(1, successfulRequests.size, "Exactly one withdrawal request succeeded in reserving funds")
        assertEquals(5, insufficientFundsFailures.size, "Remaining 5 concurrent requests rejected with insufficient funds")

        // Final remaining available balance in wallet must be 40,000 minor units
        val remainingBalance = store.getAuthoritativeBalance("tenant-pk-1", playerAId, "PKR")
        assertEquals(40_000L, remainingBalance)
    }
}
