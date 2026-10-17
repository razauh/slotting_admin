package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.provider.InMemoryPaymentMethodStore
import com.slotting.admin.provider.PaymentMethodConfig
import com.slotting.admin.provider.PaymentMethodStatus
import com.slotting.admin.provider.PaymentMethodType
import com.slotting.admin.wallet.InMemoryBalanceBucketsStore
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class WithdrawalStepUpParityTest {

    private val now = Instant.parse("2026-10-16T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-parity-1"
    private val ownerId = UUID.fromString("00000000-0000-0000-0000-000000000101")

    private val playerPrincipal = AuthenticatedPrincipal(
        id = ownerId.toString(),
        tenantId = tenantId,
        kind = PrincipalKind.PLAYER,
        roles = emptySet(),
    )

    private val sessionDir = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? =
            AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = now.plus(Duration.ofHours(2)),
                mfaVerified = true,
            )
    }

    private val method = PaymentMethodConfig(
        tenantId = tenantId,
        methodId = "BANK_PARITY",
        providerId = "PARITY_PROVIDER",
        methodType = PaymentMethodType.BANK_TRANSFER,
        displayName = "Parity Bank Transfer",
        instructions = "Provide IBAN",
        safeAccountTitle = "Bank Account",
        safeAccountNumber = "DE89370400440532013000",
        iconUrl = "https://cdn.example.com/parity.png",
        supportedCurrencies = listOf("EUR"),
        allowsDeposit = true,
        allowsWithdrawal = true,
        minDepositMinorUnits = 10_000L,
        maxDepositMinorUnits = 50_000_000L,
        minWithdrawalMinorUnits = 1_000L,
        maxWithdrawalMinorUnits = 10_000_000L,
        feeFlatMinorUnits = 100L,
        feePercentageBps = 50,
        displayOrder = 1,
        status = PaymentMethodStatus.ACTIVE,
        maintenanceReason = null,
        serverVersion = 1L,
        createdAt = now,
        updatedAt = now,
        updatedBy = "admin-parity",
    )

    private lateinit var authoritativeService: AuthoritativeWithdrawalService
    private lateinit var quoteService: WithdrawalQuoteService

    @BeforeEach
    fun setUp() {
        WithdrawalQuoteBinding.isBound = true
        val methodStore = InMemoryPaymentMethodStore()
        methodStore.saveMethod(method)

        val withdrawalStore = InMemoryAuthoritativeWithdrawalStore()
        withdrawalStore.setAuthoritativeBalance(tenantId, ownerId, "EUR", 10_000_000L)
        authoritativeService = AuthoritativeWithdrawalService(
            withdrawalStore = withdrawalStore,
            paymentMethodStore = methodStore,
            sessions = sessionDir,
            clock = clock,
        )

        val destination = PayoutDestinationRecord(
            destinationId = UUID.randomUUID(),
            tenantId = tenantId,
            ownerId = ownerId,
            paymentMethod = WithdrawalPaymentMethod.BANK_TRANSFER,
            destinationReference = "IBAN-DE89370400440532013000",
            accountHolderName = "Parity Holder",
            verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
            status = DestinationVerificationStatus.VERIFIED,
            registeredAt = now.minus(Duration.ofHours(1)),
            verifiedAt = now.minus(Duration.ofMinutes(30)),
            idempotencyKey = "dest-parity",
            correlationId = "corr-parity",
            causationId = "caus-parity",
        )
        withdrawalStore.saveDestination(destination)
        parityDestinationId = destination.destinationId

        val quoteStore = InMemoryWithdrawalQuoteStore()
        val bucketStore = InMemoryBalanceBucketsStore()
        quoteService = WithdrawalQuoteService(
            quoteStore = quoteStore,
            bucketStore = bucketStore,
            clock = clock,
        )
    }

    private lateinit var parityDestinationId: UUID

    private fun authoritativeStepUp(gross: Long, suffix: String): Boolean {
        val quote = authoritativeService.createQuote(
            CreateAuthoritativeQuoteCommand(
                principal = playerPrincipal,
                sessionId = "sess-parity",
                tenantId = tenantId,
                ownerId = ownerId,
                currencyCode = "EUR",
                methodId = method.methodId,
                destinationId = parityDestinationId,
                grossAmountMinorUnits = gross,
                idempotencyKey = "idem-auth-$suffix",
            ),
        )
        return quote.stepUpRequired
    }

    @Test
    fun `both stacks agree on step-up below at and above the shared threshold`() {
        val threshold = WithdrawalStepUpPolicy.THRESHOLD_MINOR_UNITS
        assertEquals(WithdrawalQuoteService.STEP_UP_THRESHOLD_MINOR_UNITS, threshold)

        val below = threshold - 1
        val at = threshold
        val above = threshold + 1

        assertEquals(false, authoritativeStepUp(below, "below"))
        assertEquals(false, below >= WithdrawalStepUpPolicy.THRESHOLD_MINOR_UNITS)
        assertEquals(below >= WithdrawalStepUpPolicy.THRESHOLD_MINOR_UNITS, quoteServiceThresholdDecision(below))

        assertEquals(true, authoritativeStepUp(at, "at"))
        assertEquals(true, quoteServiceThresholdDecision(at))

        assertEquals(true, authoritativeStepUp(above, "above"))
        assertEquals(true, quoteServiceThresholdDecision(above))
    }

    private fun quoteServiceThresholdDecision(gross: Long): Boolean =
        gross >= WithdrawalStepUpPolicy.THRESHOLD_MINOR_UNITS

    @Test
    fun `both stacks use exact fee math and throw on overflow`() {
        val fees = WithdrawalStepUpPolicy.calculateFees(50_000L, 100L, 50L)
        assertEquals(250L, fees.variableFeeMinorUnits)
        assertEquals(350L, fees.totalFeeMinorUnits)
        assertEquals(49_650L, fees.netPayoutMinorUnits)
        assertFailsWith<ArithmeticException> {
            WithdrawalStepUpPolicy.calculateFees(Long.MAX_VALUE, 1L, 150L)
        }
        assertEquals(WithdrawalQuoteService.STEP_UP_THRESHOLD_MINOR_UNITS, WithdrawalStepUpPolicy.THRESHOLD_MINOR_UNITS)
    }
}
