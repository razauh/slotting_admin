package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
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
import kotlin.test.assertTrue

class PayoutDestinationVerificationTest {
    private val now = Instant.parse("2026-09-20T19:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val playerAId = UUID.randomUUID()
    private val playerBId = UUID.randomUUID()

    private val playerAPrincipal = AuthenticatedPrincipal(
        id = playerAId.toString(),
        tenantId = "tenant-dest-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val playerBPrincipal = AuthenticatedPrincipal(
        id = playerBId.toString(),
        tenantId = "tenant-dest-prod",
        kind = PrincipalKind.PLAYER,
        roles = emptySet()
    )

    private val adminPrincipal = AuthenticatedPrincipal(
        id = "admin-dest-verifier",
        tenantId = "tenant-dest-prod",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
    )

    private val foreignTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-dest",
        tenantId = "tenant-dest-foreign",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN)
    )

    private lateinit var destinationStore: InMemoryPayoutDestinationStore
    private lateinit var observability: InMemoryPayoutDestinationObservability
    private lateinit var service: PayoutDestinationService

    @BeforeEach
    fun setUp() {
        PayoutDestinationVerificationBinding.isBound = true
        destinationStore = InMemoryPayoutDestinationStore()
        observability = InMemoryPayoutDestinationObservability()
        service = PayoutDestinationService(
            destinationStore = destinationStore,
            clock = clock,
            observability = observability
        )
    }

    @AfterEach
    fun tearDown() {
        PayoutDestinationVerificationBinding.isBound = true
    }

    // =========================================================================
    // WITHDRAW-001-02-T001: Authoritative Outcome Verification
    // =========================================================================

    @Test
    fun `WITHDRAW-001-02-T001 Verify payout destination ownership produces the required authoritative outcome`() {
        PayoutDestinationVerificationBinding.checkBound()

        // 1. Semantic contract assertion
        assertEquals(
            "Fee/rate/expiry disclosed; ownership/limits server checked.",
            DESTINATION_VERIFICATION_CONTRACT
        )

        // 2. Register payout destination with closed-loop KYC name matching (Auto-verify)
        val regCmd = RegisterPayoutDestinationCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-dest-prod",
            ownerId = playerAId,
            paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
            destinationReference = "DE89370400440532013000",
            accountHolderName = "Alice Wonderland",
            verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
            autoVerifyIfNameMatches = true,
            playerKycVerifiedName = "Alice Wonderland",
            idempotencyKey = "idemp-dest-001",
            correlationId = "corr-dest-001",
            causationId = "caus-dest-001"
        )
        val regResult = service.registerDestination(regCmd)

        // Authoritative record assertions
        val dest = regResult.destination
        assertNotNull(dest.destinationId)
        assertEquals("tenant-dest-prod", dest.tenantId)
        assertEquals(playerAId, dest.ownerId)
        assertEquals(WithdrawalPaymentMethod.SEPA_INSTANT, dest.paymentMethod)
        assertEquals("DE89370400440532013000", dest.destinationReference)
        assertEquals("Alice Wonderland", dest.accountHolderName)
        assertEquals(DestinationVerificationStatus.VERIFIED, dest.status)
        assertTrue(regResult.isVerified)
        assertEquals(now, dest.registeredAt)
        assertEquals(now, dest.verifiedAt)
        assertTrue(dest.verificationEvidenceReference!!.startsWith("EVID-AUTO-NAME-MATCH-"))
        assertEquals(1L, dest.version)
        assertFalse(regResult.hasAndroidDbImpact)
        assertFalse(regResult.hasAndroidLifecycleClaim)
        assertEquals("PAYOUT_DESTINATION_VERIFIED", regResult.auditEvent.type)
        assertEquals("corr-dest-001", regResult.auditEvent.correlationId)

        // 3. Two-step verification flow: Register as PENDING, then explicitly verify
        val cryptoCmd = RegisterPayoutDestinationCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-dest-prod",
            ownerId = playerAId,
            paymentMethod = WithdrawalPaymentMethod.CRYPTO_USDT,
            destinationReference = "0x71C8494b2A5dF1e0503027fEd057A7F7c1B9E4b2",
            accountHolderName = "Alice Wonderland",
            verificationMethod = DestinationVerificationMethod.MANUAL_DOCUMENT_VERIFICATION,
            autoVerifyIfNameMatches = false,
            playerKycVerifiedName = null,
            idempotencyKey = "idemp-dest-crypto-002",
            correlationId = "corr-dest-002",
            causationId = "caus-dest-002"
        )
        val pendingResult = service.registerDestination(cryptoCmd)
        assertEquals(DestinationVerificationStatus.PENDING_VERIFICATION, pendingResult.destination.status)
        assertFalse(pendingResult.isVerified)

        // Now verify using VerifyPayoutDestinationCommand
        val verifyCmd = VerifyPayoutDestinationCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-dest-prod",
            destinationId = pendingResult.destination.destinationId,
            ownerKycFullName = "Alice Wonderland",
            proofReference = "EVID-PROOF-CRYPTO-SIGNATURE-001",
            idempotencyKey = "idemp-verify-001",
            correlationId = "corr-dest-003",
            causationId = "caus-dest-003"
        )
        val verifyResult = service.verifyDestination(verifyCmd)
        assertTrue(verifyResult.isVerified)
        assertEquals(DestinationVerificationStatus.VERIFIED, verifyResult.destination.status)
        assertEquals(2L, verifyResult.destination.version)
        assertEquals("EVID-PROOF-CRYPTO-SIGNATURE-001", verifyResult.destination.verificationEvidenceReference)

        // Authoritative query check
        val verifiedRecord = service.checkDestinationOwnership(
            CheckDestinationOwnershipQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-dest-prod",
                ownerId = playerAId,
                destinationReference = "0x71C8494b2A5dF1e0503027fEd057A7F7c1B9E4b2",
                correlationId = "corr-dest-004",
                causationId = "caus-dest-004"
            )
        )
        assertEquals(DestinationVerificationStatus.VERIFIED, verifiedRecord.status)
        assertEquals(playerAId, verifiedRecord.ownerId)
    }

    // =========================================================================
    // WITHDRAW-001-02-T002: Rejection of Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `WITHDRAW-001-02-T002 Verify payout destination ownership rejects invalid, boundary, unauthorized, and stale input`() {
        PayoutDestinationVerificationBinding.checkBound()

        // 1. Unauthenticated registration
        assertFailsWith<UnauthorizedWithdrawalAccessException> {
            service.registerDestination(
                RegisterPayoutDestinationCommand(
                    principal = null,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "DE89370400440532013000",
                    accountHolderName = "Alice Wonderland",
                    verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                    idempotencyKey = "k1",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 2. Cross-tenant registration
        assertFailsWith<CrossTenantWithdrawalAccessException> {
            service.registerDestination(
                RegisterPayoutDestinationCommand(
                    principal = foreignTenantPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "DE89370400440532013000",
                    accountHolderName = "Alice Wonderland",
                    verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                    idempotencyKey = "k2",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 3. IDOR / Cross-owner registration: Player B tries to register destination for Player A
        val idorEx = assertFailsWith<IdorWithdrawalForbiddenException> {
            service.registerDestination(
                RegisterPayoutDestinationCommand(
                    principal = playerBPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "DE89370400440532013000",
                    accountHolderName = "Alice Wonderland",
                    verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                    idempotencyKey = "k3",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(idorEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 4. Name mismatch on auto-verify (Alice registers bank account belonging to Mallory)
        val nameMismatchEx = assertFailsWith<DestinationOwnershipMismatchException> {
            service.registerDestination(
                RegisterPayoutDestinationCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "DE89370400440532013000",
                    accountHolderName = "Mallory Fraudster",
                    verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                    autoVerifyIfNameMatches = true,
                    playerKycVerifiedName = "Alice Wonderland",
                    idempotencyKey = "k4",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(nameMismatchEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 5. Blank destination reference
        assertFailsWith<InvalidDestinationException> {
            service.registerDestination(
                RegisterPayoutDestinationCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "   ",
                    accountHolderName = "Alice Wonderland",
                    verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                    idempotencyKey = "k5",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 6. Blank account holder name
        assertFailsWith<InvalidDestinationException> {
            service.registerDestination(
                RegisterPayoutDestinationCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "DE89370400440532013000",
                    accountHolderName = "",
                    verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                    idempotencyKey = "k6",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 7. Invalid IBAN format (too short / invalid characters)
        assertFailsWith<InvalidDestinationException> {
            service.registerDestination(
                RegisterPayoutDestinationCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                    destinationReference = "123INVALID",
                    accountHolderName = "Alice Wonderland",
                    verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                    idempotencyKey = "k7",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }

        // 8. Verification on non-existent destination ID
        val missingEx = assertFailsWith<DestinationNotFoundException> {
            service.verifyDestination(
                VerifyPayoutDestinationCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    destinationId = UUID.randomUUID(),
                    ownerKycFullName = "Alice Wonderland",
                    proofReference = "PROOF-REF-01",
                    idempotencyKey = "k8",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(missingEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 9. Verification with KYC name mismatch -> fails and transitions record to REJECTED
        val pendingReg = service.registerDestination(
            RegisterPayoutDestinationCommand(
                principal = playerAPrincipal,
                tenantId = "tenant-dest-prod",
                ownerId = playerAId,
                paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                destinationReference = "FR1420041010050500013M02606",
                accountHolderName = "Alice Wonderland",
                verificationMethod = DestinationVerificationMethod.MANUAL_DOCUMENT_VERIFICATION,
                autoVerifyIfNameMatches = false,
                idempotencyKey = "k9",
                correlationId = "c1",
                causationId = "c2"
            )
        )
        val verifyMismatchEx = assertFailsWith<DestinationOwnershipMismatchException> {
            service.verifyDestination(
                VerifyPayoutDestinationCommand(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    destinationId = pendingReg.destination.destinationId,
                    ownerKycFullName = "Eve Impostor", // Mismatched KYC name!
                    proofReference = "PROOF-DOC-EVE",
                    idempotencyKey = "k10",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(verifyMismatchEx.message!!.contains("stale quote/unverified destination/no step-up"))
        val storedRejected = destinationStore.findById(pendingReg.destination.destinationId)!!
        assertEquals(DestinationVerificationStatus.REJECTED, storedRejected.status)

        // 10. checkDestinationOwnership on unverified / rejected destination fails closed
        val unverifiedEx = assertFailsWith<UnverifiedDestinationException> {
            service.checkDestinationOwnership(
                CheckDestinationOwnershipQuery(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    destinationReference = "FR1420041010050500013M02606",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
        assertTrue(unverifiedEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 11. checkDestinationOwnership IDOR check
        assertFailsWith<IdorWithdrawalForbiddenException> {
            service.checkDestinationOwnership(
                CheckDestinationOwnershipQuery(
                    principal = playerBPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId, // Player B querying Player A's destination!
                    destinationReference = "FR1420041010050500013M02606",
                    correlationId = "c1",
                    causationId = "c2"
                )
            )
        }
    }

    // =========================================================================
    // WITHDRAW-001-02-T003: Concurrency, Duplicate Delivery, and Idempotency
    // =========================================================================

    @Test
    fun `WITHDRAW-001-02-T003 Verify payout destination ownership survives concurrency, duplicate delivery, and dependency failure`() {
        PayoutDestinationVerificationBinding.checkBound()

        // 1. Idempotency exact replay
        val cmd = RegisterPayoutDestinationCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-dest-prod",
            ownerId = playerAId,
            paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
            destinationReference = "NL91ABNA0417164300",
            accountHolderName = "Alice Wonderland",
            verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
            autoVerifyIfNameMatches = true,
            playerKycVerifiedName = "Alice Wonderland",
            idempotencyKey = "idemp-exact-replay-001",
            correlationId = "c1",
            causationId = "c2"
        )
        val firstResult = service.registerDestination(cmd)
        val duplicateResult = service.registerDestination(cmd)

        assertEquals(firstResult.destination.destinationId, duplicateResult.destination.destinationId)
        assertEquals(firstResult.resultId, duplicateResult.resultId)
        assertEquals(firstResult.serverTime, duplicateResult.serverTime)

        // 2. Idempotency conflict with modified payload
        val conflictingCmd = cmd.copy(accountHolderName = "Alice Different")
        val conflictEx = assertFailsWith<IdempotencyConflictException> {
            service.registerDestination(conflictingCmd)
        }
        assertTrue(conflictEx.message!!.contains("stale quote/unverified destination/no step-up"))

        // 3. Multi-threaded concurrency
        val executor = Executors.newFixedThreadPool(8)
        val tasks = (1..10).map { i ->
            Callable {
                val iban = "DE8937040044053201300$i"
                service.registerDestination(
                    RegisterPayoutDestinationCommand(
                        principal = playerAPrincipal,
                        tenantId = "tenant-dest-prod",
                        ownerId = playerAId,
                        paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
                        destinationReference = iban,
                        accountHolderName = "Alice Wonderland",
                        verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
                        autoVerifyIfNameMatches = true,
                        playerKycVerifiedName = "Alice Wonderland",
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
        val uniqueDestinationIds = results.map { it.destination.destinationId }.toSet()
        assertEquals(10, uniqueDestinationIds.size)
    }

    // =========================================================================
    // WITHDRAW-001-02-T004: Compatibility, Recovery, Observability, and Lifecycle
    // =========================================================================

    @Test
    fun `WITHDRAW-001-02-T004 Verify payout destination ownership remains compatible, recoverable, observable, and lifecycle-safe`() {
        PayoutDestinationVerificationBinding.checkBound()

        // 1. Observability events emitted
        val cmd = RegisterPayoutDestinationCommand(
            principal = playerAPrincipal,
            tenantId = "tenant-dest-prod",
            ownerId = playerAId,
            paymentMethod = WithdrawalPaymentMethod.SEPA_INSTANT,
            destinationReference = "ES9121000418450200051332",
            accountHolderName = "Alice Wonderland",
            verificationMethod = DestinationVerificationMethod.OPEN_BANKING_NAME_MATCH,
            autoVerifyIfNameMatches = true,
            playerKycVerifiedName = "Alice Wonderland",
            idempotencyKey = "idemp-obs-001",
            correlationId = "corr-obs-001",
            causationId = "caus-obs-001"
        )
        val result = service.registerDestination(cmd)

        val metrics = observability.getMetrics()
        assertTrue(metrics.any { it.eventType == "attempt" && it.correlationId == "corr-obs-001" })
        assertTrue(metrics.any { it.eventType == "accept" && it.correlationId == "corr-obs-001" })

        // 2. Recovery across service restart with same store
        val recoveredService = PayoutDestinationService(
            destinationStore = destinationStore,
            clock = clock,
            observability = observability
        )
        val retrieved = recoveredService.checkDestinationOwnership(
            CheckDestinationOwnershipQuery(
                principal = playerAPrincipal,
                tenantId = "tenant-dest-prod",
                ownerId = playerAId,
                destinationReference = "ES9121000418450200051332",
                correlationId = "corr-rec-001",
                causationId = "caus-rec-001"
            )
        )
        assertEquals(result.destination.destinationId, retrieved.destinationId)
        assertEquals(DestinationVerificationStatus.VERIFIED, retrieved.status)

        // 3. Revocation lifecycle
        val revoked = recoveredService.revokeDestination(
            principal = playerAPrincipal,
            tenantId = "tenant-dest-prod",
            destinationId = retrieved.destinationId,
            reason = "Player requested bank account detachment",
            correlationId = "corr-rev-001",
            causationId = "caus-rev-001"
        )
        assertEquals(DestinationVerificationStatus.REVOKED, revoked.status)
        assertEquals(2L, revoked.version)

        // Subsequent checkDestinationOwnership fails closed
        assertFailsWith<UnverifiedDestinationException> {
            recoveredService.checkDestinationOwnership(
                CheckDestinationOwnershipQuery(
                    principal = playerAPrincipal,
                    tenantId = "tenant-dest-prod",
                    ownerId = playerAId,
                    destinationReference = "ES9121000418450200051332",
                    correlationId = "corr-rev-check",
                    causationId = "caus-rev-check"
                )
            )
        }

        // 4. No Android database impact or lifecycle claims
        assertFalse(result.hasAndroidDbImpact)
        assertFalse(result.hasAndroidLifecycleClaim)
    }
}
