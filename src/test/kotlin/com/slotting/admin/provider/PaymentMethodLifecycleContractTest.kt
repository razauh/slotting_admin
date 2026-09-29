package com.slotting.admin.provider

import com.slotting.admin.auth.*
import org.junit.jupiter.api.Test
import org.springframework.jdbc.core.JdbcTemplate
import org.mockito.Mockito.*
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/**
 * TC-010 TDD Contract Test Suite:
 * Establish durable admin-configurable payment-method lifecycle.
 */
class PaymentMethodLifecycleContractTest {

    private val now = Instant.parse("2026-09-24T18:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val superAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-super-01",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val supportAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-support-01",
        tenantId = "tenant-pk-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPPORT),
    )

    private val foreignAdminPrincipal = AuthenticatedPrincipal(
        id = "admin-foreign-01",
        tenantId = "tenant-other-2",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SUPER_ADMIN),
    )

    private val sessionDir = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? {
            return when (sessionId) {
                "sess-valid" -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(8)), mfaVerified = true)
                "sess-expired" -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.minus(Duration.ofSeconds(10)), mfaVerified = true)
                "sess-inactive" -> AdminSessionStatus(active = false, breakGlass = false, expiresAt = now.plus(Duration.ofHours(8)), mfaVerified = true)
                "sess-no-mfa" -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(8)), mfaVerified = false)
                else -> AdminSessionStatus(active = true, breakGlass = false, expiresAt = now.plus(Duration.ofHours(8)), mfaVerified = true)
            }
        }
    }

    private val policy = AdminRbacPolicy(dualControlRequired = false)

    private fun validCommand(
        action: PaymentMethodAction = PaymentMethodAction.REGISTER,
        methodId: String = "EASYPAISA",
        providerId: String = "provider-ep-1",
        displayName: String = "Easypaisa Mobile Account",
        methodType: PaymentMethodType = PaymentMethodType.MOBILE_WALLET,
        supportedCurrencies: List<String> = listOf("PKR"),
        allowsDeposit: Boolean = true,
        allowsWithdrawal: Boolean = true,
        minDepositMinorUnits: Long = 10_000L, // 100.00 PKR
        maxDepositMinorUnits: Long = 5_000_000L, // 50,000.00 PKR
        minWithdrawalMinorUnits: Long = 10_000L,
        maxWithdrawalMinorUnits: Long = 2_500_000L,
        feeFlatMinorUnits: Long = 500L, // 5.00 PKR
        feePercentageBps: Int = 150, // 1.5%
        displayOrder: Int = 1,
        safeAccountTitle: String? = "Official Merchant Wallet",
        safeAccountNumber: String? = "03001234567",
        instructions: String? = "Send payment to mobile account and enter transaction ID.",
        iconUrl: String? = "https://assets.example.com/icons/easypaisa.png",
        maintenanceReason: String? = null,
        changeReason: String? = "Initial registration",
        idempotencyKey: String = "IDEM-${UUID.randomUUID()}",
        correlationId: String = "corr-1",
        causationId: String = "caus-1",
        expectedVersion: Long = 0L,
        principal: AuthenticatedPrincipal? = superAdminPrincipal,
        sessionId: String = "sess-valid",
        tenantId: String = "tenant-pk-1",
    ) = PaymentMethodCommand(
        principal = principal,
        sessionId = sessionId,
        tenantId = tenantId,
        methodId = methodId,
        providerId = providerId,
        action = action,
        displayName = displayName,
        methodType = methodType,
        instructions = instructions,
        safeAccountTitle = safeAccountTitle,
        safeAccountNumber = safeAccountNumber,
        iconUrl = iconUrl,
        supportedCurrencies = supportedCurrencies,
        allowsDeposit = allowsDeposit,
        allowsWithdrawal = allowsWithdrawal,
        minDepositMinorUnits = minDepositMinorUnits,
        maxDepositMinorUnits = maxDepositMinorUnits,
        minWithdrawalMinorUnits = minWithdrawalMinorUnits,
        maxWithdrawalMinorUnits = maxWithdrawalMinorUnits,
        feeFlatMinorUnits = feeFlatMinorUnits,
        feePercentageBps = feePercentageBps,
        displayOrder = displayOrder,
        maintenanceReason = maintenanceReason,
        changeReason = changeReason,
        idempotencyKey = idempotencyKey,
        correlationId = correlationId,
        causationId = causationId,
        expectedVersion = expectedVersion,
    )

    // =========================================================================
    // 1. Authorization, Tenant, Session, MFA Tests
    // =========================================================================

    @Test
    fun `test01 mutation requires dedicated PAYMENT_CONFIGURATION permission`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        val cmd = validCommand(principal = supportAdminPrincipal) // Lacks PAYMENT_CONFIGURATION
        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(cmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
    }

    @Test
    fun `test02 mutation rejects foreign tenant admin`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        val cmd = validCommand(principal = foreignAdminPrincipal)
        val ex = assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(cmd)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, ex.code)
    }

    @Test
    fun `test03 mutation rejects unauthenticated, inactive, expired, or unverified MFA session`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        // Null principal
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // Expired session
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(sessionId = "sess-expired"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Inactive session
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(sessionId = "sess-inactive"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // Unverified MFA
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(sessionId = "sess-no-mfa"))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }
    }

    // =========================================================================
    // 2. Validation & Security: Bounds, Currencies, Secret Leakage
    // =========================================================================

    @Test
    fun `test04 register validates fields, bounds, currencies, and rejects secret keys`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        // Inverted deposit range (min > max)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(minDepositMinorUnits = 5000L, maxDepositMinorUnits = 1000L))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Inverted withdrawal range (min > max)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(minWithdrawalMinorUnits = 5000L, maxWithdrawalMinorUnits = 1000L))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Negative fees or invalid fee bps (> 10000)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(feePercentageBps = 10001))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(feeFlatMinorUnits = -1L))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Invalid currency code
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(supportedCurrencies = listOf("invalid_pkr")))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // Secret keys / credentials leakage attempt in instructions or title
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(instructions = "Use apiKeySecret=sk_live_secret to connect"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(validCommand(safeAccountTitle = "Merchant password=root"))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // 3. Pakistani Payment Methods Registration & Configuration
    // =========================================================================

    @Test
    fun `test05 register Pakistani payment methods successfully`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        // 1. Easypaisa
        val epResult = service.operate(
            validCommand(
                methodId = "EASYPAISA",
                displayName = "Easypaisa Wallet",
                methodType = PaymentMethodType.MOBILE_WALLET,
                safeAccountTitle = "PK Official Easypaisa",
                safeAccountNumber = "03001234567",
            )
        )
        assertEquals("EASYPAISA", epResult.method.methodId)
        assertEquals(PaymentMethodStatus.ACTIVE, epResult.method.status)
        assertEquals(1L, epResult.method.serverVersion)

        // 2. JazzCash
        val jcResult = service.operate(
            validCommand(
                methodId = "JAZZCASH",
                displayName = "JazzCash Wallet",
                methodType = PaymentMethodType.MOBILE_WALLET,
                safeAccountTitle = "PK Official JazzCash",
                safeAccountNumber = "03017654321",
                displayOrder = 2,
            )
        )
        assertEquals("JAZZCASH", jcResult.method.methodId)
        assertEquals(PaymentMethodStatus.ACTIVE, jcResult.method.status)

        // 3. Bank Transfer
        val btResult = service.operate(
            validCommand(
                methodId = "BANK_TRANSFER",
                displayName = "Direct Bank Transfer",
                methodType = PaymentMethodType.BANK_TRANSFER,
                safeAccountTitle = "Slotting Operating Pvt Ltd",
                safeAccountNumber = "PK36MEZN0001234567890101",
                displayOrder = 3,
            )
        )
        assertEquals("BANK_TRANSFER", btResult.method.methodId)
        assertEquals(PaymentMethodStatus.ACTIVE, btResult.method.status)

        // 4. Raast
        val raastResult = service.operate(
            validCommand(
                methodId = "RAAST",
                displayName = "Raast Instant Payment",
                methodType = PaymentMethodType.INSTANT_PAYMENT,
                safeAccountTitle = "Slotting Raast Alias",
                safeAccountNumber = "03001234567",
                displayOrder = 4,
            )
        )
        assertEquals("RAAST", raastResult.method.methodId)
        assertEquals(PaymentMethodStatus.ACTIVE, raastResult.method.status)

        // Verify listed methods
        val listed = service.listMethods("tenant-pk-1")
        assertEquals(4, listed.size)
    }

    // =========================================================================
    // 4. Idempotency Replay & Conflict
    // =========================================================================

    @Test
    fun `test06 idempotency replay returns cached result or CONFLICT on altered fingerprint`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        val cmd = validCommand(idempotencyKey = "IDEM-REPLAY-1")
        val firstResult = service.operate(cmd)

        // Exact replay with same idempotency key and params
        val replayed = service.operate(cmd)
        assertEquals(firstResult.resultId, replayed.resultId)
        assertEquals(firstResult.method.serverVersion, replayed.method.serverVersion)

        // Altered payload with same idempotency key -> CONFLICT
        val altered = cmd.copy(displayName = "Altered Name")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(altered)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // 5. Lifecycle Transitions: Update, Activate, Deactivate, Maintenance
    // =========================================================================

    @Test
    fun `test07 update config advances version and records history`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        val regResult = service.operate(validCommand(methodId = "EASYPAISA", expectedVersion = 0L))
        assertEquals(1L, regResult.method.serverVersion)

        val updateCmd = validCommand(
            methodId = "EASYPAISA",
            action = PaymentMethodAction.UPDATE_CONFIG,
            displayName = "Easypaisa Pro Account",
            expectedVersion = 1L,
            changeReason = "Updated merchant branding",
        )
        val updateResult = service.operate(updateCmd)
        assertEquals(2L, updateResult.method.serverVersion)
        assertEquals("Easypaisa Pro Account", updateResult.method.displayName)

        // Check history
        val history = service.listHistory("tenant-pk-1", "EASYPAISA")
        assertEquals(2, history.size)
        assertEquals("Initial registration", history[0].changeReason)
        assertEquals("Updated merchant branding", history[1].changeReason)
    }

    @Test
    fun `test08 activate, deactivate, and set maintenance with maintenance reason`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        val reg = service.operate(validCommand(methodId = "JAZZCASH", expectedVersion = 0L))
        assertEquals(PaymentMethodStatus.ACTIVE, reg.method.status)

        // Put into MAINTENANCE
        val maint = service.operate(
            validCommand(
                methodId = "JAZZCASH",
                action = PaymentMethodAction.SET_MAINTENANCE,
                expectedVersion = reg.method.serverVersion,
                maintenanceReason = "Upstream gateway downtime scheduled",
                changeReason = "Scheduled bank maintenance",
            )
        )
        assertEquals(PaymentMethodStatus.MAINTENANCE, maint.method.status)
        assertEquals("Upstream gateway downtime scheduled", maint.method.maintenanceReason)
        assertEquals(2L, maint.method.serverVersion)

        // DEACTIVATE
        val deact = service.operate(
            validCommand(
                methodId = "JAZZCASH",
                action = PaymentMethodAction.DEACTIVATE,
                expectedVersion = maint.method.serverVersion,
                changeReason = "Disabling provider temporarily",
            )
        )
        assertEquals(PaymentMethodStatus.INACTIVE, deact.method.status)
        assertEquals(3L, deact.method.serverVersion)

        // ACTIVATE
        val act = service.operate(
            validCommand(
                methodId = "JAZZCASH",
                action = PaymentMethodAction.ACTIVATE,
                expectedVersion = deact.method.serverVersion,
                changeReason = "Restoring service",
            )
        )
        assertEquals(PaymentMethodStatus.ACTIVE, act.method.status)
        assertEquals(4L, act.method.serverVersion)
        assertNull(act.method.maintenanceReason)
    }

    @Test
    fun `test09 deactivation retains method in list and preserves full history`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        service.operate(validCommand(methodId = "BANK_TRANSFER", expectedVersion = 0L))
        service.operate(
            validCommand(
                methodId = "BANK_TRANSFER",
                action = PaymentMethodAction.DEACTIVATE,
                expectedVersion = 1L,
                changeReason = "Temporarily disabled for audit",
            )
        )

        // Retained in list
        val listed = service.listMethods("tenant-pk-1")
        assertEquals(1, listed.size)
        assertEquals(PaymentMethodStatus.INACTIVE, listed[0].status)

        // History preserved
        val history = service.listHistory("tenant-pk-1", "BANK_TRANSFER")
        assertEquals(2, history.size)
        assertEquals(PaymentMethodStatus.ACTIVE, history[0].status)
        assertEquals(PaymentMethodStatus.INACTIVE, history[1].status)
    }

    // =========================================================================
    // 6. CAS Versioning and Concurrency
    // =========================================================================

    @Test
    fun `test10 stale expectedVersion rejected with STALE`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        service.operate(validCommand(methodId = "RAAST", expectedVersion = 0L))

        // Provide stale expectedVersion 0L when current is 1L
        val staleCmd = validCommand(
            methodId = "RAAST",
            action = PaymentMethodAction.DEACTIVATE,
            expectedVersion = 0L,
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.operate(staleCmd)
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }
    }

    @Test
    fun `test11 concurrent CAS updates allow exactly one winner and reject others`() {
        val store = InMemoryPaymentMethodStore()
        val service = PaymentMethodLifecycleService(policy, sessionDir, store, clock)

        service.operate(validCommand(methodId = "EASYPAISA", expectedVersion = 0L))

        val threadCount = 8
        val executor = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(1)

        val tasks = (1..threadCount).map { i ->
            {
                latch.await()
                try {
                    service.operate(
                        validCommand(
                            methodId = "EASYPAISA",
                            action = PaymentMethodAction.UPDATE_CONFIG,
                            displayName = "Concurrent Name $i",
                            expectedVersion = 1L,
                            idempotencyKey = "IDEM-CONCURRENT-$i",
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

        val successCount = results.count { it is PaymentMethodResult }
        val staleCount = results.count { it is AuthenticationFailure.Rejected && it.code == AuthErrorCode.STALE }

        assertEquals(1, successCount, "Exactly one concurrent thread succeeds on version 1")
        assertEquals(threadCount - 1, staleCount, "All other concurrent callers must be rejected as STALE")
    }

    @Test
    fun `test12 CAS row count verification in JdbcPaymentProviderConfigStore`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        val store = JdbcPaymentProviderConfigStore(mockJdbc)

        // Mock findProvider returning an existing provider config (version 1)
        val existingProvider = PaymentProviderConfig(
            providerId = "provider-test",
            displayName = "Test Provider",
            status = PaymentProviderStatus.ENABLED,
            endpointUrl = "https://api.test.com",
            maskedSecretPreview = "****1234",
            incidentReference = null,
            serverVersion = 1L,
        )
        `when`(mockJdbc.query(anyString(), any<org.springframework.jdbc.core.RowMapper<PaymentProviderConfig>>(), eq("tenant-pk-1"), eq("provider-test")))
            .thenReturn(listOf(existingProvider))

        // When jdbc.update for update returns 0 affected rows (CAS race lost)
        `when`(mockJdbc.update(startsWith("update admin_payment_provider_config"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0)

        val result = PaymentProviderConfigResult(
            resultId = UUID.randomUUID(),
            provider = existingProvider.copy(serverVersion = 2L),
            serverTime = now,
            evidenceReference = "ev-1",
        )
        val audit = AuditEvent(UUID.randomUUID(), result.resultId, "tenant-pk-1", "TEST", now, "c-1", "ca-1")
        val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, "tenant-pk-1", "TEST", now)

        // Must throw CONFLICT due to VersionedCasHelper.requireUpdated
        assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(
                result = result,
                tenantId = "tenant-pk-1",
                secretHash = "",
                queryFingerprint = "fingerprint-1",
                idempotencyKey = "idem-1",
                audit = audit,
                outbox = outbox,
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    @Test
    fun `test13 JdbcPaymentMethodStore enforces CAS row count on insert and update`() {
        val mockJdbc = mock(JdbcTemplate::class.java)
        val store = JdbcPaymentMethodStore(mockJdbc)

        val methodConfig = PaymentMethodConfig(
            tenantId = "tenant-pk-1",
            methodId = "EASYPAISA",
            providerId = "provider-ep-1",
            methodType = PaymentMethodType.MOBILE_WALLET,
            displayName = "Easypaisa Wallet",
            instructions = "Instructions",
            safeAccountTitle = "Official Title",
            safeAccountNumber = "03001234567",
            iconUrl = "https://example.com/icon.png",
            supportedCurrencies = listOf("PKR"),
            allowsDeposit = true,
            allowsWithdrawal = true,
            minDepositMinorUnits = 1000L,
            maxDepositMinorUnits = 500000L,
            minWithdrawalMinorUnits = 1000L,
            maxWithdrawalMinorUnits = 250000L,
            feeFlatMinorUnits = 500L,
            feePercentageBps = 150,
            displayOrder = 1,
            status = PaymentMethodStatus.ACTIVE,
            maintenanceReason = null,
            serverVersion = 1L,
            createdAt = now,
            updatedAt = now,
            updatedBy = "admin-1",
        )
        val result = PaymentMethodResult(
            resultId = UUID.randomUUID(),
            method = methodConfig,
            serverTime = now,
            evidenceReference = "ev-1",
        )
        val audit = AuditEvent(UUID.randomUUID(), result.resultId, "tenant-pk-1", "TEST", now, "c-1", "ca-1")
        val outbox = OutboxEvent(UUID.randomUUID(), result.resultId, "tenant-pk-1", "TEST", now)

        // 1. CAS insert failure: 0 rows inserted
        `when`(mockJdbc.update(startsWith("insert into admin_payment_method"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0)

        assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(
                result = result,
                queryFingerprint = "fp-1",
                idempotencyKey = "idem-1",
                action = PaymentMethodAction.REGISTER,
                changeReason = "reg",
                changedBy = "admin-1",
                audit = audit,
                outbox = outbox,
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }

        // 2. CAS update failure: 0 rows updated
        val updateResult = result.copy(method = methodConfig.copy(serverVersion = 2L))
        `when`(mockJdbc.update(startsWith("update admin_payment_method set"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
            .thenReturn(0)

        assertFailsWith<AuthenticationFailure.Rejected> {
            store.save(
                result = updateResult,
                queryFingerprint = "fp-2",
                idempotencyKey = "idem-2",
                action = PaymentMethodAction.UPDATE_CONFIG,
                changeReason = "update",
                changedBy = "admin-1",
                audit = audit,
                outbox = outbox,
            )
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }
}

