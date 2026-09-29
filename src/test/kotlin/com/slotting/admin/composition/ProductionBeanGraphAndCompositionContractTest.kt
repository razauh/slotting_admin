package com.slotting.admin.composition

import com.slotting.admin.auth.*
import com.slotting.admin.config.*
import com.slotting.admin.deposit.*
import com.slotting.admin.health.*
import com.slotting.admin.ledger.*
import com.slotting.admin.payment.CanonicalPaymentProviderPortBinding
import com.slotting.admin.provider.*
import com.slotting.admin.rg.*
import com.slotting.admin.security.SecurityAuthenticationFilter
import com.slotting.admin.wallet.*
import com.slotting.admin.withdrawal.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.Status
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.web.servlet.HandlerExecutionChain
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * TC-040: Production Spring composition, route security, services, workers,
 * and fail-closed readiness contract test.
 */
class ProductionBeanGraphAndCompositionContractTest {

    private val fixedClock = Clock.fixed(Instant.parse("2026-09-27T10:00:00Z"), ZoneOffset.UTC)

    // =========================================================================
    // 1. BEAN GRAPH VALIDATION & BAN OF FAKE/IN-MEMORY IN PRODUCTION
    // =========================================================================

    @Test
    fun `TC040-01 production bean graph validator rejects in-memory or fake authoritative beans`() {
        val validator = ProductionBeanGraphValidator(activeProfile = "production")

        // Given a context with an in-memory authoritative bean
        val context = AnnotationConfigApplicationContext()
        context.beanFactory.registerSingleton("inMemoryStore", InMemoryDurableAuthStore())
        context.refresh()

        val ex = assertThrows<IllegalStateException> {
            validator.postProcessBeanFactory(context.beanFactory)
        }
        assertTrue(ex.message!!.contains("InMemoryDurableAuthStore"))
        assertTrue(ex.message!!.contains("prohibited in production profile"))
    }

    @Test
    fun `TC040-02 production bean graph validator accepts durable JDBC implementations`() {
        val validator = ProductionBeanGraphValidator(activeProfile = "production")

        val context = AnnotationConfigApplicationContext()
        val mockJdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate::class.java)
        context.beanFactory.registerSingleton("jdbcDurableAuthStore", JdbcDurableAuthStore(mockJdbc))
        context.beanFactory.registerSingleton("jdbcAdminSessionDirectory", JdbcAdminSessionDirectory(mockJdbc))
        context.refresh()

        // Should not throw
        validator.postProcessBeanFactory(context.beanFactory)
        assertTrue(context.containsBean("jdbcDurableAuthStore"))
    }

    // =========================================================================
    // 2. CRITICAL DOMAIN BINDINGS INITIALIZATION
    // =========================================================================

    @Test
    fun `TC040-03 production composition binds critical payment and game domain bindings`() {
        // Reset to false first
        CanonicalPaymentProviderPortBinding.isBound = false

        // Activating production binding initializer
        val initializer = ProductionDomainBindingInitializer()
        initializer.initialize()

        // Verify bindings are now true/bound
        assertTrue(CanonicalPaymentProviderPortBinding.isBound, "CanonicalPaymentProviderPortBinding must be bound in production")
    }

    // =========================================================================
    // 3. SECURITY FILTER FAIL-CLOSED ON UNVERIFIED PRINCIPAL
    // =========================================================================

    @Test
    fun `TC040-04 security filter rejects unauthenticated request on protected route with 401`() {
        val mockAuthService = org.mockito.Mockito.mock(DurableAuthService::class.java)
        val mockSessionDir = org.mockito.Mockito.mock(AdminSessionDirectory::class.java)
        val filter = SecurityAuthenticationFilter(mockAuthService, mockSessionDir)

        val request = MockHttpServletRequest("GET", "/api/v1/tenants/tenant-1/wallet/snapshot")
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()

        filter.doFilter(request, response, chain)

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.status)
        assertNull(request.getAttribute("authenticatedPrincipal"))
    }

    @Test
    fun `TC040-05 security filter allows public endpoint without authentication`() {
        val mockAuthService = org.mockito.Mockito.mock(DurableAuthService::class.java)
        val mockSessionDir = org.mockito.Mockito.mock(AdminSessionDirectory::class.java)
        val filter = SecurityAuthenticationFilter(mockAuthService, mockSessionDir)

        val request = MockHttpServletRequest("POST", "/auth/token")
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()

        filter.doFilter(request, response, chain)

        assertEquals(HttpStatus.OK.value(), response.status)
    }

    @Test
    fun `TC040-06 security filter validates Bearer token and injects authenticated principal`() {
        val mockAuthService = org.mockito.Mockito.mock(DurableAuthService::class.java)
        val mockSessionDir = org.mockito.Mockito.mock(AdminSessionDirectory::class.java)
        val expectedPrincipal = AuthenticatedPrincipal(
            id = UUID.randomUUID().toString(),
            tenantId = "tenant-1",
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )

        org.mockito.Mockito.`when`(mockAuthService.validateAccessToken("atk.valid-test-token"))
            .thenReturn(expectedPrincipal)

        val filter = SecurityAuthenticationFilter(mockAuthService, mockSessionDir)

        val request = MockHttpServletRequest("GET", "/api/v1/tenants/tenant-1/wallet/snapshot")
        request.addHeader("Authorization", "Bearer atk.valid-test-token")
        val response = MockHttpServletResponse()
        var chainExecuted = false
        val chain = jakarta.servlet.FilterChain { req, _ ->
            chainExecuted = true
            val principal = req.getAttribute("authenticatedPrincipal") as? AuthenticatedPrincipal
            assertNotNull(principal)
            assertEquals(expectedPrincipal.id, principal.id)
            assertEquals("tenant-1", principal.tenantId)
        }

        filter.doFilter(request, response, chain)

        assertTrue(chainExecuted)
        assertEquals(HttpStatus.OK.value(), response.status)
    }

    @Test
    fun `TC040-07 security filter rejects expired or invalid Bearer token with 401`() {
        val mockAuthService = org.mockito.Mockito.mock(DurableAuthService::class.java)
        val mockSessionDir = org.mockito.Mockito.mock(AdminSessionDirectory::class.java)

        org.mockito.Mockito.`when`(mockAuthService.validateAccessToken("atk.expired-token"))
            .thenReturn(null)

        val filter = SecurityAuthenticationFilter(mockAuthService, mockSessionDir)

        val request = MockHttpServletRequest("GET", "/api/v1/tenants/tenant-1/wallet/snapshot")
        request.addHeader("Authorization", "Bearer atk.expired-token")
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()

        filter.doFilter(request, response, chain)

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.status)
        assertNull(request.getAttribute("authenticatedPrincipal"))
    }

    // =========================================================================
    // 4. READINESS PROBE FAIL-CLOSED DEPENDENCY CHECKS
    // =========================================================================

    @Test
    fun `TC040-08 readiness health indicator reports UP when all dependencies are ready`() {
        val identity = IdentityReadinessHealthIndicator { true }
        val ledger = LedgerReadinessHealthIndicator { true }
        val provider = ProviderReadinessHealthIndicator { true }
        val kms = KmsReadinessHealthIndicator { true }
        val worker = WorkerReadinessHealthIndicator { true }
        val policy = PolicyReadinessHealthIndicator { true }

        assertEquals(Status.UP, identity.health().status)
        assertEquals(Status.UP, ledger.health().status)
        assertEquals(Status.UP, provider.health().status)
        assertEquals(Status.UP, kms.health().status)
        assertEquals(Status.UP, worker.health().status)
        assertEquals(Status.UP, policy.health().status)
    }

    @Test
    fun `TC040-09 readiness health indicators fail closed (DOWN) when any dependency is degraded`() {
        val identityDegraded = IdentityReadinessHealthIndicator { false }
        val ledgerDegraded = LedgerReadinessHealthIndicator { false }
        val providerDegraded = ProviderReadinessHealthIndicator { false }
        val kmsDegraded = KmsReadinessHealthIndicator { false }
        val workerDegraded = WorkerReadinessHealthIndicator { false }
        val policyDegraded = PolicyReadinessHealthIndicator { false }

        assertEquals(Status.DOWN, identityDegraded.health().status)
        assertEquals(Status.DOWN, ledgerDegraded.health().status)
        assertEquals(Status.DOWN, providerDegraded.health().status)
        assertEquals(Status.DOWN, kmsDegraded.health().status)
        assertEquals(Status.DOWN, workerDegraded.health().status)
        assertEquals(Status.DOWN, policyDegraded.health().status)
    }

    @Test
    fun `TC040-10 schema migration indicator fails closed if schema version does not match V37`() {
        val props = SchemaMigrationProperties(supportedVersion = 37)
        val config = SchemaMigrationConfiguration(props)
        // Before migration has run, state is NOT_STARTED -> must report DOWN
        val health = config.schemaMigrationHealthIndicator().health()
        assertEquals(Status.DOWN, health.status)
        assertEquals(37, health.details["supportedVersion"])
    }

    // =========================================================================
    // 5. DURABLE REPOSITORY INTEGRATION (JDBC ADMIN SESSION DIRECTORY)
    // =========================================================================

    @Test
    fun `TC040-11 jdbc admin session directory resolves active sessions from durable database`() {
        val mockJdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate::class.java)
        val store = JdbcAdminSessionDirectory(mockJdbc)

        val expiresAt = Instant.now().plusSeconds(3600)
        org.mockito.Mockito.doReturn(listOf(AdminSessionStatus(active = true, breakGlass = false, expiresAt = expiresAt)))
            .`when`(mockJdbc).query(
                org.mockito.ArgumentMatchers.contains("from admin_mfa_authentication"),
                org.mockito.ArgumentMatchers.any(org.springframework.jdbc.core.RowMapper::class.java),
                org.mockito.ArgumentMatchers.eq("tenant-1"),
                org.mockito.ArgumentMatchers.eq("admin-1"),
                org.mockito.ArgumentMatchers.eq("session-1")
            )

        val status = store.find("tenant-1", "admin-1", "session-1")
        assertNotNull(status)
        assertTrue(status.active)
        assertFalse(status.breakGlass)
        assertEquals(expiresAt, status.expiresAt)
    }

    @Test
    fun `TC040-12 jdbc admin session directory returns null for non-existent session`() {
        val mockJdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate::class.java)
        val store = JdbcAdminSessionDirectory(mockJdbc)

        org.mockito.Mockito.doReturn(emptyList<AdminSessionStatus>())
            .`when`(mockJdbc).query(
                org.mockito.ArgumentMatchers.contains("from admin_mfa_authentication"),
                org.mockito.ArgumentMatchers.any(org.springframework.jdbc.core.RowMapper::class.java),
                org.mockito.ArgumentMatchers.eq("tenant-1"),
                org.mockito.ArgumentMatchers.eq("unknown"),
                org.mockito.ArgumentMatchers.eq("session-unknown")
            )

        val status = store.find("tenant-1", "unknown", "session-unknown")
        assertNull(status)
    }

    // =========================================================================
    // 6. END-TO-END CONTROLLER SMOKE JOURNEY WITH AUTHENTICATED PRINCIPAL
    // =========================================================================

    @Test
    fun `TC040-13 end to end player wallet snapshot smoke journey with verified principal`() {
        val mockWalletService = org.mockito.Mockito.mock(AuthoritativeWalletService::class.java)
        val controller = PlayerWalletController(mockWalletService)

        val playerId = UUID.randomUUID()
        val principal = AuthenticatedPrincipal(
            id = playerId.toString(),
            tenantId = "tenant-test",
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )

        val snapshot = AuthoritativeWalletSnapshot(
            ownerReference = playerId.toString(),
            tenantId = "tenant-test",
            currencyBalances = listOf(CurrencyBalance("EUR", 5000L)),
            ledgerVersion = 42L,
            serverVersion = 42L,
            generatedAt = Instant.now(),
            expiresAt = Instant.now().plusSeconds(60),
            syncStatus = WalletSyncStatus.FRESH,
            evidenceReference = "ev-snap-1",
        )

        org.mockito.Mockito.`when`(
            mockWalletService.getWalletSnapshot(
                WalletSnapshotQuery(
                    principal = principal,
                    tenantId = "tenant-test",
                    ownerReference = playerId.toString(),
                    expectedLedgerVersion = null,
                    allowStale = true,
                )
            )
        ).thenReturn(snapshot)

        val response = controller.getSnapshot(
            tenantId = "tenant-test",
            ownerReference = null,
            expectedLedgerVersion = null,
            allowStale = true,
            sessionId = "sess-1",
            principalAttr = principal,
        )

        assertEquals(HttpStatus.OK, response.statusCode)
        val body = response.body as AuthoritativeWalletSnapshot
        assertEquals(playerId.toString(), body.ownerReference)
        assertEquals(5000L, body.currencyBalances.first().balanceMinorUnits)
    }

    // =========================================================================
    // 7. COMPREHENSIVE SCENARIO VALIDATION (BOOT, TRANSITION, LIFECYCLE)
    // =========================================================================

    @Test
    fun `TC040-14 normal boot and bean graph inspection with production composition`() {
        val mockJdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate::class.java)

        val context = AnnotationConfigApplicationContext()
        context.environment.setActiveProfiles("production")
        context.beanFactory.registerSingleton("jdbcTemplate", mockJdbc)
        context.beanFactory.registerSingleton("dataSource", org.mockito.Mockito.mock(javax.sql.DataSource::class.java))
        context.register(
            ProductionCompositionConfiguration::class.java,
            ProductionDomainBindingInitializer::class.java,
            ProductionBeanGraphValidator::class.java,
            JdbcDurableAuthStore::class.java,
            JdbcAdminSessionDirectory::class.java,
            JdbcLedgerJournalStore::class.java,
            JdbcAuthoritativeWithdrawalStore::class.java,
            JdbcDepositWorkflowStore::class.java,
            JdbcPaymentMethodStore::class.java,
            JdbcDurableResponsibleGamingStore::class.java,
            IdentityReadinessHealthIndicator::class.java,
            LedgerReadinessHealthIndicator::class.java,
            ProviderReadinessHealthIndicator::class.java,
            KmsReadinessHealthIndicator::class.java,
            WorkerReadinessHealthIndicator::class.java,
            PolicyReadinessHealthIndicator::class.java,
            SecurityAuthenticationFilter::class.java,
            DurableAuthService::class.java,
            PlayerWalletController::class.java,
            AuthoritativeWalletService::class.java,
            JdbcAuthoritativeWalletStore::class.java,
        )
        context.refresh()

        // Context booted successfully
        assertTrue(context.isRunning)
        assertTrue(context.containsBean("authoritativeWithdrawalService"))
        assertTrue(context.containsBean("durableDepositWorkflowService"))
        assertTrue(context.containsBean("paymentMethodQueryService"))
        assertTrue(context.containsBean("durableResponsibleGamingService"))
        assertTrue(context.containsBean("securityAuthenticationFilter"))

        // Ban verification: ensure no InMemory, Fake, or Sandbox bean exists
        for (beanName in context.beanDefinitionNames) {
            val bean = context.getBean(beanName)
            val name = bean.javaClass.simpleName
            assertFalse(
                name.contains("InMemory") || name.contains("Fake") || name.contains("Sandbox"),
                "Production context must not contain bean $beanName with class $name"
            )
        }

        context.close()
    }

    @Test
    fun `TC040-15 readiness transition dynamically reflects dependency health`() {
        var isKmsReady = false
        val kmsIndicator = KmsReadinessHealthIndicator { isKmsReady }

        // Initially DOWN
        assertEquals(Status.DOWN, kmsIndicator.health().status)

        // Dependency recovers
        isKmsReady = true
        assertEquals(Status.UP, kmsIndicator.health().status)

        // Dependency degrades
        isKmsReady = false
        assertEquals(Status.DOWN, kmsIndicator.health().status)
    }

    @Test
    fun `TC040-16 context restart cleanly runs without orphan state`() {
        val mockJdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate::class.java)

        fun createAndStartContext(): AnnotationConfigApplicationContext {
            val ctx = AnnotationConfigApplicationContext()
            ctx.beanFactory.registerSingleton("jdbcTemplate", mockJdbc)
            ctx.register(
                ProductionDomainBindingInitializer::class.java,
                ProductionCompositionConfiguration::class.java,
                JdbcLedgerJournalStore::class.java,
                JdbcAuthoritativeWithdrawalStore::class.java,
                JdbcDepositWorkflowStore::class.java,
                JdbcPaymentMethodStore::class.java,
                JdbcDurableResponsibleGamingStore::class.java,
                JdbcAdminSessionDirectory::class.java,
            )
            ctx.refresh()
            return ctx
        }

        val ctx1 = createAndStartContext()
        assertTrue(ctx1.isRunning)
        ctx1.close()
        assertFalse(ctx1.isRunning)

        // Restart cleanly
        val ctx2 = createAndStartContext()
        assertTrue(ctx2.isRunning)
        ctx2.close()
        assertFalse(ctx2.isRunning)
    }

    @Test
    fun `TC040-17 partial feature degradation keeps capability unavailable and marks readiness DOWN`() {
        val degradedIndicator = ProviderReadinessHealthIndicator { false }
        val health = degradedIndicator.health()

        assertEquals(Status.DOWN, health.status)
        assertEquals("degraded", health.details["provider"])
    }
}
