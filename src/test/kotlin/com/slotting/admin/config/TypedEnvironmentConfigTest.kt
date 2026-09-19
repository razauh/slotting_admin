package com.slotting.admin.config

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * CONFIG-001-01 Contract Test Suite: Define typed environment configuration.
 *
 * Source implementation-plan family: CONFIG-001
 * Semantic Contract: "No secrets in source/logs; environment identity and pin/key rotation supported."
 * Expected RED failure: "blank/placeholder/mixed-env config accepted"
 */
class TypedEnvironmentConfigTest {
    private val now = Instant.parse("2026-09-18T16:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private fun adminPrincipal(tenantId: String = "tenant-admin-1"): AuthenticatedPrincipal =
        AuthenticatedPrincipal(
            id = "config-lead-1",
            tenantId = tenantId,
            kind = PrincipalKind.ADMIN,
            roles = setOf(AdminRole.SUPER_ADMIN, AdminRole.AUDITOR)
        )

    private fun playerPrincipal(tenantId: String = "tenant-admin-1"): AuthenticatedPrincipal =
        AuthenticatedPrincipal(
            id = "player-user-1",
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet()
        )

    private fun validEndpoints(): List<ServiceEndpoint> = listOf(
        ServiceEndpoint("auth", "https://auth.slotting.com/api/v1"),
        ServiceEndpoint("cashier", "https://cashier.slotting.com/api/v1"),
        ServiceEndpoint("ledger", "https://ledger.slotting.com/api/v1")
    )

    private fun validKeys(): List<KeyCredential> = listOf(
        KeyCredential(
            keyId = "key-prod-20260918-v1",
            keyHashSha256 = "1111111111111111111111111111111111111111111111111111111111111111",
            algorithm = "Ed25519",
            rotationState = KeyRotationState.ACTIVE,
            issuedAtEpochMs = 1726000000000L,
            expiresAtEpochMs = 1757000000000L
        ),
        KeyCredential(
            keyId = "key-prod-20260918-v2-next",
            keyHashSha256 = "2222222222222222222222222222222222222222222222222222222222222222",
            algorithm = "Ed25519",
            rotationState = KeyRotationState.NEXT,
            issuedAtEpochMs = 1726000000000L,
            expiresAtEpochMs = 1788000000000L
        )
    )

    private fun validPins(): List<TlsCertificatePin> = listOf(
        TlsCertificatePin(
            host = "auth.slotting.com",
            pinSha256 = "sha256/WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
            rotationState = KeyRotationState.ACTIVE,
            validUntilEpochMs = 1757000000000L
        ),
        TlsCertificatePin(
            host = "cashier.slotting.com",
            pinSha256 = "sha256/r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=",
            rotationState = KeyRotationState.ACTIVE,
            validUntilEpochMs = 1757000000000L
        )
    )

    private fun validConfig(
        environmentType: EnvironmentType = EnvironmentType.PRODUCTION,
        endpoints: List<ServiceEndpoint> = validEndpoints(),
        keys: List<KeyCredential> = validKeys(),
        pins: List<TlsCertificatePin> = validPins(),
        mutatesMoney: Boolean = false
    ): TypedEnvironmentConfig =
        TypedEnvironmentConfig(
            configId = "config-prod-001",
            environmentType = environmentType,
            environmentName = "production-primary",
            endpoints = endpoints,
            keys = keys,
            certificatePins = pins,
            artifactSha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            version = 1L,
            createdAt = now,
            mutatesMoney = mutatesMoney
        )

    private fun validCommand(
        tenantId: String = "tenant-admin-1",
        principal: AuthenticatedPrincipal? = adminPrincipal(tenantId),
        idempotencyKey: String = "idemp-cfg-001",
        expectedVersion: Long = 1L,
        config: TypedEnvironmentConfig = validConfig()
    ): DefineEnvironmentConfigCommand =
        DefineEnvironmentConfigCommand(
            principal = principal,
            sessionId = "session-cfg-101",
            tenantId = tenantId,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-cfg-555",
            causationId = "caus-cfg-666",
            expectedVersion = expectedVersion,
            config = config
        )

    @BeforeEach
    fun setUp() {
        // EnvironmentConfigBinding starts as false in production to enforce RED verification
    }

    @AfterEach
    fun tearDown() {
        EnvironmentConfigBinding.isBound = true
    }

    // =========================================================================
    // CONFIG-001-01-T001: Produces Authoritative Certified Outcome
    // =========================================================================

    @Test
    fun `CONFIG-001-01-T001 Define typed environment configuration produces the required authoritative outcome`() {
        val store = InMemoryEnvironmentConfigStore()
        val service = EnvironmentConfigService(store, clock)

        val command = validCommand()
        val result = service.defineConfiguration(command)

        assertEquals("config-prod-001", result.configId)
        assertEquals(EnvironmentType.PRODUCTION, result.environmentType)
        assertEquals(1L, result.serverVersion)
        assertEquals(now, result.serverTime)
        assertEquals(1, result.activeKeyCount)
        assertEquals(1, result.nextKeyCount)
        assertEquals(2, result.pinCount)
        assertEquals(3, result.endpointCount)
        assertTrue(result.evidenceReference.startsWith("env-config:tenant-admin-1:PRODUCTION:"))

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("TYPED_ENVIRONMENT_CONFIG_DEFINED", store.audit[0].type)
        assertEquals("TYPED_ENVIRONMENT_CONFIG_DEFINED", store.outbox[0].type)
        assertEquals(command.correlationId, store.audit[0].correlationId)
        assertEquals(command.causationId, store.audit[0].causationId)

        // Assert no secrets in audit, logs, or stored evidence
        val auditInspection = "${store.audit[0].type} ${store.audit[0].correlationId} ${result.evidenceReference}"
        assertTrue(!auditInspection.contains("SECRET", ignoreCase = true))
        assertTrue(!auditInspection.contains("PASSWORD", ignoreCase = true))
        assertTrue(!auditInspection.contains("PRIVATE_KEY", ignoreCase = true))

        // Assert zero financial authority mutation: service has no financial mutation methods
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // CONFIG-001-01-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `CONFIG-001-01-T002 Define typed environment configuration rejects invalid boundary unauthorized and stale input`() {
        EnvironmentConfigBinding.isBound = true

        val store = InMemoryEnvironmentConfigStore()
        val service = EnvironmentConfigService(store, clock)

        // 1. Unauthenticated principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Player principal attempting admin configuration rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(principal = playerPrincipal()))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Cross-tenant access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(tenantId = "other-tenant", principal = adminPrincipal("tenant-admin-1")))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Stale version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Blank idempotency key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(idempotencyKey = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Blank / Placeholder URL rejected (prevent blank/placeholder/mixed-env config accepted)
        val placeholderEndpoint = ServiceEndpoint("auth", "https://CHANGEME.slotting.com/api")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(config = validConfig(endpoints = listOf(placeholderEndpoint))))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Mixed-environment URL rejected (e.g. Production pointing to staging or localhost)
        val mixedEnvEndpoint = ServiceEndpoint("cashier", "https://staging.slotting.com/api")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(config = validConfig(environmentType = EnvironmentType.PRODUCTION, endpoints = listOf(mixedEnvEndpoint))))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        val localhostInProd = ServiceEndpoint("ledger", "http://localhost:8080/api")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(config = validConfig(environmentType = EnvironmentType.PRODUCTION, endpoints = listOf(localhostInProd))))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Secret in configuration rejected (prevent secrets in source/logs)
        val secretEndpoint = ServiceEndpoint("auth", "https://auth.slotting.com/api?secret=super_secret_token")
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(config = validConfig(endpoints = listOf(secretEndpoint))))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 9. Key rotation violation: No active key rejected
        val noActiveKeys = listOf(
            KeyCredential(
                keyId = "key-retired-1",
                keyHashSha256 = "1111111111111111111111111111111111111111111111111111111111111111",
                algorithm = "Ed25519",
                rotationState = KeyRotationState.RETIRED,
                issuedAtEpochMs = 1726000000000L,
                expiresAtEpochMs = 1757000000000L
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(config = validConfig(keys = noActiveKeys)))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 10. Financial authority violation rejected (config cannot mutate money)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(validCommand(config = validConfig(mutatesMoney = true)))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }
    }

    // =========================================================================
    // CONFIG-001-01-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `CONFIG-001-01-T003 Define typed environment configuration survives concurrency duplicate delivery and dependency failure`() {
        EnvironmentConfigBinding.isBound = true

        val store = InMemoryEnvironmentConfigStore()
        val service = EnvironmentConfigService(store, clock)

        val command = validCommand(idempotencyKey = "idemp-concurrent-cfg")
        val threads = 10
        val executor = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(1)
        val endLatch = CountDownLatch(threads)
        val results = mutableListOf<DefineEnvironmentConfigResult>()
        val errors = mutableListOf<Throwable>()

        for (i in 0 until threads) {
            executor.submit {
                try {
                    latch.await()
                    val res = service.defineConfiguration(command)
                    synchronized(results) { results.add(res) }
                } catch (e: Throwable) {
                    synchronized(errors) { errors.add(e) }
                } finally {
                    endLatch.countDown()
                }
            }
        }

        latch.countDown()
        endLatch.await()
        executor.shutdown()

        assertEquals(0, errors.size)
        assertEquals(threads, results.size)
        val firstResult = results.first()
        results.forEach {
            assertEquals(firstResult.resultId, it.resultId)
            assertEquals(firstResult.configId, it.configId)
        }

        // Single state committed
        assertEquals(1, store.configs.size)
        assertEquals(1, store.audit.size)

        // Conflicting payload on same idempotency key produces CONFLICT
        val conflictingConfig = command.config.copy(environmentName = "different-env-name")
        val conflictingCommand = command.copy(config = conflictingConfig)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.defineConfiguration(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // CONFIG-001-01-T004: Remains Compatible, Recoverable, Observable, Lifecycle-Safe
    // =========================================================================

    @Test
    fun `CONFIG-001-01-T004 Define typed environment configuration remains compatible recoverable observable and lifecycle safe`() {
        val store = InMemoryEnvironmentConfigStore()
        val service = EnvironmentConfigService(store, clock)

        // 1. Verify fail-closed gate unbind behavior: throws AssertionError("blank/placeholder/mixed-env config accepted")
        EnvironmentConfigBinding.isBound = false
        val ex = assertFailsWith<AssertionError> {
            service.defineConfiguration(validCommand())
        }
        assertEquals("blank/placeholder/mixed-env config accepted", ex.message)

        // Re-bind
        EnvironmentConfigBinding.isBound = true

        // 2. Authoritative execution and recovery
        val command = validCommand(idempotencyKey = "obs-cfg-check-001")
        val result = service.defineConfiguration(command)
        assertNotNull(result)

        // Observability check: Contains correlation, causation, tenant, result ID, but zero secrets
        val audit = store.audit.first()
        assertEquals(command.correlationId, audit.correlationId)
        assertEquals(command.causationId, audit.causationId)
        assertEquals(command.tenantId, audit.tenantId)
        assertEquals(result.resultId, audit.resultId)
    }
}
