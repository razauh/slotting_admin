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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * CONFIG-001-02 Contract Test Suite: Enforce secret-reference startup validation.
 *
 * Source implementation-plan family: CONFIG-001
 * Semantic Contract: "No secrets in source/logs; environment identity and pin/key rotation supported."
 * Expected RED failure: "blank/placeholder/mixed-env config accepted"
 */
class SecretReferenceStartupValidationTest {
    private val now = Instant.parse("2026-09-18T16:30:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private fun adminPrincipal(tenantId: String = "tenant-admin-1"): AuthenticatedPrincipal =
        AuthenticatedPrincipal(
            id = "sec-admin-1",
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

    private fun validReferences(
        environmentType: EnvironmentType = EnvironmentType.PRODUCTION
    ): List<SecretReference> = listOf(
        SecretReference(
            referenceId = "ref-jwt-signing-key",
            secretKeyName = "jwt.token.signing.key",
            providerType = SecretProviderType.VAULT,
            referenceUri = "vault://slotting/prod/jwt-signing#primary",
            environmentType = environmentType,
            rotationState = KeyRotationState.ACTIVE,
            expectedHashSha256 = "1111111111111111111111111111111111111111111111111111111111111111",
            versionTag = "v1"
        ),
        SecretReference(
            referenceId = "ref-jwt-signing-key-next",
            secretKeyName = "jwt.token.signing.key.next",
            providerType = SecretProviderType.VAULT,
            referenceUri = "vault://slotting/prod/jwt-signing#next",
            environmentType = environmentType,
            rotationState = KeyRotationState.ROTATING,
            expectedHashSha256 = "2222222222222222222222222222222222222222222222222222222222222222",
            versionTag = "v2"
        ),
        SecretReference(
            referenceId = "ref-db-credentials",
            secretKeyName = "datasource.primary.credentials",
            providerType = SecretProviderType.AWS_SECRETS_MANAGER,
            referenceUri = "arn:aws:secretsmanager:us-east-1:123456789012:secret:slotting/prod/db-creds",
            environmentType = environmentType,
            rotationState = KeyRotationState.ACTIVE,
            expectedHashSha256 = "3333333333333333333333333333333333333333333333333333333333333333",
            versionTag = "v1"
        )
    )

    private fun validCommand(
        tenantId: String = "tenant-admin-1",
        principal: AuthenticatedPrincipal? = adminPrincipal(tenantId),
        idempotencyKey: String = "idemp-sec-001",
        expectedVersion: Long = 1L,
        environmentType: EnvironmentType = EnvironmentType.PRODUCTION,
        references: List<SecretReference> = validReferences(environmentType),
        mutatesMoney: Boolean = false
    ): ValidateSecretReferencesCommand =
        ValidateSecretReferencesCommand(
            principal = principal,
            sessionId = "session-sec-101",
            tenantId = tenantId,
            idempotencyKey = idempotencyKey,
            correlationId = "corr-sec-555",
            causationId = "caus-sec-666",
            expectedVersion = expectedVersion,
            environmentType = environmentType,
            references = references,
            mutatesMoney = mutatesMoney
        )

    @BeforeEach
    fun setUp() {
        // SecretReferenceStartupValidationBinding starts as false in production to enforce RED verification
    }

    @AfterEach
    fun tearDown() {
        SecretReferenceStartupValidationBinding.isBound = true
    }

    // =========================================================================
    // CONFIG-001-02-T001: Produces Authoritative Certified Outcome
    // =========================================================================

    @Test
    fun `CONFIG-001-02-T001 Enforce secret-reference startup validation produces the required authoritative outcome`() {
        val store = InMemorySecretReferenceStartupValidationStore()
        val resolver = InMemorySecretReferenceResolver(clock)
        val service = SecretReferenceStartupValidationService(store, resolver, clock)

        val command = validCommand()
        val result = service.validateStartup(command)

        assertTrue(result.isStartupApproved)
        assertEquals(EnvironmentType.PRODUCTION, result.environmentType)
        assertEquals(3, result.totalReferences)
        assertEquals(2, result.resolvedCount)
        assertEquals(1, result.rotatingCount)
        assertEquals(1L, result.serverVersion)
        assertEquals(now, result.serverTime)
        assertTrue(result.evidenceReference.startsWith("secret-startup:tenant-admin-1:PRODUCTION:"))

        // Verify audit and outbox emission
        assertEquals(1, store.audit.size)
        assertEquals(1, store.outbox.size)
        assertEquals("SECRET_REFERENCE_STARTUP_VALIDATION_COMPLETED", store.audit[0].type)
        assertEquals("SECRET_REFERENCE_STARTUP_VALIDATION_COMPLETED", store.outbox[0].type)
        assertEquals(command.correlationId, store.audit[0].correlationId)
        assertEquals(command.causationId, store.audit[0].causationId)

        // Assert no secrets in source, audit, logs, or stored evidence
        val auditInspection = "${store.audit[0].type} ${store.audit[0].correlationId} ${result.evidenceReference}"
        assertTrue(!auditInspection.contains("SECRET=", ignoreCase = true))
        assertTrue(!auditInspection.contains("PASSWORD=", ignoreCase = true))
        assertTrue(!auditInspection.contains("PRIVATE_KEY", ignoreCase = true))

        // Assert zero financial authority mutation: service has no financial mutation methods
        val methods = service::class.java.methods.map { it.name }
        assertTrue(methods.none { it.contains("credit") || it.contains("debit") || it.contains("settle") })
    }

    // =========================================================================
    // CONFIG-001-02-T002: Rejects Invalid, Boundary, Unauthorized, and Stale Input
    // =========================================================================

    @Test
    fun `CONFIG-001-02-T002 Enforce secret-reference startup validation rejects invalid boundary unauthorized and stale input`() {
        SecretReferenceStartupValidationBinding.isBound = true

        val store = InMemorySecretReferenceStartupValidationStore()
        val resolver = InMemorySecretReferenceResolver(clock)
        val service = SecretReferenceStartupValidationService(store, resolver, clock)

        // 1. Unauthenticated principal rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(principal = null))
        }.also { assertEquals(AuthErrorCode.UNAUTHENTICATED, it.code) }

        // 2. Player principal attempting admin startup validation rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(principal = playerPrincipal()))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 3. Cross-tenant access rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(tenantId = "other-tenant", principal = adminPrincipal("tenant-admin-1")))
        }.also { assertEquals(AuthErrorCode.FORBIDDEN, it.code) }

        // 4. Stale version rejected (< 1)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(expectedVersion = 0L))
        }.also { assertEquals(AuthErrorCode.STALE, it.code) }

        // 5. Blank idempotency key rejected
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(idempotencyKey = "   "))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 6. Blank / Placeholder secret reference rejected (prevent blank/placeholder/mixed-env config accepted)
        val placeholderRef = SecretReference(
            referenceId = "ref-placeholder",
            secretKeyName = "api.key",
            providerType = SecretProviderType.VAULT,
            referenceUri = "vault://CHANGEME/placeholder/key",
            environmentType = EnvironmentType.PRODUCTION,
            rotationState = KeyRotationState.ACTIVE,
            expectedHashSha256 = "4444444444444444444444444444444444444444444444444444444444444444"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(references = listOf(placeholderRef)))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 7. Mixed-environment reference rejected (Production environment pointing to staging secret path)
        val mixedEnvRef = SecretReference(
            referenceId = "ref-mixed",
            secretKeyName = "jwt.key",
            providerType = SecretProviderType.VAULT,
            referenceUri = "vault://slotting/staging/jwt-key",
            environmentType = EnvironmentType.PRODUCTION,
            rotationState = KeyRotationState.ACTIVE,
            expectedHashSha256 = "5555555555555555555555555555555555555555555555555555555555555555"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(references = listOf(mixedEnvRef)))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 8. Raw secret leak in reference rejected (No secrets in source/logs)
        val rawSecretLeakRef = SecretReference(
            referenceId = "ref-leak",
            secretKeyName = "db.password=SuperSecretPassword123!",
            providerType = SecretProviderType.VAULT,
            referenceUri = "vault://slotting/prod/db",
            environmentType = EnvironmentType.PRODUCTION,
            rotationState = KeyRotationState.ACTIVE,
            expectedHashSha256 = "6666666666666666666666666666666666666666666666666666666666666666"
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(references = listOf(rawSecretLeakRef)))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 9. Key rotation violation: No active reference rejected
        val onlyRetiredRefs = listOf(
            SecretReference(
                referenceId = "ref-retired",
                secretKeyName = "old.key",
                providerType = SecretProviderType.VAULT,
                referenceUri = "vault://slotting/prod/old",
                environmentType = EnvironmentType.PRODUCTION,
                rotationState = KeyRotationState.RETIRED,
                expectedHashSha256 = "7777777777777777777777777777777777777777777777777777777777777777"
            )
        )
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(references = onlyRetiredRefs))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 10. Financial authority violation rejected (startup validation cannot mutate money)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(validCommand(mutatesMoney = true))
        }.also { assertEquals(AuthErrorCode.INVALID, it.code) }

        // 11. Downstream provider failure results in startup disapproval (fail closed!)
        val failingResolver = InMemorySecretReferenceResolver(
            clock = clock,
            failForReferenceIds = setOf("ref-jwt-signing-key")
        )
        val failingService = SecretReferenceStartupValidationService(store, failingResolver, clock)
        val failedResult = failingService.validateStartup(validCommand(idempotencyKey = "idemp-failed-res"))
        assertFalse(failedResult.isStartupApproved)
        assertEquals(SecretReferenceValidationStatus.PROVIDER_UNAVAILABLE, failedResult.records.first { it.referenceId == "ref-jwt-signing-key" }.status)
    }

    // =========================================================================
    // CONFIG-001-02-T003: Concurrency, Duplicate Delivery, Failure Recovery
    // =========================================================================

    @Test
    fun `CONFIG-001-02-T003 Enforce secret-reference startup validation survives concurrency duplicate delivery and dependency failure`() {
        SecretReferenceStartupValidationBinding.isBound = true

        val store = InMemorySecretReferenceStartupValidationStore()
        val resolver = InMemorySecretReferenceResolver(clock)
        val service = SecretReferenceStartupValidationService(store, resolver, clock)

        val command = validCommand(idempotencyKey = "idemp-concurrent-sec")
        val threads = 10
        val executor = Executors.newFixedThreadPool(threads)
        val latch = CountDownLatch(1)
        val endLatch = CountDownLatch(threads)
        val results = mutableListOf<SecretReferenceStartupValidationResult>()
        val errors = mutableListOf<Throwable>()

        for (i in 0 until threads) {
            executor.submit {
                try {
                    latch.await()
                    val res = service.validateStartup(command)
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
            assertEquals(firstResult.isStartupApproved, it.isStartupApproved)
        }

        // Single state committed
        assertEquals(1, store.results.size)
        assertEquals(1, store.audit.size)

        // Conflicting payload on same idempotency key produces CONFLICT
        val conflictingCommand = command.copy(environmentType = EnvironmentType.STAGING)
        assertFailsWith<AuthenticationFailure.Rejected> {
            service.validateStartup(conflictingCommand)
        }.also { assertEquals(AuthErrorCode.CONFLICT, it.code) }
    }

    // =========================================================================
    // CONFIG-001-02-T004: Remains Compatible, Recoverable, Observable, Lifecycle-Safe
    // =========================================================================

    @Test
    fun `CONFIG-001-02-T004 Enforce secret-reference startup validation remains compatible recoverable observable and lifecycle safe`() {
        val store = InMemorySecretReferenceStartupValidationStore()
        val resolver = InMemorySecretReferenceResolver(clock)
        val service = SecretReferenceStartupValidationService(store, resolver, clock)

        // 1. Verify fail-closed gate unbind behavior: throws AssertionError("blank/placeholder/mixed-env config accepted")
        SecretReferenceStartupValidationBinding.isBound = false
        val ex = assertFailsWith<AssertionError> {
            service.validateStartup(validCommand())
        }
        assertEquals("blank/placeholder/mixed-env config accepted", ex.message)

        // Re-bind
        SecretReferenceStartupValidationBinding.isBound = true

        // 2. Authoritative execution and recovery
        val command = validCommand(idempotencyKey = "obs-sec-check-001")
        val result = service.validateStartup(command)
        assertNotNull(result)

        // Observability check: Contains correlation, causation, tenant, result ID, but zero secrets
        val audit = store.audit.first()
        assertEquals(command.correlationId, audit.correlationId)
        assertEquals(command.causationId, audit.causationId)
        assertEquals(command.tenantId, audit.tenantId)
        assertEquals(result.resultId, audit.resultId)
    }
}
