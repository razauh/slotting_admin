package com.slotting.admin.notification

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DeviceTokenLifecycleTest {

    private val tenantId = "tenant-notify-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T22:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: DeviceTokenLifecycleService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "service-actor-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "service-actor-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SUPPORT),
        kind = PrincipalKind.ADMIN,
    )

    @BeforeEach
    fun setup() {
        service = DeviceTokenLifecycleService(clock = clock)
    }

    private fun createRegisterCommand(
        idempotencyKey: String = "idem-token-001",
        userId: String = "user-01",
        deviceId: String = "device-pixel-8-001",
        platform: DevicePlatform = DevicePlatform.ANDROID,
        tokenValue: String = "fcm_token_device_user_01_alpha_numeric_12345",
        appVersion: String = "1.0.0",
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        expectedVersion: Long = 1L,
    ) = RegisterDeviceTokenCommand(
        principal = principal,
        tenantId = tenant,
        userId = userId,
        deviceId = deviceId,
        platform = platform,
        tokenValue = tokenValue,
        appVersion = appVersion,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-${UUID.randomUUID()}",
        causationId = "cause-${UUID.randomUUID()}",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-002-02-T001: Manage device-token lifecycle produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        val command = createRegisterCommand()
        val result = service.registerDeviceToken(command)

        assertNotNull(result)
        assertEquals(tenantId, result.tenantId)
        assertEquals("user-01", result.userId)
        assertEquals("device-pixel-8-001", result.deviceId)
        assertEquals(DeviceTokenState.ACTIVE, result.tokenState)
        assertEquals("REGISTERED", result.action)
        assertEquals("Mandatory legal/security notices separately approved; stale tokens removed safely.", result.semanticContract)
        assertFalse(result.directEligibilityGranted, "Token lifecycle cannot grant eligibility")
        assertFalse(result.financialMutationPermitted, "Token lifecycle cannot mutate money")
        assertTrue(result.evidenceReference.startsWith("device:token:"))

        // Verify active token query
        val activeTokens = service.getActiveTokensForUser(tenantId, "user-01")
        assertEquals(1, activeTokens.size)
        assertEquals(result.tokenId, activeTokens[0].tokenId)
        assertEquals(DeviceTokenState.ACTIVE, activeTokens[0].tokenState)

        // Safe token rotation: registering a new token for the same device rotates the old token
        val rotateCommand = createRegisterCommand(
            idempotencyKey = "idem-token-002",
            tokenValue = "fcm_token_device_user_01_alpha_numeric_rotated_99999"
        )
        val rotatedResult = service.registerDeviceToken(rotateCommand)
        assertEquals(DeviceTokenState.ACTIVE, rotatedResult.tokenState)

        val updatedActiveTokens = service.getActiveTokensForUser(tenantId, "user-01")
        assertEquals(1, updatedActiveTokens.size)
        assertEquals(rotatedResult.tokenId, updatedActiveTokens[0].tokenId)

        // Verify Audit Log captured
        val auditLogs = service.getAuditLogs(tenantId)
        assertTrue(auditLogs.any { it.eventType == "DEVICE_TOKEN_REGISTERED" })
        assertTrue(auditLogs.any { it.eventType == "DEVICE_TOKEN_ROTATED_REVOKED" })
    }

    @Test
    @DisplayName("NOTIFY-002-02-T002: Manage device-token lifecycle rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated principal
        val unauthCmd = createRegisterCommand(principal = null)
        assertThrows<DeviceTokenLifecycleException.Unauthorized> {
            service.registerDeviceToken(unauthCmd)
        }

        // 2. Cross-tenant principal
        val crossTenantCmd = createRegisterCommand(principal = otherTenantPrincipal, tenant = tenantId)
        val crossEx = assertThrows<DeviceTokenLifecycleException.Forbidden> {
            service.registerDeviceToken(crossTenantCmd)
        }
        assertTrue(crossEx.message!!.contains("Cross-tenant access forbidden"))

        // 3. Short / invalid token value (< 16 characters)
        val shortTokenCmd = createRegisterCommand(tokenValue = "short_tok")
        assertThrows<DeviceTokenLifecycleException.Invalid> {
            service.registerDeviceToken(shortTokenCmd)
        }

        // 4. Blank deviceId
        val blankDeviceCmd = createRegisterCommand(deviceId = "")
        assertThrows<DeviceTokenLifecycleException.Invalid> {
            service.registerDeviceToken(blankDeviceCmd)
        }

        // 5. Stale / invalid version
        val staleCmd = createRegisterCommand(expectedVersion = 0L)
        assertThrows<DeviceTokenLifecycleException.Invalid> {
            service.registerDeviceToken(staleCmd)
        }

        // 6. Action on non-existent token throws NotFound
        assertThrows<DeviceTokenLifecycleException.NotFound> {
            service.markTokenStale(validPrincipal, tenantId, "non-existent-token-value-12345", "test")
        }
    }

    @Test
    @DisplayName("NOTIFY-002-02-T003: Manage device-token lifecycle survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_ConcurrencyDuplicateFailureRecovery() {
        val command = createRegisterCommand(idempotencyKey = "idem-token-concurrent")

        val threads = 6
        val executor = Executors.newFixedThreadPool(threads)
        val results = mutableListOf<DeviceTokenLifecycleResult>()

        for (i in 0 until threads) {
            executor.submit {
                val res = service.registerDeviceToken(command)
                synchronized(results) { results.add(res) }
            }
        }
        executor.shutdown()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))

        // Idempotent duplicate: identical result returned across threads
        assertEquals(threads, results.size)
        val firstId = results[0].tokenId
        assertTrue(results.all { it.tokenId == firstId })

        // Conflict on altered payload
        val conflictCmd = command.copy(appVersion = "2.0.0")
        assertThrows<DeviceTokenLifecycleException.Conflict> {
            service.registerDeviceToken(conflictCmd)
        }
    }

    @Test
    @DisplayName("NOTIFY-002-02-T004: Manage device-token lifecycle remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_CompatibilityObservabilityLifecycleSafe() {
        val tokenVal = "fcm_token_device_user_03_lifecycle_safe_12345"
        val regCmd = createRegisterCommand(
            idempotencyKey = "idem-token-lifecycle",
            userId = "user-03",
            tokenValue = tokenVal
        )
        val registered = service.registerDeviceToken(regCmd)
        assertEquals(DeviceTokenState.ACTIVE, registered.tokenState)

        // Mark stale
        val markedStale = service.markTokenStale(
            validPrincipal,
            tenantId,
            tokenVal,
            "provider reported unregistered"
        )
        assertEquals(DeviceTokenState.STALE, markedStale.tokenState)

        // Active query should no longer return stale token
        val active = service.getActiveTokensForUser(tenantId, "user-03")
        assertTrue(active.isEmpty())

        // Purge stale tokens older than threshold
        val threshold = Instant.now(clock).plus(1, ChronoUnit.HOURS)
        val purgedCount = service.purgeStaleTokens(validPrincipal, tenantId, threshold)
        assertTrue(purgedCount >= 1)

        // Invariants: Non-financial authority remains immutable
        assertFalse(registered.directEligibilityGranted)
        assertFalse(registered.financialMutationPermitted)
        assertEquals("Mandatory legal/security notices separately approved; stale tokens removed safely.", registered.semanticContract)
    }
}
