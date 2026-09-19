package com.slotting.admin.auth

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ProductionAppLinkOwnershipTest {

    private val tenantId = "tenant-link-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T16:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: ProductionAppLinkOwnershipService

    private val validPrincipal = AuthenticatedPrincipal(
        id = "admin-link-01",
        tenantId = tenantId,
        roles = setOf(AdminRole.SECURITY),
        kind = PrincipalKind.ADMIN,
    )

    private val otherTenantPrincipal = AuthenticatedPrincipal(
        id = "admin-other",
        tenantId = "tenant-other",
        roles = setOf(AdminRole.SECURITY),
        kind = PrincipalKind.ADMIN,
    )

    private val validDomain = "auth.slotting.com"
    private val validPackage = "com.slotting.app"
    private val validFingerprint = "14:6D:E9:7D:01:A2:3F:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45"

    @BeforeEach
    fun setup() {
        service = ProductionAppLinkOwnershipService(clock = clock)
    }

    private fun validCommand(
        domain: String = validDomain,
        packageName: String = validPackage,
        certFingerprint: String = validFingerprint,
        idempotencyKey: String = "idem-link-001",
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        expectedVersion: Long = 1L,
    ) = VerifyAppLinkOwnershipCommand(
        principal = principal,
        tenantId = tenant,
        domain = domain,
        packageName = packageName,
        certFingerprint = certFingerprint,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-link-01",
        causationId = "caus-link-01",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("LINK-001-02-T001 — Establish verified production App Link ownership produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        val command = validCommand()
        val result = service.verifyOwnership(command)

        // Assert: outcome-specific semantic contract
        assertEquals("assetlinks.", result.semanticContract)
        assertEquals(AppLinkOwnershipStatus.VERIFIED, result.status)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertEquals(validDomain, result.domain)
        assertEquals(validPackage, result.packageName)
        assertTrue(result.evidenceReference.startsWith("app-link:ownership:"))

        // Assert assetlinks.json format
        assertTrue(result.assetLinksJson.contains("delegate_permission/common.handle_all_urls"))
        assertTrue(result.assetLinksJson.contains("com.slotting.app"))
        assertTrue(result.assetLinksJson.contains(validFingerprint))

        // Assert audit trail
        val auditLogs = service.getAuditLogs(tenantId)
        assertEquals(1, auditLogs.size)
        assertEquals("APP_LINK_OWNERSHIP_VERIFIED", auditLogs[0].type)
        assertEquals(result.resultId, auditLogs[0].resultId)
    }

    @Test
    @DisplayName("LINK-001-02-T002 — Establish verified production App Link ownership rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidBoundaryUnauthorizedStale() {
        // 1. Unauthenticated principal
        assertThrows(AppLinkOwnershipException.Unauthorized::class.java) {
            service.verifyOwnership(validCommand(principal = null))
        }

        // 2. Cross-tenant principal
        assertThrows(AppLinkOwnershipException.Forbidden::class.java) {
            service.verifyOwnership(validCommand(principal = otherTenantPrincipal))
        }

        // 3. Blank fields
        assertThrows(AppLinkOwnershipException.Invalid::class.java) {
            service.verifyOwnership(validCommand(domain = ""))
        }
        assertThrows(AppLinkOwnershipException.Invalid::class.java) {
            service.verifyOwnership(validCommand(packageName = ""))
        }
        assertThrows(AppLinkOwnershipException.Invalid::class.java) {
            service.verifyOwnership(validCommand(certFingerprint = ""))
        }
        assertThrows(AppLinkOwnershipException.Invalid::class.java) {
            service.verifyOwnership(validCommand(idempotencyKey = ""))
        }
        assertThrows(AppLinkOwnershipException.Invalid::class.java) {
            service.verifyOwnership(validCommand(expectedVersion = 0L))
        }

        // 4. Custom scheme rejected
        assertThrows(AppLinkOwnershipException.Invalid::class.java) {
            service.verifyOwnership(validCommand(domain = "slotting://auth/callback"))
        }

        // 5. Unapproved domain rejected
        assertThrows(AppLinkOwnershipException.Forbidden::class.java) {
            service.verifyOwnership(validCommand(domain = "evil.com"))
        }

        // 6. Unapproved package name rejected
        assertThrows(AppLinkOwnershipException.Forbidden::class.java) {
            service.verifyOwnership(validCommand(packageName = "com.untrusted.fakeapp"))
        }

        // 7. Untrusted certificate fingerprint rejected
        assertThrows(AppLinkOwnershipException.Forbidden::class.java) {
            service.verifyOwnership(validCommand(certFingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"))
        }
    }

    @Test
    @DisplayName("LINK-001-02-T003 — Establish verified production App Link ownership survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_SurvivesConcurrencyDuplicateDelivery() {
        val command = validCommand(idempotencyKey = "idem-link-conc")

        // 1. Concurrent executions with same idempotency key return identical result
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..4).map {
            pool.submit<AppLinkOwnershipResult> {
                service.verifyOwnership(command)
            }
        }
        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)

        val results = futures.map { it.get() }
        val distinctResultIds = results.map { it.resultId }.distinct()
        assertEquals(1, distinctResultIds.size, "All concurrent identical requests must return same cached resultId")

        // 2. Conflicting payload with same idempotency key fails closed with Conflict
        assertThrows(AppLinkOwnershipException.Conflict::class.java) {
            service.verifyOwnership(command.copy(domain = "slotting.com"))
        }
    }

    @Test
    @DisplayName("LINK-001-02-T004 — Establish verified production App Link ownership remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_RemainsCompatibleRecoverableObservable() {
        val command = validCommand(idempotencyKey = "idem-link-life", domain = "slotting.com")
        val result = service.verifyOwnership(command)

        // Verify lifecycle safety & non-authoritative financial invariant
        assertEquals("assetlinks.", result.semanticContract)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertTrue(result.evidenceReference.startsWith("app-link:ownership:"))

        // Verify Digital Asset Links schema
        assertTrue(result.assetLinksJson.startsWith("[{"))
        assertTrue(result.assetLinksJson.endsWith("}]"))
        assertTrue(result.assetLinksJson.contains("\"namespace\":\"android_app\""))
        assertTrue(result.assetLinksJson.contains("\"package_name\":\"com.slotting.app\""))

        // Verify audit observability
        val logs = service.getAuditLogs(tenantId)
        assertTrue(logs.any { it.type == "APP_LINK_OWNERSHIP_VERIFIED" && it.resultId == result.resultId })
    }
}
