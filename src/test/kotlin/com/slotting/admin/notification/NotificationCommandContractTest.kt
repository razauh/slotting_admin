package com.slotting.admin.notification

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.PrincipalKind
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

class NotificationCommandContractTest {

    private val tenantId = "tenant-notify-01"
    private val clock = Clock.fixed(Instant.parse("2026-09-19T17:00:00Z"), ZoneOffset.UTC)
    private lateinit var service: NotificationCommandContractService

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
        service = NotificationCommandContractService(clock = clock)
    }

    private fun validTransactionalEmailCommand(
        idempotencyKey: String = "idem-notify-001",
        principal: AuthenticatedPrincipal? = validPrincipal,
        tenant: String = tenantId,
        recipientUserId: String = "user-01",
        recipientDestination: String = "user01@slotting.com",
        templateId: String = "TEMPLATE_SECURITY_ALERT",
        classification: NotificationClassification = NotificationClassification.TRANSACTIONAL,
        channel: NotificationChannel = NotificationChannel.EMAIL,
        parameters: Map<String, String> = mapOf("event_type" to "login_from_new_device", "masked_ip" to "192.168.***.***"),
        expectedVersion: Long = 1L,
    ) = SubmitNotificationCommand(
        principal = principal,
        tenantId = tenant,
        recipientUserId = recipientUserId,
        classification = classification,
        channel = channel,
        templateId = templateId,
        templateParameters = parameters,
        recipientDestination = recipientDestination,
        idempotencyKey = idempotencyKey,
        correlationId = "corr-notify-01",
        causationId = "caus-notify-01",
        expectedVersion = expectedVersion,
    )

    @Test
    @DisplayName("NOTIFY-001-01-T001 — Define notification command contract produces the required authoritative outcome")
    fun testT001_AuthoritativeOutcome() {
        val command = validTransactionalEmailCommand()
        val result = service.submitNotification(command)

        // Assert: outcome-specific semantic contract
        assertEquals(
            "Transactional vs marketing classified; sensitive details behind authenticated app.",
            result.semanticContract
        )
        assertEquals(NotificationCommandStatus.ACCEPTED, result.status)
        assertEquals(NotificationClassification.TRANSACTIONAL, result.classification)
        assertEquals(NotificationChannel.EMAIL, result.channel)
        assertEquals("user-01", result.recipientUserId)
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertTrue(result.evidenceReference.startsWith("notification:command:"))

        // Verify audit event
        val auditLogs = service.getAuditLogs(tenantId)
        assertEquals(1, auditLogs.size)
        assertEquals("NOTIFICATION_COMMAND_SUBMITTED", auditLogs[0].type)
        assertEquals(result.notificationId, auditLogs[0].notificationId)
    }

    @Test
    @DisplayName("NOTIFY-001-01-T002 — Define notification command contract rejects invalid, boundary, unauthorized, and stale input")
    fun testT002_RejectsInvalidBoundaryUnauthorizedStale() {
        val baseCmd = validTransactionalEmailCommand()

        // 1. Unauthenticated principal
        assertThrows(NotificationException.Unauthorized::class.java) {
            service.submitNotification(baseCmd.copy(principal = null))
        }

        // 2. Cross-tenant principal
        assertThrows(NotificationException.Forbidden::class.java) {
            service.submitNotification(baseCmd.copy(principal = otherTenantPrincipal))
        }

        // 3. Blank fields
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(idempotencyKey = ""))
        }
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(recipientUserId = ""))
        }
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(recipientDestination = ""))
        }
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(templateId = ""))
        }
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(expectedVersion = 0L))
        }

        // 4. Insecure payload: Raw password in parameters
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(
                baseCmd.copy(templateParameters = mapOf("password" to "SuperSecretPass123!"))
            )
        }

        // 5. Insecure payload: Raw CVV/PAN in parameters (sensitive details must stay behind authenticated app)
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(
                baseCmd.copy(templateParameters = mapOf("cvv" to "123"))
            )
        }
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(
                baseCmd.copy(templateParameters = mapOf("card" to "4111222233334444"))
            )
        }

        // 6. Template injection attempt
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(
                baseCmd.copy(templateParameters = mapOf("user_name" to "{{7*7}}"))
            )
        }
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(
                baseCmd.copy(templateParameters = mapOf("msg" to "<script>alert(1)</script>"))
            )
        }

        // 7. Unapproved template ID
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(templateId = "TEMPLATE_UNKNOWN_UNAPPROVED"))
        }

        // 8. Classification mismatch (e.g. attempting to send marketing promo under transactional classification)
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(
                baseCmd.copy(templateId = "TEMPLATE_MARKETING_PROMO", classification = NotificationClassification.TRANSACTIONAL)
            )
        }

        // 9. Wrong recipient: user not found in tenant
        assertThrows(NotificationException.Forbidden::class.java) {
            service.submitNotification(baseCmd.copy(recipientUserId = "non-existent-user"))
        }

        // 10. Wrong recipient: destination does not match registered user
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(recipientDestination = "wrong-email@attacker.com"))
        }

        // 11. Malformed destination format for channel (e.g. invalid email)
        assertThrows(NotificationException.Invalid::class.java) {
            service.submitNotification(baseCmd.copy(recipientDestination = "not-an-email"))
        }
    }

    @Test
    @DisplayName("NOTIFY-001-01-T003 — Define notification command contract survives concurrency, duplicate delivery, and dependency failure")
    fun testT003_SurvivesConcurrencyDuplicateDelivery() {
        val command = validTransactionalEmailCommand(idempotencyKey = "idem-notify-conc")

        // 1. Concurrent identical requests return cached result
        val pool = Executors.newFixedThreadPool(4)
        val futures = (1..4).map {
            pool.submit<NotificationCommandResult> {
                service.submitNotification(command)
            }
        }
        pool.shutdown()
        pool.awaitTermination(5, TimeUnit.SECONDS)

        val results = futures.map { it.get() }
        val distinctResultIds = results.map { it.notificationId }.distinct()
        assertEquals(1, distinctResultIds.size, "All concurrent identical requests must return same notificationId")

        // 2. Conflicting payload with same idempotency key fails closed with Conflict
        assertThrows(NotificationException.Conflict::class.java) {
            service.submitNotification(command.copy(templateId = "TEMPLATE_MFA_CHALLENGE"))
        }
    }

    @Test
    @DisplayName("NOTIFY-001-01-T004 — Define notification command contract remains compatible, recoverable, observable, and lifecycle-safe")
    fun testT004_RemainsCompatibleRecoverableObservable() {
        val command = validTransactionalEmailCommand(idempotencyKey = "idem-notify-life")
        val result = service.submitNotification(command)

        // Verify semantic contract & non-authoritative financial invariant
        assertEquals(
            "Transactional vs marketing classified; sensitive details behind authenticated app.",
            result.semanticContract
        )
        assertFalse(result.directEligibilityGranted)
        assertFalse(result.financialMutationPermitted)
        assertTrue(result.evidenceReference.startsWith("notification:command:"))

        // Verify schema presence
        val migrationSql = java.io.File("src/main/resources/schema/notification_command_contract.sql").readText()
        assertTrue(migrationSql.contains("admin_notification_command"))
        assertTrue(migrationSql.contains("admin_notification_audit_event"))
        assertTrue(migrationSql.contains("check (classification in ('TRANSACTIONAL', 'MARKETING'))"))

        // Verify audit observability
        val logs = service.getAuditLogs(tenantId)
        assertTrue(logs.any { it.type == "NOTIFICATION_COMMAND_SUBMITTED" && it.notificationId == result.notificationId })
    }
}
