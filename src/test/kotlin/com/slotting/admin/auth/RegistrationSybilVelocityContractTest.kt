package com.slotting.admin.auth

import org.junit.jupiter.api.Test
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RegistrationSybilVelocityContractTest {

    private val clock = Clock.fixed(Instant.parse("2026-10-16T12:00:00Z"), ZoneOffset.UTC)

    private fun jdbc(): JdbcTemplate {
        val jdbcUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
            ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        val dbUser = System.getenv("SLOTTING_ADMIN_DATABASE_USERNAME") ?: "ci_runner"
        val dbPassword = System.getenv("SLOTTING_ADMIN_DATABASE_PASSWORD") ?: "ci_test_password_ephemeral"
        return JdbcTemplate(DriverManagerDataSource(jdbcUrl, dbUser, dbPassword))
    }

    private fun reachable(jdbcUrl: String): Boolean {
        val hostPort = jdbcUrl.removePrefix("jdbc:postgresql://").substringBefore("/").substringBefore("?")
        val host = hostPort.substringBefore(":")
        val port = hostPort.substringAfter(":", "5432").toIntOrNull() ?: 5432
        return runCatching {
            java.net.Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(host, port), 2000)
                true
            }
        }.getOrDefault(false)
    }

    private fun authService(): DurableAuthService = DurableAuthService(
        store = InMemoryDurableAuthStore(),
        clock = clock,
    )

    @Test
    fun `registrations beyond the per-ip hourly cap are held for review with no bonus activation`() {
        val jdbcUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
            ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        org.junit.jupiter.api.Assumptions.assumeTrue(reachable(jdbcUrl), "PostgreSQL required for Sybil velocity test")
        val jdbc = jdbc()
        val scopedTenant = "tenant-sybil-velocity-${UUID.randomUUID()}"
        val authService = authService()
        val service = RegistrationSybilControlService(
            jdbc = jdbc,
            authService = authService,
            clock = clock,
            signalPepper = "sybil-velocity-test-pepper-not-for-production",
        )
        try {
            val cap = RegistrationSybilControlService.MAX_REGISTRATIONS_PER_IP_PER_HOUR
            val sharedIp = "203.0.113.${UUID.randomUUID().toString().take(4).filter { it.isDigit() }.padEnd(2, '7').take(2)}"
            repeat(cap) { index ->
                val assessment = service.register(
                    tenantId = scopedTenant,
                    identifier = "velocity-$index-${UUID.randomUUID()}@example.com",
                    password = "VelocitySecure123!",
                    deviceFingerprint = "velocity-device-$index-${UUID.randomUUID()}",
                    ipAddress = sharedIp,
                )
                assertFalse(assessment.heldForReview, "registration $index within the cap must activate")
            }
            val overflow = service.register(
                tenantId = scopedTenant,
                identifier = "velocity-overflow-${UUID.randomUUID()}@example.com",
                password = "VelocitySecure123!",
                deviceFingerprint = "velocity-device-overflow-${UUID.randomUUID()}",
                ipAddress = sharedIp,
            )
            assertTrue(overflow.heldForReview, "registration beyond the cap must be held for review")
            val openReviews = service.openReviews(scopedTenant)
            assertTrue(openReviews.any { it.playerId == overflow.credential.playerId })
        } finally {
            jdbc.update("delete from registration_risk_review_audit where tenant_id = ?", scopedTenant)
            jdbc.update("delete from registration_risk_review where tenant_id = ?", scopedTenant)
            jdbc.update("delete from registration_risk_signal where tenant_id = ?", scopedTenant)
            jdbc.update("delete from player_credential where tenant_id = ?", scopedTenant)
        }
    }

    @Test
    fun `device reuse holds for review while distinct devices under the ip cap activate`() {
        val jdbcUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
            ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        org.junit.jupiter.api.Assumptions.assumeTrue(reachable(jdbcUrl), "PostgreSQL required for Sybil velocity test")
        val jdbc = jdbc()
        val scopedTenant = "tenant-sybil-device-${UUID.randomUUID()}"
        val authService = authService()
        val service = RegistrationSybilControlService(
            jdbc = jdbc,
            authService = authService,
            clock = clock,
            signalPepper = "sybil-velocity-test-pepper-not-for-production",
        )
        try {
            val sharedDevice = "shared-velocity-device-${UUID.randomUUID()}"
            val first = service.register(
                tenantId = scopedTenant,
                identifier = "device-first-${UUID.randomUUID()}@example.com",
                password = "VelocitySecure123!",
                deviceFingerprint = sharedDevice,
                ipAddress = "198.51.100.11",
            )
            assertFalse(first.heldForReview)
            val second = service.register(
                tenantId = scopedTenant,
                identifier = "device-second-${UUID.randomUUID()}@example.com",
                password = "VelocitySecure123!",
                deviceFingerprint = sharedDevice,
                ipAddress = "198.51.100.22",
            )
            assertTrue(second.heldForReview, "device reuse must hold the second registration")

            val distinct = service.register(
                tenantId = scopedTenant,
                identifier = "device-distinct-${UUID.randomUUID()}@example.com",
                password = "VelocitySecure123!",
                deviceFingerprint = "distinct-velocity-device-${UUID.randomUUID()}",
                ipAddress = "198.51.100.33",
            )
            assertFalse(distinct.heldForReview, "distinct device under the ip cap must activate")

            assertTrue(service.clearReview(scopedTenant, second.credential.playerId, "reviewer-1", "verified distinct user"))
            assertEquals("ACTIVE", authService.findCredentialByPlayerId(scopedTenant, second.credential.playerId)?.status)
        } finally {
            jdbc.update("delete from registration_risk_review_audit where tenant_id = ?", scopedTenant)
            jdbc.update("delete from registration_risk_review where tenant_id = ?", scopedTenant)
            jdbc.update("delete from registration_risk_signal where tenant_id = ?", scopedTenant)
            jdbc.update("delete from player_credential where tenant_id = ?", scopedTenant)
        }
    }
}
