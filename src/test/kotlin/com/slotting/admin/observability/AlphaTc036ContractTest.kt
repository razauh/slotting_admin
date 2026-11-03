package com.slotting.admin.observability

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.PrincipalKind
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AlphaTc036ContractTest {
    private val approvedTesterId = "player-approved-tc036"

    private fun gate() = ConfiguredAlphaTesterGate(
        AlphaTesterGateConfig(enabled = true, allowlistedTesterIds = setOf(approvedTesterId)),
    )

    private fun player(id: String) = AuthenticatedPrincipal(id, "tenant-tc036", PrincipalKind.PLAYER, emptySet())

    private fun admin(roles: Set<AdminRole> = setOf(AdminRole.SUPER_ADMIN)) = AuthenticatedPrincipal(
        id = "admin-tc036",
        tenantId = "tenant-tc036",
        kind = PrincipalKind.ADMIN,
        roles = roles,
    )

    @Test
    fun `TC-036-R1 only allowlisted players may act and admin roles are never testers`() {
        gate().assertTesterAllowed(player(approvedTesterId))

        val notAllowlisted = assertFailsWith<AuthenticationFailure.Rejected> {
            gate().assertTesterAllowed(player("player-random"))
        }
        assertEquals(AuthErrorCode.FORBIDDEN, notAllowlisted.code)

        val adminAsTester = assertFailsWith<AuthenticationFailure.Rejected> {
            gate().assertTesterAllowed(admin())
        }
        assertEquals(AuthErrorCode.FORBIDDEN, adminAsTester.code)

        val anonymous = assertFailsWith<AuthenticationFailure.Rejected> {
            gate().assertTesterAllowed(null)
        }
        assertEquals(AuthErrorCode.UNAUTHENTICATED, anonymous.code)

        val disabledGate = ConfiguredAlphaTesterGate(AlphaTesterGateConfig.DISABLED)
        disabledGate.assertTesterAllowed(player("player-random"))
        disabledGate.assertTesterAllowed(admin())
    }

    @Test
    fun `TC-036-R1 expired and revoked sessions cannot move money while approved testers complete the simulated journey`() {
        val now = java.time.Instant.parse("2026-10-31T18:00:00Z")
        val sessions = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus? = when (sessionId) {
                "session-expired" -> AdminSessionStatus(true, false, now.minusSeconds(60), true)
                "session-revoked" -> AdminSessionStatus(false, false, now.plusSeconds(600), true)
                "session-active" -> AdminSessionStatus(true, false, now.plusSeconds(600), true)
                else -> null
            }
        }
        val service = AdminDiagnosticsQueryService(
            jdbc = org.springframework.jdbc.core.JdbcTemplate(),
            sessions = sessions,
            policy = AdminRbacPolicy(dualControlRequired = false),
            clock = java.time.Clock.fixed(now, java.time.ZoneOffset.UTC),
        )
        val expired = assertFailsWith<AuthenticationFailure.Rejected> {
            service.search(admin(), "tenant-tc036", "session-expired", DiagnosticSearchFilters(now, now.plusSeconds(1)), null, 10)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, expired.code)
        val revoked = assertFailsWith<AuthenticationFailure.Rejected> {
            service.search(admin(), "tenant-tc036", "session-revoked", DiagnosticSearchFilters(now, now.plusSeconds(1)), null, 10)
        }
        assertEquals(AuthErrorCode.FORBIDDEN, revoked.code)
        assertTrue(
            sessions.find("tenant-tc036", "admin-tc036", "session-active")!!.active,
            "the approved session remains usable in the simulated journey",
        )
    }
}
