package com.slotting.admin.ops

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OpsAdminControllerTest {
    private val notices = InMemoryOpsNoticeRepository()
    private val repository = JdbcOpsDecisionRepository { error("no database in this test") }
    private val controller = OpsAdminController(notices, repository, Clock.fixed(Instant.parse("2026-11-10T12:00:00Z"), ZoneOffset.UTC))
    private val admin = AuthenticatedPrincipal(id = "admin-1", tenantId = "tenant-1", kind = PrincipalKind.ADMIN, roles = setOf(AdminRole.SECURITY))
    private val player = AuthenticatedPrincipal(id = "player-1", tenantId = "tenant-1", kind = PrincipalKind.PLAYER, roles = emptySet())

    private fun seed() = notices.open(
        OpsNotice("TEST_CAUSE", "TEST", OpsSeverity.WARNING, "phase-only hint notice", Instant.parse("2026-11-10T12:00:00Z")),
    )

    @Test
    fun `unauthenticated caller is rejected`() {
        assertFailsWith<AuthenticationFailure.Rejected> { controller.listNotices(null) }
        assertFailsWith<AuthenticationFailure.Rejected> { controller.ack("TEST_CAUSE", null) }
        assertFailsWith<AuthenticationFailure.Rejected> { controller.registry(null) }
    }

    @Test
    fun `non-admin caller is forbidden`() {
        assertFailsWith<AuthenticationFailure.Rejected> { controller.listNotices(player) }
        assertFailsWith<AuthenticationFailure.Rejected> { controller.ack("TEST_CAUSE", player) }
        assertFailsWith<AuthenticationFailure.Rejected> { controller.registry(player) }
    }

    @Test
    fun `admin sees open notices`() {
        seed()
        val response = controller.listNotices(admin)
        assertEquals(1, response.items.size)
        assertEquals("TEST_CAUSE", response.items.single().cause)
        assertEquals("WARNING", response.items.single().severity)
    }

    @Test
    fun `ack is idempotent at the endpoint`() {
        seed()
        val first = controller.ack("TEST_CAUSE", admin)
        val second = controller.ack("TEST_CAUSE", admin)
        assertEquals(true, first["acknowledged"])
        assertEquals(true, second["acknowledged"])
        assertEquals(first["cause"], second["cause"])
    }

    @Test
    fun `ack unknown cause is refused without state change`() {
        val response = controller.ack("MISSING", admin)
        assertEquals(false, response["acknowledged"])
        assertTrue(notices.list().isEmpty())
    }

    @Test
    fun `rejected responses carry no credential material`() {
        seed()
        val payload = controller.listNotices(admin).toString() + controller.ack("TEST_CAUSE", admin).toString()
        assertFalse(payload.contains("Bearer"))
        assertFalse(payload.contains("postgresql://"))
        assertFalse(payload.contains("service_role"))
        assertFalse(payload.contains("hintToken"))
    }
}
