package com.slotting.admin.provider

import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuditEvent
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.OutboxEvent
import com.slotting.admin.auth.PrincipalKind
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AdminPaymentProviderControllerTest {
    private val now = Instant.parse("2026-10-31T10:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val admin = AuthenticatedPrincipal(
        id = "admin-1",
        tenantId = "tenant-1",
        kind = PrincipalKind.ADMIN,
        roles = setOf(AdminRole.SECURITY),
    )

    private fun controller(
        store: ControllerProviderStore = ControllerProviderStore(),
        sessions: AdminSessionDirectory = ControllerSessionDirectory(),
    ): Pair<AdminPaymentProviderController, ControllerProviderStore> {
        val service = PaymentProviderConfigService(AdminRbacPolicy(true), sessions, store, clock, TestProviderCredentialWriter())
        val controller = AdminPaymentProviderController(service, csrfTokens = AdminCsrfTokenService(byteArrayOf(1, 2, 3, 4)))
        return controller to store
    }

    private fun token(controller: AdminPaymentProviderController): String =
        (controller.csrfToken("session-1", admin).body as Map<*, *>)["csrfToken"] as String

    private fun mutation(
        action: String = "REGISTER",
        expectedVersion: Long = 0L,
        apiKeySecret: String? = "fake-secret-value",
        providerId: String = "JAZZCASH",
    ) = AdminProviderMutationRequest(
        action = action,
        displayName = "JazzCash",
        endpointUrl = "https://provider.example/v1",
        environment = "SANDBOX",
        walletCurrencies = setOf("PKR"),
        settlementCurrencies = setOf("PKR"),
        supportedOperations = setOf("DEPOSIT"),
        expectedVersion = expectedVersion,
        incidentReference = "CHG-015",
        apiKeySecret = apiKeySecret,
        idempotencyKey = "idem-${action}-${System.nanoTime()}",
        correlationId = "corr-1",
        causationId = "cause-1",
    )

    @Test
    fun `TC-015-R1 authorized admin saves settings and responses never expose the secret`() {
        val (controller, _) = controller()
        val response = controller.mutate(
            providerId = "JAZZCASH",
            request = mutation(),
            sessionId = "session-1",
            csrfToken = token(controller),
            principal = admin,
        )
        assertEquals(200, response.statusCode.value())
        val body = response.body.toString()
        assertFalse(body.contains("fake-secret-value"))
        assertTrue(body.contains("JAZZCASH"))
        assertTrue(body.contains("********"))

        val list = controller.listProviders(admin)
        assertEquals(200, list.statusCode.value())
        assertFalse(list.body.toString().contains("fake-secret-value"))
    }

    @Test
    fun `TC-015-R2 support player expired and MFA incomplete principals are denied`() {
        val (controller, _) = controller(sessions = ControllerSessionDirectory(mfaVerified = false))
        val support = AuthenticatedPrincipal("support-1", "tenant-1", PrincipalKind.ADMIN, setOf(AdminRole.SUPPORT))
        val player = AuthenticatedPrincipal("player-1", "tenant-1", PrincipalKind.PLAYER, emptySet())
        assertEquals(403, controller.listProviders(support).statusCode.value())
        assertEquals(403, controller.listProviders(player).statusCode.value())
        assertEquals(403, controller.mutate("JAZZCASH", mutation(), "session-1", token(controller), support).statusCode.value())
        assertEquals(403, controller.mutate("JAZZCASH", mutation(), "session-1", token(controller), admin).statusCode.value())
        assertEquals(403, controller.mutate("JAZZCASH", mutation(), "session-1", null, admin).statusCode.value())
    }

    @Test
    fun `TC-015-R3 stale version conflicts and invalid fields do not echo input`() {
        val (controller, _) = controller()
        controller.mutate("JAZZCASH", mutation(), "session-1", token(controller), admin)
        val stale = controller.mutate(
            "JAZZCASH",
            mutation(action = "UPDATE_CONFIG", expectedVersion = 99L, apiKeySecret = "another-secret"),
            "session-1",
            token(controller),
            admin,
        )
        assertEquals(409, stale.statusCode.value())
        assertTrue(stale.body.toString().contains("Reload"))
        assertFalse(stale.body.toString().contains("another-secret"))

        val invalid = controller.mutate(
            "UNKNOWN_PROVIDER",
            mutation(providerId = "UNKNOWN_PROVIDER", apiKeySecret = "do-not-echo"),
            "session-1",
            token(controller),
            admin,
        )
        assertEquals(400, invalid.statusCode.value())
        assertFalse(invalid.body.toString().contains("do-not-echo"))
    }

    @Test
    fun `TC-015-R4 admin page is server-served and secret fields are write-only`() {
        val html = java.io.File("src/main/resources/static/admin/payment-providers.html").readText()
        assertTrue(html.contains("type=\"password\""))
        assertTrue(html.contains("credentials: 'same-origin'"))
        assertFalse(html.contains("localStorage"))
        assertFalse(html.contains("sessionStorage"))
    }
}

private class ControllerSessionDirectory(
    private val active: Boolean = true,
    private val mfaVerified: Boolean = true,
    private val expired: Boolean = false,
) : AdminSessionDirectory {
    override fun find(tenantId: String, principalId: String, sessionId: String): AdminSessionStatus =
        AdminSessionStatus(
            active = active,
            breakGlass = false,
            expiresAt = if (expired) Instant.parse("2026-10-31T09:00:00Z") else Instant.parse("2026-10-31T18:00:00Z"),
            mfaVerified = mfaVerified,
        )
}

private class ControllerProviderStore : PaymentProviderConfigStore {
    private val items = mutableMapOf<String, PaymentProviderConfig>()
    private val results = mutableMapOf<String, Pair<String, PaymentProviderConfigResult>>()

    override fun findByIdempotency(tenantId: String, key: String) = results["$tenantId:$key"]

    override fun findProvider(tenantId: String, providerId: String) = items["$tenantId:$providerId"]

    override fun listProviders(tenantId: String): List<PaymentProviderConfig> =
        items.filterKeys { it.startsWith("$tenantId:") }.values.toList()

    override fun save(
        result: PaymentProviderConfigResult,
        tenantId: String,
        secretHash: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        items["$tenantId:${result.provider.providerId}"] = result.provider
        results["$tenantId:$idempotencyKey"] = queryFingerprint to result
    }
}
