package com.slotting.admin.auth

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpServletRequest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class PasswordCheckThrottleContractTest {

    private val now = Instant.parse("2026-10-16T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val tenantId = "tenant-throttle-contract"
    private val identifier = "throttle-user@example.com"
    private val password = "SecurePassword123!"

    private fun loginRequest(): MockHttpServletRequest {
        val request = MockHttpServletRequest()
        request.remoteAddr = "10.0.0.7"
        return request
    }

    private fun baseLogin() = mapOf(
        "clientId" to "slotting-android",
        "redirectUri" to "https://app.slotting.internal/auth/callback",
        "state" to "throttle-state",
        "codeChallenge" to "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    )

    private fun registeredAuthService(): DurableAuthService {
        val service = DurableAuthService(store = InMemoryDurableAuthStore(), clock = clock)
        service.registerPlayer(tenantId, identifier, password)
        return service
    }

    @BeforeEach
    fun resetClients() {
        OAuthClientRegistry.reset()
    }

    @Test
    fun `repeated bad passwords lock account while blocked login is refused before credential check`() {
        val authService = registeredAuthService()
        val throttle = mock(PasswordLoginThrottleService::class.java)
        `when`(throttle.isBlocked(tenantId, identifier, "10.0.0.7")).thenReturn(false, false, true)
        val controller = OAuth2Controller(
            authService = authService,
            registrationSybilControl = PermissiveRegistrationSybilControl(authService),
            loginThrottle = throttle,
        )
        val base = baseLogin()

        val first = controller.login(null, base["clientId"]!!, base["redirectUri"]!!, "openid profile", base["state"]!!, null, base["codeChallenge"]!!, "S256", tenantId, identifier, "WrongPassword1!", loginRequest())
        assertEquals(401, first.statusCode.value())
        verify(throttle).recordFailure(tenantId, identifier, "10.0.0.7")

        val second = controller.login(null, base["clientId"]!!, base["redirectUri"]!!, "openid profile", base["state"]!!, null, base["codeChallenge"]!!, "S256", tenantId, identifier, "WrongPassword2!", loginRequest())
        assertEquals(401, second.statusCode.value())
        verify(throttle, times(2)).recordFailure(tenantId, identifier, "10.0.0.7")

        val blocked = controller.login(null, base["clientId"]!!, base["redirectUri"]!!, "openid profile", base["state"]!!, null, base["codeChallenge"]!!, "S256", tenantId, identifier, password, loginRequest())
        assertEquals(401, blocked.statusCode.value())
        verify(throttle, times(2)).recordFailure(tenantId, identifier, "10.0.0.7")
        verify(throttle, never()).recordSuccess(tenantId, identifier)
    }

    @Test
    fun `correct password with unblocked throttle succeeds and resets the counter`() {
        val authService = registeredAuthService()
        val throttle = mock(PasswordLoginThrottleService::class.java)
        `when`(throttle.isBlocked(tenantId, identifier, "10.0.0.7")).thenReturn(false)
        val controller = OAuth2Controller(
            authService = authService,
            registrationSybilControl = PermissiveRegistrationSybilControl(authService),
            loginThrottle = throttle,
        )
        val base = baseLogin()

        val response = controller.login(null, base["clientId"]!!, base["redirectUri"]!!, "openid profile", base["state"]!!, null, base["codeChallenge"]!!, "S256", tenantId, identifier, password, loginRequest())
        assertEquals(302, response.statusCode.value())
        assertNotNull(response.headers.location)
        verify(throttle).recordSuccess(tenantId, identifier)
        verify(throttle, never()).recordFailure(tenantId, identifier, "10.0.0.7")
    }

    @Test
    fun `throttle service locks the account after five failures and lockout survives success callback`() {
        val jdbcUrl = System.getenv("SLOTTING_ADMIN_DATABASE_URL")
            ?: "jdbc:postgresql://127.0.0.1:5432/slotting_admin_ci"
        val dbUser = System.getenv("SLOTTING_ADMIN_DATABASE_USERNAME") ?: "ci_runner"
        val dbPassword = System.getenv("SLOTTING_ADMIN_DATABASE_PASSWORD") ?: "ci_test_password_ephemeral"
        val hostPort = jdbcUrl.removePrefix("jdbc:postgresql://").substringBefore("/").substringBefore("?")
        val host = hostPort.substringBefore(":")
        val port = hostPort.substringAfter(":", "5432").toIntOrNull() ?: 5432
        val reachable = runCatching {
            java.net.Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(host, port), 2000)
                true
            }
        }.getOrDefault(false)
        org.junit.jupiter.api.Assumptions.assumeTrue(reachable, "PostgreSQL required for durable throttle test")

        val dataSource = org.springframework.jdbc.datasource.DriverManagerDataSource(jdbcUrl, dbUser, dbPassword)
        val jdbc = JdbcTemplate(dataSource)
        jdbc.execute("create table if not exists player_login_attempt (tenant_id varchar(128) not null, subject_key varchar(64) not null, attempt_count integer not null, expires_at timestamptz not null, primary key (tenant_id, subject_key))")
        jdbc.execute("create table if not exists player_login_lockout (tenant_id varchar(128) not null, account_key varchar(64) not null, locked_until timestamptz not null, primary key (tenant_id, account_key))")
        val scopedTenant = "$tenantId-${java.util.UUID.randomUUID()}"
        try {
            val throttle = PasswordLoginThrottleService(jdbc, throttlePepper = "contract-test-pepper-with-32-plus-characters")

            repeat(5) {
                assertEquals(false, throttle.isBlocked(scopedTenant, identifier, "10.1.0.$it"))
                throttle.recordFailure(scopedTenant, identifier, "10.1.0.$it")
            }
            assertEquals(true, throttle.isBlocked(scopedTenant, identifier, "10.1.0.9"))

            throttle.recordSuccess(scopedTenant, identifier)
            assertEquals(true, throttle.isBlocked(scopedTenant, identifier, "10.1.0.9"))
            assertEquals(1, jdbc.queryForObject("select count(*) from player_login_lockout where tenant_id = ?", Int::class.java, scopedTenant))
        } finally {
            jdbc.update("delete from player_login_lockout where tenant_id = ?", scopedTenant)
            jdbc.update("delete from player_login_attempt where tenant_id = ?", scopedTenant)
        }
    }
}

private class PermissiveRegistrationSybilControl(
    private val authService: DurableAuthService,
) : RegistrationSybilControl {
    override fun register(tenantId: String, identifier: String, password: String, deviceFingerprint: String?, ipAddress: String?): RegistrationAssessment {
        val credential = authService.registerPlayer(tenantId, identifier, password)
        return RegistrationAssessment(credential, false)
    }

    override fun openReviews(tenantId: String): List<RegistrationReview> = emptyList()

    override fun clearReview(tenantId: String, playerId: java.util.UUID, reviewerId: String, reason: String): Boolean = false
}
