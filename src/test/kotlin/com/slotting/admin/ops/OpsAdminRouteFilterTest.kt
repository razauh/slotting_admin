package com.slotting.admin.ops

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.InMemoryDurableAuthStore
import com.slotting.admin.security.SecurityAuthenticationFilter
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

@RestControllerAdvice
class OpsAuthFailureAdvice {
    @ExceptionHandler(AuthenticationFailure.Rejected::class)
    fun rejected(failure: AuthenticationFailure.Rejected): ResponseEntity<Map<String, Any>> =
        ResponseEntity.status(
            when (failure.code) {
                AuthErrorCode.UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED
                AuthErrorCode.FORBIDDEN -> HttpStatus.FORBIDDEN
                else -> HttpStatus.BAD_REQUEST
            },
        ).body(mapOf("error" to failure.code.name))
}

class OpsAdminRouteFilterTest {
    private val tenantId = "tenant-ops"
    private val adminId = "admin-ops"
    private val sessionId = "session-ops"
    private val notices = InMemoryOpsNoticeRepository()
    private val decisions = object : OpsDecisionSource {
        override fun all(): List<OpsDecision> = listOf(
            OpsDecision("JWT_KEYS_TIMELINE", null, null, OpsDecisionStatus.UNSCHEDULED, "rotation"),
            OpsDecision("REALTIME_PAYLOAD_SCOPE", null, null, OpsDecisionStatus.UNSCHEDULED, "payload"),
            OpsDecision("KILLSWITCH_RUNTIME_TOGGLE", null, null, OpsDecisionStatus.UNSCHEDULED, "toggle"),
            OpsDecision("TC16_EXPOSURE_FINAL", null, null, OpsDecisionStatus.UNSCHEDULED, "exposure"),
            OpsDecision("TC38_PLATFORM_FLIP", null, null, OpsDecisionStatus.UNSCHEDULED, "flip"),
        )
    }
    private val controller = OpsAdminController(notices, decisions, Clock.fixed(Instant.parse("2026-11-10T12:00:00Z"), ZoneOffset.UTC))

    private fun mockMvc(roles: Set<AdminRole> = setOf(AdminRole.SUPER_ADMIN)): MockMvc {
        val filter = SecurityAuthenticationFilter(
            DurableAuthService(store = InMemoryDurableAuthStore()),
            object : AdminSessionDirectory {
                override fun find(tenantId: String, principalId: String, sessionId: String) = AdminSessionStatus(
                    active = true,
                    breakGlass = false,
                    expiresAt = Instant.now().plusSeconds(600),
                    mfaVerified = true,
                    mfaExpiresAt = Instant.now().plusSeconds(600),
                    roles = roles,
                )
            },
        )
        val builder = MockMvcBuilders.standaloneSetup(controller)
        builder.addFilters<StandaloneMockMvcBuilder>(filter)
        builder.setControllerAdvice(OpsAuthFailureAdvice())
        return builder.build()
    }

    private fun request(mockMvc: MockMvc, method: String, path: String, authed: Boolean) =
        if (method == "POST") {
            val builder = post(path)
            if (authed) {
                builder.header("X-Tenant-Id", tenantId).header("X-Admin-Id", adminId).header("X-Admin-Session-Id", sessionId)
            }
            mockMvc.perform(builder)
        } else {
            val builder = get(path)
            if (authed) {
                builder.header("X-Tenant-Id", tenantId).header("X-Admin-Id", adminId).header("X-Admin-Session-Id", sessionId)
            }
            mockMvc.perform(builder)
        }

    @Test
    fun `all three routes answer 401 without credentials`() {
        val mockMvc = mockMvc()
        request(mockMvc, "GET", "/admin/ops/notices", authed = false).andExpect(status().isUnauthorized)
        request(mockMvc, "POST", "/admin/ops/notices/TEST/ack", authed = false).andExpect(status().isUnauthorized)
        request(mockMvc, "GET", "/admin/ops/registry", authed = false).andExpect(status().isUnauthorized)
    }

    @Test
    fun `all three routes answer 403 for a non-ops admin role`() {
        val mockMvc = mockMvc(roles = setOf(AdminRole.SUPPORT))
        request(mockMvc, "GET", "/admin/ops/notices", authed = true).andExpect(status().isForbidden)
        request(mockMvc, "POST", "/admin/ops/notices/TEST/ack", authed = true).andExpect(status().isForbidden)
        request(mockMvc, "GET", "/admin/ops/registry", authed = true).andExpect(status().isForbidden)
    }

    @Test
    fun `all three routes answer 200 for an ops-capable admin`() {
        notices.open(OpsNotice("TEST_CAUSE", "TEST", OpsSeverity.WARNING, "phase-only hint notice", Instant.parse("2026-11-10T12:00:00Z")))
        val mockMvc = mockMvc()
        request(mockMvc, "GET", "/admin/ops/notices", authed = true).andExpect(status().isOk)
        request(mockMvc, "POST", "/admin/ops/notices/TEST_CAUSE/ack", authed = true).andExpect(status().isOk)
        request(mockMvc, "GET", "/admin/ops/registry", authed = true).andExpect(status().isOk)
    }

    @Test
    fun `ack is idempotent through the filter chain`() {
        notices.open(OpsNotice("TEST_CAUSE", "TEST", OpsSeverity.WARNING, "phase-only hint notice", Instant.parse("2026-11-10T12:00:00Z")))
        val mockMvc = mockMvc()
        request(mockMvc, "POST", "/admin/ops/notices/TEST_CAUSE/ack", authed = true).andExpect(status().isOk)
        request(mockMvc, "POST", "/admin/ops/notices/TEST_CAUSE/ack", authed = true).andExpect(status().isOk)
    }

    @Test
    fun `responses carry no credential material`() {
        notices.open(OpsNotice("TEST_CAUSE", "TEST", OpsSeverity.WARNING, "phase-only hint notice", Instant.parse("2026-11-10T12:00:00Z")))
        val mockMvc = mockMvc()
        val body = request(mockMvc, "GET", "/admin/ops/notices", authed = true).andExpect(status().isOk).andReturn().response.contentAsString
        listOf("Bearer", "postgresql://", "service_role", "hintToken").forEach { secret ->
            assert(!body.contains(secret)) { "response leaked $secret" }
        }
    }
}
