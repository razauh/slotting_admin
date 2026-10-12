package com.slotting.admin.security

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.InMemoryDurableAuthStore
import com.slotting.admin.auth.PrincipalKind
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RestController
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder

class SecurityAuthenticationFilterContractTest {
    private val tenantId = "tenant-security-${UUID.randomUUID()}"
    private val adminId = "admin-${UUID.randomUUID()}"
    private val sessionId = "session-${UUID.randomUUID()}"
    private val expiresAt = Instant.now().plusSeconds(600)

    @Test
    fun activeNonPrivilegedSessionKeepsOnlyItsServerSideRoles() {
        val mockMvc = mockMvc { requestedTenant, requestedAdmin, requestedSession ->
            if (requestedTenant == tenantId && requestedAdmin == adminId && requestedSession == sessionId) {
                session(roles = setOf(AdminRole.SUPPORT))
            } else null
        }
        val response = mockMvc.perform(
            get("/api/admin/principal")
                .header("X-Tenant-Id", tenantId)
                .header("X-Admin-Id", adminId)
                .header("X-Admin-Session-Id", sessionId),
        ).andExpect(status().isOk).andReturn().response.contentAsString
        assertTrue(response.contains("SUPPORT"))
        assertFalse(response.contains("SUPER_ADMIN"))
        mockMvc.perform(
            get("/api/admin/super-only")
                .header("X-Tenant-Id", tenantId)
                .header("X-Admin-Id", adminId)
                .header("X-Admin-Session-Id", sessionId),
        ).andExpect(status().isForbidden)
    }

    @Test
    fun inactiveUnknownAndTenantMismatchedSessionsReturn401() {
        val mockMvc = mockMvc { requestedTenant, requestedAdmin, requestedSession ->
            when {
                requestedTenant == tenantId && requestedAdmin == adminId && requestedSession == sessionId -> session(active = false)
                requestedTenant == "other-tenant" && requestedAdmin == adminId && requestedSession == sessionId -> null
                else -> null
            }
        }
        protectedRequest(mockMvc, tenantId, adminId, sessionId).andExpect(status().isUnauthorized)
        protectedRequest(mockMvc, "other-tenant", adminId, sessionId).andExpect(status().isUnauthorized)
        protectedRequest(mockMvc, tenantId, adminId, "unknown-session").andExpect(status().isUnauthorized)
    }

    @Test
    fun missingBlankOrMfaExpiredHeadersCannotAuthenticate() {
        val mockMvc = mockMvc { _, _, _ -> session() }
        mockMvc.perform(get("/api/admin/principal")).andExpect(status().isUnauthorized)
        mockMvc.perform(
            get("/api/admin/principal")
                .header("X-Tenant-Id", tenantId)
                .header("X-Admin-Id", " ")
                .header("X-Admin-Session-Id", sessionId),
        ).andExpect(status().isUnauthorized)
        val expiredMfaMvc = mockMvc { _, _, _ -> session(mfaExpiresAt = Instant.now().minusSeconds(1)) }
        protectedRequest(expiredMfaMvc, tenantId, adminId, sessionId).andExpect(status().isUnauthorized)
    }

    @Test
    fun directoryFailureFailsClosedAndPublicPathRemainsReachable() {
        val failingMvc = mockMvc { _, _, _ -> throw IllegalStateException("directory unavailable") }
        protectedRequest(failingMvc, tenantId, adminId, sessionId).andExpect(status().isUnauthorized)
        failingMvc.perform(get("/auth/token")).andExpect(status().isOk)
    }

    @Test
    fun validBearerTokenTakesPrecedenceOverAdminHeaders() {
        val authService = org.mockito.Mockito.mock(DurableAuthService::class.java)
        val bearerPrincipal = AuthenticatedPrincipal("bearer-user", tenantId, PrincipalKind.PLAYER, emptySet())
        org.mockito.Mockito.`when`(authService.validateAccessToken("bearer-token")).thenReturn(bearerPrincipal)
        val filter = SecurityAuthenticationFilter(authService, directory { _, _, _ -> session(roles = setOf(AdminRole.SUPER_ADMIN)) })
        val controller = SecurityPrincipalProbeController()
        val builder = MockMvcBuilders.standaloneSetup(controller)
        builder.addFilters<StandaloneMockMvcBuilder>(filter)
        val mockMvc = builder.build()
        val body = mockMvc.perform(
            get("/api/admin/principal")
                .header("Authorization", "Bearer bearer-token")
                .header("X-Tenant-Id", tenantId)
                .header("X-Admin-Id", adminId)
                .header("X-Admin-Session-Id", sessionId),
        ).andExpect(status().isOk).andReturn().response.contentAsString
        assertTrue(body.contains("bearer-user"))
        assertFalse(body.contains("SUPER_ADMIN"))
    }

    private fun protectedRequest(mockMvc: MockMvc, tenant: String, admin: String, session: String) =
        mockMvc.perform(
            get("/api/admin/principal")
                .header("X-Tenant-Id", tenant)
                .header("X-Admin-Id", admin)
                .header("X-Admin-Session-Id", session),
        )

    private fun mockMvc(lookup: (String, String, String) -> AdminSessionStatus?): MockMvc {
        val filter = SecurityAuthenticationFilter(
            DurableAuthService(store = InMemoryDurableAuthStore()),
            directory(lookup),
        )
        val builder = MockMvcBuilders.standaloneSetup(SecurityPrincipalProbeController())
        builder.addFilters<StandaloneMockMvcBuilder>(filter)
        return builder.build()
    }

    private fun directory(lookup: (String, String, String) -> AdminSessionStatus?) = object : AdminSessionDirectory {
        override fun find(tenantId: String, principalId: String, sessionId: String) = lookup(tenantId, principalId, sessionId)
    }

    private fun session(
        active: Boolean = true,
        roles: Set<AdminRole> = setOf(AdminRole.SUPPORT),
        mfaExpiresAt: Instant = expiresAt,
    ) = AdminSessionStatus(
        active = active,
        breakGlass = false,
        expiresAt = expiresAt,
        mfaVerified = true,
        mfaExpiresAt = mfaExpiresAt,
        roles = roles,
    )
}

@RestController
private class SecurityPrincipalProbeController {
    @GetMapping("/api/admin/principal")
    fun principal(@RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal) =
        ResponseEntity.ok(mapOf("id" to principal.id, "roles" to principal.roles.map(AdminRole::name)))

    @GetMapping("/api/admin/super-only")
    fun superOnly(@RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal): ResponseEntity<Any> =
        if (principal.roles.contains(AdminRole.SUPER_ADMIN)) ResponseEntity.ok(mapOf("allowed" to true))
        else ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))

    @GetMapping("/auth/token")
    fun publicToken() = ResponseEntity.ok(mapOf("public" to true))
}
