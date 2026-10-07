package com.slotting.admin.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.slotting.admin.auth.*
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

/**
 * Authoritative production security filter (TC-040, BE-002, XREP-001).
 * Validates player bearer tokens and admin session tokens, injecting a verified AuthenticatedPrincipal
 * into the request attributes ("authenticatedPrincipal").
 * Fails closed with HTTP 401 on protected routes when credentials are missing or invalid.
 */
@Component
@Order(1)
class SecurityAuthenticationFilter(
    private val authService: DurableAuthService,
    private val adminSessionDirectory: AdminSessionDirectory,
    private val objectMapper: ObjectMapper = ObjectMapper(),
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(javaClass)

    companion object {
        const val AUTHENTICATED_PRINCIPAL_ATTR = "authenticatedPrincipal"

        private val PUBLIC_PATHS = listOf(
            "/auth/token",
            "/auth/revoke",
            "/auth/logout",
            "/actuator",
            "/error",
        )

        private val PUBLIC_EXACT_PATHS = setOf(
            "/api/bet-limits",
        )
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val uri = request.requestURI

        // 1. Resolve principal from Bearer token if present
        var principal: AuthenticatedPrincipal? = null
        val authHeader = request.getHeader("Authorization")
        if (!authHeader.isNullOrBlank() && authHeader.startsWith("Bearer ", ignoreCase = true)) {
            val token = authHeader.substring(7).trim()
            principal = runCatching { authService.validateAccessToken(token) }.getOrNull()
        }

        // 1b. Resolve principal from X-Session-Token if Bearer did not authenticate
        if (principal == null) {
            val sessionToken = request.getHeader("X-Session-Token")
            if (!sessionToken.isNullOrBlank()) {
                principal = runCatching { authService.validateAccessToken(sessionToken.trim()) }.getOrNull()
            }
        }

        // 2. Resolve admin session if admin headers are present
        if (principal == null) {
            val adminId = request.getHeader("X-Admin-Id")
            val adminSessionId = request.getHeader("X-Admin-Session-Id")
            val tenantId = request.getHeader("X-Tenant-Id")
            if (!adminId.isNullOrBlank() && !adminSessionId.isNullOrBlank() && !tenantId.isNullOrBlank()) {
                val status = runCatching {
                    adminSessionDirectory.find(tenantId, adminId, adminSessionId)
                }.getOrNull()

                if (status != null && status.active) {
                    principal = AuthenticatedPrincipal(
                        id = adminId,
                        tenantId = tenantId,
                        kind = PrincipalKind.ADMIN,
                        roles = setOf(AdminRole.SUPER_ADMIN),
                    )
                }
            }
        }

        // 3. Attach verified principal if found
        if (principal != null) {
            request.setAttribute(AUTHENTICATED_PRINCIPAL_ATTR, principal)
        }

        // 4. Fail closed on protected routes if unauthenticated
        val isPublic = isPublicPath(uri)
        if (!isPublic && principal == null) {
            log.warn("Unauthorized access attempt to protected route: uri={}", uri)
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.contentType = "application/json"
            response.writer.write(
                objectMapper.writeValueAsString(
                    mapOf("error" to "UNAUTHENTICATED", "message" to "Authentication required to access this resource")
                )
            )
            return
        }

        // 5. Proceed
        filterChain.doFilter(request, response)
    }

    private fun isPublicPath(uri: String): Boolean {
        if (uri in PUBLIC_EXACT_PATHS) return true
        return PUBLIC_PATHS.any { publicPath ->
            uri == publicPath || uri.startsWith("$publicPath/")
        }
    }
}
