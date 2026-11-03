package com.slotting.admin.observability

import com.slotting.admin.auth.AuthenticatedPrincipal
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.UUID

data class DiagnosticsSearchRequest(
    val from: Instant,
    val to: Instant,
    val severity: String?,
    val eventType: String?,
    val userId: String?,
    val correlationId: String?,
    val roundId: String?,
    val betId: String?,
    val paymentId: String?,
    val cursor: String?,
    val limit: Int,
)

@RestController
@RequestMapping("/api/admin/diagnostics")
class AdminDiagnosticsController(
    private val queryService: AdminDiagnosticsQueryService,
) {
    @GetMapping("/search")
    fun search(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantId: String,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
        @RequestParam from: Instant,
        @RequestParam to: Instant,
        @RequestParam(required = false) severity: String?,
        @RequestParam(required = false) eventType: String?,
        @RequestParam(required = false) userId: String?,
        @RequestParam(required = false) correlationId: String?,
        @RequestParam(required = false) roundId: String?,
        @RequestParam(required = false) betId: String?,
        @RequestParam(required = false) paymentId: String?,
        @RequestParam(required = false) cursor: String?,
        @RequestParam(defaultValue = "50") limit: Int,
    ): ResponseEntity<Any> = handle {
        ResponseEntity.ok(
            queryService.search(
                principal = principal,
                tenantId = tenantId,
                sessionId = sessionId,
                filters = DiagnosticSearchFilters(
                    from = from,
                    to = to,
                    severity = severity,
                    eventType = eventType,
                    userId = userId,
                    correlationId = correlationId,
                    roundId = roundId,
                    betId = betId,
                    paymentId = paymentId,
                ),
                cursor = cursor,
                limit = limit,
            )
        )
    }

    @GetMapping("/events/{eventId}")
    fun detail(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantId: String,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
        @PathVariable eventId: UUID,
    ): ResponseEntity<Any> = handle {
        ResponseEntity.ok(queryService.detail(principal, tenantId, sessionId, eventId))
    }

    private fun handle(block: () -> ResponseEntity<Any>): ResponseEntity<Any> = try {
        block()
    } catch (rejected: com.slotting.admin.auth.AuthenticationFailure.Rejected) {
        val status = when (rejected.code) {
            com.slotting.admin.auth.AuthErrorCode.UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED
            else -> HttpStatus.FORBIDDEN
        }
        ResponseEntity.status(status).body(mapOf("error" to rejected.code.name))
    } catch (notFound: DiagnosticEventNotFoundException) {
        ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "NOT_FOUND"))
    } catch (invalid: IllegalArgumentException) {
        ResponseEntity.badRequest().body(mapOf("error" to (invalid.message ?: "INVALID")))
    } catch (dependency: DiagnosticsDependencyUnavailableException) {
        ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(mapOf("error" to "DEPENDENCY_UNAVAILABLE"))
    }
}
