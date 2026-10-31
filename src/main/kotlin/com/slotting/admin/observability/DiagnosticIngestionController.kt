package com.slotting.admin.observability

import com.fasterxml.jackson.databind.JsonNode
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/player/diagnostics")
class DiagnosticIngestionController(
    private val ingestionService: DiagnosticIngestionService,
) {
    @PostMapping("/batch")
    fun ingestBatch(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantId: String,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
        @RequestBody items: List<JsonNode>,
    ): ResponseEntity<Any> {
        return try {
            ResponseEntity.ok(ingestionService.ingest(principal, tenantId, items))
        } catch (failure: AuthenticationFailure.Rejected) {
            val status = if (failure.code == AuthErrorCode.UNAUTHENTICATED) HttpStatus.UNAUTHORIZED else HttpStatus.FORBIDDEN
            ResponseEntity.status(status).body(mapOf("error" to failure.code.name))
        } catch (rate: DiagnosticRateLimitExceededException) {
            ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(mapOf("error" to "RATE_LIMITED"))
        } catch (invalid: IllegalArgumentException) {
            ResponseEntity.badRequest().body(mapOf("error" to (invalid.message ?: "INVALID")))
        }
    }
}
