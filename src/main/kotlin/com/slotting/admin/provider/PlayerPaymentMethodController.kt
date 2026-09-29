package com.slotting.admin.provider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

/**
 * Player-facing REST endpoint exposing server-approved active payment methods (TC-011).
 * All availability decisions and restrictions are authoritative on the server.
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/payment-methods")
class PlayerPaymentMethodController(
    private val queryService: PaymentMethodQueryService,
) {

    @GetMapping
    fun getPaymentMethods(
        @PathVariable tenantId: String,
        @RequestParam transactionType: String,
        @RequestParam(required = false) currency: String?,
        @RequestParam(required = false) amountMinorUnits: Long?,
        @RequestParam(required = false) clientKnownVersion: Long?,
        @RequestParam(required = false, defaultValue = "false") includeUnavailable: Boolean,
        @RequestHeader(name = "X-Session-Id", required = false) sessionIdHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val txType = try {
            TransactionType.valueOf(transactionType.uppercase())
        } catch (_: Exception) {
            return ResponseEntity.badRequest().body(mapOf("error" to "INVALID_TRANSACTION_TYPE"))
        }

        val sessionId = sessionIdHeader ?: "sess-default"
        val principal = principalAttr ?: AuthenticatedPrincipal(
            id = "anonymous",
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )

        return try {
            val query = PaymentMethodQuery(
                principal = principal,
                sessionId = sessionId,
                tenantId = tenantId,
                transactionType = txType,
                currency = currency,
                amountMinorUnits = amountMinorUnits,
                clientKnownVersion = clientKnownVersion,
                includeUnavailable = includeUnavailable,
            )
            val response = queryService.query(query)
            ResponseEntity.ok(response)
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
                AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))
                AuthErrorCode.DEPENDENCY_UNAVAILABLE -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(mapOf("error" to "SERVICE_UNAVAILABLE"))
                else -> ResponseEntity.badRequest().body(mapOf("error" to e.code.name))
            }
        }
    }
}
