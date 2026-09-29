package com.slotting.admin.deposit

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.provider.PaymentMethodUnavailableException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.util.UUID

data class CreateDepositIntentRequest(
    val methodId: String,
    val amountMinorUnits: Long,
    val currencyCode: String,
    val customerIdentifier: String,
    val methodExpectedVersion: Long = 1L,
    val idempotencyKey: String,
    val clientReturnUrl: String? = null,
)

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/deposits")
class PlayerDepositController(
    private val workflowService: DurableDepositWorkflowService,
) {

    @PostMapping("/intents")
    fun createIntent(
        @PathVariable tenantId: String,
        @RequestHeader(name = "X-Session-Id", required = false) sessionIdHeader: String?,
        @RequestHeader(name = "X-Correlation-Id", required = false) correlationIdHeader: String?,
        @RequestHeader(name = "X-Causation-Id", required = false) causationIdHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
        @RequestBody request: CreateDepositIntentRequest,
    ): ResponseEntity<Any> {
        val sessionId = sessionIdHeader ?: "sess-default"
        val correlationId = correlationIdHeader ?: UUID.randomUUID().toString()
        val causationId = causationIdHeader ?: UUID.randomUUID().toString()
        val principal = principalAttr ?: AuthenticatedPrincipal(
            id = "anonymous",
            tenantId = tenantId,
            kind = PrincipalKind.PLAYER,
            roles = emptySet(),
        )

        if (request.amountMinorUnits <= 0) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(
                mapOf("error" to "INVALID_MONEY", "message" to "Deposit amount must be strictly positive")
            )
        }
        val validCurrencies = setOf("PKR", "INR", "USD", "EUR", "GBP")
        if (!validCurrencies.contains(request.currencyCode)) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(
                mapOf("error" to "INVALID_MONEY", "message" to "Unsupported currency code")
            )
        }

        val command = CreateDepositIntentCommand(
            principal = principal,
            sessionId = sessionId,
            tenantId = tenantId,
            playerId = try {
                UUID.fromString(principal.id)
            } catch (_: Exception) {
                UUID.nameUUIDFromBytes(principal.id.toByteArray())
            },
            methodId = request.methodId,
            amountMinorUnits = request.amountMinorUnits,
            currencyCode = request.currencyCode,
            customerIdentifier = request.customerIdentifier,
            methodExpectedVersion = request.methodExpectedVersion,
            idempotencyKey = request.idempotencyKey,
            correlationId = correlationId,
            causationId = causationId,
            clientReturnUrl = request.clientReturnUrl,
        )

        return try {
            val result = workflowService.createIntent(command)
            ResponseEntity.ok(result)
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.UNAUTHENTICATED ->
                    ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
                AuthErrorCode.FORBIDDEN ->
                    ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
                AuthErrorCode.CONFLICT ->
                    ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
                else ->
                    ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
            }
        } catch (e: PaymentMethodUnavailableException) {
            ResponseEntity.status(HttpStatus.CONFLICT).body(
                mapOf(
                    "error" to "METHOD_UNAVAILABLE",
                    "code" to e.code.name,
                    "methodId" to e.methodId,
                    "message" to e.message,
                )
            )
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/intents/{intentId}")
    fun getIntent(
        @PathVariable tenantId: String,
        @PathVariable intentId: UUID,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        return try {
            val playerId = try {
                UUID.fromString(principal.id)
            } catch (_: Exception) {
                UUID.nameUUIDFromBytes(principal.id.toByteArray())
            }
            val intent = workflowService.getIntent(tenantId, intentId, playerId)
            ResponseEntity.ok(intent)
        } catch (e: AuthenticationFailure.Rejected) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to e.message))
        }
    }

    @PostMapping("/callback/{providerId}")
    fun handleCallback(
        @PathVariable tenantId: String,
        @PathVariable providerId: String,
        @RequestHeader headers: Map<String, String>,
        @RequestParam queryParams: Map<String, String>,
        @RequestBody rawBody: String,
    ): ResponseEntity<Any> {
        val eventId = headers["x-provider-event-id"]
            ?: headers["x-event-id"]
            ?: UUID.randomUUID().toString()

        val command = DepositCallbackCommand(
            tenantId = tenantId,
            providerId = providerId,
            providerEventId = eventId,
            rawBody = rawBody,
            headers = headers,
            queryParams = queryParams,
        )

        return try {
            val result = workflowService.processCallback(command)
            ResponseEntity.ok(result)
        } catch (e: AuthenticationFailure.Rejected) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "SIGNATURE_VERIFICATION_FAILED"))
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "CALLBACK_ERROR")))
        }
    }

    @PostMapping("/intents/{intentId}/reconcile")
    fun reconcileIntent(
        @PathVariable tenantId: String,
        @PathVariable intentId: UUID,
        @RequestHeader(name = "X-Session-Id", required = false) sessionIdHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val sessionId = sessionIdHeader ?: "sess-admin"
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()

        val command = DepositReconciliationCommand(
            tenantId = tenantId,
            intentId = intentId,
            principal = principal,
            sessionId = sessionId,
        )

        return try {
            val result = workflowService.reconcile(command)
            ResponseEntity.ok(result)
        } catch (e: AuthenticationFailure.Rejected) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to e.message))
        }
    }

    @GetMapping("/intents/{intentId}/return")
    fun handleClientReturn(
        @PathVariable tenantId: String,
        @PathVariable intentId: UUID,
        @RequestParam returnParams: Map<String, String>,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        return try {
            workflowService.handleClientReturn(tenantId, intentId, returnParams, principalAttr)
            ResponseEntity.ok(mapOf("status" to "RETURN_RECEIVED"))
        } catch (e: AuthenticationFailure.Rejected) {
            // Explains to caller that return URL is strictly presentation, cannot settle
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                mapOf(
                    "error" to "RETURN_URL_CANNOT_SETTLE",
                    "detail" to "Client return URL is presentation-only; settlement requires authenticated webhook callback or admin reconciliation",
                )
            )
        }
    }
}
