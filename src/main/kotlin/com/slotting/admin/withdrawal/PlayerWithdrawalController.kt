package com.slotting.admin.withdrawal

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.provider.PaymentMethodUnavailableException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.util.UUID

data class CreateWithdrawalQuoteRequest(
    val methodId: String,
    val destinationId: UUID,
    val grossAmountMinorUnits: Long,
    val currencyCode: String,
    val idempotencyKey: String,
)

data class CreateWithdrawalRequestPayload(
    val quoteId: UUID,
    val destinationId: UUID,
    val idempotencyKey: String,
    val stepUpToken: String? = null,
)

data class IssueStepUpRequestPayload(
    val quoteId: UUID,
)

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/withdrawals")
class PlayerWithdrawalController(
    private val withdrawalService: AuthoritativeWithdrawalService,
) {

    @PostMapping("/quotes")
    fun createQuote(
        @PathVariable tenantId: String,
        @RequestHeader(name = "X-Session-Id", required = false) sessionIdHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
        @RequestBody request: CreateWithdrawalQuoteRequest,
    ): ResponseEntity<Any> {
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )
        val sessionId = sessionIdHeader ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )

        val ownerId = try {
            UUID.fromString(principal.id)
        } catch (_: Exception) {
            UUID.nameUUIDFromBytes(principal.id.toByteArray())
        }

        if (request.grossAmountMinorUnits <= 0) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(
                mapOf("error" to "INVALID_MONEY", "message" to "Gross amount must be strictly positive")
            )
        }

        val command = CreateAuthoritativeQuoteCommand(
            principal = principal,
            sessionId = sessionId,
            tenantId = tenantId,
            ownerId = ownerId,
            currencyCode = request.currencyCode,
            methodId = request.methodId,
            destinationId = request.destinationId,
            grossAmountMinorUnits = request.grossAmountMinorUnits,
            idempotencyKey = request.idempotencyKey,
        )

        return try {
            val quote = withdrawalService.createQuote(command)
            ResponseEntity.ok(quote)
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
                AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
                AuthErrorCode.CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
                else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
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
        } catch (e: RestrictedAccountException) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "ACCOUNT_RESTRICTED", "message" to e.message))
        } catch (e: UnverifiedDestinationException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(mapOf("error" to "UNVERIFIED_DESTINATION", "message" to e.message))
        } catch (e: InsufficientWithdrawableFundsException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(mapOf("error" to "INSUFFICIENT_FUNDS", "message" to e.message))
        } catch (e: InvalidFeeBoundaryException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(mapOf("error" to "INVALID_FEE_BOUNDARY", "message" to e.message))
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(mapOf("error" to "INVALID_INPUT", "message" to e.message))
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @PostMapping("/quotes/{quoteId}/step-up")
    fun issueStepUp(
        @PathVariable tenantId: String,
        @PathVariable quoteId: UUID,
        @RequestHeader(name = "X-Session-Id", required = false) sessionIdHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )
        val sessionId = sessionIdHeader ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )

        val ownerId = try {
            UUID.fromString(principal.id)
        } catch (_: Exception) {
            UUID.nameUUIDFromBytes(principal.id.toByteArray())
        }

        val command = IssueStepUpAssertionCommand(
            principal = principal,
            sessionId = sessionId,
            tenantId = tenantId,
            ownerId = ownerId,
            quoteId = quoteId,
        )

        return try {
            val assertion = withdrawalService.issueStepUpAssertion(command)
            ResponseEntity.ok(assertion)
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
                AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
                else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
            }
        } catch (e: StaleQuoteException) {
            ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to "STALE_QUOTE", "message" to e.message))
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "NOT_FOUND", "message" to e.message))
        }
    }

    @PostMapping("/requests")
    fun createWithdrawalRequest(
        @PathVariable tenantId: String,
        @RequestHeader(name = "X-Session-Id", required = false) sessionIdHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
        @RequestBody request: CreateWithdrawalRequestPayload,
    ): ResponseEntity<Any> {
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )
        val sessionId = sessionIdHeader ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )

        val ownerId = try {
            UUID.fromString(principal.id)
        } catch (_: Exception) {
            UUID.nameUUIDFromBytes(principal.id.toByteArray())
        }

        val command = CreateAuthoritativeWithdrawalRequestCommand(
            principal = principal,
            sessionId = sessionId,
            tenantId = tenantId,
            ownerId = ownerId,
            quoteId = request.quoteId,
            destinationId = request.destinationId,
            stepUpToken = request.stepUpToken,
            idempotencyKey = request.idempotencyKey,
        )

        return try {
            val result = withdrawalService.createWithdrawalRequest(command)
            ResponseEntity.ok(result)
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
                AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
                AuthErrorCode.CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
                else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
            }
        } catch (e: StaleQuoteException) {
            ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to "STALE_QUOTE", "message" to e.message))
        } catch (e: DestinationMismatchException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(mapOf("error" to "DESTINATION_MISMATCH", "message" to e.message))
        } catch (e: UnverifiedDestinationException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(mapOf("error" to "UNVERIFIED_DESTINATION", "message" to e.message))
        } catch (e: StepUpAuthenticationRequiredException) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "STEP_UP_REQUIRED", "message" to e.message))
        } catch (e: StepUpReplayException) {
            ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to "STEP_UP_REPLAY", "message" to e.message))
        } catch (e: StepUpBindingMismatchException) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "STEP_UP_BINDING_MISMATCH", "message" to e.message))
        } catch (e: InsufficientWithdrawableFundsException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(mapOf("error" to "INSUFFICIENT_FUNDS", "message" to e.message))
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to (e.message ?: "INVALID_REQUEST")))
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/requests/{requestId}")
    fun getWithdrawalRequest(
        @PathVariable tenantId: String,
        @PathVariable requestId: UUID,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )

        val ownerId = try {
            UUID.fromString(principal.id)
        } catch (_: Exception) {
            UUID.nameUUIDFromBytes(principal.id.toByteArray())
        }

        return try {
            val req = withdrawalService.getRequest(tenantId, requestId, ownerId)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "NOT_FOUND"))
            ResponseEntity.ok(req)
        } catch (e: AuthenticationFailure.Rejected) {
            ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
        }
    }
}
