package com.slotting.admin.account

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.wallet.AuthoritativeWalletService
import com.slotting.admin.wallet.StatementPageQuery
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.util.UUID

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/account")
class PlayerAccountController(
    private val accountService: AuthoritativeAccountService,
    private val walletService: AuthoritativeWalletService? = null,
) {

    private fun resolveOwnerUserId(principal: AuthenticatedPrincipal?, requestedOwner: UUID?): UUID {
        if (principal == null) throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (requestedOwner != null) {
            if (principal.kind == PrincipalKind.PLAYER && principal.id != requestedOwner.toString()) {
                throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
            }
            return requestedOwner
        }
        return try {
            UUID.fromString(principal.id)
        } catch (_: Exception) {
            UUID.nameUUIDFromBytes(principal.id.toByteArray())
        }
    }

    @GetMapping("/profile")
    fun getProfile(
        @PathVariable tenantId: String,
        @RequestParam(required = false) ownerUserId: UUID?,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        return try {
            val owner = resolveOwnerUserId(principal, ownerUserId)
            val profile = accountService.getProfile(principal, sessionId, tenantId, owner)
            ResponseEntity.ok(profile)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/statement")
    fun getStatement(
        @PathVariable tenantId: String,
        @RequestParam(required = false) ownerUserId: UUID?,
        @RequestParam(required = false, defaultValue = "PKR") currencyCode: String,
        @RequestParam(required = false) cursor: String?,
        @RequestParam(required = false, defaultValue = "20") pageSize: Int,
        @RequestParam(required = false) idempotencyKey: String?,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val p = principal ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        return try {
            val owner = resolveOwnerUserId(p, ownerUserId)
            val query = StatementPageQuery(
                principal = p,
                tenantId = tenantId,
                ownerReference = owner.toString(),
                currencyCode = currencyCode,
                cursor = cursor,
                limit = pageSize,
                idempotencyKey = idempotencyKey,
            )
            // Use walletService if provided, otherwise query through statement
            val ws = walletService ?: return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build()
            val page = ws.getStatementPage(query)
            ResponseEntity.ok(page)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @PostMapping("/support/cases")
    fun createSupportCase(
        @PathVariable tenantId: String,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
        @RequestBody request: CreateSupportCaseRequest,
    ): ResponseEntity<Any> {
        val p = principal ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        return try {
            val owner = resolveOwnerUserId(p, null)
            val command = CreateSupportCaseCommand(
                principal = p,
                tenantId = tenantId,
                ownerUserId = owner,
                category = request.category,
                subject = request.subject,
                description = request.description,
                roundId = request.roundId,
                idempotencyKey = request.idempotencyKey,
                correlationId = request.correlationId ?: "corr-supp-${UUID.randomUUID()}",
            )
            val created = accountService.createSupportCase(command)
            ResponseEntity.ok(created)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/support/cases")
    fun listSupportCases(
        @PathVariable tenantId: String,
        @RequestParam(required = false) ownerUserId: UUID?,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val p = principal ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        return try {
            val owner = resolveOwnerUserId(p, ownerUserId)
            val cases = accountService.listSupportCases(p, sessionId, tenantId, owner)
            ResponseEntity.ok(cases)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/support/cases/{caseId}")
    fun getSupportCase(
        @PathVariable tenantId: String,
        @PathVariable caseId: UUID,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val p = principal ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        return try {
            val case = accountService.getSupportCase(p, sessionId, tenantId, caseId)
            ResponseEntity.ok(case)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "NOT_FOUND", "message" to e.message))
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @PostMapping("/closure/requests")
    fun requestClosure(
        @PathVariable tenantId: String,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
        @RequestBody request: AccountClosureRequest,
    ): ResponseEntity<Any> {
        val p = principal ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        return try {
            val owner = resolveOwnerUserId(p, request.ownerUserId)
            val command = SubmitAccountClosureCommand(
                principal = p,
                tenantId = tenantId,
                ownerUserId = owner,
                reason = request.reason,
                reasonDetails = request.reasonDetails,
                settlementAcknowledgment = request.settlementAcknowledgment,
                idempotencyKey = request.idempotencyKey,
                correlationId = request.correlationId ?: "corr-close-${UUID.randomUUID()}",
            )
            val result = accountService.requestAccountClosure(command)
            ResponseEntity.ok(result)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: PositiveBalanceUnacknowledgedException) {
            ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(
                mapOf("error" to "SETTLEMENT_ACKNOWLEDGMENT_REQUIRED", "message" to e.message)
            )
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/closure/status")
    fun getClosureStatus(
        @PathVariable tenantId: String,
        @RequestParam(required = false) ownerUserId: UUID?,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val p = principal ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        return try {
            val owner = resolveOwnerUserId(p, ownerUserId)
            val status = accountService.getClosureStatus(p, sessionId, tenantId, owner)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("status" to "NONE"))
            ResponseEntity.ok(status)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/restrictions")
    fun getRestrictions(
        @PathVariable tenantId: String,
        @RequestParam(required = false) ownerUserId: UUID?,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val p = principal ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        return try {
            val owner = resolveOwnerUserId(p, ownerUserId)
            val summary = accountService.getRestrictionsSummary(p, sessionId, tenantId, owner)
            ResponseEntity.ok(summary)
        } catch (e: AuthenticationFailure.Rejected) {
            mapAuthException(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    private fun mapAuthException(e: AuthenticationFailure.Rejected): ResponseEntity<Any> {
        return when (e.code) {
            AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
            AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
            AuthErrorCode.CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
            AuthErrorCode.DEPENDENCY_UNAVAILABLE -> ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(mapOf("error" to e.code.name))
            AuthErrorCode.STALE -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
            else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
        }
    }
}
