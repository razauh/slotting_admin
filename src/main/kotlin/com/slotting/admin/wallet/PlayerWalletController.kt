package com.slotting.admin.wallet

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/wallet")
class PlayerWalletController(
    private val walletService: AuthoritativeWalletService,
) {

    @GetMapping("/snapshot")
    fun getSnapshot(
        @PathVariable tenantId: String,
        @RequestParam(required = false) ownerReference: String?,
        @RequestParam(required = false) expectedLedgerVersion: Long?,
        @RequestParam(required = false, defaultValue = "true") allowStale: Boolean,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )

        val targetOwner = ownerReference ?: principal.id

        // Strict cross-owner IDOR prevention
        if (principal.kind == PrincipalKind.PLAYER && principal.id != targetOwner) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                mapOf("error" to "FORBIDDEN", "message" to "Cross-owner access prohibited")
            )
        }

        val query = WalletSnapshotQuery(
            principal = principal,
            tenantId = tenantId,
            ownerReference = targetOwner,
            expectedLedgerVersion = expectedLedgerVersion,
            allowStale = allowStale,
        )

        return try {
            val snapshot = walletService.getWalletSnapshot(query)
            ResponseEntity.ok(snapshot)
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
                AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
                AuthErrorCode.STALE -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
                else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
            }
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/statement")
    fun getStatement(
        @PathVariable tenantId: String,
        @RequestParam(required = false) ownerReference: String?,
        @RequestParam(required = false, defaultValue = "PKR") currencyCode: String,
        @RequestParam(required = false) cursor: String?,
        @RequestParam(required = false, defaultValue = "20") pageSize: Int,
        @RequestParam(required = false) idempotencyKey: String?,
        @RequestHeader(name = "X-Session-Id", required = false) sessionId: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        val principal = principalAttr ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            mapOf("error" to "UNAUTHENTICATED")
        )

        val targetOwner = ownerReference ?: principal.id

        if (principal.kind == PrincipalKind.PLAYER && principal.id != targetOwner) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                mapOf("error" to "FORBIDDEN", "message" to "Cross-owner access prohibited")
            )
        }

        val query = StatementPageQuery(
            principal = principal,
            tenantId = tenantId,
            ownerReference = targetOwner,
            currencyCode = currencyCode,
            cursor = cursor,
            limit = pageSize,
            idempotencyKey = idempotencyKey,
        )

        return try {
            val page = walletService.getStatementPage(query)
            ResponseEntity.ok(page)
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
                AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
                AuthErrorCode.CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
                else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
            }
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }
}
