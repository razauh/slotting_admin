package com.slotting.admin.rg

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.util.UUID

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/players/{playerId}/rg")
class PlayerResponsibleGamingController(
    private val rgService: DurableResponsibleGamingService
) {

    private fun checkAccess(principal: AuthenticatedPrincipal?, tenantId: String, playerId: String): ResponseEntity<Any>? {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        }
        if (principal.tenantId != tenantId) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))
        }
        if (principal.kind == PrincipalKind.PLAYER && principal.id != playerId) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN", "message" to "Cross-owner access prohibited"))
        }
        return null
    }

    @GetMapping("/status")
    fun getStatus(
        @PathVariable tenantId: String,
        @PathVariable playerId: String,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?
    ): ResponseEntity<Any> {
        val error = checkAccess(principal, tenantId, playerId)
        if (error != null) return error

        return try {
            val status = rgService.getPlayerRgStatus(tenantId, playerId)
            ResponseEntity.ok(status)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    data class ChangeLimitRequest(
        val limitType: String,
        val period: String = "DAILY",
        val limitValueMinor: Long,
        val timezone: String = "UTC",
        val expectedVersion: Long = 1L
    )

    @PostMapping("/limits")
    fun changeLimit(
        @PathVariable tenantId: String,
        @PathVariable playerId: String,
        @RequestBody request: ChangeLimitRequest,
        @RequestHeader(name = "Idempotency-Key", required = false) idempHeader: String?,
        @RequestHeader(name = "X-Correlation-Id", required = false) corrHeader: String?,
        @RequestHeader(name = "X-Causation-Id", required = false) causHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?
    ): ResponseEntity<Any> {
        val error = checkAccess(principal, tenantId, playerId)
        if (error != null) return error

        val idemp = idempHeader ?: "idemp-limit-${UUID.randomUUID()}"
        val corr = corrHeader ?: "corr-${UUID.randomUUID()}"
        val caus = causHeader ?: "caus-${UUID.randomUUID()}"

        return try {
            val limitType = RgLimitType.valueOf(request.limitType.uppercase())
            val period = RgLimitPeriod.valueOf(request.period.uppercase())

            val cmd = ChangeLimitCommand(
                tenantId = tenantId,
                playerId = playerId,
                limitType = limitType,
                period = period,
                limitValueMinor = request.limitValueMinor,
                timezone = request.timezone,
                idempotencyKey = idemp,
                correlationId = corr,
                causationId = caus,
                expectedVersion = request.expectedVersion,
                principal = principal
            )
            val receipt = rgService.changeLimit(cmd)
            ResponseEntity.ok(receipt)
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to "INVALID_ARGUMENT", "message" to e.message))
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.STALE -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to "STALE", "message" to "Limit version mismatch"))
                AuthErrorCode.CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to "CONFLICT", "message" to "Idempotency conflict"))
                AuthErrorCode.INVALID -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to "INVALID"))
                else -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
            }
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    data class ApplyExclusionRequest(
        val exclusionType: String,
        val durationDays: Int? = null,
        val reason: String = "Player requested exclusion",
        val expectedVersion: Long = 1L
    )

    @PostMapping("/exclusions")
    fun applyExclusion(
        @PathVariable tenantId: String,
        @PathVariable playerId: String,
        @RequestBody request: ApplyExclusionRequest,
        @RequestHeader(name = "Idempotency-Key", required = false) idempHeader: String?,
        @RequestHeader(name = "X-Correlation-Id", required = false) corrHeader: String?,
        @RequestHeader(name = "X-Causation-Id", required = false) causHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?
    ): ResponseEntity<Any> {
        val error = checkAccess(principal, tenantId, playerId)
        if (error != null) return error

        val idemp = idempHeader ?: "idemp-excl-${UUID.randomUUID()}"
        val corr = corrHeader ?: "corr-${UUID.randomUUID()}"
        val caus = causHeader ?: "caus-${UUID.randomUUID()}"

        return try {
            val exclType = DurableExclusionType.valueOf(request.exclusionType.uppercase())
            val cmd = ApplyPlayerExclusionCommand(
                tenantId = tenantId,
                playerId = playerId,
                exclusionType = exclType,
                durationDays = request.durationDays,
                reason = request.reason,
                idempotencyKey = idemp,
                correlationId = corr,
                causationId = caus,
                expectedVersion = request.expectedVersion,
                principal = principal
            )
            val result = rgService.applyExclusion(cmd)
            ResponseEntity.ok(result)
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to "INVALID_ARGUMENT", "message" to e.message))
        } catch (e: AuthenticationFailure.Rejected) {
            when (e.code) {
                AuthErrorCode.CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to "CONFLICT"))
                AuthErrorCode.INVALID -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to "INVALID"))
                else -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
            }
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    data class ReserveUsageRequest(
        val limitType: String,
        val amountMinor: Long,
        val product: String = "CASINO",
        val referenceId: String,
        val timezone: String = "UTC"
    )

    @PostMapping("/reserve-usage")
    fun reserveUsage(
        @PathVariable tenantId: String,
        @PathVariable playerId: String,
        @RequestBody request: ReserveUsageRequest,
        @RequestHeader(name = "Idempotency-Key", required = false) idempHeader: String?,
        @RequestHeader(name = "X-Correlation-Id", required = false) corrHeader: String?,
        @RequestHeader(name = "X-Causation-Id", required = false) causHeader: String?,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?
    ): ResponseEntity<Any> {
        val error = checkAccess(principal, tenantId, playerId)
        if (error != null) return error

        val idemp = idempHeader ?: "idemp-res-${UUID.randomUUID()}"
        val corr = corrHeader ?: "corr-${UUID.randomUUID()}"
        val caus = causHeader ?: "caus-${UUID.randomUUID()}"

        return try {
            val limitType = RgLimitType.valueOf(request.limitType.uppercase())
            val result = rgService.reserveUsage(
                tenantId = tenantId,
                playerId = playerId,
                limitType = limitType,
                amountMinor = request.amountMinor,
                product = request.product,
                referenceId = request.referenceId,
                idempotencyKey = idemp,
                correlationId = corr,
                causationId = caus,
                timezone = request.timezone
            )
            ResponseEntity.ok(result)
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to "INVALID_ARGUMENT", "message" to e.message))
        } catch (e: AuthenticationFailure.Rejected) {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }
}
