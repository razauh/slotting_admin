package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.math.BigDecimal

data class GameAccountMoney(
    val amountMinor: Long? = null,
    val currency: String? = null,
)

data class GameCommandRequest(
    val schemaVersion: Int? = null,
    val protocolVersion: String? = null,
    val rulesVersion: String? = null,
    val commandId: String = "",
    val causationId: String? = null,
    val gameId: String = "aviator",
    val roundId: String = "",
    val handId: String = "hand_primary",
    val action: String = "",
    val expectedRoundVersion: Long? = null,
    val wagerMinorUnits: Long? = null,
    val currencyCode: String? = null,
    val accountMoney: GameAccountMoney? = null,
    val autoCashOutMultiplier: String? = null,
    val cashOutMultiplier: BigDecimal? = null,
    val correlationId: String? = null,
)

@RestController
@RequestMapping("/api")
class AviatorGameRestController(
    private val snapshotAndEventService: AuthoritativeGameSnapshotAndEventService,
    private val gameService: DurableGameWagerAndSettlementService,
) {

    private fun resolvePrincipal(
        tenantId: String,
        sessionToken: String?,
        authHeader: String?,
        principalAttr: AuthenticatedPrincipal?,
    ): AuthenticatedPrincipal? {
        if (principalAttr != null) return principalAttr
        val token = sessionToken?.takeIf { it.isNotBlank() }
            ?: authHeader?.removePrefix("Bearer ")?.takeIf { it.isNotBlank() }
            ?: return null

        return try {
            snapshotAndEventService.authenticateSession(tenantId, token)
        } catch (e: Exception) {
            null
        }
    }

    @GetMapping("/bootstrap")
    fun getBootstrap(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestParam(required = false, defaultValue = "AVIATOR") gameId: String,
        @RequestHeader(name = "X-Session-Token", required = false) sessionToken: String? = null,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal? = null,
    ): ResponseEntity<Any> {
        return try {
            val response = snapshotAndEventService.getBootstrap(tenantIdHeader, gameId.uppercase())
            ResponseEntity.ok(response)
        } catch (e: AuthenticationFailure.Rejected) {
            handleAuthFailure(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/bet-limits")
    fun getBetLimits(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestParam(required = false, defaultValue = "AVIATOR") gameId: String,
    ): ResponseEntity<CrashBetLimits> {
        return ResponseEntity.ok(snapshotAndEventService.getLimits())
    }

    @GetMapping("/my-info")
    fun getMyInfo(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestHeader(name = "X-Session-Token", required = false) sessionToken: String? = null,
        @RequestHeader(name = "Authorization", required = false) authHeader: String? = null,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal? = null,
    ): ResponseEntity<Any> {
        val principal = resolvePrincipal(tenantIdHeader, sessionToken, authHeader, principalAttr)
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))

        return try {
            val info = snapshotAndEventService.getMyInfo(tenantIdHeader, principal)
            ResponseEntity.ok(info)
        } catch (e: AuthenticationFailure.Rejected) {
            handleAuthFailure(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @PostMapping("/my-info")
    fun postMyInfo(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestBody(required = false) body: Map<String, Any>?,
        @RequestHeader(name = "X-Session-Token", required = false) sessionToken: String? = null,
        @RequestHeader(name = "Authorization", required = false) authHeader: String? = null,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal? = null,
    ): ResponseEntity<Any> {
        val principal = resolvePrincipal(tenantIdHeader, sessionToken, authHeader, principalAttr)
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))

        val limit = (body?.get("limit") as? Number)?.toInt() ?: 20
        return try {
            val bets = snapshotAndEventService.getMyBets(tenantIdHeader, principal, limit)
            ResponseEntity.ok(bets)
        } catch (e: AuthenticationFailure.Rejected) {
            handleAuthFailure(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping(value = ["/get-day-history", "/get-month-history", "/get-year-history"])
    fun getTopHistory(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestHeader(name = "X-Session-Token", required = false) sessionToken: String? = null,
        @RequestHeader(name = "Authorization", required = false) authHeader: String? = null,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal? = null,
    ): ResponseEntity<Any> {
        val principal = resolvePrincipal(tenantIdHeader, sessionToken, authHeader, principalAttr)
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))

        return try {
            val history = snapshotAndEventService.getTopHistory(tenantIdHeader, principal, 20)
            ResponseEntity.ok(history)
        } catch (e: AuthenticationFailure.Rejected) {
            handleAuthFailure(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/snapshot")
    fun getSnapshot(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestParam(required = false, defaultValue = "AVIATOR") gameId: String,
        @RequestParam(required = false) roundId: String? = null,
        @RequestParam(name = "round_id", required = false) roundIdSnake: String? = null,
        @RequestHeader(name = "X-Session-Token", required = false) sessionToken: String? = null,
        @RequestHeader(name = "Authorization", required = false) authHeader: String? = null,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal? = null,
    ): ResponseEntity<Any> {
        val principal = resolvePrincipal(tenantIdHeader, sessionToken, authHeader, principalAttr)
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))

        val targetRoundId = roundId ?: roundIdSnake
        return try {
            val snapshot = snapshotAndEventService.getAuthoritativeSnapshot(
                tenantId = tenantIdHeader,
                principal = principal,
                gameId = gameId.uppercase(),
                roundId = targetRoundId
            )
            ResponseEntity.ok(snapshot)
        } catch (e: AuthenticationFailure.Rejected) {
            handleAuthFailure(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/round-history")
    fun getRoundHistory(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestParam(required = false, defaultValue = "AVIATOR") gameId: String,
        @RequestParam(required = false, defaultValue = "20") limit: Int,
    ): ResponseEntity<List<RoundHistoryEntry>> {
        val boundedLimit = limit.coerceIn(1, 100)
        val history = snapshotAndEventService.getRoundHistory(tenantIdHeader, gameId.uppercase(), boundedLimit)
        return ResponseEntity.ok(history)
    }

    @PostMapping("/command")
    fun postCommand(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestBody request: GameCommandRequest,
        @RequestHeader(name = "X-Session-Token", required = false) sessionToken: String? = null,
        @RequestHeader(name = "Authorization", required = false) authHeader: String? = null,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal? = null,
    ): ResponseEntity<Any> {
        val principal = resolvePrincipal(tenantIdHeader, sessionToken, authHeader, principalAttr)
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))

        val resolvedWager = request.accountMoney?.amountMinor ?: request.wagerMinorUnits
        val resolvedCurrency = request.accountMoney?.currency ?: request.currencyCode ?: "INR"
        val resolvedCausationId = request.causationId ?: request.commandId
        val resolvedCorrelationId = request.correlationId ?: request.commandId
        val resolvedProtocolVersion = request.protocolVersion ?: "1.2.0"
        val resolvedRulesVersion = request.rulesVersion ?: "1.0.0"

        val command = AviatorRestCommand(
            tenantId = tenantIdHeader,
            principal = principal,
            commandId = request.commandId,
            causationId = resolvedCausationId,
            roundId = request.roundId,
            handId = request.handId,
            action = request.action,
            wagerMinor = resolvedWager,
            currency = resolvedCurrency,
            autoCashOutMultiplier = request.autoCashOutMultiplier,
            cashOutMultiplier = request.cashOutMultiplier?.toDouble(),
            correlationId = resolvedCorrelationId,
            protocolVersion = resolvedProtocolVersion,
            rulesVersion = resolvedRulesVersion,
            expectedRoundVersion = request.expectedRoundVersion,
        )

        return try {
            val result = gameService.processCommand(command)
            ResponseEntity.ok(result)
        } catch (e: AuthenticationFailure.Rejected) {
            handleAuthFailure(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    @GetMapping("/command-result")
    fun getCommandResult(
        @RequestHeader(name = "X-Tenant-Id", required = false, defaultValue = "default") tenantIdHeader: String,
        @RequestParam(required = false, defaultValue = "AVIATOR") gameId: String,
        @RequestParam roundId: String,
        @RequestParam commandId: String,
        @RequestHeader(name = "X-Session-Token", required = false) sessionToken: String? = null,
        @RequestHeader(name = "Authorization", required = false) authHeader: String? = null,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principalAttr: AuthenticatedPrincipal? = null,
    ): ResponseEntity<Any> {
        val principal = resolvePrincipal(tenantIdHeader, sessionToken, authHeader, principalAttr)
            ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))

        return try {
            val result = snapshotAndEventService.getCommandResult(
                tenantId = tenantIdHeader,
                principal = principal,
                gameId = gameId.uppercase(),
                roundId = roundId,
                commandId = commandId
            )
            if (result == null) {
                ResponseEntity.status(HttpStatus.NOT_FOUND).body(mapOf("error" to "COMMAND_NOT_FOUND"))
            } else {
                ResponseEntity.ok(result)
            }
        } catch (e: AuthenticationFailure.Rejected) {
            handleAuthFailure(e)
        } catch (e: Exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mapOf("error" to (e.message ?: "UNKNOWN_ERROR")))
        }
    }

    private fun handleAuthFailure(e: AuthenticationFailure.Rejected): ResponseEntity<Any> {
        return when (e.code) {
            AuthErrorCode.UNAUTHENTICATED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to e.code.name))
            AuthErrorCode.FORBIDDEN -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to e.code.name))
            AuthErrorCode.STALE, AuthErrorCode.CONFLICT -> ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to e.code.name))
            else -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapOf("error" to e.code.name))
        }
    }
}
