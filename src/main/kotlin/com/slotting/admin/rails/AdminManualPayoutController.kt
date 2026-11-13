package com.slotting.admin.rails

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.auth.PrincipalKind
import com.slotting.admin.security.SecurityAuthenticationFilter
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Clock
import java.time.Instant

data class PayoutQueueItemView(
    val id: String,
    val playerId: String,
    val amountUsd: String,
    val feeUsd: String,
    val netUsd: String,
    val payoutPkr: String,
    val destType: String,
    val destTitle: String,
    val destNumber: String,
    val status: String,
    val requestedUtc: String,
    val receiptUrl: String?,
)

data class PayoutReceiptUploadRequest(
    val fileName: String,
    val contentType: String,
)

data class PayoutDecisionResponse(
    val id: String,
    val status: String,
)

@RestController
@RequestMapping("/admin/rails/payout-requests")
class AdminManualPayoutController(
    private val settings: ManualRailsSettingsStore,
    private val requests: PayoutRequestRepository,
    private val queue: PayoutQueueStore,
    private val receiptStore: PayoutReceiptStore,
    private val poster: PayoutLedgerDebitPoster,
    private val receipts: ManualRailsReceiptService,
    private val audit: RailsAuditRecorder,
    private val clock: Clock = Clock.systemUTC(),
    private val rbac: AdminRbacPolicy = AdminRbacPolicy(true),
) {
    @GetMapping
    fun queue(
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestParam(required = false, defaultValue = "PENDING") status: String,
    ): List<PayoutQueueItemView> {
        val admin = requireAdmin(principal)
        val parsed = try {
            PayoutStatus.valueOf(status)
        } catch (_: Exception) {
            throw RailsHttpException("INVALID_STATUS", HttpStatus.BAD_REQUEST, "status is invalid")
        }
        return queue.listByStatus(admin.tenantId, parsed).map {
            PayoutQueueItemView(
                id = it.id,
                playerId = it.playerId,
                amountUsd = it.amountUsd.toPlainString(),
                feeUsd = it.feeUsd.toPlainString(),
                netUsd = it.netUsd.toPlainString(),
                payoutPkr = it.payoutPkr.toPlainString(),
                destType = it.destType,
                destTitle = it.destTitle,
                destNumber = it.destNumber,
                status = it.status.name,
                requestedUtc = it.requestedUtc.toString(),
                receiptUrl = it.receiptObject?.let { path -> receipts.readUrl(it.tenantId, it.playerId, path).url },
            )
        }
    }

    @PostMapping("/{id}/lock")
    fun lock(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): PayoutDecisionResponse {
        val admin = requireAdmin(principal)
        val row = queue.find(id) ?: throw RailsHttpException("PAYOUT_REQUEST_NOT_FOUND", HttpStatus.NOT_FOUND, "payout request not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val result = flow().lock(id, admin.id)
        return when (result.outcome) {
            PayoutOutcome.LOCKED -> {
                audit.record(RailsAuditEntry(admin.tenantId, admin.id, "PAYOUT_LOCKED", id, row.status.name, PayoutStatus.APPROVED_FUNDS_LOCKED.name, Instant.now(clock)))
                PayoutDecisionResponse(id, PayoutStatus.APPROVED_FUNDS_LOCKED.name)
            }
            PayoutOutcome.ALREADY_DECIDED -> throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "payout request is not pending")
            else -> throw RailsHttpException("INVALID_STATE", HttpStatus.CONFLICT, "payout request is not in a valid state")
        }
    }

    @PostMapping("/{id}/reject")
    fun reject(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody body: Map<String, String>,
    ): PayoutDecisionResponse {
        val admin = requireAdmin(principal)
        val reason = body["reason"]?.trim().orEmpty()
        if (reason.isBlank()) {
            throw RailsHttpException("REJECT_REASON_REQUIRED", HttpStatus.BAD_REQUEST, "reason is required")
        }
        val row = queue.find(id) ?: throw RailsHttpException("PAYOUT_REQUEST_NOT_FOUND", HttpStatus.NOT_FOUND, "payout request not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val result = flow().reject(id, reason, admin.id)
        return when (result.outcome) {
            PayoutOutcome.REJECTED -> {
                audit.record(RailsAuditEntry(admin.tenantId, admin.id, "PAYOUT_REJECTED", id, row.status.name, reason, Instant.now(clock)))
                PayoutDecisionResponse(id, PayoutStatus.REJECTED.name)
            }
            PayoutOutcome.ALREADY_DECIDED -> throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "payout request was already decided")
            else -> throw RailsHttpException("INVALID_STATE", HttpStatus.CONFLICT, "payout request is not in a valid state")
        }
    }

    @PostMapping("/{id}/receipt")
    fun uploadReceipt(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
        @RequestBody body: PayoutReceiptUploadRequest,
    ): Map<String, Any> {
        val admin = requireAdmin(principal)
        receipts.requireImage(body.fileName, body.contentType)
        val row = queue.find(id) ?: throw RailsHttpException("PAYOUT_REQUEST_NOT_FOUND", HttpStatus.NOT_FOUND, "payout request not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val path = receipts.payoutObjectPath(row.tenantId, row.playerId, id, body.fileName)
        if (!receiptStore.updateReceiptObject(id, path)) {
            throw RailsHttpException("PAYOUT_REQUEST_NOT_FOUND", HttpStatus.NOT_FOUND, "payout request not found")
        }
        val signed = receipts.uploadUrl(row.tenantId, row.playerId, path)
        audit.record(RailsAuditEntry(admin.tenantId, admin.id, "PAYOUT_RECEIPT_RECORDED", id, row.receiptObject, path, Instant.now(clock)))
        return mapOf("id" to id, "objectPath" to path, "uploadUrl" to signed.url, "expiresInSeconds" to signed.expiresInSeconds)
    }

    @PostMapping("/{id}/mark-paid")
    fun markPaid(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): PayoutDecisionResponse {
        val admin = requireAdmin(principal)
        val row = queue.find(id) ?: throw RailsHttpException("PAYOUT_REQUEST_NOT_FOUND", HttpStatus.NOT_FOUND, "payout request not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val alreadyPaid = (requests.find(id)?.status ?: row.status) == PayoutStatus.PAID
        val result = ManualPayoutLedgerDebitFlow(requests, poster).markPaid(id, admin.id)
        return when (result.outcome) {
            PayoutOutcome.PAID -> {
                if (!alreadyPaid) {
                    audit.record(RailsAuditEntry(admin.tenantId, admin.id, "PAYOUT_MARKED_PAID", id, row.status.name, "${row.netUsd}:${row.payoutPkr}", Instant.now(clock)))
                }
                PayoutDecisionResponse(id, PayoutStatus.PAID.name)
            }
            PayoutOutcome.RECEIPT_REQUIRED -> throw RailsHttpException("RECEIPT_REQUIRED", HttpStatus.CONFLICT, "receipt is required before marking paid")
            PayoutOutcome.INVALID_STATE -> throw RailsHttpException("INVALID_STATE", HttpStatus.CONFLICT, "payout request is not locked")
            PayoutOutcome.ALREADY_DECIDED -> throw RailsHttpException("ALREADY_DECIDED", HttpStatus.CONFLICT, "payout request was already decided")
            PayoutOutcome.NOT_FOUND -> throw RailsHttpException("PAYOUT_REQUEST_NOT_FOUND", HttpStatus.NOT_FOUND, "payout request not found")
            else -> throw RailsHttpException("INVALID_STATE", HttpStatus.CONFLICT, "payout request is not in a valid state")
        }
    }

    @GetMapping("/{id}/receipt")
    fun receipt(
        @PathVariable id: String,
        @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?,
    ): Map<String, Any> {
        val admin = requireAdmin(principal)
        val row = queue.find(id) ?: throw RailsHttpException("PAYOUT_REQUEST_NOT_FOUND", HttpStatus.NOT_FOUND, "payout request not found")
        if (row.tenantId != admin.tenantId) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        val path = row.receiptObject
            ?: throw RailsHttpException("RECEIPT_REQUIRED", HttpStatus.NOT_FOUND, "payout receipt is not available")
        val signed = receipts.readUrl(row.tenantId, row.playerId, path)
        return mapOf("id" to id, "url" to signed.url, "expiresInSeconds" to signed.expiresInSeconds)
    }

    private fun flow(): ManualPayoutFlow {
        val current = settings.get()
        return ManualPayoutFlow(requests, PayoutSettings(current.payoutRate, current.feePercent))
    }

    private fun requireAdmin(principal: AuthenticatedPrincipal?): AuthenticatedPrincipal {
        val caller = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (caller.kind != PrincipalKind.ADMIN) throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        if (!rbac.isPermitted(caller, AdminPermission.OPERATIONS_MANAGE)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
        return caller
    }
}
