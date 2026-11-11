package com.slotting.admin.ops

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.AuthenticationFailure
import com.slotting.admin.security.SecurityAuthenticationFilter
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Clock

data class OpsNoticeView(
    val id: String,
    val cause: String,
    val classTag: String,
    val severity: String,
    val text: String,
    val createdAt: String,
    val acknowledged: Boolean,
)

data class OpsRegistryRowView(
    val itemName: String,
    val owner: String?,
    val ownerAbsent: Boolean,
    val status: String,
    val dueDate: String?,
    val reopenTrigger: String,
)

data class OpsNoticesResponse(
    val serverTime: String,
    val items: List<OpsNoticeView>,
)

data class OpsRegistryResponse(
    val serverTime: String,
    val items: List<OpsRegistryRowView>,
)

@RestController
class OpsAdminController(
    private val notices: OpsNoticeRepository,
    private val decisions: OpsDecisionSource,
    private val clock: Clock = Clock.systemUTC(),
    private val rbac: AdminRbacPolicy = AdminRbacPolicy(true),
) {
    @GetMapping("/admin/ops/notices")
    fun listNotices(@RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?): OpsNoticesResponse {
        requirePermission(principal)
        return OpsNoticesResponse(
            serverTime = clock.instant().toString(),
            items = notices.list().map { notice ->
                OpsNoticeView(
                    id = notice.cause,
                    cause = notice.cause,
                    classTag = notice.classTag,
                    severity = notice.severity.name,
                    text = notice.text,
                    createdAt = notice.createdAt.toString(),
                    acknowledged = false,
                )
            },
        )
    }

    @PostMapping("/admin/ops/notices/{id}/ack")
    fun ack(@PathVariable id: String, @RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?): Map<String, Any> {
        requirePermission(principal)
        return mapOf(
            "cause" to id,
            "acknowledged" to notices.ack(id),
            "serverTime" to clock.instant().toString(),
        )
    }

    @GetMapping("/admin/ops/registry")
    fun registry(@RequestAttribute(SecurityAuthenticationFilter.AUTHENTICATED_PRINCIPAL_ATTR) principal: AuthenticatedPrincipal?): OpsRegistryResponse {
        requirePermission(principal)
        return OpsRegistryResponse(
            serverTime = clock.instant().toString(),
            items = decisions.all().map { row ->
                OpsRegistryRowView(
                    itemName = row.itemName,
                    owner = row.owner,
                    ownerAbsent = row.owner == null,
                    status = row.status.name,
                    dueDate = row.dueDate?.toString(),
                    reopenTrigger = row.reopenTrigger,
                )
            },
        )
    }

    private fun requirePermission(principal: AuthenticatedPrincipal?) {
        val caller = principal ?: throw AuthenticationFailure.Rejected(AuthErrorCode.UNAUTHENTICATED)
        if (!rbac.isPermitted(caller, AdminPermission.OPERATIONS_MANAGE)) {
            throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
        }
    }
}
