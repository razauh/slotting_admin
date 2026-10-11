package com.slotting.admin.gameprovider

import com.slotting.admin.auth.AdminPermission
import com.slotting.admin.auth.AdminRbacPolicy
import com.slotting.admin.auth.AuthenticatedPrincipal
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

class LifecycleDiagnosticsForbiddenException : RuntimeException()

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/games/{gameId}/rounds/{roundId}/lifecycle")
class AviatorLifecycleDiagnosticsController(
    private val reconciliation: AviatorLifecycleReconciliationService,
    private val policy: AdminRbacPolicy = AdminRbacPolicy(dualControlRequired = false),
) {
    @GetMapping("/diagnostics")
    fun diagnostics(
        @PathVariable tenantId: String,
        @PathVariable gameId: String,
        @PathVariable roundId: String,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        if (principal == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mapOf("error" to "UNAUTHENTICATED"))
        if (principal.tenantId != tenantId || !policy.isPermitted(principal, AdminPermission.READ_SUPPORT)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "FORBIDDEN"))
        }
        return ResponseEntity.ok(reconciliation.reconcile(tenantId, gameId, roundId))
    }
}
