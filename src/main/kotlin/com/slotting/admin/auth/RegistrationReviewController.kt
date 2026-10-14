package com.slotting.admin.auth

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestAttribute
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
class RegistrationReviewController(
    private val registrationSybilControl: RegistrationSybilControl,
) {
    @GetMapping("/admin/registration-reviews")
    fun list(
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        if (!canReview(principal)) return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "forbidden"))
        return ResponseEntity.ok(registrationSybilControl.openReviews(requireNotNull(principal).tenantId))
    }

    @PostMapping("/admin/registration-reviews/{playerId}/clear")
    fun clear(
        @PathVariable playerId: UUID,
        @RequestParam reason: String,
        @RequestAttribute(name = "authenticatedPrincipal", required = false) principal: AuthenticatedPrincipal?,
    ): ResponseEntity<Any> {
        if (!canReview(principal)) return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "forbidden"))
        if (reason.isBlank() || reason.length > 500) {
            return ResponseEntity.badRequest().body(mapOf("error" to "A review reason of 1 to 500 characters is required"))
        }
        val reviewer = requireNotNull(principal)
        val cleared = registrationSybilControl.clearReview(reviewer.tenantId, playerId, reviewer.id, reason)
        return if (cleared) ResponseEntity.ok(mapOf("status" to "CLEARED", "playerId" to playerId))
        else ResponseEntity.status(HttpStatus.CONFLICT).body(mapOf("error" to "Review is not open"))
    }

    private fun canReview(principal: AuthenticatedPrincipal?): Boolean =
        principal?.kind == PrincipalKind.ADMIN &&
            (AdminRole.SECURITY in principal.roles || AdminRole.SUPER_ADMIN in principal.roles)
}
