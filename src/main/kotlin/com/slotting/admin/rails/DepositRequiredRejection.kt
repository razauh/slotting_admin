package com.slotting.admin.rails

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity

object DepositRequiredRejection {
    const val CODE = "NO_VERIFIED_DEPOSIT"

    fun response(error: NoVerifiedDepositException): ResponseEntity<Any> =
        ResponseEntity.status(HttpStatus.FORBIDDEN).body(
            mapOf(
                "error" to CODE,
                "message" to (error.message ?: "a verified deposit is required before placing bets"),
            ),
        )
}
