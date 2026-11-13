package com.slotting.admin.rails

import com.slotting.admin.auth.AuthErrorCode
import com.slotting.admin.auth.AuthenticationFailure
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class RailsHttpAdvice {
    @ExceptionHandler(RailsHttpException::class)
    fun typed(error: RailsHttpException): ResponseEntity<Map<String, Any>> =
        ResponseEntity.status(error.status).body(
            mapOf(
                "error" to error.code,
                "message" to (error.message ?: error.code),
            ),
        )

    @ExceptionHandler(AuthenticationFailure.Rejected::class)
    fun rejected(failure: AuthenticationFailure.Rejected): ResponseEntity<Map<String, Any>> =
        ResponseEntity.status(
            when (failure.code) {
                AuthErrorCode.UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED
                AuthErrorCode.FORBIDDEN -> HttpStatus.FORBIDDEN
                AuthErrorCode.CONFLICT -> HttpStatus.CONFLICT
                else -> HttpStatus.BAD_REQUEST
            },
        ).body(mapOf("error" to failure.code.name))
}
