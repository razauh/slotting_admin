package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DepositRequiredRejectionTest {
    @Test
    fun `refused bet maps to a typed 403 rejection not a 500`() {
        val response = DepositRequiredRejection.response(NoVerifiedDepositException())

        assertEquals(HttpStatus.FORBIDDEN, response.statusCode)
        val body = requireNotNull(response.body) as Map<*, *>
        assertEquals("NO_VERIFIED_DEPOSIT", body["error"])
        assertTrue((body["message"] as String).contains("verified deposit"))
    }
}
