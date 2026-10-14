package com.slotting.admin.infra

import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.auth.InMemoryDurableAuthStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

class DurableRequestRateLimitFilterTest {
    @Test
    fun throttledProtectedRequestReturnsRetryAfterAndDoesNotReachTheApplication() {
        val policy = RecordingRateLimitPolicy(
            DurableRateLimitDecision(false, "USER", 17, false, 20, 0)
        )
        val filter = DurableRequestRateLimitFilter(policy, DurableAuthService(InMemoryDurableAuthStore()))
        val request = MockHttpServletRequest("POST", "/api/v1/tenants/t1/deposits/intents")
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()

        filter.doFilter(request, response, chain)

        assertEquals(429, response.status)
        assertEquals("17", response.getHeader("Retry-After"))
        assertEquals("0", response.getHeader("RateLimit-Remaining"))
        assertNull(chain.request)
    }

    @Test
    fun authenticationJsonUsesActorBucketAcrossRotatingAddresses() {
        val policy = RecordingRateLimitPolicy(DurableRateLimitDecision(true, "ALLOWED", 0, false, 20, 19))
        val filter = DurableRequestRateLimitFilter(policy, DurableAuthService(InMemoryDurableAuthStore()))
        val request = MockHttpServletRequest("POST", "/auth/token")
        request.contentType = "application/json"
        request.setContent("{\"identifier\":\"Player@Example.test\",\"password\":\"not-used\"}".toByteArray())
        request.remoteAddr = "198.51.100.45"
        val response = MockHttpServletResponse()

        filter.doFilter(request, response, MockFilterChain())

        assertEquals("player@example.test", policy.actorId)
        assertEquals("AUTH", policy.category)
        assertEquals("198.51.100.45", policy.clientIp)
        assertTrue(response.status < 400)
    }

    @Test
    fun rateStoreFailureFailsClosed() {
        val policy = RecordingRateLimitPolicy(null, fail = true)
        val filter = DurableRequestRateLimitFilter(policy, DurableAuthService(InMemoryDurableAuthStore()))
        val request = MockHttpServletRequest("POST", "/api/v1/tenants/t1/deposits/intents")
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()

        filter.doFilter(request, response, chain)

        assertEquals(503, response.status)
        assertEquals("30", response.getHeader("Retry-After"))
        assertNull(chain.request)
    }

    @Test
    fun oversizedInspectableBodyIsRejectedInsteadOfPassingUnscannedContent() {
        val policy = RecordingRateLimitPolicy(DurableRateLimitDecision(true, "ALLOWED", 0, false, 60, 59))
        val filter = DurableRequestRateLimitFilter(policy, DurableAuthService(InMemoryDurableAuthStore()))
        val request = MockHttpServletRequest("POST", "/api/v1/tenants/t1/deposits/intents")
        request.contentType = "application/json"
        request.setContent(ByteArray(65_537) { 32 })
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()

        filter.doFilter(request, response, chain)

        assertEquals(413, response.status)
        assertNull(policy.category)
        assertNull(chain.request)
    }

    private class RecordingRateLimitPolicy(
        private val decision: DurableRateLimitDecision?,
        private val fail: Boolean = false,
    ) : DurableRequestRateLimitPolicy {
        var actorId: String? = null
        var category: String? = null
        var clientIp: String? = null

        override fun evaluate(
            tenantId: String,
            actorId: String?,
            deviceId: String?,
            clientIp: String,
            category: String,
        ): DurableRateLimitDecision {
            this.actorId = actorId
            this.category = category
            this.clientIp = clientIp
            if (fail) throw IllegalStateException("rate store unavailable")
            return requireNotNull(decision)
        }

        override fun clearQuarantine(tenantId: String, actorId: String, reviewerId: String, reason: String): Boolean = false
    }
}
