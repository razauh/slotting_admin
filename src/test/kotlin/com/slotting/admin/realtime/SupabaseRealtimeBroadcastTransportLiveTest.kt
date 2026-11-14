package com.slotting.admin.realtime

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SupabaseRealtimeBroadcastTransportLiveTest {
    @Test
    fun `live sender posts with apikey and service authorization`() {
        assumeTrue(System.getenv("BB10_LIVE") == "1", "BB10_LIVE not enabled")
        val base = System.getenv("SUPABASE_URL").orEmpty()
        val apikey = System.getenv("SUPABASE_ANON_KEY").orEmpty()
        val service = System.getenv("SUPABASE_SERVICE_ROLE_KEY").orEmpty()
        assumeTrue(base.startsWith("https://") && apikey.isNotBlank() && service.isNotBlank(), "live credentials absent")
        val transport = SupabaseRealtimeBroadcastTransport(base, service, apikey, maxAttempts = 1)
        transport.send(
            "tenant:bb10-live:player:bb10-live",
            listOf(
                RealtimeHint(
                    channel = "tenant:bb10-live:player:bb10-live",
                    event = "phase",
                    payload = mapOf("roundId" to "bb10-live-round", "phase" to "FLYING", "phaseVersion" to 1),
                    eventId = "bb10-live-1",
                    sequence = 1,
                )
            ),
        )
        assertEquals(1, transport.sent.get())
        assertEquals(0, transport.failed.get())
        assertNull(transport.lastFailure.get())
    }
}
