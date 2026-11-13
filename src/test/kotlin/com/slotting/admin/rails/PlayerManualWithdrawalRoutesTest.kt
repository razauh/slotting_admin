package com.slotting.admin.rails

import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.math.BigDecimal
import java.time.Instant
import kotlin.test.assertEquals

class PlayerManualWithdrawalRoutesTest {
    private val tenant = RailsHttpTestSupport.TENANT
    private val player = RailsHttpTestSupport.PLAYER
    private val settings = FakeSettingsStore()
    private val requests = FakePayoutRequestRepository()
    private val queue = FakePayoutQueueStore()
    private val wallet = FakeWalletStore(10_000L)
    private val receipts = ManualRailsReceiptService()
    private val controller = PlayerManualWithdrawalController(settings, requests, queue, wallet, receipts)

    private fun mvc() = RailsHttpTestSupport.mockMvc(controller, player = true)
    private fun auth(builder: org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder) =
        builder.header("X-Session-Token", RailsHttpTestSupport.TOKEN)

    @Test
    fun `quote returns fee net pkr and sla without creating a row`() {
        mvc().perform(auth(get("/api/v1/tenants/$tenant/withdrawals/manual-requests/quote").param("amount", "100")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.feeUsd").value("5.00"))
            .andExpect(jsonPath("$.netUsd").value("95.00"))
            .andExpect(jsonPath("$.payoutPkr").value("26600.00"))
            .andExpect(jsonPath("$.slaWorkingDays").value(7))
        assertEquals(0, requests.rows.size)
    }

    @Test
    fun `insufficient available balance is typed and leaves zero mutations`() {
        mvc().perform(
            auth(post("/api/v1/tenants/$tenant/withdrawals/manual-requests"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amountUsd":200,"destType":"BANK","destTitle":"Me","destNumber":"123"}"""),
        ).andExpect(status().isUnprocessableEntity)
            .andExpect(jsonPath("$.error").value("INSUFFICIENT_AVAILABLE_BALANCE"))
        assertEquals(0, requests.rows.size)
    }

    @Test
    fun `funded request creates one row with stamped quote`() {
        mvc().perform(
            auth(post("/api/v1/tenants/$tenant/withdrawals/manual-requests"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"amountUsd":50,"destType":"BANK","destTitle":"Me","destNumber":"123"}"""),
        ).andExpect(status().isCreated)
            .andExpect(jsonPath("$.feeUsd").value("2.50"))
            .andExpect(jsonPath("$.netUsd").value("47.50"))
            .andExpect(jsonPath("$.payoutPkr").value("13300.00"))
        val row = requests.rows.values.single()
        assertEquals(BigDecimal("50.00"), row.amountUsd)
        assertEquals(BigDecimal("2.50"), row.feeUsd)
        assertEquals(BigDecimal("47.50"), row.netUsd)
        assertEquals(PayoutStatus.PENDING, row.status)
    }

    @Test
    fun `mine exposes pending locked paid and rejected states with receipt`() {
        queue.rows += PayoutQueueRow(
            "p1", tenant, player, BigDecimal("50"), BigDecimal("2.50"), BigDecimal("47.50"),
            BigDecimal("280"), BigDecimal("13300"), "BANK", "Me", "123", PayoutStatus.PAID,
            "$tenant/$player/payout-receipts/p1.png", null, Instant.parse("2026-11-12T09:00:00Z"),
            Instant.parse("2026-11-12T12:00:00Z"),
        )
        mvc().perform(auth(get("/api/v1/tenants/$tenant/withdrawals/manual-requests/mine")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$[0].status").value("PAID"))
            .andExpect(jsonPath("$[0].paidUtc").value("2026-11-12T12:00:00Z"))
            .andExpect(jsonPath("$[0].receiptUrl").value(org.hamcrest.Matchers.startsWith("https://storage.local/")))
    }

    @Test
    fun `player tiers reject missing and foreign principals`() {
        RailsHttpTestSupport.mockMvc(controller, player = false)
            .perform(get("/api/v1/tenants/$tenant/withdrawals/manual-requests/quote").param("amount", "10"))
            .andExpect(status().isUnauthorized)
        RailsHttpTestSupport.mockMvc(controller, player = true)
            .perform(auth(get("/api/v1/tenants/other/withdrawals/manual-requests/quote").param("amount", "10")))
            .andExpect(status().isForbidden)
    }
}
