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

class PlayerFundingRoutesTest {
    private val tenant = RailsHttpTestSupport.TENANT
    private val player = RailsHttpTestSupport.PLAYER
    private val accounts = FakeFundingAccountsStore().apply {
        insert(FundingAccount("a-2", tenant, "RAAST", "Second", "222", null, 2))
        insert(FundingAccount("a-1", tenant, "BANK", "First", "111", "Branch", 1))
        insert(FundingAccount("a-hidden", tenant, "BANK", "Hidden", "333", null, 3, visible = false))
    }
    private val settings = FakeSettingsStore()
    private val submissions = FakeDepositSubmissionRepository()
    private val receipts = ManualRailsReceiptService()
    private val controller = PlayerFundingController(accounts, settings, submissions, receipts)

    private fun mvc() = RailsHttpTestSupport.mockMvc(controller, player = true)

    private fun auth(builder: org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder) =
        builder.header("X-Session-Token", RailsHttpTestSupport.TOKEN)

    @Test
    fun `visible funding accounts are sorted and carry rate and sla`() {
        mvc().perform(auth(get("/api/v1/tenants/$tenant/deposits/accounts")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.accounts.length()").value(2))
            .andExpect(jsonPath("$.accounts[0].id").value("a-1"))
            .andExpect(jsonPath("$.accounts[1].id").value("a-2"))
            .andExpect(jsonPath("$.depositRatePkrPerUsd").value("280"))
            .andExpect(jsonPath("$.slaWorkingDays").value(7))
    }

    @Test
    fun `upload url rejects non-image and enforces the player prefix`() {
        mvc().perform(
            auth(post("/api/v1/tenants/$tenant/deposits/manual-submissions/upload-url"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"fileName":"proof.pdf","contentType":"application/pdf"}"""),
        ).andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("INVALID_RECEIPT_TYPE"))

        mvc().perform(
            auth(post("/api/v1/tenants/$tenant/deposits/manual-submissions/upload-url"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"fileName":"proof.png","contentType":"image/png"}"""),
        ).andExpect(status().isOk)
            .andExpect(jsonPath("$.objectPath").value(org.hamcrest.Matchers.startsWith("$tenant/$player/deposit-receipts/")))
    }

    @Test
    fun `create rejects invalid amount and unknown account with typed errors`() {
        val invalidAmount = """{"amountPkr":0,"transferReference":"ref","transferredUtc":"2026-11-12T10:00:00Z","fundingAccountId":"a-1","receiptObject":"$tenant/$player/deposit-receipts/x.png"}"""
        mvc().perform(auth(post("/api/v1/tenants/$tenant/deposits/manual-submissions")).contentType(MediaType.APPLICATION_JSON).content(invalidAmount))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("INVALID_AMOUNT"))

        val unknown = """{"amountPkr":100,"transferReference":"ref","transferredUtc":"2026-11-12T10:00:00Z","fundingAccountId":"missing","receiptObject":"$tenant/$player/deposit-receipts/x.png"}"""
        mvc().perform(auth(post("/api/v1/tenants/$tenant/deposits/manual-submissions")).contentType(MediaType.APPLICATION_JSON).content(unknown))
            .andExpect(status().isNotFound)
            .andExpect(jsonPath("$.error").value("FUNDING_ACCOUNT_NOT_FOUND"))
    }

    @Test
    fun `multiple pending submissions are allowed and mine labels the estimate`() {
        val body = """{"amountPkr":2800,"transferReference":"ref","transferredUtc":"2026-11-12T10:00:00Z","fundingAccountId":"a-1","receiptObject":"$tenant/$player/deposit-receipts/x.png"}"""
        repeat(2) {
            mvc().perform(auth(post("/api/v1/tenants/$tenant/deposits/manual-submissions")).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated)
        }
        assertEquals(2, submissions.insertCount)
        mvc().perform(auth(get("/api/v1/tenants/$tenant/deposits/manual-submissions/mine")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.length()").value(2))
            .andExpect(jsonPath("$[0].status").value("SUBMITTED"))
            .andExpect(jsonPath("$[0].estimateUsd").value("10.00"))
    }

    @Test
    fun `player route tiers reject missing and foreign principals`() {
        RailsHttpTestSupport.mockMvc(controller, player = false)
            .perform(get("/api/v1/tenants/$tenant/deposits/accounts"))
            .andExpect(status().isUnauthorized)

        RailsHttpTestSupport.mockMvc(controller, player = true)
            .perform(auth(get("/api/v1/tenants/other/deposits/accounts")))
            .andExpect(status().isForbidden)
    }
}
