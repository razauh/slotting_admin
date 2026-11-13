package com.slotting.admin.rails

import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.LedgerPostingService
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.math.BigDecimal
import java.time.Instant
import kotlin.test.assertEquals

class AdminFundingRoutesTest {
    private val tenant = RailsHttpTestSupport.TENANT
    private val player = RailsHttpTestSupport.PLAYER
    private val admin = RailsHttpTestSupport.ADMIN
    private val ledger = InMemoryLedgerJournalStore()
    private val ledgerService = LedgerPostingService(ledger)
    private val settings = FakeSettingsStore()
    private val accounts = FakeFundingAccountsStore()
    private val substitutions = FakeDepositSubmissionRepository()
    private val queue = FakeDepositQueueStore()
    private val audit = RecordingAuditRecorder()
    private val receipts = ManualRailsReceiptService()
    private val controller = AdminFundingController(accounts, settings, substitutions, queue, ledgerService, receipts, audit)

    private fun mvc() = RailsHttpTestSupport.mockMvc(controller, roles = setOf(com.slotting.admin.auth.AdminRole.SUPER_ADMIN))
    private fun auth(builder: org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder) =
        builder.header("X-Admin-Id", admin).header("X-Admin-Session-Id", "sess-bb6").header("X-Tenant-Id", tenant)

    private fun seed() {
        accounts.insert(FundingAccount("a-1", tenant, "BANK", "Bank", "111", null, 1))
        substitutions.rows["s1"] = DepositSubmission("s1", tenant, player, BigDecimal("2800"), SubmissionStatus.SUBMITTED)
        queue.rows += DepositQueueRow(
            "s1", tenant, player, BigDecimal("2800"), "ref-1", Instant.parse("2026-11-12T10:00:00Z"),
            "Bank", "111", "$tenant/$player/deposit-receipts/proof.png", SubmissionStatus.SUBMITTED, null, null, null,
        )
    }

    @Test
    fun `approve credits through the crash-safe flow and a double approve is typed 409 with no new legs`() {
        seed()
        mvc().perform(auth(post("/admin/rails/deposit-submissions/s1/approve")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("APPROVED"))
            .andExpect(jsonPath("$.amountUsd").value("10.00"))
        assertEquals(1000L, ledger.findBalance(tenant, "PLAYER:$player", "USD"))
        assertEquals(2, ledger.findAllLegsForTenant(tenant).size)
        assertEquals(1, audit.entries.count { it.action == "DEPOSIT_APPROVED" })

        mvc().perform(auth(post("/admin/rails/deposit-submissions/s1/approve")))
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error").value("ALREADY_DECIDED"))
        assertEquals(2, ledger.findAllLegsForTenant(tenant).size)
    }

    @Test
    fun `reject requires a reason and records the audit row`() {
        seed()
        mvc().perform(auth(post("/admin/rails/deposit-submissions/s1/reject")).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("REJECT_REASON_REQUIRED"))

        mvc().perform(auth(post("/admin/rails/deposit-submissions/s1/reject")).contentType(MediaType.APPLICATION_JSON).content("""{"reason":"proof unreadable"}"""))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("REJECTED"))
        assertEquals(SubmissionStatus.REJECTED, substitutions.rows["s1"]!!.status)
        assertEquals(1, audit.entries.count { it.action == "DEPOSIT_REJECTED" })
    }

    @Test
    fun `accounts crud visibility and referenced delete are typed`() {
        seed()
        mvc().perform(auth(post("/admin/rails/accounts")).contentType(MediaType.APPLICATION_JSON).content("""{"type":"RAAST","accountTitle":"Raast","accountNumber":"222","sortOrder":2}"""))
            .andExpect(status().isCreated)
        val createdId = accounts.accounts.values.first { it.accountTitle == "Raast" }.id
        val visibility = mvc().perform(auth(put("/admin/rails/accounts/$createdId")).contentType(MediaType.APPLICATION_JSON).content("""{"visible":false}""")).andReturn()
        kotlin.test.assertTrue(visibility.response.status == 200, visibility.response.contentAsString)
        accounts.deleteAllowed = false
        mvc().perform(auth(delete("/admin/rails/accounts/a-1")))
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error").value("FUNDING_ACCOUNT_REFERENCED"))
    }

    @Test
    fun `settings update validates and audits old to new`() {
        mvc().perform(auth(put("/admin/rails/settings")).contentType(MediaType.APPLICATION_JSON).content("""{"depositRatePkrPerUsd":0,"payoutRatePkrPerUsd":280,"withdrawalFeePercent":5,"payoutSlaWorkingDays":7}"""))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("INVALID_RATE"))
        mvc().perform(auth(put("/admin/rails/settings")).contentType(MediaType.APPLICATION_JSON).content("""{"depositRatePkrPerUsd":300,"payoutRatePkrPerUsd":300,"withdrawalFeePercent":4,"payoutSlaWorkingDays":5}"""))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.depositRatePkrPerUsd").value("300"))
        assertEquals(1, audit.entries.count { it.action == "MANUAL_RAILS_SETTINGS" })
    }

    @Test
    fun `queue and receipt are path scoped and admin tiers hold`() {
        seed()
        mvc().perform(auth(get("/admin/rails/deposit-submissions")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$[0].id").value("s1"))
            .andExpect(jsonPath("$[0].receiptUrl").value(org.hamcrest.Matchers.startsWith("https://storage.local/player-documents/")))
        mvc().perform(auth(get("/admin/rails/deposit-submissions/s1/receipt")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.url").value(org.hamcrest.Matchers.startsWith("https://storage.local/player-documents/")))

        RailsHttpTestSupport.mockMvc(controller, roles = setOf(com.slotting.admin.auth.AdminRole.SUPPORT))
            .perform(auth(get("/admin/rails/deposit-submissions")))
            .andExpect(status().isForbidden)
        RailsHttpTestSupport.mockMvc(controller)
            .perform(get("/admin/rails/deposit-submissions"))
            .andExpect(status().isUnauthorized)
    }
}
