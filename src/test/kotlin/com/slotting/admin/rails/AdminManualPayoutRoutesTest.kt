package com.slotting.admin.rails

import com.slotting.admin.ledger.InMemoryLedgerJournalStore
import com.slotting.admin.ledger.JournalEntryDirection
import com.slotting.admin.ledger.LedgerPostingService
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.math.BigDecimal
import java.time.Instant
import kotlin.test.assertEquals

class AdminManualPayoutRoutesTest {
    private val tenant = RailsHttpTestSupport.TENANT
    private val player = RailsHttpTestSupport.PLAYER
    private val admin = RailsHttpTestSupport.ADMIN
    private val ledger = InMemoryLedgerJournalStore()
    private val ledgerService = LedgerPostingService(ledger)
    private val settings = FakeSettingsStore()
    private val requests = FakePayoutRequestRepository()
    private val queue = FakePayoutQueueStore()
    private val receiptStore = FakePayoutReceiptStore(queue, requests)
    private val audit = RecordingAuditRecorder()
    private val receipts = ManualRailsReceiptService()
    private val controller = AdminManualPayoutController(
        settings, requests, queue, receiptStore, PayoutLedgerDebitPoster(ledgerService), receipts, audit,
    )

    private fun mvc() = RailsHttpTestSupport.mockMvc(controller, roles = setOf(com.slotting.admin.auth.AdminRole.SUPER_ADMIN))
    private fun auth(builder: org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder) =
        builder.header("X-Admin-Id", admin).header("X-Admin-Session-Id", "sess-bb6").header("X-Tenant-Id", tenant)

    private fun seed(status: PayoutStatus = PayoutStatus.PENDING, receipt: String? = null) {
        requests.rows["p1"] = PayoutRequest(
            "p1", tenant, player, BigDecimal("100"), BigDecimal("5"), BigDecimal("95"),
            BigDecimal("280"), BigDecimal("26600"), "BANK", "Me", "123", status, receipt,
        )
        queue.rows += PayoutQueueRow(
            "p1", tenant, player, BigDecimal("100"), BigDecimal("5"), BigDecimal("95"),
            BigDecimal("280"), BigDecimal("26600"), "BANK", "Me", "123", status, receipt, null,
            Instant.parse("2026-11-12T09:00:00Z"), null,
        )
    }

    @Test
    fun `lock is one winner and audited`() {
        seed()
        mvc().perform(auth(post("/admin/rails/payout-requests/p1/lock")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("APPROVED_FUNDS_LOCKED"))
        mvc().perform(auth(post("/admin/rails/payout-requests/p1/lock")))
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error").value("ALREADY_DECIDED"))
        assertEquals(1, audit.entries.count { it.action == "PAYOUT_LOCKED" })
    }

    @Test
    fun `reject needs a reason and unlocks a locked row`() {
        seed(PayoutStatus.APPROVED_FUNDS_LOCKED)
        mvc().perform(auth(post("/admin/rails/payout-requests/p1/reject")).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("REJECT_REASON_REQUIRED"))
        mvc().perform(auth(post("/admin/rails/payout-requests/p1/reject")).contentType(MediaType.APPLICATION_JSON).content("""{"reason":"wrong account"}"""))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("REJECTED"))
        assertEquals(PayoutStatus.REJECTED, requests.rows["p1"]!!.status)
    }

    @Test
    fun `mark paid without receipt is typed 409 and posts zero legs`() {
        seed(PayoutStatus.APPROVED_FUNDS_LOCKED, null)
        mvc().perform(auth(post("/admin/rails/payout-requests/p1/mark-paid")))
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error").value("RECEIPT_REQUIRED"))
        assertEquals(0, ledger.findAllLegsForTenant(tenant).size)
    }

    @Test
    fun `receipt upload enforces image mime and mark paid posts the three legs exactly once`() {
        seed(PayoutStatus.APPROVED_FUNDS_LOCKED, null)
        mvc().perform(auth(post("/admin/rails/payout-requests/p1/receipt")).contentType(MediaType.APPLICATION_JSON).content("""{"fileName":"proof.pdf","contentType":"application/pdf"}"""))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("INVALID_RECEIPT_TYPE"))
        mvc().perform(auth(post("/admin/rails/payout-requests/p1/receipt")).contentType(MediaType.APPLICATION_JSON).content("""{"fileName":"proof.png","contentType":"image/png"}"""))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.objectPath").value(org.hamcrest.Matchers.startsWith("$tenant/$player/payout-receipts/p1-")))

        mvc().perform(auth(post("/admin/rails/payout-requests/p1/mark-paid")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("PAID"))
        val legs = ledger.findAllLegsForTenant(tenant)
        assertEquals(3, legs.size)
        assertEquals(10000L, legs.first { it.accountReference == "PLAYER:$player" && it.direction == JournalEntryDirection.DEBIT }.amountMinorUnits)
        assertEquals(9500L, legs.first { it.accountReference == "house:funding:clearing" }.amountMinorUnits)
        assertEquals(500L, legs.first { it.accountReference == "revenue:processing-fee" }.amountMinorUnits)

        mvc().perform(auth(post("/admin/rails/payout-requests/p1/mark-paid")))
            .andExpect(status().isOk)
        assertEquals(3, ledger.findAllLegsForTenant(tenant).size)
        assertEquals(1, audit.entries.count { it.action == "PAYOUT_MARKED_PAID" })
    }

    @Test
    fun `receipt read is signed and admin tiers hold`() {
        seed(PayoutStatus.PENDING, "$tenant/$player/payout-receipts/p1-proof.png")
        mvc().perform(auth(get("/admin/rails/payout-requests/p1/receipt")))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.url").value(org.hamcrest.Matchers.startsWith("https://storage.local/player-documents/")))
        RailsHttpTestSupport.mockMvc(controller, roles = setOf(com.slotting.admin.auth.AdminRole.SUPPORT))
            .perform(auth(get("/admin/rails/payout-requests")))
            .andExpect(status().isForbidden)
        RailsHttpTestSupport.mockMvc(controller)
            .perform(get("/admin/rails/payout-requests"))
            .andExpect(status().isUnauthorized)
    }
}
