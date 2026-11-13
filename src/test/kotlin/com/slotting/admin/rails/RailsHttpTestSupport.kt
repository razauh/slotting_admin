package com.slotting.admin.rails

import com.slotting.admin.auth.AdminRole
import com.slotting.admin.auth.AdminSessionDirectory
import com.slotting.admin.auth.AdminSessionStatus
import com.slotting.admin.auth.AuthenticatedPrincipal
import com.slotting.admin.auth.DurableAuthService
import com.slotting.admin.security.SecurityAuthenticationFilter
import com.slotting.admin.wallet.AuthoritativeWalletStore
import com.slotting.admin.wallet.CurrencyBalance
import com.slotting.admin.wallet.AuthoritativeStatementEntry
import com.slotting.admin.wallet.ProjectionRebuildReport
import org.mockito.Mockito
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder
import java.math.BigDecimal
import java.time.Instant
import java.util.UUID

class FakeSettingsStore(var current: ManualRailsSettings = ManualRailsSettings(BigDecimal("280"), BigDecimal("280"), BigDecimal("5"), 7)) : ManualRailsSettingsStore {
    override fun get(): ManualRailsSettings = current
    override fun update(settings: ManualRailsSettings, by: String) { current = settings }
}

class FakeFundingAccountsStore : RailsFundingAccountStore {
    val accounts = linkedMapOf<String, FundingAccount>()
    var deleteAllowed = true

    override fun listVisible(tenantId: String) = accounts.values.filter { it.tenantId == tenantId && it.visible }.sortedBy { it.sortOrder }
    override fun listAll(tenantId: String) = accounts.values.filter { it.tenantId == tenantId }.sortedBy { it.sortOrder }
    override fun find(id: String) = accounts[id]
    override fun insert(account: FundingAccount) { accounts[account.id] = account }
    override fun updateVisibility(id: String, visible: Boolean): Boolean {
        val row = accounts[id] ?: return false
        accounts[id] = row.copy(visible = visible)
        return true
    }
    override fun deleteIfUnreferenced(id: String): Boolean {
        if (!deleteAllowed) return false
        return accounts.remove(id) != null
    }
}

class FakeDepositSubmissionRepository : DepositSubmissionRepository {
    val rows = linkedMapOf<String, DepositSubmission>()
    var insertCount = 0

    override fun find(id: String) = rows[id]
    override fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String): Boolean {
        val row = rows[id] ?: return false
        if (row.status != SubmissionStatus.SUBMITTED) return false
        rows[id] = row.copy(status = SubmissionStatus.APPROVED, rateApplied = rate, amountUsd = usd)
        return true
    }
    override fun markRejected(id: String, reason: String, by: String): Boolean {
        val row = rows[id] ?: return false
        if (row.status != SubmissionStatus.SUBMITTED) return false
        rows[id] = row.copy(status = SubmissionStatus.REJECTED, rejectReason = reason)
        return true
    }
    override fun hasApprovedDeposit(playerId: String) = rows.values.any { it.playerId == playerId && it.status == SubmissionStatus.APPROVED }
    override fun insert(submission: DepositSubmission, fundingAccountId: String, transferReference: String, transferredUtc: Instant, receiptObject: String) {
        rows[submission.id] = submission
        insertCount++
    }
    override fun listByStatus(tenantId: String, status: SubmissionStatus) = rows.values.filter { it.tenantId == tenantId && it.status == status }
    override fun listMine(tenantId: String, playerId: String) = rows.values.filter { it.tenantId == tenantId && it.playerId == playerId }
    override fun revertApproval(id: String): Boolean {
        val row = rows[id] ?: return false
        rows[id] = row.copy(status = SubmissionStatus.SUBMITTED, rateApplied = null, amountUsd = null)
        return true
    }
}

class FakeDepositQueueStore(val rows: MutableList<DepositQueueRow> = mutableListOf()) : DepositQueueStore {
    override fun listSubmitted(tenantId: String) = rows.filter { it.tenantId == tenantId && it.status == SubmissionStatus.SUBMITTED }
    override fun find(id: String) = rows.firstOrNull { it.id == id }
}

class FakePayoutRequestRepository : PayoutRequestRepository {
    val rows = linkedMapOf<String, PayoutRequest>()

    override fun insert(request: PayoutRequest): Boolean {
        if (rows.containsKey(request.id)) return false
        rows[request.id] = request
        return true
    }
    override fun find(id: String) = rows[id]
    override fun lockedTotal(tenantId: String, playerId: String): BigDecimal =
        rows.values.filter { it.tenantId == tenantId && it.playerId == playerId && (it.status == PayoutStatus.PENDING || it.status == PayoutStatus.APPROVED_FUNDS_LOCKED) }
            .fold(BigDecimal.ZERO) { acc, row -> acc + row.amountUsd }
    override fun markLocked(id: String, by: String): Boolean {
        val row = rows[id] ?: return false
        if (row.status != PayoutStatus.PENDING) return false
        rows[id] = row.copy(status = PayoutStatus.APPROVED_FUNDS_LOCKED)
        return true
    }
    override fun markPaid(id: String, by: String): Boolean {
        val row = rows[id] ?: return false
        if (row.status != PayoutStatus.APPROVED_FUNDS_LOCKED) return false
        rows[id] = row.copy(status = PayoutStatus.PAID)
        return true
    }
    override fun markRejected(id: String, reason: String, by: String): Boolean {
        val row = rows[id] ?: return false
        if (row.status != PayoutStatus.PENDING && row.status != PayoutStatus.APPROVED_FUNDS_LOCKED) return false
        rows[id] = row.copy(status = PayoutStatus.REJECTED)
        return true
    }
}

class FakePayoutQueueStore(val rows: MutableList<PayoutQueueRow> = mutableListOf()) : PayoutQueueStore {
    override fun listByStatus(tenantId: String, status: PayoutStatus) = rows.filter { it.tenantId == tenantId && it.status == status }
    override fun listMine(tenantId: String, playerId: String) = rows.filter { it.tenantId == tenantId && it.playerId == playerId }
    override fun find(id: String) = rows.firstOrNull { it.id == id }
}

class FakePayoutReceiptStore(
    private val queue: FakePayoutQueueStore,
    private val requests: FakePayoutRequestRepository,
) : PayoutReceiptStore {
    override fun updateReceiptObject(id: String, path: String): Boolean {
        val row = requests.rows[id] ?: return false
        requests.rows[id] = row.copy(receiptObject = path)
        val index = queue.rows.indexOfFirst { it.id == id }
        if (index >= 0) queue.rows[index] = queue.rows[index].copy(receiptObject = path)
        return true
    }
}

class RecordingAuditRecorder : RailsAuditRecorder {
    val entries = mutableListOf<RailsAuditEntry>()
    override fun record(entry: RailsAuditEntry) { entries += entry }
}

class FakeWalletStore(private var balanceMinor: Long = 0L) : AuthoritativeWalletStore {
    fun setBalance(minor: Long) { balanceMinor = minor }
    override fun findBalances(tenantId: String, ownerReference: String): List<CurrencyBalance> = emptyList()
    override fun findBalance(tenantId: String, ownerReference: String, currencyCode: String): Long = balanceMinor
    override fun findLatestLedgerVersion(tenantId: String): Long = 1L
    override fun queryStatementEntries(tenantId: String, ownerReference: String, currencyCode: String, afterSeq: Long?, limit: Int, fromTime: Instant?, toTime: Instant?): List<AuthoritativeStatementEntry> = emptyList()
    override fun findStatementReceipt(tenantId: String, idempotencyKey: String): Pair<String, com.slotting.admin.wallet.AuthoritativeStatementPage>? = null
    override fun saveStatementReceipt(tenantId: String, idempotencyKey: String, fingerprint: String, page: com.slotting.admin.wallet.AuthoritativeStatementPage) {}
    override fun rebuildProjections(tenantId: String): ProjectionRebuildReport = ProjectionRebuildReport(tenantId, 0, 0L, 1L, true, 0L)
    override fun clearProjections(tenantId: String) {}
}

object RailsHttpTestSupport {
    const val TENANT = "tenant-bb6"
    const val PLAYER = "player-bb6"
    const val ADMIN = "admin-bb6"
    const val TOKEN = "player-token-bb6"

    fun playerPrincipal(tenant: String = TENANT, player: String = PLAYER) =
        AuthenticatedPrincipal(player, tenant, com.slotting.admin.auth.PrincipalKind.PLAYER, emptySet())

    fun adminPrincipal(tenant: String = TENANT, admin: String = ADMIN, roles: Set<AdminRole> = setOf(AdminRole.SUPER_ADMIN)) =
        AuthenticatedPrincipal(admin, tenant, com.slotting.admin.auth.PrincipalKind.ADMIN, roles)

    fun mockMvc(controller: Any, player: Boolean = false, roles: Set<AdminRole> = setOf(AdminRole.SUPER_ADMIN)): MockMvc {
        val auth = Mockito.mock(DurableAuthService::class.java)
        if (player) {
            Mockito.`when`(auth.validateAccessToken(TOKEN)).thenReturn(playerPrincipal())
        }
        val directory = object : AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String) = AdminSessionStatus(
                active = true,
                breakGlass = false,
                expiresAt = Instant.now().plusSeconds(600),
                mfaVerified = true,
                mfaExpiresAt = Instant.now().plusSeconds(600),
                roles = roles,
            )
        }
        val filter = SecurityAuthenticationFilter(auth, directory)
        val builder = MockMvcBuilders.standaloneSetup(controller)
        builder.addFilters<StandaloneMockMvcBuilder>(filter)
        builder.setControllerAdvice(RailsHttpAdvice())
        return builder.build()
    }

    fun adminHeaders(): Pair<String, String> = "X-Admin-Id" to ADMIN
}
