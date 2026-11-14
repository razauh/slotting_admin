package com.slotting.admin.rails

import com.slotting.admin.audit.AdminAuditService
import com.slotting.admin.audit.AdminAuditStore
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import java.math.BigDecimal
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

@Repository
class JdbcManualRailsSettingsStore(private val jdbc: JdbcTemplate) : ManualRailsSettingsStore {
    override fun get(): ManualRailsSettings =
        jdbc.query(
            "select deposit_rate_pkr_per_usd, payout_rate_pkr_per_usd, withdrawal_fee_percent, payout_sla_working_days from public.manual_rails_settings where id = 1",
            { rs, _ ->
                ManualRailsSettings(
                    depositRate = rs.getBigDecimal(1),
                    payoutRate = rs.getBigDecimal(2),
                    feePercent = rs.getBigDecimal(3),
                    slaWorkingDays = rs.getInt(4),
                )
            },
        ).first()
            ?: ManualRailsSettings(BigDecimal.ONE, BigDecimal.ONE, BigDecimal.ZERO, 7)

    override fun update(settings: ManualRailsSettings, by: String) {
        jdbc.update(
            "update public.manual_rails_settings set deposit_rate_pkr_per_usd = ?, payout_rate_pkr_per_usd = ?, withdrawal_fee_percent = ?, payout_sla_working_days = ?, updated_by = ?, updated_utc = now() where id = 1",
            settings.depositRate,
            settings.payoutRate,
            settings.feePercent,
            settings.slaWorkingDays,
            by,
        )
    }
}

@Repository
class JdbcRailsFundingAccountStore(private val jdbc: JdbcTemplate) : RailsFundingAccountStore {
    override fun listVisible(tenantId: String): List<FundingAccount> =
        query("select id, tenant_id, type, account_title, account_number, instructions, sort_order, visible from public.funding_accounts where tenant_id = ? and visible = true order by sort_order asc, created_utc asc", tenantId)

    override fun listAll(tenantId: String): List<FundingAccount> =
        query("select id, tenant_id, type, account_title, account_number, instructions, sort_order, visible from public.funding_accounts where tenant_id = ? order by sort_order asc, created_utc asc", tenantId)

    override fun find(id: String): FundingAccount? =
        query("select id, tenant_id, type, account_title, account_number, instructions, sort_order, visible from public.funding_accounts where id = ?", UUID.fromString(id)).firstOrNull()

    override fun insert(account: FundingAccount) {
        jdbc.update(
            "insert into public.funding_accounts (id, tenant_id, type, account_title, account_number, instructions, sort_order, visible) values (?, ?, ?, ?, ?, ?, ?, ?)",
            UUID.fromString(account.id),
            account.tenantId,
            account.type,
            account.accountTitle,
            account.accountNumber,
            account.instructions,
            account.sortOrder,
            account.visible,
        )
    }

    override fun updateVisibility(id: String, visible: Boolean): Boolean =
        jdbc.update("update public.funding_accounts set visible = ?, updated_utc = now() where id = ?", visible, UUID.fromString(id)) == 1

    override fun deleteIfUnreferenced(id: String): Boolean =
        jdbc.update(
            "delete from public.funding_accounts a where a.id = ? and not exists (select 1 from public.deposit_submissions s where s.funding_account_id = a.id)",
            UUID.fromString(id),
        ) == 1

    private fun query(sql: String, parameter: Any): List<FundingAccount> =
        jdbc.query(sql, { rs, _ ->
            FundingAccount(
                id = rs.getObject(1).toString(),
                tenantId = rs.getString(2),
                type = rs.getString(3),
                accountTitle = rs.getString(4),
                accountNumber = rs.getString(5),
                instructions = rs.getString(6),
                sortOrder = rs.getInt(7),
                visible = rs.getBoolean(8),
            )
        }, parameter)
}

@Repository
class JdbcDepositQueueStore(private val jdbc: JdbcTemplate) : DepositQueueStore {
    override fun listSubmitted(tenantId: String): List<DepositQueueRow> = query(
        "select s.id, s.tenant_id, s.player_id, s.amount_pkr, s.transfer_reference, s.transferred_utc, a.account_title, a.account_number, s.receipt_object, s.status, s.amount_usd, s.rate_applied, s.reject_reason from public.deposit_submissions s join public.funding_accounts a on a.id = s.funding_account_id where s.tenant_id = ? and s.status = 'SUBMITTED' order by s.transferred_utc asc",
        tenantId,
    )

    override fun find(id: String): DepositQueueRow? = query(
        "select s.id, s.tenant_id, s.player_id, s.amount_pkr, s.transfer_reference, s.transferred_utc, a.account_title, a.account_number, s.receipt_object, s.status, s.amount_usd, s.rate_applied, s.reject_reason from public.deposit_submissions s join public.funding_accounts a on a.id = s.funding_account_id where s.id = ?",
        UUID.fromString(id),
    ).firstOrNull()

    private fun query(sql: String, parameter: Any): List<DepositQueueRow> =
        jdbc.query(sql, { rs, _ ->
            DepositQueueRow(
                id = rs.getObject(1).toString(),
                tenantId = rs.getString(2),
                playerId = rs.getString(3),
                amountPkr = rs.getBigDecimal(4),
                transferReference = rs.getString(5),
                transferredUtc = rs.getTimestamp(6).toInstant(),
                fundingAccountTitle = rs.getString(7),
                fundingAccountNumber = rs.getString(8),
                receiptObject = rs.getString(9),
                status = SubmissionStatus.valueOf(rs.getString(10)),
                amountUsd = rs.getBigDecimal(11),
                rateApplied = rs.getBigDecimal(12),
                rejectReason = rs.getString(13),
            )
        }, parameter)
}

@Repository
class JdbcPayoutQueueStore(private val jdbc: JdbcTemplate) : PayoutQueueStore {
    override fun listByStatus(tenantId: String, status: PayoutStatus): List<PayoutQueueRow> =
        query("select id, tenant_id, player_id, amount_usd, fee_usd, net_usd, payout_rate_pkr_per_usd, payout_pkr, dest_type, dest_account_title, dest_account_number, status, receipt_object, reject_reason, requested_utc, paid_utc from public.payout_requests where tenant_id = ? and status = ? order by requested_utc asc", tenantId, status.name)

    override fun listMine(tenantId: String, playerId: String): List<PayoutQueueRow> =
        query("select id, tenant_id, player_id, amount_usd, fee_usd, net_usd, payout_rate_pkr_per_usd, payout_pkr, dest_type, dest_account_title, dest_account_number, status, receipt_object, reject_reason, requested_utc, paid_utc from public.payout_requests where tenant_id = ? and player_id = ? order by requested_utc desc", tenantId, playerId)

    override fun find(id: String): PayoutQueueRow? =
        query("select id, tenant_id, player_id, amount_usd, fee_usd, net_usd, payout_rate_pkr_per_usd, payout_pkr, dest_type, dest_account_title, dest_account_number, status, receipt_object, reject_reason, requested_utc, paid_utc from public.payout_requests where id = ?", UUID.fromString(id)).firstOrNull()

    private fun query(sql: String, vararg parameters: Any): List<PayoutQueueRow> =
        jdbc.query(sql, { rs, _ ->
            PayoutQueueRow(
                id = rs.getObject(1).toString(),
                tenantId = rs.getString(2),
                playerId = rs.getString(3),
                amountUsd = rs.getBigDecimal(4),
                feeUsd = rs.getBigDecimal(5),
                netUsd = rs.getBigDecimal(6),
                payoutRate = rs.getBigDecimal(7),
                payoutPkr = rs.getBigDecimal(8),
                destType = rs.getString(9),
                destTitle = rs.getString(10),
                destNumber = rs.getString(11),
                status = PayoutStatus.valueOf(rs.getString(12)),
                receiptObject = rs.getString(13),
                rejectReason = rs.getString(14),
                requestedUtc = rs.getTimestamp(15).toInstant(),
                paidUtc = rs.getTimestamp(16)?.toInstant(),
            )
        }, *parameters)
}

@Repository
class JdbcPayoutReceiptStore(private val jdbc: JdbcTemplate) : PayoutReceiptStore {
    override fun updateReceiptObject(id: String, path: String): Boolean =
        jdbc.update("update public.payout_requests set receipt_object = ? where id = ?", path, UUID.fromString(id)) == 1
}

@Repository
class Slf4jRailsAuditRecorder(
    store: AdminAuditStore,
    clock: java.time.Clock = java.time.Clock.systemUTC(),
) : RailsAuditRecorder {
    private val logger = org.slf4j.LoggerFactory.getLogger(Slf4jRailsAuditRecorder::class.java)
    private val mapper = com.fasterxml.jackson.databind.ObjectMapper()
    private val audit = AdminAuditService(
        com.slotting.admin.auth.AdminRbacPolicy(true),
        object : com.slotting.admin.auth.AdminSessionDirectory {
            override fun find(tenantId: String, principalId: String, sessionId: String): com.slotting.admin.auth.AdminSessionStatus? = null
        },
        store,
        clock,
    )

    override fun record(entry: RailsAuditEntry) {
        logger.info(
            "rails_audit tenant={} admin={} action={} subject={} old={} new={} at={}",
            entry.tenantId,
            entry.adminId,
            entry.action,
            entry.subjectId,
            entry.oldValue,
            entry.newValue,
            entry.occurredAt,
        )
        val details = mapper.writeValueAsString(
            mapOf(
                "action" to entry.action,
                "subjectId" to entry.subjectId,
                "oldValue" to entry.oldValue,
                "newValue" to entry.newValue,
            )
        )
        runCatching {
            audit.recordEvent(
                tenantId = entry.tenantId,
                eventType = "RAILS_${entry.action}",
                occurredAt = entry.occurredAt,
                correlationId = "rails:${entry.subjectId}",
                causationId = "admin:${entry.adminId}",
                redactedDetails = details,
            )
        }.onFailure { failure ->
            logger.warn("rails_audit_persist_failed action={} reason={}", entry.action, failure.javaClass.simpleName)
        }
    }
}
