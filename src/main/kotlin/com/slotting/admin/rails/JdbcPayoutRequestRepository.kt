package com.slotting.admin.rails

import java.math.BigDecimal
import java.util.UUID

class JdbcPayoutRequestRepository(
    private val openConnection: () -> java.sql.Connection,
) : PayoutRequestRepository {
    override fun insert(request: PayoutRequest): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "insert into public.payout_requests (id, tenant_id, player_id, amount_usd, fee_usd, net_usd, payout_rate_pkr_per_usd, payout_pkr, dest_type, dest_account_title, dest_account_number, status) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING') on conflict (id) do nothing",
            ).use { statement ->
                statement.setObject(1, UUID.fromString(request.id))
                statement.setString(2, request.tenantId)
                statement.setString(3, request.playerId)
                statement.setBigDecimal(4, request.amountUsd)
                statement.setBigDecimal(5, request.feeUsd)
                statement.setBigDecimal(6, request.netUsd)
                statement.setBigDecimal(7, request.payoutRate)
                statement.setBigDecimal(8, request.payoutPkr)
                statement.setString(9, request.destType)
                statement.setString(10, request.destTitle)
                statement.setString(11, request.destNumber)
                statement.executeUpdate() == 1
            }
        }

    override fun find(id: String): PayoutRequest? =
        openConnection().use { connection ->
            connection.prepareStatement(
                "select id, tenant_id, player_id, amount_usd, fee_usd, net_usd, payout_rate_pkr_per_usd, payout_pkr, dest_type, dest_account_title, dest_account_number, status, receipt_object from public.payout_requests where id = ?",
            ).use { statement ->
                statement.setObject(1, UUID.fromString(id))
                statement.executeQuery().use { rows -> if (rows.next()) mapRow(rows) else null }
            }
        }

    override fun lockedTotal(tenantId: String, playerId: String): BigDecimal =
        openConnection().use { connection ->
            connection.prepareStatement(
                "select coalesce(sum(amount_usd), 0) from public.payout_requests where tenant_id = ? and player_id = ? and status in ('PENDING', 'APPROVED_FUNDS_LOCKED')",
            ).use { statement ->
                statement.setString(1, tenantId)
                statement.setString(2, playerId)
                statement.executeQuery().use { rows -> rows.next(); rows.getBigDecimal(1) }
            }
        }

    override fun markLocked(id: String, by: String): Boolean =
        update("update public.payout_requests set status = 'APPROVED_FUNDS_LOCKED', locked_by = ?, locked_utc = now() where id = ? and status = 'PENDING'", listOf(by, UUID.fromString(id)))

    override fun markPaid(id: String, by: String): Boolean =
        update("update public.payout_requests set status = 'PAID', paid_by = ?, paid_utc = now() where id = ? and status = 'APPROVED_FUNDS_LOCKED'", listOf(by, UUID.fromString(id)))

    override fun markRejected(id: String, reason: String, by: String): Boolean =
        update("update public.payout_requests set status = 'REJECTED', reject_reason = ?, rejected_utc = now() where id = ? and status in ('PENDING', 'APPROVED_FUNDS_LOCKED')", listOf(reason, UUID.fromString(id)))

    fun listByStatus(tenantId: String, status: PayoutStatus): List<PayoutRequest> =
        query("select id, tenant_id, player_id, amount_usd, fee_usd, net_usd, payout_rate_pkr_per_usd, payout_pkr, dest_type, dest_account_title, dest_account_number, status, receipt_object from public.payout_requests where tenant_id = ? and status = ? order by requested_utc asc", listOf(tenantId, status.name))

    fun listMine(tenantId: String, playerId: String): List<PayoutRequest> =
        query("select id, tenant_id, player_id, amount_usd, fee_usd, net_usd, payout_rate_pkr_per_usd, payout_pkr, dest_type, dest_account_title, dest_account_number, status, receipt_object from public.payout_requests where tenant_id = ? and player_id = ? order by requested_utc desc", listOf(tenantId, playerId))

    fun updateReceiptObject(id: String, path: String): Boolean =
        update("update public.payout_requests set receipt_object = ? where id = ?", listOf(path, UUID.fromString(id)))

    private fun update(sql: String, parameters: List<Any>): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                parameters.forEachIndexed { index, value -> statement.setObject(index + 1, value) }
                statement.executeUpdate() == 1
            }
        }

    private fun query(sql: String, parameters: List<Any>): List<PayoutRequest> =
        openConnection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                parameters.forEachIndexed { index, value -> statement.setObject(index + 1, value) }
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) add(mapRow(rows))
                    }
                }
            }
        }

    private fun mapRow(rows: java.sql.ResultSet): PayoutRequest =
        PayoutRequest(
            id = rows.getObject(1).toString(),
            tenantId = rows.getString(2),
            playerId = rows.getString(3),
            amountUsd = rows.getBigDecimal(4),
            feeUsd = rows.getBigDecimal(5),
            netUsd = rows.getBigDecimal(6),
            payoutRate = rows.getBigDecimal(7),
            payoutPkr = rows.getBigDecimal(8),
            destType = rows.getString(9),
            destTitle = rows.getString(10),
            destNumber = rows.getString(11),
            status = PayoutStatus.valueOf(rows.getString(12)),
            receiptObject = rows.getString(13),
        )
}
