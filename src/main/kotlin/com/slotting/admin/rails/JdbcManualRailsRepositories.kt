package com.slotting.admin.rails

import java.math.BigDecimal
import java.time.Instant
import java.sql.Timestamp
import java.util.UUID

data class FundingAccount(
    val id: String,
    val tenantId: String,
    val type: String,
    val accountTitle: String,
    val accountNumber: String,
    val instructions: String?,
    val sortOrder: Int,
    val visible: Boolean = true,
)

class JdbcDepositSubmissionRepository(
    private val openConnection: () -> java.sql.Connection,
) : DepositSubmissionRepository {
    override fun find(id: String): DepositSubmission? =
        openConnection().use { connection ->
            connection.prepareStatement(
                "select id, tenant_id, player_id, amount_pkr, status, rate_applied, amount_usd, reject_reason from public.deposit_submissions where id = ?",
            ).use { statement ->
                statement.setObject(1, UUID.fromString(id))
                statement.executeQuery().use { rows -> if (rows.next()) mapRow(rows) else null }
            }
        }

    override fun markApproved(id: String, rate: BigDecimal, usd: BigDecimal, by: String): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "update public.deposit_submissions set status = 'APPROVED', rate_applied = ?, amount_usd = ?, approved_by = ?, approved_utc = now() where id = ? and status = 'SUBMITTED'",
            ).use { statement ->
                statement.setBigDecimal(1, rate)
                statement.setBigDecimal(2, usd)
                statement.setString(3, by)
                statement.setObject(4, UUID.fromString(id))
                statement.executeUpdate() == 1
            }
        }

    override fun markRejected(id: String, reason: String, by: String): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "update public.deposit_submissions set status = 'REJECTED', reject_reason = ?, approved_by = ?, approved_utc = now() where id = ? and status = 'SUBMITTED'",
            ).use { statement ->
                statement.setString(1, reason)
                statement.setString(2, by)
                statement.setObject(3, UUID.fromString(id))
                statement.executeUpdate() == 1
            }
        }

    override fun hasApprovedDeposit(playerId: String): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "select exists (select 1 from public.deposit_submissions where player_id = ? and status = 'APPROVED')",
            ).use { statement ->
                statement.setString(1, playerId)
                statement.executeQuery().use { rows -> rows.next() && rows.getBoolean(1) }
            }
        }

    override fun insert(
        submission: DepositSubmission,
        fundingAccountId: String,
        transferReference: String,
        transferredUtc: Instant,
        receiptObject: String,
    ) {
        openConnection().use { connection ->
            connection.prepareStatement(
                "insert into public.deposit_submissions (id, tenant_id, player_id, funding_account_id, amount_pkr, transfer_reference, transferred_utc, receipt_object) values (?, ?, ?, ?, ?, ?, ?, ?)",
            ).use { statement ->
                statement.setObject(1, UUID.fromString(submission.id))
                statement.setString(2, submission.tenantId)
                statement.setString(3, submission.playerId)
                statement.setObject(4, UUID.fromString(fundingAccountId))
                statement.setBigDecimal(5, submission.amountPkr)
                statement.setString(6, transferReference)
                statement.setTimestamp(7, Timestamp.from(transferredUtc))
                statement.setString(8, receiptObject)
                statement.executeUpdate()
            }
        }
    }

    override fun listByStatus(tenantId: String, status: SubmissionStatus): List<DepositSubmission> =
        query(
            "select id, tenant_id, player_id, amount_pkr, status, rate_applied, amount_usd, reject_reason from public.deposit_submissions where tenant_id = ? and status = ? order by transferred_utc asc",
            listOf(tenantId, status.name),
        )

    override fun listMine(tenantId: String, playerId: String): List<DepositSubmission> =
        query(
            "select id, tenant_id, player_id, amount_pkr, status, rate_applied, amount_usd, reject_reason from public.deposit_submissions where tenant_id = ? and player_id = ? order by created_utc desc",
            listOf(tenantId, playerId),
        )

    override fun revertApproval(id: String): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "update public.deposit_submissions set status = 'SUBMITTED', rate_applied = null, amount_usd = null, approved_by = null, approved_utc = null where id = ? and status = 'APPROVED'",
            ).use { statement ->
                statement.setObject(1, UUID.fromString(id))
                statement.executeUpdate() == 1
            }
        }

    private fun query(sql: String, parameters: List<Any>): List<DepositSubmission> =
        openConnection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                parameters.forEachIndexed { index, value -> statement.setObject(index + 1, value) }
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(mapRow(rows))
                        }
                    }
                }
            }
        }

    private fun mapRow(rows: java.sql.ResultSet): DepositSubmission =
        DepositSubmission(
            id = rows.getObject(1).toString(),
            tenantId = rows.getString(2),
            playerId = rows.getString(3),
            amountPkr = rows.getBigDecimal(4),
            status = SubmissionStatus.valueOf(rows.getString(5)),
            rateApplied = rows.getBigDecimal(6),
            amountUsd = rows.getBigDecimal(7),
            rejectReason = rows.getString(8),
        )
}

class JdbcFundingAccountsRepository(
    private val openConnection: () -> java.sql.Connection,
) {
    fun insert(account: FundingAccount) {
        openConnection().use { connection ->
            connection.prepareStatement(
                "insert into public.funding_accounts (id, tenant_id, type, account_title, account_number, instructions, sort_order, visible) values (?, ?, ?, ?, ?, ?, ?, ?)",
            ).use { statement ->
                statement.setObject(1, UUID.fromString(account.id))
                statement.setString(2, account.tenantId)
                statement.setString(3, account.type)
                statement.setString(4, account.accountTitle)
                statement.setString(5, account.accountNumber)
                statement.setString(6, account.instructions)
                statement.setInt(7, account.sortOrder)
                statement.setBoolean(8, account.visible)
                statement.executeUpdate()
            }
        }
    }

    fun listVisible(tenantId: String): List<FundingAccount> =
        query("select id, tenant_id, type, account_title, account_number, instructions, sort_order, visible from public.funding_accounts where tenant_id = ? and visible = true order by sort_order asc, created_utc asc", tenantId)

    fun listAll(tenantId: String): List<FundingAccount> =
        query("select id, tenant_id, type, account_title, account_number, instructions, sort_order, visible from public.funding_accounts where tenant_id = ? order by sort_order asc, created_utc asc", tenantId)

    fun deleteIfUnreferenced(id: String): Boolean =
        openConnection().use { connection ->
            connection.prepareStatement(
                "delete from public.funding_accounts a where a.id = ? and not exists (select 1 from public.deposit_submissions s where s.funding_account_id = a.id)",
            ).use { statement ->
                statement.setObject(1, UUID.fromString(id))
                statement.executeUpdate() == 1
            }
        }

    private fun query(sql: String, tenantId: String): List<FundingAccount> =
        openConnection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setString(1, tenantId)
                statement.executeQuery().use { rows ->
                    buildList {
                        while (rows.next()) {
                            add(
                                FundingAccount(
                                    id = rows.getObject(1).toString(),
                                    tenantId = rows.getString(2),
                                    type = rows.getString(3),
                                    accountTitle = rows.getString(4),
                                    accountNumber = rows.getString(5),
                                    instructions = rows.getString(6),
                                    sortOrder = rows.getInt(7),
                                    visible = rows.getBoolean(8),
                                ),
                            )
                        }
                    }
                }
            }
        }
}
