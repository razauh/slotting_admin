package com.slotting.admin.ledger

import org.springframework.jdbc.core.JdbcTemplate
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

data class LegacyCurrencyInventoryRow(
    val tenantId: String,
    val accountReferenceHash: String,
    val currency: String,
    val accountState: String,
    val accountType: String,
    val legCount: Long,
    val totalDebitsMinorUnits: Long,
    val totalCreditsMinorUnits: Long,
    val netMinorUnits: Long,
)

data class LegacyCurrencyInventoryReport(
    val environment: String?,
    val environmentClassified: Boolean,
    val rows: List<LegacyCurrencyInventoryRow>,
    val totalsByCurrency: Map<String, Long>,
    val walletTotalsByCurrency: Map<String, Long>,
    val depositTotalsByCurrency: Map<String, Long>,
    val discrepancies: List<String>,
    val checksum: String,
)

data class LegacyCurrencyTransitionDecision(
    val allowed: Boolean,
    val reason: String?,
    val quarantineLegacyInr: Boolean,
)

data class LegacyCurrencyTransitionResult(
    val decision: LegacyCurrencyTransitionDecision,
    val quarantinedAccounts: Int,
    val report: LegacyCurrencyInventoryReport,
)

class LegacyCurrencyTransitionService(
    private val jdbc: JdbcTemplate,
) {
    fun inventory(environment: String?): LegacyCurrencyInventoryReport {
        val rows = jdbc.query(
            """
            select a.tenant_id, a.account_reference, a.currency_code, a.status, a.account_type,
                   count(l.leg_id) as leg_count,
                   coalesce(sum(case when l.direction = 'DEBIT' then l.amount_minor_units else 0 end), 0) as debit_total,
                   coalesce(sum(case when l.direction = 'CREDIT' then l.amount_minor_units else 0 end), 0) as credit_total
            from ledger_account a
            left join ledger_leg l
              on l.tenant_id = a.tenant_id
             and l.account_reference = a.account_reference
             and l.currency_code = a.currency_code
            group by a.tenant_id, a.account_reference, a.currency_code, a.status, a.account_type
            order by a.currency_code, a.account_reference
            """.trimIndent(),
        ) { rs, _ ->
            val debits = rs.getLong("debit_total")
            val credits = rs.getLong("credit_total")
            LegacyCurrencyInventoryRow(
                tenantId = rs.getString("tenant_id"),
                accountReferenceHash = redact(rs.getString("account_reference")),
                currency = rs.getString("currency_code"),
                accountState = rs.getString("status"),
                accountType = rs.getString("account_type"),
                legCount = rs.getLong("leg_count"),
                totalDebitsMinorUnits = debits,
                totalCreditsMinorUnits = credits,
                netMinorUnits = Math.subtractExact(credits, debits),
            )
        }

        val totalsByCurrency = rows.groupBy { it.currency }
            .mapValues { (_, currencyRows) ->
                currencyRows.fold(0L) { total, row -> Math.addExact(total, row.totalCreditsMinorUnits) }
            }

        val walletTotals = jdbc.query(
            "select currency_code, coalesce(sum(balance_minor_units), 0) as total from wallet_projection group by currency_code order by currency_code",
        ) { rs, _ -> rs.getString("currency_code") to rs.getLong("total") }.toMap()

        val depositTotals = jdbc.query(
            "select currency_code, coalesce(sum(amount_minor_units), 0) as total from admin_deposit_intent group by currency_code order by currency_code",
        ) { rs, _ -> rs.getString("currency_code") to rs.getLong("total") }.toMap()

        val ledgerPlayerTotals = jdbc.query(
            """
            select tenant_id, account_reference, currency_code,
                   coalesce(sum(case when direction = 'CREDIT' then amount_minor_units else -amount_minor_units end), 0) as net
            from ledger_leg
            where account_reference like 'PLAYER:%'
            group by tenant_id, account_reference, currency_code
            """.trimIndent(),
        ) { rs, _ ->
            val key = "${rs.getString("tenant_id")}:${rs.getString("account_reference")}:${rs.getString("currency_code")}"
            key to rs.getLong("net")
        }.toMap()

        val walletByOwner = jdbc.query(
            "select tenant_id, owner_reference, currency_code, balance_minor_units from wallet_projection",
        ) { rs, _ ->
            val key = "${rs.getString("tenant_id")}:PLAYER:${rs.getString("owner_reference")}:${rs.getString("currency_code")}"
            key to rs.getLong("balance_minor_units")
        }.toMap()

        val discrepancies = mutableListOf<String>()
        for ((key, ledgerNet) in ledgerPlayerTotals) {
            val walletNet = walletByOwner[key]
            if (walletNet != null && walletNet != ledgerNet) {
                discrepancies.add("WALLET_LEDGER_MISMATCH:${redactKey(key)}")
            }
        }

        val checksum = checksumOf(rows, walletTotals, depositTotals)
        return LegacyCurrencyInventoryReport(
            environment = environment,
            environmentClassified = !environment.isNullOrBlank(),
            rows = rows,
            totalsByCurrency = totalsByCurrency,
            walletTotalsByCurrency = walletTotals,
            depositTotalsByCurrency = depositTotals,
            discrepancies = discrepancies,
            checksum = checksum,
        )
    }

    fun evaluateActivation(
        report: LegacyCurrencyInventoryReport,
        provenanceApproved: Boolean,
    ): LegacyCurrencyTransitionDecision {
        if (!report.environmentClassified) {
            return LegacyCurrencyTransitionDecision(false, "UNKNOWN_PROVENANCE", false)
        }
        if (!provenanceApproved) {
            return LegacyCurrencyTransitionDecision(false, "OWNER_CLASSIFICATION_REQUIRED", false)
        }
        if (report.discrepancies.isNotEmpty()) {
            return LegacyCurrencyTransitionDecision(false, "RECONCILIATION_MISMATCH", false)
        }
        return LegacyCurrencyTransitionDecision(true, null, true)
    }

    fun applyDefaultTransition(
        environment: String,
        provenanceApproved: Boolean,
    ): LegacyCurrencyTransitionResult {
        val report = inventory(environment)
        val decision = evaluateActivation(report, provenanceApproved)
        if (!decision.allowed) {
            throw IllegalStateException("Legacy currency transition blocked: ${decision.reason}")
        }
        val quarantined = jdbc.update(
            "update ledger_account set status = 'QUARANTINED' where currency_code = 'INR' and status = 'ACTIVE'",
        )
        return LegacyCurrencyTransitionResult(decision, quarantined, report)
    }

    fun databaseChecksum(): String {
        val accountRows = jdbc.query(
            "select tenant_id, account_reference, currency_code, status, account_type from ledger_account order by tenant_id, account_reference, currency_code",
        ) { rs, _ ->
            listOf(
                rs.getString("tenant_id"),
                rs.getString("account_reference"),
                rs.getString("currency_code"),
                rs.getString("status"),
                rs.getString("account_type"),
            ).joinToString("|")
        }
        val legRows = jdbc.query(
            "select tenant_id, account_reference, currency_code, direction, amount_minor_units from ledger_leg order by tenant_id, account_reference, currency_code, line_order",
        ) { rs, _ ->
            listOf(
                rs.getString("tenant_id"),
                rs.getString("account_reference"),
                rs.getString("currency_code"),
                rs.getString("direction"),
                rs.getLong("amount_minor_units").toString(),
            ).joinToString("|")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        (accountRows + legRows).forEach {
            digest.update(it.toByteArray(StandardCharsets.UTF_8))
            digest.update('\n'.code.toByte())
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun checksumOf(
        rows: List<LegacyCurrencyInventoryRow>,
        walletTotals: Map<String, Long>,
        depositTotals: Map<String, Long>,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        rows.forEach { row ->
            digest.update(
                "${row.tenantId}|${row.accountReferenceHash}|${row.currency}|${row.accountState}|${row.legCount}|${row.totalDebitsMinorUnits}|${row.totalCreditsMinorUnits}\n"
                    .toByteArray(StandardCharsets.UTF_8),
            )
        }
        walletTotals.toSortedMap().forEach { (currency, total) ->
            digest.update("wallet|$currency|$total\n".toByteArray(StandardCharsets.UTF_8))
        }
        depositTotals.toSortedMap().forEach { (currency, total) ->
            digest.update("deposit|$currency|$total\n".toByteArray(StandardCharsets.UTF_8))
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun redact(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(value.toByteArray(StandardCharsets.UTF_8))
        return hash.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun redactKey(value: String): String = redact(value)
}
