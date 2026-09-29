package com.slotting.admin.provider

import com.slotting.admin.auth.*
import com.slotting.admin.infra.VersionedCasHelper
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

class InMemoryPaymentMethodStore : PaymentMethodStore {
    private val methods = ConcurrentHashMap<Pair<String, String>, PaymentMethodConfig>()
    private val idempotency = ConcurrentHashMap<Pair<String, String>, Pair<String, PaymentMethodResult>>()
    private val history = CopyOnWriteArrayList<PaymentMethodHistoryRecord>()
    private val lock = Any()

    override fun findByIdempotency(tenantId: String, key: String): Pair<String, PaymentMethodResult>? {
        return idempotency[tenantId to key]
    }

    override fun findMethod(tenantId: String, methodId: String): PaymentMethodConfig? {
        return methods[tenantId to methodId]
    }

    override fun listMethods(tenantId: String): List<PaymentMethodConfig> {
        return methods.values.filter { it.tenantId == tenantId }.sortedBy { it.displayOrder }
    }

    override fun listHistory(tenantId: String, methodId: String): List<PaymentMethodHistoryRecord> {
        return history.filter { it.tenantId == tenantId && it.methodId == methodId }.sortedBy { it.serverVersion }
    }

    fun saveMethod(method: PaymentMethodConfig) {
        methods[method.tenantId to method.methodId] = method
    }

    override fun save(
        result: PaymentMethodResult,
        queryFingerprint: String,
        idempotencyKey: String,
        action: PaymentMethodAction,
        changeReason: String,
        changedBy: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        synchronized(lock) {
            val key = result.method.tenantId to result.method.methodId
            val existing = methods[key]
            if (action == PaymentMethodAction.REGISTER) {
                if (existing != null) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.CONFLICT)
                }
            } else {
                if (existing == null) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.FORBIDDEN)
                }
                if (existing.serverVersion != result.method.serverVersion - 1) {
                    throw AuthenticationFailure.Rejected(AuthErrorCode.STALE)
                }
            }

            methods[key] = result.method
            idempotency[result.method.tenantId to idempotencyKey] = queryFingerprint to result

            val historyRecord = PaymentMethodHistoryRecord(
                historyId = UUID.randomUUID(),
                tenantId = result.method.tenantId,
                methodId = result.method.methodId,
                providerId = result.method.providerId,
                displayName = result.method.displayName,
                status = result.method.status,
                snapshotPayload = result.method.toString(),
                changeReason = changeReason,
                changedBy = changedBy,
                serverVersion = result.method.serverVersion,
                changedAt = result.serverTime,
            )
            history.add(historyRecord)
        }
    }
}

@Repository
class JdbcPaymentMethodStore(private val jdbc: JdbcTemplate) : PaymentMethodStore {

    override fun findByIdempotency(tenantId: String, key: String): Pair<String, PaymentMethodResult>? {
        return jdbc.query(
            """
            select r.query_fingerprint, r.result_id, r.evidence_reference, r.occurred_at,
                   m.tenant_id, m.method_id, m.provider_id, m.method_type, m.display_name,
                   m.instructions, m.safe_account_title, m.safe_account_number, m.icon_url,
                   m.supported_currencies, m.allows_deposit, m.allows_withdrawal,
                   m.min_deposit_minor_units, m.max_deposit_minor_units,
                   m.min_withdrawal_minor_units, m.max_withdrawal_minor_units,
                   m.fee_flat_minor_units, m.fee_percentage_bps, m.display_order,
                   m.status, m.maintenance_reason, m.server_version, m.created_at, m.updated_at, m.updated_by
            from admin_payment_method_result r
            join admin_payment_method m on r.tenant_id = m.tenant_id and r.method_id = m.method_id
            where r.tenant_id = ? and r.idempotency_key = ?
            """.trimIndent(),
            { rs, _ ->
                val fingerprint = rs.getString("query_fingerprint")
                val config = rs.toPaymentMethodConfig()
                val result = PaymentMethodResult(
                    resultId = rs.getObject("result_id", UUID::class.java),
                    method = config,
                    serverTime = rs.getTimestamp("occurred_at").toInstant(),
                    evidenceReference = rs.getString("evidence_reference"),
                )
                fingerprint to result
            },
            tenantId, key
        ).firstOrNull()
    }

    override fun findMethod(tenantId: String, methodId: String): PaymentMethodConfig? {
        return jdbc.query(
            """
            select tenant_id, method_id, provider_id, method_type, display_name,
                   instructions, safe_account_title, safe_account_number, icon_url,
                   supported_currencies, allows_deposit, allows_withdrawal,
                   min_deposit_minor_units, max_deposit_minor_units,
                   min_withdrawal_minor_units, max_withdrawal_minor_units,
                   fee_flat_minor_units, fee_percentage_bps, display_order,
                   status, maintenance_reason, server_version, created_at, updated_at, updated_by
            from admin_payment_method
            where tenant_id = ? and method_id = ?
            """.trimIndent(),
            { rs, _ -> rs.toPaymentMethodConfig() },
            tenantId, methodId
        ).firstOrNull()
    }

    override fun listMethods(tenantId: String): List<PaymentMethodConfig> {
        return jdbc.query(
            """
            select tenant_id, method_id, provider_id, method_type, display_name,
                   instructions, safe_account_title, safe_account_number, icon_url,
                   supported_currencies, allows_deposit, allows_withdrawal,
                   min_deposit_minor_units, max_deposit_minor_units,
                   min_withdrawal_minor_units, max_withdrawal_minor_units,
                   fee_flat_minor_units, fee_percentage_bps, display_order,
                   status, maintenance_reason, server_version, created_at, updated_at, updated_by
            from admin_payment_method
            where tenant_id = ?
            order by display_order asc
            """.trimIndent(),
            { rs, _ -> rs.toPaymentMethodConfig() },
            tenantId
        )
    }

    override fun listHistory(tenantId: String, methodId: String): List<PaymentMethodHistoryRecord> {
        return jdbc.query(
            """
            select history_id, tenant_id, method_id, provider_id, display_name,
                   status, snapshot_payload, change_reason, changed_by, server_version, changed_at
            from admin_payment_method_history
            where tenant_id = ? and method_id = ?
            order by server_version asc
            """.trimIndent(),
            { rs, _ ->
                PaymentMethodHistoryRecord(
                    historyId = rs.getObject("history_id", UUID::class.java),
                    tenantId = rs.getString("tenant_id"),
                    methodId = rs.getString("method_id"),
                    providerId = rs.getString("provider_id"),
                    displayName = rs.getString("display_name"),
                    status = PaymentMethodStatus.valueOf(rs.getString("status")),
                    snapshotPayload = rs.getString("snapshot_payload"),
                    changeReason = rs.getString("change_reason"),
                    changedBy = rs.getString("changed_by"),
                    serverVersion = rs.getLong("server_version"),
                    changedAt = rs.getTimestamp("changed_at").toInstant(),
                )
            },
            tenantId, methodId
        )
    }

    @Transactional
    override fun save(
        result: PaymentMethodResult,
        queryFingerprint: String,
        idempotencyKey: String,
        action: PaymentMethodAction,
        changeReason: String,
        changedBy: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        val m = result.method
        val currenciesStr = m.supportedCurrencies.joinToString(",")

        if (action == PaymentMethodAction.REGISTER) {
            val inserted = jdbc.update(
                """
                insert into admin_payment_method (
                    tenant_id, method_id, provider_id, method_type, display_name,
                    instructions, safe_account_title, safe_account_number, icon_url,
                    supported_currencies, allows_deposit, allows_withdrawal,
                    min_deposit_minor_units, max_deposit_minor_units,
                    min_withdrawal_minor_units, max_withdrawal_minor_units,
                    fee_flat_minor_units, fee_percentage_bps, display_order,
                    status, maintenance_reason, server_version, created_at, updated_at, updated_by
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                m.tenantId, m.methodId, m.providerId, m.methodType.name, m.displayName,
                m.instructions, m.safeAccountTitle, m.safeAccountNumber, m.iconUrl,
                currenciesStr, m.allowsDeposit, m.allowsWithdrawal,
                m.minDepositMinorUnits, m.maxDepositMinorUnits,
                m.minWithdrawalMinorUnits, m.maxWithdrawalMinorUnits,
                m.feeFlatMinorUnits, m.feePercentageBps, m.displayOrder,
                m.status.name, m.maintenanceReason, m.serverVersion, m.createdAt, m.updatedAt, m.updatedBy
            )
            VersionedCasHelper.requireUpdated(inserted)
        } else {
            val updated = jdbc.update(
                """
                update admin_payment_method set
                    provider_id = ?, method_type = ?, display_name = ?,
                    instructions = ?, safe_account_title = ?, safe_account_number = ?, icon_url = ?,
                    supported_currencies = ?, allows_deposit = ?, allows_withdrawal = ?,
                    min_deposit_minor_units = ?, max_deposit_minor_units = ?,
                    min_withdrawal_minor_units = ?, max_withdrawal_minor_units = ?,
                    fee_flat_minor_units = ?, fee_percentage_bps = ?, display_order = ?,
                    status = ?, maintenance_reason = ?, server_version = ?, updated_at = ?, updated_by = ?
                where tenant_id = ? and method_id = ? and server_version = ?
                """.trimIndent(),
                m.providerId, m.methodType.name, m.displayName,
                m.instructions, m.safeAccountTitle, m.safeAccountNumber, m.iconUrl,
                currenciesStr, m.allowsDeposit, m.allowsWithdrawal,
                m.minDepositMinorUnits, m.maxDepositMinorUnits,
                m.minWithdrawalMinorUnits, m.maxWithdrawalMinorUnits,
                m.feeFlatMinorUnits, m.feePercentageBps, m.displayOrder,
                m.status.name, m.maintenanceReason, m.serverVersion, m.updatedAt, m.updatedBy,
                m.tenantId, m.methodId, m.serverVersion - 1
            )
            VersionedCasHelper.requireUpdated(updated)
        }

        // Insert into history
        jdbc.update(
            """
            insert into admin_payment_method_history (
                history_id, tenant_id, method_id, provider_id, display_name,
                status, snapshot_payload, change_reason, changed_by, server_version, changed_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            UUID.randomUUID(), m.tenantId, m.methodId, m.providerId, m.displayName,
            m.status.name, m.toString(), changeReason, changedBy, m.serverVersion, result.serverTime
        )

        // Insert into result
        jdbc.update(
            """
            insert into admin_payment_method_result (
                result_id, tenant_id, method_id, action, query_fingerprint,
                status, server_version, evidence_reference, occurred_at,
                idempotency_key, correlation_id, causation_id
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            result.resultId, m.tenantId, m.methodId, action.name, queryFingerprint,
            m.status.name, m.serverVersion, result.evidenceReference, result.serverTime,
            idempotencyKey, audit.correlationId, audit.causationId
        )

        // Standard operational audit/outbox entries
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, m.tenantId, "PAYMENT_METHOD_${action.name}", result.serverTime
        )
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, m.tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, RedactedEventJson.audit(audit)
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, m.tenantId, outbox.type, outbox.createdAt, RedactedEventJson.outbox(outbox, audit)
        )
    }

    private fun ResultSet.toPaymentMethodConfig(): PaymentMethodConfig {
        return PaymentMethodConfig(
            tenantId = getString("tenant_id"),
            methodId = getString("method_id"),
            providerId = getString("provider_id"),
            methodType = PaymentMethodType.valueOf(getString("method_type")),
            displayName = getString("display_name"),
            instructions = getString("instructions"),
            safeAccountTitle = getString("safe_account_title"),
            safeAccountNumber = getString("safe_account_number"),
            iconUrl = getString("icon_url"),
            supportedCurrencies = getString("supported_currencies").split(",").map { it.trim() }.filter { it.isNotBlank() },
            allowsDeposit = getBoolean("allows_deposit"),
            allowsWithdrawal = getBoolean("allows_withdrawal"),
            minDepositMinorUnits = getLong("min_deposit_minor_units"),
            maxDepositMinorUnits = getLong("max_deposit_minor_units"),
            minWithdrawalMinorUnits = getLong("min_withdrawal_minor_units"),
            maxWithdrawalMinorUnits = getLong("max_withdrawal_minor_units"),
            feeFlatMinorUnits = getLong("fee_flat_minor_units"),
            feePercentageBps = getInt("fee_percentage_bps"),
            displayOrder = getInt("display_order"),
            status = PaymentMethodStatus.valueOf(getString("status")),
            maintenanceReason = getString("maintenance_reason"),
            serverVersion = getLong("server_version"),
            createdAt = getTimestamp("created_at").toInstant(),
            updatedAt = getTimestamp("updated_at").toInstant(),
            updatedBy = getString("updated_by"),
        )
    }
}
