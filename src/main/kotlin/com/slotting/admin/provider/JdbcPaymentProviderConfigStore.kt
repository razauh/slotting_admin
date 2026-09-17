package com.slotting.admin.provider

import com.slotting.admin.auth.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.UUID

@Repository
class JdbcPaymentProviderConfigStore(private val jdbc: JdbcTemplate) : PaymentProviderConfigStore {
    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query(
        "select result_id, query_fingerprint, evidence_reference, provider_id, display_name, status, endpoint_url, masked_secret, incident_reference, server_version, occurred_at from admin_payment_provider_config_result where tenant_id = ? and idempotency_key = ?",
        { rs, _ -> rs.toResult() }, tenantId, key
    ).firstOrNull()

    override fun findProvider(tenantId: String, providerId: String) = jdbc.query(
        "select provider_id, display_name, status, endpoint_url, masked_secret, incident_reference, server_version from admin_payment_provider_config where tenant_id = ? and provider_id = ?",
        { rs, _ ->
            PaymentProviderConfig(
                providerId = rs.getString("provider_id"),
                displayName = rs.getString("display_name"),
                status = PaymentProviderStatus.valueOf(rs.getString("status")),
                endpointUrl = rs.getString("endpoint_url"),
                maskedSecretPreview = rs.getString("masked_secret"),
                incidentReference = rs.getString("incident_reference"),
                serverVersion = rs.getLong("server_version"),
            )
        },
        tenantId, providerId
    ).firstOrNull()

    @Transactional
    override fun save(
        result: PaymentProviderConfigResult,
        tenantId: String,
        secretHash: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        val existing = findProvider(tenantId, result.provider.providerId)
        if (existing == null) {
            jdbc.update(
                "insert into admin_payment_provider_config(tenant_id, provider_id, display_name, status, endpoint_url, secret_hash, masked_secret, incident_reference, server_version, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tenantId, result.provider.providerId, result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, secretHash, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, result.serverTime
            )
        } else {
            if (secretHash.isNotBlank()) {
                jdbc.update(
                    "update admin_payment_provider_config set display_name = ?, status = ?, endpoint_url = ?, secret_hash = ?, masked_secret = ?, incident_reference = ?, server_version = ?, updated_at = ? where tenant_id = ? and provider_id = ? and server_version = ?",
                    result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, secretHash, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, result.serverTime, tenantId, result.provider.providerId, result.provider.serverVersion - 1
                )
            } else {
                jdbc.update(
                    "update admin_payment_provider_config set display_name = ?, status = ?, endpoint_url = ?, masked_secret = ?, incident_reference = ?, server_version = ?, updated_at = ? where tenant_id = ? and provider_id = ? and server_version = ?",
                    result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, result.serverTime, tenantId, result.provider.providerId, result.provider.serverVersion - 1
                )
            }
        }

        jdbc.update(
            "insert into admin_payment_provider_config_result(result_id, tenant_id, provider_id, query_fingerprint, evidence_reference, display_name, status, endpoint_url, masked_secret, incident_reference, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, result.provider.providerId, queryFingerprint, result.evidenceReference, result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId
        )
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, tenantId, "PAYMENT_PROVIDER_CONFIG", result.serverTime
        )
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, tenantId, audit.type, audit.occurredAt, audit.correlationId, audit.causationId, "{}"
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, tenantId, outbox.type, outbox.createdAt, "{}"
        )
    }

    private fun ResultSet.toResult(): Pair<String, PaymentProviderConfigResult> {
        val id = getObject("result_id", UUID::class.java)
        val provider = PaymentProviderConfig(
            providerId = getString("provider_id"),
            displayName = getString("display_name"),
            status = PaymentProviderStatus.valueOf(getString("status")),
            endpointUrl = getString("endpoint_url"),
            maskedSecretPreview = getString("masked_secret"),
            incidentReference = getString("incident_reference"),
            serverVersion = getLong("server_version"),
        )
        val res = PaymentProviderConfigResult(
            resultId = id,
            provider = provider,
            serverTime = getTimestamp("occurred_at").toInstant(),
            evidenceReference = getString("evidence_reference"),
        )
        return getString("query_fingerprint") to res
    }
}
