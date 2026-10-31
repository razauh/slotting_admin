package com.slotting.admin.provider

import com.slotting.admin.auth.*
import com.slotting.admin.provider.port.ProviderEnvironment
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.UUID

@Repository
class JdbcPaymentProviderConfigStore(private val jdbc: JdbcTemplate) : PaymentProviderConfigStore {
    private val columns = "provider_id, display_name, status, endpoint_url, masked_secret, incident_reference, server_version, environment, wallet_currencies, settlement_currencies, supported_operations, capability_version, setup_status, permitted_use_approved, technical_verification_approved, external_evidence_reference, reviewer, credential_version, last_probe_status, last_probe_at"

    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query(
        "select result_id, query_fingerprint, evidence_reference, provider_id, display_name, status, endpoint_url, masked_secret, incident_reference, server_version, occurred_at from admin_payment_provider_config_result where tenant_id = ? and idempotency_key = ?",
        { rs, _ -> rs.toResult() }, tenantId, key
    ).firstOrNull()

    override fun findProvider(tenantId: String, providerId: String) = jdbc.query(
        "select $columns from admin_payment_provider_config where tenant_id = ? and provider_id = ?",
        { rs, _ -> rs.toProvider() },
        tenantId, providerId
    ).firstOrNull()

    override fun listProviders(tenantId: String): List<PaymentProviderConfig> = jdbc.query(
        "select $columns from admin_payment_provider_config where tenant_id = ? order by provider_id",
        { rs, _ -> rs.toProvider() },
        tenantId,
    )

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
            val inserted = jdbc.update(
                "insert into admin_payment_provider_config(tenant_id, provider_id, display_name, status, endpoint_url, secret_hash, masked_secret, incident_reference, server_version, updated_at, environment, wallet_currencies, settlement_currencies, supported_operations, capability_version, setup_status, permitted_use_approved, technical_verification_approved, external_evidence_reference, reviewer, credential_version, last_probe_status, last_probe_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tenantId, result.provider.providerId, result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, secretHash, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, java.sql.Timestamp.from(result.serverTime),
                result.provider.environment.name, result.provider.walletCurrencies.joinToString(","), result.provider.settlementCurrencies.joinToString(","), result.provider.supportedOperations.joinToString(","), result.provider.capabilityVersion, result.provider.setupStatus.name, result.provider.permittedUseApproved, result.provider.technicalVerificationApproved, result.provider.externalEvidenceReference, result.provider.reviewer, result.provider.credentialVersion, result.provider.lastProbeStatus, java.sql.Timestamp.from(result.provider.lastProbeAt ?: java.time.Instant.EPOCH)
            )
            com.slotting.admin.infra.VersionedCasHelper.requireUpdated(inserted)
        } else {
            val updated = if (secretHash.isNotBlank()) {
                jdbc.update(
                    "update admin_payment_provider_config set display_name = ?, status = ?, endpoint_url = ?, secret_hash = ?, masked_secret = ?, incident_reference = ?, server_version = ?, updated_at = ?, environment = ?, wallet_currencies = ?, settlement_currencies = ?, supported_operations = ?, capability_version = ?, setup_status = ?, permitted_use_approved = ?, technical_verification_approved = ?, external_evidence_reference = ?, reviewer = ?, credential_version = ?, last_probe_status = ?, last_probe_at = ? where tenant_id = ? and provider_id = ? and server_version = ?",
                    result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, secretHash, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, java.sql.Timestamp.from(result.serverTime),
                    result.provider.environment.name, result.provider.walletCurrencies.joinToString(","), result.provider.settlementCurrencies.joinToString(","), result.provider.supportedOperations.joinToString(","), result.provider.capabilityVersion, result.provider.setupStatus.name, result.provider.permittedUseApproved, result.provider.technicalVerificationApproved, result.provider.externalEvidenceReference, result.provider.reviewer, result.provider.credentialVersion, result.provider.lastProbeStatus, java.sql.Timestamp.from(result.provider.lastProbeAt ?: java.time.Instant.EPOCH), tenantId, result.provider.providerId, result.provider.serverVersion - 1
                )
            } else {
                jdbc.update(
                    "update admin_payment_provider_config set display_name = ?, status = ?, endpoint_url = ?, masked_secret = ?, incident_reference = ?, server_version = ?, updated_at = ?, environment = ?, wallet_currencies = ?, settlement_currencies = ?, supported_operations = ?, capability_version = ?, setup_status = ?, permitted_use_approved = ?, technical_verification_approved = ?, external_evidence_reference = ?, reviewer = ?, credential_version = ?, last_probe_status = ?, last_probe_at = ? where tenant_id = ? and provider_id = ? and server_version = ?",
                    result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, java.sql.Timestamp.from(result.serverTime),
                    result.provider.environment.name, result.provider.walletCurrencies.joinToString(","), result.provider.settlementCurrencies.joinToString(","), result.provider.supportedOperations.joinToString(","), result.provider.capabilityVersion, result.provider.setupStatus.name, result.provider.permittedUseApproved, result.provider.technicalVerificationApproved, result.provider.externalEvidenceReference, result.provider.reviewer, result.provider.credentialVersion, result.provider.lastProbeStatus, java.sql.Timestamp.from(result.provider.lastProbeAt ?: java.time.Instant.EPOCH), tenantId, result.provider.providerId, result.provider.serverVersion - 1
                )
            }
            com.slotting.admin.infra.VersionedCasHelper.requireUpdated(updated)
        }

        jdbc.update(
            "insert into admin_payment_provider_config_result(result_id, tenant_id, provider_id, query_fingerprint, evidence_reference, display_name, status, endpoint_url, masked_secret, incident_reference, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, result.provider.providerId, queryFingerprint, result.evidenceReference, result.provider.displayName, result.provider.status.name, result.provider.endpointUrl, result.provider.maskedSecretPreview, result.provider.incidentReference, result.provider.serverVersion, java.sql.Timestamp.from(result.serverTime), idempotencyKey, audit.correlationId, audit.causationId
        )
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, tenantId, "PAYMENT_PROVIDER_CONFIG", java.sql.Timestamp.from(result.serverTime)
        )
        jdbc.update(
            "insert into admin_audit_event(event_id, result_id, tenant_id, event_type, occurred_at, correlation_id, causation_id, redacted_details) values (?, ?, ?, ?, ?, ?, ?, cast(? as jsonb))",
            audit.eventId, audit.resultId, tenantId, audit.type, java.sql.Timestamp.from(audit.occurredAt), audit.correlationId, audit.causationId, com.slotting.admin.auth.RedactedEventJson.audit(audit)
        )
        jdbc.update(
            "insert into admin_outbox_event(event_id, result_id, tenant_id, event_type, created_at, payload) values (?, ?, ?, ?, ?, cast(? as jsonb))",
            outbox.eventId, outbox.resultId, tenantId, outbox.type, java.sql.Timestamp.from(outbox.createdAt), com.slotting.admin.auth.RedactedEventJson.outbox(outbox, audit)
        )
    }

    private fun ResultSet.toProvider(): PaymentProviderConfig = PaymentProviderConfig(
        providerId = getString("provider_id"),
        displayName = getString("display_name"),
        status = PaymentProviderStatus.valueOf(getString("status")),
        endpointUrl = getString("endpoint_url"),
        maskedSecretPreview = getString("masked_secret"),
        incidentReference = getString("incident_reference"),
        serverVersion = getLong("server_version"),
        environment = runCatching { ProviderEnvironment.valueOf(getString("environment")) }.getOrDefault(ProviderEnvironment.SANDBOX),
        walletCurrencies = getString("wallet_currencies").split(",").filter { it.isNotBlank() }.toSet(),
        settlementCurrencies = getString("settlement_currencies").split(",").filter { it.isNotBlank() }.toSet(),
        supportedOperations = getString("supported_operations").split(",").filter { it.isNotBlank() }.toSet(),
        capabilityVersion = getLong("capability_version"),
        setupStatus = runCatching { ProviderSetupState.valueOf(getString("setup_status")) }.getOrDefault(ProviderSetupState.DISABLED),
        permittedUseApproved = getBoolean("permitted_use_approved"),
        technicalVerificationApproved = getBoolean("technical_verification_approved"),
        externalEvidenceReference = getString("external_evidence_reference"),
        reviewer = getString("reviewer"),
        credentialVersion = getLong("credential_version"),
        lastProbeStatus = getString("last_probe_status"),
        lastProbeAt = getTimestamp("last_probe_at")?.toInstant()?.takeUnless { it == java.time.Instant.EPOCH },
    )

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
