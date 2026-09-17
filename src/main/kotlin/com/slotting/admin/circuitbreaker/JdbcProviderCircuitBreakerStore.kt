package com.slotting.admin.circuitbreaker

import com.slotting.admin.auth.*
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.util.UUID

@Repository
class JdbcProviderCircuitBreakerStore(private val jdbc: JdbcTemplate) : ProviderCircuitBreakerStore {
    override fun findByIdempotency(tenantId: String, key: String) = jdbc.query(
        "select result_id, query_fingerprint, evidence_reference, provider_id, provider_type, state, failure_threshold, cooldown_seconds, incident_reference, server_version, occurred_at from admin_provider_circuit_breaker_result where tenant_id = ? and idempotency_key = ?",
        { rs, _ -> rs.toResult() }, tenantId, key
    ).firstOrNull()

    override fun findBreaker(tenantId: String, providerId: String) = jdbc.query(
        "select provider_id, provider_type, state, failure_threshold, cooldown_seconds, incident_reference, masked_secret, server_version from admin_provider_circuit_breaker where tenant_id = ? and provider_id = ?",
        { rs, _ ->
            ProviderCircuitBreaker(
                providerId = rs.getString("provider_id"),
                providerType = ProviderType.valueOf(rs.getString("provider_type")),
                state = CircuitBreakerState.valueOf(rs.getString("state")),
                failureThreshold = rs.getInt("failure_threshold"),
                cooldownSeconds = rs.getLong("cooldown_seconds"),
                incidentReference = rs.getString("incident_reference"),
                maskedSecretPreview = rs.getString("masked_secret"),
                serverVersion = rs.getLong("server_version"),
            )
        },
        tenantId, providerId
    ).firstOrNull()

    @Transactional
    override fun save(
        result: ProviderCircuitBreakerResult,
        tenantId: String,
        queryFingerprint: String,
        idempotencyKey: String,
        audit: AuditEvent,
        outbox: OutboxEvent,
    ) {
        val existing = findBreaker(tenantId, result.circuitBreaker.providerId)
        if (existing == null) {
            jdbc.update(
                "insert into admin_provider_circuit_breaker(tenant_id, provider_id, provider_type, state, failure_threshold, cooldown_seconds, incident_reference, masked_secret, server_version, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tenantId, result.circuitBreaker.providerId, result.circuitBreaker.providerType.name, result.circuitBreaker.state.name, result.circuitBreaker.failureThreshold, result.circuitBreaker.cooldownSeconds, result.circuitBreaker.incidentReference, result.circuitBreaker.maskedSecretPreview, result.circuitBreaker.serverVersion, result.serverTime
            )
        } else {
            jdbc.update(
                "update admin_provider_circuit_breaker set provider_type = ?, state = ?, failure_threshold = ?, cooldown_seconds = ?, incident_reference = ?, server_version = ?, updated_at = ? where tenant_id = ? and provider_id = ? and server_version = ?",
                result.circuitBreaker.providerType.name, result.circuitBreaker.state.name, result.circuitBreaker.failureThreshold, result.circuitBreaker.cooldownSeconds, result.circuitBreaker.incidentReference, result.circuitBreaker.serverVersion, result.serverTime, tenantId, result.circuitBreaker.providerId, result.circuitBreaker.serverVersion - 1
            )
        }

        jdbc.update(
            "insert into admin_provider_circuit_breaker_result(result_id, tenant_id, provider_id, provider_type, query_fingerprint, evidence_reference, state, failure_threshold, cooldown_seconds, incident_reference, server_version, occurred_at, idempotency_key, correlation_id, causation_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            result.resultId, tenantId, result.circuitBreaker.providerId, result.circuitBreaker.providerType.name, queryFingerprint, result.evidenceReference, result.circuitBreaker.state.name, result.circuitBreaker.failureThreshold, result.circuitBreaker.cooldownSeconds, result.circuitBreaker.incidentReference, result.circuitBreaker.serverVersion, result.serverTime, idempotencyKey, audit.correlationId, audit.causationId
        )
        jdbc.update(
            "insert into admin_operation(result_id, tenant_id, operation_type, created_at) values (?, ?, ?, ?)",
            result.resultId, tenantId, "PROVIDER_CIRCUIT_BREAKER", result.serverTime
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

    private fun ResultSet.toResult(): Pair<String, ProviderCircuitBreakerResult> {
        val id = getObject("result_id", UUID::class.java)
        val breaker = ProviderCircuitBreaker(
            providerId = getString("provider_id"),
            providerType = ProviderType.valueOf(getString("provider_type")),
            state = CircuitBreakerState.valueOf(getString("state")),
            failureThreshold = getInt("failure_threshold"),
            cooldownSeconds = getLong("cooldown_seconds"),
            incidentReference = getString("incident_reference"),
            maskedSecretPreview = "****",
            serverVersion = getLong("server_version"),
        )
        val res = ProviderCircuitBreakerResult(
            resultId = id,
            circuitBreaker = breaker,
            serverTime = getTimestamp("occurred_at").toInstant(),
            evidenceReference = getString("evidence_reference"),
        )
        return getString("query_fingerprint") to res
    }
}
