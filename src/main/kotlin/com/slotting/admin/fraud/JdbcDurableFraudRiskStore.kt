package com.slotting.admin.fraud

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.dao.DuplicateKeyException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

open class JdbcDurableFraudRiskStore(
    private val jdbcTemplate: JdbcTemplate,
    private val objectMapper: ObjectMapper = ObjectMapper().findAndRegisterModules(),
) : DurableFraudRiskStore {

    private val eventRowMapper = RowMapper<DurableRiskEvent> { rs: ResultSet, _ ->
        val amount = rs.getObject("amount_minor_units")?.let { (it as Number).toLong() }
        val currency = rs.getString("currency_code")
        val money = if (amount != null && currency != null) RiskMoney(amount, currency) else null

        val metadataJson = rs.getString("metadata_json")
        val metadata: Map<String, String> = if (!metadataJson.isNullOrBlank()) {
            runCatching {
                objectMapper.readValue(metadataJson, object : TypeReference<Map<String, String>>() {})
            }.getOrDefault(emptyMap())
        } else {
            emptyMap()
        }

        DurableRiskEvent(
            eventId = rs.getObject("event_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            subjectReference = rs.getString("subject_reference"),
            eventType = RiskEventType.valueOf(rs.getString("event_type")),
            source = EventSource.valueOf(rs.getString("source")),
            confidence = SourceConfidence.valueOf(rs.getString("confidence")),
            accountReference = rs.getString("account_reference"),
            deviceFingerprint = rs.getString("device_fingerprint"),
            ipAddress = rs.getString("ip_address"),
            paymentInstrumentHash = rs.getString("payment_instrument_hash"),
            money = money,
            eventTimestamp = rs.getTimestamp("event_timestamp").toInstant(),
            ingestTimestamp = rs.getTimestamp("ingest_timestamp").toInstant(),
            idempotencyKey = rs.getString("idempotency_key"),
            correlationId = rs.getString("correlation_id"),
            causationId = rs.getString("causation_id"),
            metadata = metadata,
        )
    }

    private val decisionRowMapper = RowMapper<RiskEvaluationDecision> { rs: ResultSet, _ ->
        val matchedJson = rs.getString("matched_rules_json")
        val matches: List<RiskRuleMatch> = if (!matchedJson.isNullOrBlank()) {
            runCatching {
                objectMapper.readValue(matchedJson, object : TypeReference<List<RiskRuleMatch>>() {})
            }.getOrDefault(emptyList())
        } else {
            emptyList()
        }

        RiskEvaluationDecision(
            decisionId = rs.getObject("decision_id", UUID::class.java),
            tenantId = rs.getString("tenant_id"),
            subjectReference = rs.getString("subject_reference"),
            ruleSetVersion = rs.getLong("rule_set_version"),
            action = RiskActionRecommendation.valueOf(rs.getString("action")),
            matchedRules = matches,
            evidenceReference = rs.getString("evidence_reference"),
            expiresAt = rs.getTimestamp("expires_at")?.toInstant(),
            requiresCase = rs.getBoolean("requires_case"),
            caseReference = rs.getString("case_reference"),
            evaluatedAt = rs.getTimestamp("evaluated_at").toInstant(),
            idempotencyKey = rs.getString("idempotency_key"),
        )
    }

    override fun saveEvent(event: DurableRiskEvent): Boolean {
        val sql = """
            INSERT INTO fraud_risk_events (
                event_id, tenant_id, subject_reference, event_type, source, confidence,
                account_reference, device_fingerprint, ip_address, payment_instrument_hash,
                amount_minor_units, currency_code, event_timestamp, ingest_timestamp,
                idempotency_key, correlation_id, causation_id, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        """.trimIndent()

        val metadataJson = objectMapper.writeValueAsString(event.metadata)
        val rows = jdbcTemplate.update(
            sql,
            event.eventId,
            event.tenantId,
            event.subjectReference,
            event.eventType.name,
            event.source.name,
            event.confidence.name,
            event.accountReference,
            event.deviceFingerprint,
            event.ipAddress,
            event.paymentInstrumentHash,
            event.money?.amountMinorUnits,
            event.money?.currencyCode,
            Timestamp.from(event.eventTimestamp),
            Timestamp.from(event.ingestTimestamp),
            event.idempotencyKey,
            event.correlationId,
            event.causationId,
            metadataJson,
        )
        return rows > 0
    }

    override fun findEventByIdempotency(tenantId: String, idempotencyKey: String): DurableRiskEvent? {
        val sql = "SELECT * FROM fraud_risk_events WHERE tenant_id = ? AND idempotency_key = ?"
        return jdbcTemplate.query(sql, eventRowMapper, tenantId, idempotencyKey).firstOrNull()
    }

    override fun findEventsForSubject(
        tenantId: String,
        subjectReference: String,
        fromTime: Instant,
        toTime: Instant
    ): List<DurableRiskEvent> {
        val sql = """
            SELECT * FROM fraud_risk_events
            WHERE tenant_id = ? AND subject_reference = ?
              AND event_timestamp >= ? AND event_timestamp <= ?
            ORDER BY event_timestamp ASC
        """.trimIndent()
        return jdbcTemplate.query(
            sql,
            eventRowMapper,
            tenantId,
            subjectReference,
            Timestamp.from(fromTime),
            Timestamp.from(toTime),
        )
    }

    override fun findEventsByPaymentInstrument(
        tenantId: String,
        paymentInstrumentHash: String,
        fromTime: Instant
    ): List<DurableRiskEvent> {
        val sql = """
            SELECT * FROM fraud_risk_events
            WHERE tenant_id = ? AND payment_instrument_hash = ?
              AND event_timestamp >= ?
            ORDER BY event_timestamp ASC
        """.trimIndent()
        return jdbcTemplate.query(
            sql,
            eventRowMapper,
            tenantId,
            paymentInstrumentHash,
            Timestamp.from(fromTime),
        )
    }

    override fun saveDecision(decision: RiskEvaluationDecision): Boolean {
        val sql = """
            INSERT INTO fraud_risk_decisions (
                decision_id, tenant_id, subject_reference, rule_set_version, action,
                matched_rules_json, evidence_reference, expires_at, requires_case,
                case_reference, evaluated_at, idempotency_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        """.trimIndent()

        val matchedJson = objectMapper.writeValueAsString(decision.matchedRules)
        val rows = jdbcTemplate.update(
            sql,
            decision.decisionId,
            decision.tenantId,
            decision.subjectReference,
            decision.ruleSetVersion,
            decision.action.name,
            matchedJson,
            decision.evidenceReference,
            decision.expiresAt?.let { Timestamp.from(it) },
            decision.requiresCase,
            decision.caseReference,
            Timestamp.from(decision.evaluatedAt),
            decision.idempotencyKey,
        )
        return rows > 0
    }

    override fun findDecisionByIdempotency(tenantId: String, idempotencyKey: String): RiskEvaluationDecision? {
        val sql = "SELECT * FROM fraud_risk_decisions WHERE tenant_id = ? AND idempotency_key = ?"
        return jdbcTemplate.query(sql, decisionRowMapper, tenantId, idempotencyKey).firstOrNull()
    }

    override fun saveRuleSet(ruleSet: RiskRuleSet): Boolean {
        val sql = """
            INSERT INTO fraud_risk_rule_sets (version, active, rules_json, created_at, activated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (version) DO UPDATE SET
                active = EXCLUDED.active,
                activated_at = EXCLUDED.activated_at
        """.trimIndent()

        val rulesNames = ruleSet.rules.map { it.ruleId }
        val rulesJson = objectMapper.writeValueAsString(rulesNames)

        val rows = jdbcTemplate.update(
            sql,
            ruleSet.version,
            ruleSet.active,
            rulesJson,
            Timestamp.from(ruleSet.createdAt),
            ruleSet.activatedAt?.let { Timestamp.from(it) },
        )
        return rows > 0
    }

    override fun findRuleSet(version: Long): RiskRuleSet? {
        val sql = "SELECT * FROM fraud_risk_rule_sets WHERE version = ?"
        return jdbcTemplate.query(sql, { rs: ResultSet, _ ->
            RiskRuleSet(
                version = rs.getLong("version"),
                active = rs.getBoolean("active"),
                rules = instantiateRules(rs.getString("rules_json")),
                createdAt = rs.getTimestamp("created_at").toInstant(),
                activatedAt = rs.getTimestamp("activated_at")?.toInstant(),
            )
        }, version).firstOrNull()
    }

    override fun findActiveRuleSet(): RiskRuleSet? {
        val sql = "SELECT * FROM fraud_risk_rule_sets WHERE active = true ORDER BY version DESC LIMIT 1"
        return jdbcTemplate.query(sql, { rs: ResultSet, _ ->
            RiskRuleSet(
                version = rs.getLong("version"),
                active = rs.getBoolean("active"),
                rules = instantiateRules(rs.getString("rules_json")),
                createdAt = rs.getTimestamp("created_at").toInstant(),
                activatedAt = rs.getTimestamp("activated_at")?.toInstant(),
            )
        }).firstOrNull()
    }

    override fun activateRuleSet(version: Long, activatedAt: Instant): Boolean {
        jdbcTemplate.update("UPDATE fraud_risk_rule_sets SET active = false WHERE active = true")
        val rows = jdbcTemplate.update(
            "UPDATE fraud_risk_rule_sets SET active = true, activated_at = ? WHERE version = ?",
            Timestamp.from(activatedAt),
            version,
        )
        return rows > 0
    }

    private fun instantiateRules(rulesJson: String): List<RiskRule> {
        val ruleIds: List<String> = runCatching {
            objectMapper.readValue(rulesJson, object : TypeReference<List<String>>() {})
        }.getOrDefault(emptyList())

        return ruleIds.mapNotNull { id ->
            when (id) {
                "RULE_FAILED_DEPOSITS_BURST" -> FailedDepositsBurstRule()
                "RULE_FAILED_WITHDRAWALS_BURST" -> FailedWithdrawalsRule()
                "RULE_DEPOSIT_WITHDRAW_CYCLING" -> DepositWithdrawCyclingRule()
                "RULE_UNUSUAL_WITHDRAWAL" -> UnusualWithdrawalRule()
                "RULE_AUTH_ANOMALIES" -> AuthAnomaliesRule()
                "RULE_PAYMENT_INSTRUMENT_REUSE" -> PaymentReuseRule()
                "RULE_PROVIDER_ANOMALY" -> ProviderAnomalyRule()
                "RULE_MANUAL_FRAUD_FLAG" -> ManualFlagRule()
                else -> null
            }
        }
    }
}
