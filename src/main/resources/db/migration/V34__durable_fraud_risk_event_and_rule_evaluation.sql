-- TC-031: Durable fraud risk-event ingestion and versioned rule evaluation
-- Immutable risk events, versioned rule-sets, and reproducible risk evaluation decisions

CREATE TABLE IF NOT EXISTS fraud_risk_events (
    event_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    subject_reference VARCHAR(128) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    source VARCHAR(32) NOT NULL,
    confidence VARCHAR(16) NOT NULL,
    account_reference VARCHAR(128),
    device_fingerprint VARCHAR(128),
    ip_address VARCHAR(64),
    payment_instrument_hash VARCHAR(128),
    amount_minor_units BIGINT,
    currency_code VARCHAR(3),
    event_timestamp TIMESTAMPTZ NOT NULL,
    ingest_timestamp TIMESTAMPTZ NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    metadata_json TEXT,
    CONSTRAINT uq_fraud_risk_events_tenant_idem UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_fraud_risk_events_subject_time
    ON fraud_risk_events (tenant_id, subject_reference, event_timestamp);

CREATE INDEX IF NOT EXISTS idx_fraud_risk_events_payment_instrument
    ON fraud_risk_events (tenant_id, payment_instrument_hash)
    WHERE payment_instrument_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_fraud_risk_events_device
    ON fraud_risk_events (tenant_id, device_fingerprint)
    WHERE device_fingerprint IS NOT NULL;

CREATE TABLE IF NOT EXISTS fraud_risk_rule_sets (
    version BIGINT PRIMARY KEY,
    active BOOLEAN NOT NULL DEFAULT false,
    rules_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS fraud_risk_decisions (
    decision_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    subject_reference VARCHAR(128) NOT NULL,
    rule_set_version BIGINT NOT NULL,
    action VARCHAR(32) NOT NULL,
    matched_rules_json TEXT NOT NULL,
    evidence_reference VARCHAR(256) NOT NULL,
    expires_at TIMESTAMPTZ,
    requires_case BOOLEAN NOT NULL DEFAULT false,
    case_reference VARCHAR(128),
    evaluated_at TIMESTAMPTZ NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    CONSTRAINT uq_fraud_risk_decisions_tenant_idem UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_fraud_risk_decisions_subject_eval
    ON fraud_risk_decisions (tenant_id, subject_reference, evaluated_at);
