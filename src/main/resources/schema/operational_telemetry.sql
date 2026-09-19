-- Schema for OBS-001-01: Emit Correlated Structured Logs, Metrics, and Traces
-- Authoritative server-side persistence for operational telemetry events, alert triggers, and incident paging records.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."

CREATE TABLE IF NOT EXISTS operational_telemetry_events (
    event_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    service_name VARCHAR(64) NOT NULL,
    signal_type VARCHAR(32) NOT NULL, -- LOG, METRIC, TRACE, ALERT
    incident_type VARCHAR(64) NOT NULL, -- DUPLICATE_REQUEST, POSTING_FAILURE, BALANCE_IMBALANCE, CATALOG_MISMATCH, CALLBACK_FAILURE, STUCK_WITHDRAWAL
    severity VARCHAR(32) NOT NULL, -- INFO, WARN, ERROR, CRITICAL
    message VARCHAR(512) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    trace_id VARCHAR(128),
    span_id VARCHAR(128),
    metric_name VARCHAR(128),
    metric_value DOUBLE PRECISION,
    paged BOOLEAN NOT NULL DEFAULT FALSE,
    emitted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    evidence_reference VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_telemetry_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS operational_paging_alerts (
    alert_id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    incident_type VARCHAR(64) NOT NULL,
    pager_target VARCHAR(128) NOT NULL,
    payload_summary VARCHAR(512) NOT NULL,
    delivered BOOLEAN NOT NULL DEFAULT TRUE,
    paged_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_incident
    ON operational_telemetry_events (tenant_id, incident_type, severity, emitted_at);

CREATE INDEX IF NOT EXISTS idx_telemetry_correlation
    ON operational_telemetry_events (correlation_id);
