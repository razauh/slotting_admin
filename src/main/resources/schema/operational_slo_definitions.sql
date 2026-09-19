-- Schema for OBS-001-02: Define Production SLOs
-- Authoritative server-side persistence for Service Level Objectives (SLOs), Service Level Indicators (SLIs), error budgets, and breach alert definitions.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."

CREATE TABLE IF NOT EXISTS operational_slo_definitions (
    slo_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    slo_name VARCHAR(128) NOT NULL,
    service_name VARCHAR(64) NOT NULL,
    indicator_type VARCHAR(64) NOT NULL, -- AVAILABILITY, LATENCY, ERROR_RATE, DUPLICATE_RATE
    incident_focus VARCHAR(64) NOT NULL, -- DUPLICATE_REQUEST, POSTING_FAILURE, BALANCE_IMBALANCE, CATALOG_MISMATCH, CALLBACK_FAILURE, STUCK_WITHDRAWAL
    target_percentage DOUBLE PRECISION NOT NULL, -- e.g. 99.9, 99.99
    evaluation_window_minutes INT NOT NULL DEFAULT 60,
    current_burn_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    error_budget_remaining DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    slo_status VARCHAR(32) NOT NULL DEFAULT 'HEALTHY', -- HEALTHY, WARNING, BREACHED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    evidence_reference VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_slo_tenant_name UNIQUE (tenant_id, slo_name),
    CONSTRAINT chk_slo_target CHECK (target_percentage > 0.0 AND target_percentage <= 100.0),
    CONSTRAINT chk_slo_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS operational_slo_breach_audit (
    breach_id UUID PRIMARY KEY,
    slo_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    slo_name VARCHAR(128) NOT NULL,
    incident_focus VARCHAR(64) NOT NULL,
    observed_percentage DOUBLE PRECISION NOT NULL,
    burn_rate DOUBLE PRECISION NOT NULL,
    paged BOOLEAN NOT NULL DEFAULT TRUE,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_slo_tenant_status
    ON operational_slo_definitions (tenant_id, slo_status);

CREATE INDEX IF NOT EXISTS idx_slo_breach_slo
    ON operational_slo_breach_audit (slo_id);
