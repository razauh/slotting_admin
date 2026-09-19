-- Schema for OBS-001-03: Page on Critical Financial and Security Failures
-- Authoritative server-side persistence for critical incident paging policies, on-call escalations, incident states, and resolution logs.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."

CREATE TABLE IF NOT EXISTS operational_paging_incidents (
    incident_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    incident_category VARCHAR(32) NOT NULL, -- FINANCIAL, SECURITY
    failure_type VARCHAR(64) NOT NULL, -- POSTING_FAILURE, BALANCE_IMBALANCE, STUCK_WITHDRAWAL, AUTH_BREACH, RBAC_VIOLATION, FRAUD_SUSPECT
    severity VARCHAR(32) NOT NULL DEFAULT 'CRITICAL',
    title VARCHAR(256) NOT NULL,
    description VARCHAR(1024) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PAGING_TRIGGERED', -- PAGING_TRIGGERED, ACKNOWLEDGED, RESOLVED, ESCALATED
    target_tier VARCHAR(64) NOT NULL DEFAULT 'PRIMARY_ONCALL',
    pager_reference VARCHAR(128),
    paged_at TIMESTAMP WITH TIME ZONE NOT NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    acknowledged_by VARCHAR(64),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(64),
    resolution_summary VARCHAR(512),
    evidence_reference VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_paging_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS operational_paging_audit (
    audit_id UUID PRIMARY KEY,
    incident_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_paging_incidents_tenant_status
    ON operational_paging_incidents (tenant_id, status, paged_at);

CREATE INDEX IF NOT EXISTS idx_paging_audit_incident
    ON operational_paging_audit (incident_id);
