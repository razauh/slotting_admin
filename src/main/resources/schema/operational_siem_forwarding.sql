-- Schema for OBS-001-04: Forward Controlled Security Events to SIEM
-- Authoritative server-side persistence for security event logging, redaction controls, and SIEM forwarding outbox.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."

CREATE TABLE IF NOT EXISTS operational_siem_events (
    event_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    category VARCHAR(64) NOT NULL, -- AUTH_FAILURE, RBAC_VIOLATION, PRIVILEGE_ESCALATION, FRAUD_SUSPECT, SECRET_ACCESSED, POLICY_DENIED, INTEGRITY_BREACH
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH', -- LOW, MEDIUM, HIGH, CRITICAL
    actor_principal VARCHAR(128) NOT NULL,
    action VARCHAR(128) NOT NULL,
    target_resource VARCHAR(256) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    user_agent VARCHAR(256),
    forward_status VARCHAR(32) NOT NULL DEFAULT 'PENDING_FORWARD', -- PENDING_FORWARD, FORWARDED, FORWARD_FAILED, QUARANTINED
    destination VARCHAR(64) NOT NULL DEFAULT 'ENTERPRISE_SIEM',
    redacted_payload TEXT NOT NULL,
    siem_receipt_id VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    forwarded_at TIMESTAMP WITH TIME ZONE,
    retry_count INT NOT NULL DEFAULT 0,
    evidence_reference VARCHAR(256) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT chk_siem_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS operational_siem_audit (
    audit_id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    details VARCHAR(512),
    CONSTRAINT fk_siem_audit_event FOREIGN KEY (event_id) REFERENCES operational_siem_events(event_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_siem_events_tenant_status ON operational_siem_events(tenant_id, forward_status);
CREATE INDEX IF NOT EXISTS idx_siem_events_correlation ON operational_siem_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_siem_audit_event ON operational_siem_audit(event_id);
