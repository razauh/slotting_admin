-- TC-032: Durable fraud cases, actions, and disposition lifecycle

CREATE TABLE IF NOT EXISTS fraud_cases (
    case_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    subject_reference VARCHAR(128) NOT NULL,
    case_reference VARCHAR(128) NOT NULL UNIQUE,
    state VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    risk_decision_refs_json TEXT NOT NULL,
    detected_reasons_json TEXT NOT NULL,
    claimed_by VARCHAR(64),
    claim_expires_at TIMESTAMPTZ,
    restriction_id UUID,
    disposition_reason TEXT,
    disposed_by VARCHAR(64),
    disposed_at TIMESTAMPTZ,
    second_approver_id VARCHAR(64),
    admin_notes_json TEXT,
    server_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fraud_cases_subject_state
    ON fraud_cases (tenant_id, subject_reference, state);

CREATE TABLE IF NOT EXISTS fraud_case_actions (
    action_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    case_reference VARCHAR(128) NOT NULL,
    action VARCHAR(32) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    second_approver_id VARCHAR(64),
    from_state VARCHAR(32) NOT NULL,
    to_state VARCHAR(32) NOT NULL,
    reason TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    CONSTRAINT uq_fraud_case_actions_tenant_idem UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_fraud_case_actions_case
    ON fraud_case_actions (tenant_id, case_reference, occurred_at);
