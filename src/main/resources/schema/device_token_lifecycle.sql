-- Schema for NOTIFY-002-02: Manage Device-Token Lifecycle
-- Authoritative server-side persistence for device push tokens, state transitions, and audit events.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.

CREATE TABLE IF NOT EXISTS notification_device_tokens (
    token_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    platform VARCHAR(32) NOT NULL,
    token_value VARCHAR(512) NOT NULL,
    token_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    app_version VARCHAR(64) NOT NULL,
    registered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    evidence_reference VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_device_token_value UNIQUE (tenant_id, token_value),
    CONSTRAINT chk_device_token_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS notification_device_token_audit (
    event_id UUID PRIMARY KEY,
    token_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    token_state VARCHAR(32) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_tenant_user
    ON notification_device_tokens (tenant_id, user_id, token_state);

CREATE INDEX IF NOT EXISTS idx_device_token_audit_token
    ON notification_device_token_audit (token_id);
