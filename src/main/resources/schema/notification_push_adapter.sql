-- Schema for NOTIFY-001-04: Approved Push Adapter and Templates
-- Authoritative server-side persistence for FCM push provider config, push journal, and audit events.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.

CREATE TABLE IF NOT EXISTS notification_push_provider_config (
    config_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    provider_name VARCHAR(64) NOT NULL DEFAULT 'FIREBASE_CLOUD_MESSAGING',
    fcm_project_id VARCHAR(128) NOT NULL,
    service_account_hash VARCHAR(128) NOT NULL,
    signing_secret_hash VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_push_provider_config_tenant UNIQUE (tenant_id)
);

CREATE TABLE IF NOT EXISTS notification_push_journal (
    dispatch_id UUID PRIMARY KEY,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    recipient_user_id VARCHAR(64) NOT NULL,
    recipient_push_token VARCHAR(512) NOT NULL,
    classification VARCHAR(32) NOT NULL,
    template_id VARCHAR(64) NOT NULL,
    provider_reference VARCHAR(128) NOT NULL,
    delivery_state VARCHAR(32) NOT NULL,
    server_time TIMESTAMP WITH TIME ZONE NOT NULL,
    server_version BIGINT NOT NULL DEFAULT 1,
    evidence_reference VARCHAR(256) NOT NULL,
    semantic_contract VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_push_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS notification_push_audit (
    event_id UUID PRIMARY KEY,
    dispatch_id UUID NOT NULL,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL DEFAULT 'PUSH',
    classification VARCHAR(32) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_push_journal_tenant_recipient
    ON notification_push_journal (tenant_id, recipient_user_id);

CREATE INDEX IF NOT EXISTS idx_push_audit_dispatch
    ON notification_push_audit (dispatch_id);
