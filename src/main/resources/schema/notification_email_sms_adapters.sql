-- Schema for NOTIFY-001-03: Approved Email and SMS Adapters
-- Authoritative server-side persistence for provider configuration, dispatch journal, and audit events.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.

CREATE TABLE IF NOT EXISTS notification_provider_config (
    config_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    provider_name VARCHAR(64) NOT NULL,
    sender_identity VARCHAR(256) NOT NULL,
    signing_secret_hash VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_provider_config_tenant_channel UNIQUE (tenant_id, channel)
);

CREATE TABLE IF NOT EXISTS notification_email_sms_journal (
    dispatch_id UUID PRIMARY KEY,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    recipient_user_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    classification VARCHAR(32) NOT NULL,
    template_id VARCHAR(64) NOT NULL,
    recipient_destination VARCHAR(256) NOT NULL,
    provider_reference VARCHAR(128) NOT NULL,
    delivery_state VARCHAR(32) NOT NULL,
    server_time TIMESTAMP WITH TIME ZONE NOT NULL,
    server_version BIGINT NOT NULL DEFAULT 1,
    evidence_reference VARCHAR(256) NOT NULL,
    semantic_contract VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_email_sms_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS notification_email_sms_audit (
    event_id UUID PRIMARY KEY,
    dispatch_id UUID NOT NULL,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    classification VARCHAR(32) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_sms_journal_tenant_recipient
    ON notification_email_sms_journal (tenant_id, recipient_user_id);

CREATE INDEX IF NOT EXISTS idx_email_sms_audit_dispatch
    ON notification_email_sms_audit (dispatch_id);
