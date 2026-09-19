-- Schema for NOTIFY-002-01: Enforce Notification Suppression
-- Authoritative server-side persistence for user suppression lists, stale token management, and audit logs.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.

CREATE TABLE IF NOT EXISTS notification_suppression_record (
    record_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32), -- NULL means global suppression across all channels
    reason VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    suppressed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    evidence_reference VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_suppression_audit (
    event_id UUID PRIMARY KEY,
    check_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    classification VARCHAR(32) NOT NULL,
    template_id VARCHAR(64) NOT NULL,
    decision VARCHAR(64) NOT NULL,
    is_allowed BOOLEAN NOT NULL,
    reason VARCHAR(64),
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_suppression_record_tenant_user
    ON notification_suppression_record (tenant_id, user_id, is_active);

CREATE INDEX IF NOT EXISTS idx_suppression_audit_check
    ON notification_suppression_audit (check_id);
