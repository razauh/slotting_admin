-- Schema for NOTIFY-003-01: Track Notification Delivery States
-- Authoritative server-side persistence for notification outbox delivery tracking, provider state transitions, latency metrics, and audit evidence.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Delivery status not proof user read; health/latency/failure dashboards."

CREATE TABLE IF NOT EXISTS notification_delivery_tracking (
    tracking_id UUID PRIMARY KEY,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    recipient_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    delivery_state VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    provider_reference VARCHAR(128),
    error_code VARCHAR(64),
    error_detail VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    queued_at TIMESTAMP WITH TIME ZONE,
    sent_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    failed_at TIMESTAMP WITH TIME ZONE,
    latency_ms BIGINT,
    evidence_reference VARCHAR(256) NOT NULL,
    is_user_read BOOLEAN NOT NULL DEFAULT FALSE,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_delivery_notification_tenant UNIQUE (tenant_id, notification_id),
    CONSTRAINT chk_delivery_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    ),
    CONSTRAINT chk_delivery_not_read_proof CHECK (
        is_user_read = FALSE
    )
);

CREATE TABLE IF NOT EXISTS notification_delivery_audit (
    event_id UUID PRIMARY KEY,
    tracking_id UUID NOT NULL,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    from_state VARCHAR(32),
    to_state VARCHAR(32) NOT NULL,
    attempt_number INT NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delivery_tracking_tenant_state
    ON notification_delivery_tracking (tenant_id, delivery_state, channel);

CREATE INDEX IF NOT EXISTS idx_delivery_audit_tracking
    ON notification_delivery_audit (tracking_id);
