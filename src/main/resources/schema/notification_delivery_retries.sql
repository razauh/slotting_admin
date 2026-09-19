-- Schema for NOTIFY-003-02: Retry Notification Delivery with Bounds
-- Authoritative server-side persistence for retry policies, backoff schedules, retry attempt records, and bounded exhaustion alerts.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Delivery status not proof user read; health/latency/failure dashboards."

CREATE TABLE IF NOT EXISTS notification_delivery_retry_policy (
    policy_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    max_retries INT NOT NULL DEFAULT 3,
    initial_interval_seconds INT NOT NULL DEFAULT 60,
    backoff_multiplier DOUBLE PRECISION NOT NULL DEFAULT 2.0,
    max_interval_seconds INT NOT NULL DEFAULT 3600,
    dead_letter_after_exhaustion BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_retry_policy_tenant_channel UNIQUE (tenant_id, channel),
    CONSTRAINT chk_retry_bounds CHECK (
        max_retries >= 1 AND max_retries <= 10 AND
        initial_interval_seconds >= 1 AND
        max_interval_seconds >= initial_interval_seconds AND
        backoff_multiplier >= 1.0
    )
);

CREATE TABLE IF NOT EXISTS notification_delivery_retries (
    retry_id UUID PRIMARY KEY,
    tracking_id UUID NOT NULL,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    attempt_number INT NOT NULL,
    max_attempts INT NOT NULL,
    retry_status VARCHAR(32) NOT NULL DEFAULT 'SCHEDULED',
    scheduled_at TIMESTAMP WITH TIME ZONE NOT NULL,
    executed_at TIMESTAMP WITH TIME ZONE,
    error_reason VARCHAR(256),
    is_exhausted BOOLEAN NOT NULL DEFAULT FALSE,
    evidence_reference VARCHAR(256) NOT NULL,
    is_user_read BOOLEAN NOT NULL DEFAULT FALSE,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_delivery_retry_attempt UNIQUE (tracking_id, attempt_number),
    CONSTRAINT chk_retry_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    ),
    CONSTRAINT chk_retry_not_read_proof CHECK (
        is_user_read = FALSE
    )
);

CREATE TABLE IF NOT EXISTS notification_delivery_retry_audit (
    event_id UUID PRIMARY KEY,
    retry_id UUID NOT NULL,
    tracking_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    attempt_number INT NOT NULL,
    retry_status VARCHAR(32) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delivery_retries_scheduled
    ON notification_delivery_retries (tenant_id, retry_status, scheduled_at);

CREATE INDEX IF NOT EXISTS idx_delivery_retries_tracking
    ON notification_delivery_retries (tracking_id);
