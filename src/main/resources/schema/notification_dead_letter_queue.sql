-- Schema for NOTIFY-003-03: Quarantine Notification Failures in a DLQ
-- Authoritative server-side persistence for dead-letter queue (DLQ), poisoned event isolation, manual resolution workflows, and alert tracking.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Delivery status not proof user read; health/latency/failure dashboards."

CREATE TABLE IF NOT EXISTS notification_dead_letter_queue (
    dlq_id UUID PRIMARY KEY,
    tracking_id UUID NOT NULL,
    notification_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    recipient_id VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    quarantine_reason VARCHAR(64) NOT NULL,
    quarantine_detail VARCHAR(1024),
    failure_count INT NOT NULL DEFAULT 1,
    dlq_status VARCHAR(32) NOT NULL DEFAULT 'QUARANTINED',
    quarantined_at TIMESTAMP WITH TIME ZONE NOT NULL,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(64),
    resolution_action VARCHAR(64),
    resolution_note VARCHAR(512),
    alert_emitted BOOLEAN NOT NULL DEFAULT TRUE,
    evidence_reference VARCHAR(256) NOT NULL,
    is_user_read BOOLEAN NOT NULL DEFAULT FALSE,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_dlq_notification UNIQUE (tenant_id, notification_id),
    CONSTRAINT chk_dlq_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    ),
    CONSTRAINT chk_dlq_not_read_proof CHECK (
        is_user_read = FALSE
    )
);

CREATE TABLE IF NOT EXISTS notification_dlq_audit (
    event_id UUID PRIMARY KEY,
    dlq_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    notification_id UUID NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    from_status VARCHAR(32),
    to_status VARCHAR(32) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_dlq_tenant_status
    ON notification_dead_letter_queue (tenant_id, dlq_status, quarantined_at);

CREATE INDEX IF NOT EXISTS idx_notification_dlq_audit_dlq
    ON notification_dlq_audit (dlq_id);
