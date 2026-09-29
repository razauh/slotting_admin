-- Consolidated versioned history for the operational schemas formerly stored as
-- disconnected SQL fragments. Do not edit after release; add V18+ migrations.

-- SOURCE: device_token_lifecycle.sql
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

-- SOURCE: notification_command_contract.sql
-- Notification command contract schema for NOTIFY-001-01
-- Enforces transactional vs marketing classification, approved channels, and non-authoritative audit logging.

create table admin_notification_command (
    notification_id uuid primary key,
    tenant_id varchar(128) not null,
    recipient_user_id varchar(128) not null,
    classification varchar(32) not null,
    channel varchar(32) not null,
    template_id varchar(128) not null,
    recipient_destination varchar(256) not null,
    status varchar(32) not null,
    parameters_json text not null,
    evidence_reference varchar(256) not null,
    server_version bigint not null default 1,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    created_at timestamptz not null,
    unique (tenant_id, idempotency_key),
    check (classification in ('TRANSACTIONAL', 'MARKETING')),
    check (channel in ('EMAIL', 'SMS', 'PUSH')),
    check (status in ('QUEUED', 'ACCEPTED', 'DELIVERED', 'FAILED', 'REJECTED')),
    check (server_version >= 1)
);

create index ix_admin_notification_user
    on admin_notification_command (tenant_id, recipient_user_id);

create index ix_admin_notification_classification
    on admin_notification_command (tenant_id, classification, status);

create table admin_notification_audit_event (
    event_id uuid primary key,
    notification_id uuid not null,
    tenant_id varchar(128) not null,
    event_type varchar(64) not null,
    occurred_at timestamptz not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    foreign key (notification_id) references admin_notification_command(notification_id)
);

-- SOURCE: notification_dead_letter_queue.sql
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

-- SOURCE: notification_delivery_retries.sql
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

-- SOURCE: notification_delivery_tracking.sql
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

-- SOURCE: notification_email_sms_adapters.sql
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

-- SOURCE: notification_push_adapter.sql
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

-- SOURCE: notification_suppression.sql
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

-- SOURCE: operational_critical_paging.sql
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

-- SOURCE: operational_siem_forwarding.sql
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

-- SOURCE: operational_slo_definitions.sql
-- Schema for OBS-001-02: Define Production SLOs
-- Authoritative server-side persistence for Service Level Objectives (SLOs), Service Level Indicators (SLIs), error budgets, and breach alert definitions.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."

CREATE TABLE IF NOT EXISTS operational_slo_definitions (
    slo_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    slo_name VARCHAR(128) NOT NULL,
    service_name VARCHAR(64) NOT NULL,
    indicator_type VARCHAR(64) NOT NULL, -- AVAILABILITY, LATENCY, ERROR_RATE, DUPLICATE_RATE
    incident_focus VARCHAR(64) NOT NULL, -- DUPLICATE_REQUEST, POSTING_FAILURE, BALANCE_IMBALANCE, CATALOG_MISMATCH, CALLBACK_FAILURE, STUCK_WITHDRAWAL
    target_percentage DOUBLE PRECISION NOT NULL, -- e.g. 99.9, 99.99
    evaluation_window_minutes INT NOT NULL DEFAULT 60,
    current_burn_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    error_budget_remaining DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    slo_status VARCHAR(32) NOT NULL DEFAULT 'HEALTHY', -- HEALTHY, WARNING, BREACHED
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    evidence_reference VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_slo_tenant_name UNIQUE (tenant_id, slo_name),
    CONSTRAINT chk_slo_target CHECK (target_percentage > 0.0 AND target_percentage <= 100.0),
    CONSTRAINT chk_slo_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS operational_slo_breach_audit (
    breach_id UUID PRIMARY KEY,
    slo_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    slo_name VARCHAR(128) NOT NULL,
    incident_focus VARCHAR(64) NOT NULL,
    observed_percentage DOUBLE PRECISION NOT NULL,
    burn_rate DOUBLE PRECISION NOT NULL,
    paged BOOLEAN NOT NULL DEFAULT TRUE,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_slo_tenant_status
    ON operational_slo_definitions (tenant_id, slo_status);

CREATE INDEX IF NOT EXISTS idx_slo_breach_slo
    ON operational_slo_breach_audit (slo_id);

-- SOURCE: operational_telemetry.sql
-- Schema for OBS-001-01: Emit Correlated Structured Logs, Metrics, and Traces
-- Authoritative server-side persistence for operational telemetry events, alert triggers, and incident paging records.
-- Financial authority invariant: non-financial; cannot mutate balances or grant direct eligibility.
-- Semantic contract: "Dashboards include duplicates, posting failures, imbalance, mismatch, failed callbacks, stuck withdrawals."

CREATE TABLE IF NOT EXISTS operational_telemetry_events (
    event_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    service_name VARCHAR(64) NOT NULL,
    signal_type VARCHAR(32) NOT NULL, -- LOG, METRIC, TRACE, ALERT
    incident_type VARCHAR(64) NOT NULL, -- DUPLICATE_REQUEST, POSTING_FAILURE, BALANCE_IMBALANCE, CATALOG_MISMATCH, CALLBACK_FAILURE, STUCK_WITHDRAWAL
    severity VARCHAR(32) NOT NULL, -- INFO, WARN, ERROR, CRITICAL
    message VARCHAR(512) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    trace_id VARCHAR(128),
    span_id VARCHAR(128),
    metric_name VARCHAR(128),
    metric_value DOUBLE PRECISION,
    paged BOOLEAN NOT NULL DEFAULT FALSE,
    emitted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    evidence_reference VARCHAR(256) NOT NULL,
    direct_eligibility_granted BOOLEAN NOT NULL DEFAULT FALSE,
    financial_mutation_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_telemetry_non_financial CHECK (
        direct_eligibility_granted = FALSE AND financial_mutation_permitted = FALSE
    )
);

CREATE TABLE IF NOT EXISTS operational_paging_alerts (
    alert_id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    incident_type VARCHAR(64) NOT NULL,
    pager_target VARCHAR(128) NOT NULL,
    payload_summary VARCHAR(512) NOT NULL,
    delivered BOOLEAN NOT NULL DEFAULT TRUE,
    paged_at TIMESTAMP WITH TIME ZONE NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_incident
    ON operational_telemetry_events (tenant_id, incident_type, severity, emitted_at);

CREATE INDEX IF NOT EXISTS idx_telemetry_correlation
    ON operational_telemetry_events (correlation_id);

