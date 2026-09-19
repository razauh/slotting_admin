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
