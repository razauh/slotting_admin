create table request_rate_bucket (
    tenant_id varchar(128) not null,
    subject_kind varchar(16) not null,
    subject_hash char(64) not null,
    category varchar(16) not null,
    window_start timestamptz not null,
    request_count integer not null,
    updated_at timestamptz not null,
    primary key (tenant_id, subject_kind, subject_hash, category, window_start),
    check (subject_kind in ('USER', 'DEVICE', 'IP')),
    check (category in ('AUTH', 'CASHIER', 'GAMEPLAY', 'GENERAL')),
    check (request_count > 0)
);

create index request_rate_bucket_expiry_idx on request_rate_bucket(window_start);

create table request_abuse_quarantine (
    tenant_id varchar(128) not null,
    actor_hash char(64) not null,
    reason varchar(64) not null,
    created_at timestamptz not null,
    primary key (tenant_id, actor_hash)
);

create table request_abuse_quarantine_audit (
    audit_id bigserial primary key,
    tenant_id varchar(128) not null,
    actor_hash char(64) not null,
    action varchar(16) not null,
    reviewer_id varchar(128) not null,
    reason varchar(500) not null,
    occurred_at timestamptz not null,
    check (action in ('PLACED', 'CLEARED'))
);

create index request_abuse_quarantine_audit_actor_idx on request_abuse_quarantine_audit(tenant_id, actor_hash, occurred_at desc);
