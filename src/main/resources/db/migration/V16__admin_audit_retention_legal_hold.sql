create table admin_audit_legal_hold (
    tenant_id varchar(128) not null,
    hold_reference varchar(128) not null,
    reason varchar(256) not null,
    approver_id varchar(128) not null,
    active boolean not null default true,
    applied_at timestamptz not null,
    released_at timestamptz,
    server_version bigint not null default 1,
    updated_at timestamptz not null,
    primary key (tenant_id, hold_reference),
    check (server_version >= 0)
);

create index ix_admin_audit_legal_hold_active
    on admin_audit_legal_hold (tenant_id, active);

create table admin_audit_query_result (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    query_fingerprint varchar(512) not null,
    evidence_reference varchar(128) not null,
    action varchar(32) not null,
    records_count int not null,
    checksum_sha256 varchar(64),
    legal_hold_active boolean not null,
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    check (server_version >= 0),
    check (records_count >= 0)
);
