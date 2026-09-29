-- V32: Durable temporary/permanent administrative bans, unbans, and idempotency (TC-027 / BE-008, BE-009)

create table if not exists administrative_bans (
    ban_id uuid primary key,
    tenant_id varchar(128) not null,
    subject_reference varchar(128) not null,
    ban_type varchar(32) not null check (ban_type in ('TEMPORARY', 'PERMANENT')),
    reason_category varchar(64) not null,
    reason_code varchar(128) not null,
    permitted_note varchar(512) not null,
    internal_note varchar(1024) null,
    issuer_id varchar(128) not null,
    effective_from timestamptz not null,
    expires_at timestamptz null,
    case_reference_id varchar(128) not null,
    status varchar(32) not null check (status in ('ACTIVE', 'EXPIRED', 'REVERSED')),
    reversed_at timestamptz null,
    reversed_by varchar(128) null,
    reversal_reason varchar(512) null,
    version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists ix_admin_bans_subject
    on administrative_bans (tenant_id, subject_reference, status, effective_from, expires_at);

create table if not exists administrative_ban_idempotency (
    tenant_id varchar(128) not null,
    idempotency_key varchar(128) not null,
    request_fingerprint varchar(128) not null,
    result_json text not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, idempotency_key)
);
