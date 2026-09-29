-- V27: Authoritative Account Support Cases, Account Closure, and Legal Hold Workflows (TC-018)

create table if not exists account_support_case (
    case_id uuid primary key,
    tenant_id varchar(128) not null,
    owner_user_id uuid not null,
    category varchar(64) not null,
    subject varchar(255) not null,
    description text not null,
    round_id varchar(128) null,
    status varchar(32) not null default 'SUBMITTED',
    resolution_summary text null,
    idempotency_key varchar(128) not null,
    request_fingerprint varchar(128) not null,
    correlation_id varchar(128) not null,
    server_version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, idempotency_key)
);

create index if not exists ix_account_support_case_owner
    on account_support_case (tenant_id, owner_user_id, status);

create table if not exists account_closure_record (
    closure_id uuid primary key,
    tenant_id varchar(128) not null,
    owner_user_id uuid not null,
    reason varchar(64) not null,
    reason_details text not null,
    status varchar(32) not null, -- 'PENDING_SETTLEMENT', 'LEGAL_HOLD', 'CLOSED', 'REJECTED'
    pending_balance_minor_units bigint not null default 0,
    settlement_acknowledged boolean not null default false,
    has_pending_financial_ops boolean not null default false,
    has_legal_hold boolean not null default false,
    retention_policy_reference varchar(128) not null,
    server_receipt varchar(255) not null,
    idempotency_key varchar(128) not null,
    request_fingerprint varchar(128) not null,
    correlation_id varchar(128) not null,
    closed_at timestamptz null,
    server_version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, idempotency_key)
);

create index if not exists ix_account_closure_owner
    on account_closure_record (tenant_id, owner_user_id);

create table if not exists account_legal_hold (
    hold_id uuid primary key,
    tenant_id varchar(128) not null,
    owner_user_id uuid not null,
    reason varchar(256) not null,
    is_active boolean not null default true,
    placed_by varchar(128) not null,
    created_at timestamptz not null default now(),
    released_at timestamptz null
);

create index if not exists ix_account_legal_hold_lookup
    on account_legal_hold (tenant_id, owner_user_id, is_active);
