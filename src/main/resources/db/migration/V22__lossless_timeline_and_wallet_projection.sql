-- V22: Lossless timeline replay and authoritative wallet projections (TC-009 / BE-019, AND-002)

-- 1. Lossless timeline read entries (BE-019 fix)
create table if not exists admin_ledger_timeline_read_entry (
    read_entry_id uuid primary key,
    result_id uuid not null references admin_ledger_timeline_read(result_id) on delete cascade,
    ledger_entry_id varchar(128) not null,
    player_reference varchar(128) not null,
    occurred_at timestamptz not null,
    entry_type varchar(64) not null,
    amount_minor_units bigint not null check (amount_minor_units >= 0),
    currency_code varchar(3) not null,
    line_order integer not null check (line_order >= 1)
);

create index if not exists admin_ledger_timeline_read_entry_idx
    on admin_ledger_timeline_read_entry (result_id, line_order);

-- 2. Authoritative wallet projections derived from committed ledger (AND-002 backend foundation)
create table if not exists wallet_projection (
    projection_id uuid primary key,
    tenant_id varchar(128) not null,
    owner_reference varchar(128) not null,
    currency_code varchar(3) not null,
    balance_minor_units bigint not null default 0,
    ledger_version bigint not null default 0,
    server_version bigint not null default 1,
    last_entry_id uuid null,
    updated_at timestamptz not null default now(),
    unique (tenant_id, owner_reference, currency_code)
);

create index if not exists wallet_projection_lookup_idx
    on wallet_projection (tenant_id, owner_reference);

-- 3. Idempotent statement query receipts
create table if not exists statement_query_receipt (
    receipt_id uuid primary key,
    tenant_id varchar(128) not null,
    idempotency_key varchar(128) not null,
    query_fingerprint varchar(128) not null,
    response_payload text not null,
    ledger_version bigint not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, idempotency_key)
);
