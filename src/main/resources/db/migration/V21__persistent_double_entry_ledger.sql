-- V21: Persistent double-entry ledger and idempotent journal posting (TC-008 / BE-001, BE-018)

create table if not exists ledger_account (
    account_id uuid primary key,
    tenant_id varchar(128) not null,
    account_reference varchar(128) not null,
    currency_code varchar(3) not null,
    account_type varchar(32) not null default 'STANDARD',
    status varchar(32) not null default 'ACTIVE',
    created_at timestamptz not null default now(),
    unique (tenant_id, account_reference, currency_code)
);

create index if not exists ledger_account_lookup_idx
    on ledger_account (tenant_id, account_reference);

create table if not exists ledger_version_tracker (
    tenant_id varchar(128) primary key,
    latest_version bigint not null default 0 check (latest_version >= 0),
    updated_at timestamptz not null default now()
);

create table if not exists ledger_transaction (
    transaction_id uuid primary key,
    tenant_id varchar(128) not null,
    transaction_reference varchar(128) not null,
    currency_code varchar(3) not null,
    total_debits_minor_units bigint not null check (total_debits_minor_units >= 0),
    total_credits_minor_units bigint not null check (total_credits_minor_units >= 0),
    is_balanced boolean not null default true check (is_balanced = true),
    status varchar(32) not null check (status in ('POSTED', 'COMPENSATED', 'REJECTED')),
    entry_count integer not null check (entry_count >= 2),
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    posted_by varchar(128) not null,
    posted_at timestamptz not null default now(),
    effective_at timestamptz not null default now(),
    ledger_version bigint not null check (ledger_version >= 1),
    compensation_for_reference varchar(128) null,
    evidence_reference varchar(255) not null,
    check (total_debits_minor_units = total_credits_minor_units),
    unique (tenant_id, transaction_reference),
    unique (tenant_id, idempotency_key)
);

create index if not exists ledger_transaction_tenant_idx
    on ledger_transaction (tenant_id, posted_at);

create table if not exists ledger_leg (
    leg_id uuid primary key,
    transaction_id uuid not null references ledger_transaction(transaction_id),
    tenant_id varchar(128) not null,
    account_reference varchar(128) not null,
    direction varchar(16) not null check (direction in ('DEBIT', 'CREDIT')),
    amount_minor_units bigint not null check (amount_minor_units > 0),
    currency_code varchar(3) not null,
    line_order integer not null check (line_order >= 1),
    narration text null,
    created_at timestamptz not null default now(),
    unique (transaction_id, line_order)
);

create index if not exists ledger_leg_account_idx
    on ledger_leg (tenant_id, account_reference, currency_code);

create table if not exists ledger_idempotency_receipt (
    receipt_id uuid primary key,
    tenant_id varchar(128) not null,
    idempotency_key varchar(128) not null,
    payload_digest varchar(128) not null,
    transaction_id uuid not null references ledger_transaction(transaction_id),
    transaction_reference varchar(128) not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, idempotency_key)
);
