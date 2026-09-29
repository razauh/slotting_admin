-- V24: Durable deposit intent, callback, credit, and reconciliation workflow (TC-013)

create table if not exists admin_deposit_intent (
    intent_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    method_id varchar(64) not null,
    provider_id varchar(128) not null,
    amount_minor_units bigint not null check (amount_minor_units > 0),
    currency_code varchar(3) not null,
    status varchar(32) not null check (status in ('CREATED', 'DISPATCH_PENDING', 'PROVIDER_PENDING', 'SETTLED', 'FAILED', 'EXPIRED', 'AMBIGUOUS_RECONCILING')),
    provider_reference varchar(128) null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    expires_at timestamptz not null,
    settled_at timestamptz null,
    ledger_transaction_reference varchar(128) null,
    failure_reason text null,
    server_version bigint not null default 1 check (server_version >= 1),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, idempotency_key)
);

create index if not exists ix_deposit_intent_player
    on admin_deposit_intent (tenant_id, player_id, status);

create index if not exists ix_deposit_intent_provider_ref
    on admin_deposit_intent (tenant_id, provider_id, provider_reference);

create table if not exists admin_deposit_inbox (
    event_id uuid primary key,
    tenant_id varchar(128) not null,
    provider_id varchar(128) not null,
    provider_event_id varchar(128) not null,
    payload_hash varchar(128) not null,
    signature_valid boolean not null,
    processed boolean not null default false,
    intent_id uuid null,
    received_at timestamptz not null default now(),
    processed_at timestamptz null,
    unique (tenant_id, provider_id, provider_event_id)
);

create index if not exists ix_deposit_inbox_processed
    on admin_deposit_inbox (tenant_id, processed, received_at);

create table if not exists admin_deposit_reconciliation (
    reconciliation_id uuid primary key,
    tenant_id varchar(128) not null,
    intent_id uuid not null,
    status_before varchar(32) not null,
    status_after varchar(32) not null,
    provider_status varchar(64) null,
    reconciled_by varchar(128) not null,
    reconciled_at timestamptz not null default now(),
    evidence text null,
    foreign key (intent_id) references admin_deposit_intent(intent_id)
);
