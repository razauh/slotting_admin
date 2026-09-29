-- V23: Durable admin-configurable payment-method lifecycle (TC-010)

create table if not exists admin_payment_method (
    tenant_id varchar(128) not null,
    method_id varchar(64) not null,
    provider_id varchar(128) not null,
    method_type varchar(32) not null,
    display_name varchar(128) not null,
    instructions text null,
    safe_account_title varchar(128) null,
    safe_account_number varchar(64) null,
    icon_url varchar(512) null,
    supported_currencies text not null,
    allows_deposit boolean not null default true,
    allows_withdrawal boolean not null default true,
    min_deposit_minor_units bigint not null default 0 check (min_deposit_minor_units >= 0),
    max_deposit_minor_units bigint not null default 0 check (max_deposit_minor_units >= min_deposit_minor_units),
    min_withdrawal_minor_units bigint not null default 0 check (min_withdrawal_minor_units >= 0),
    max_withdrawal_minor_units bigint not null default 0 check (max_withdrawal_minor_units >= min_withdrawal_minor_units),
    fee_flat_minor_units bigint not null default 0 check (fee_flat_minor_units >= 0),
    fee_percentage_bps integer not null default 0 check (fee_percentage_bps >= 0 and fee_percentage_bps <= 10000),
    display_order integer not null default 0,
    status varchar(32) not null check (status in ('ACTIVE', 'INACTIVE', 'MAINTENANCE')),
    maintenance_reason text null,
    server_version bigint not null default 1 check (server_version >= 1),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    updated_by varchar(128) not null,
    primary key (tenant_id, method_id)
);

create index if not exists ix_payment_method_status
    on admin_payment_method (tenant_id, status);

create table if not exists admin_payment_method_history (
    history_id uuid primary key,
    tenant_id varchar(128) not null,
    method_id varchar(64) not null,
    provider_id varchar(128) not null,
    display_name varchar(128) not null,
    status varchar(32) not null,
    snapshot_payload text not null,
    change_reason varchar(128) not null,
    changed_by varchar(128) not null,
    server_version bigint not null,
    changed_at timestamptz not null default now(),
    foreign key (tenant_id, method_id) references admin_payment_method(tenant_id, method_id)
);

create index if not exists ix_payment_method_history
    on admin_payment_method_history (tenant_id, method_id, changed_at);

create table if not exists admin_payment_method_result (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    method_id varchar(64) not null,
    action varchar(32) not null,
    query_fingerprint varchar(512) not null,
    status varchar(32) not null,
    server_version bigint not null,
    evidence_reference varchar(128) not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    foreign key (tenant_id, method_id) references admin_payment_method(tenant_id, method_id)
);
