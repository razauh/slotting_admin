create table admin_manual_adjustment_batch (
    tenant_id varchar(128) not null,
    adjustment_reference varchar(128) not null,
    state varchar(32) not null,
    currency_code varchar(3) not null,
    total_debits bigint not null,
    total_credits bigint not null,
    maker_id varchar(128) not null,
    second_approver_id varchar(128),
    posting_reference varchar(128),
    server_version bigint not null default 0,
    updated_at timestamptz not null,
    primary key (tenant_id, adjustment_reference),
    check (state in ('DRAFT', 'PREVIEWED', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED')),
    check (server_version >= 0),
    check (total_debits = total_credits),
    check (total_debits > 0)
);

create index ix_manual_adjustment_batch_state
    on admin_manual_adjustment_batch (tenant_id, state);

create table admin_manual_adjustment_result (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    adjustment_reference varchar(128) not null,
    query_fingerprint varchar(512) not null,
    reason_code varchar(64) not null,
    evidence_reference varchar(128) not null,
    state varchar(32) not null,
    currency_code varchar(3) not null,
    total_debits bigint not null,
    total_credits bigint not null,
    maker_id varchar(128) not null,
    second_approver_id varchar(128),
    posting_reference varchar(128),
    receipt_reference varchar(128) not null,
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    foreign key (tenant_id, adjustment_reference) references admin_manual_adjustment_batch(tenant_id, adjustment_reference),
    check (state in ('DRAFT', 'PREVIEWED', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED')),
    check (server_version >= 0),
    check (total_debits = total_credits),
    check (total_debits > 0)
);
