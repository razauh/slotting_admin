create table admin_reconciliation_exception (
    tenant_id varchar(128) not null,
    exception_reference varchar(128) not null,
    report_reference varchar(128) not null,
    currency_code varchar(3) not null,
    discrepancy_amount bigint not null,
    external_reference varchar(128) not null,
    ledger_entry_reference varchar(128) not null,
    state varchar(32) not null,
    assignee_id varchar(128),
    reason_code varchar(64),
    resolution_notes varchar(512),
    approver_id varchar(128),
    checksum_sha256 varchar(64) not null,
    server_version bigint not null default 1,
    updated_at timestamptz not null,
    primary key (tenant_id, exception_reference),
    foreign key (tenant_id, report_reference) references admin_reconciliation_report(tenant_id, report_reference),
    check (state in ('OPEN', 'ASSIGNED', 'RESOLVED', 'CLOSED')),
    check (discrepancy_amount >= 0),
    check (server_version >= 0)
);

create index ix_reconciliation_exception_state
    on admin_reconciliation_exception (tenant_id, state);

create table admin_reconciliation_exception_result (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    exception_reference varchar(128) not null,
    query_fingerprint varchar(512) not null,
    evidence_reference varchar(128) not null,
    report_reference varchar(128) not null,
    currency_code varchar(3) not null,
    discrepancy_amount bigint not null,
    external_reference varchar(128) not null,
    ledger_entry_reference varchar(128) not null,
    state varchar(32) not null,
    assignee_id varchar(128),
    reason_code varchar(64),
    resolution_notes varchar(512),
    approver_id varchar(128),
    checksum_sha256 varchar(64) not null,
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    foreign key (tenant_id, exception_reference) references admin_reconciliation_exception(tenant_id, exception_reference),
    check (state in ('OPEN', 'ASSIGNED', 'RESOLVED', 'CLOSED')),
    check (discrepancy_amount >= 0),
    check (server_version >= 0)
);
