create table admin_ledger_timeline_read (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    query_fingerprint varchar(512) not null,
    access_reason varchar(64) not null,
    state varchar(16) not null,
    ledger_version bigint not null,
    entry_count integer not null,
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    check (state in ('FOUND', 'EMPTY')),
    check (ledger_version >= 0),
    check (entry_count >= 0 and entry_count <= 100),
    check (server_version >= 1)
);

create index admin_ledger_timeline_scope_idx
    on admin_ledger_timeline_read (tenant_id, occurred_at);
