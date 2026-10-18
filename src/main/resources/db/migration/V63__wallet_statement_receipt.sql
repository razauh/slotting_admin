create table if not exists wallet_statement_receipt (
    tenant_id varchar(128) not null,
    idempotency_key varchar(256) not null,
    fingerprint varchar(256) not null,
    page_json text not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, idempotency_key)
);
