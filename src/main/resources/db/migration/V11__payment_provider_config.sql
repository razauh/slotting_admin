create table admin_payment_provider_config (
    tenant_id varchar(128) not null,
    provider_id varchar(128) not null,
    display_name varchar(128) not null,
    status varchar(32) not null,
    endpoint_url varchar(512) not null,
    secret_hash varchar(64) not null,
    masked_secret varchar(32) not null,
    incident_reference varchar(128),
    server_version bigint not null default 1,
    updated_at timestamptz not null,
    primary key (tenant_id, provider_id),
    check (status in ('ENABLED', 'DISABLED', 'SUSPENDED')),
    check (server_version >= 0)
);

create index ix_payment_provider_config_status
    on admin_payment_provider_config (tenant_id, status);

create table admin_payment_provider_config_result (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    provider_id varchar(128) not null,
    query_fingerprint varchar(512) not null,
    evidence_reference varchar(128) not null,
    display_name varchar(128) not null,
    status varchar(32) not null,
    endpoint_url varchar(512) not null,
    masked_secret varchar(32) not null,
    incident_reference varchar(128),
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    foreign key (tenant_id, provider_id) references admin_payment_provider_config(tenant_id, provider_id),
    check (status in ('ENABLED', 'DISABLED', 'SUSPENDED')),
    check (server_version >= 0)
);
