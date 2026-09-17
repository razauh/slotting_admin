create table admin_provider_circuit_breaker (
    tenant_id varchar(128) not null,
    provider_id varchar(128) not null,
    provider_type varchar(32) not null,
    state varchar(32) not null,
    failure_threshold int not null,
    cooldown_seconds bigint not null,
    incident_reference varchar(128),
    masked_secret varchar(32) not null,
    server_version bigint not null default 1,
    updated_at timestamptz not null,
    primary key (tenant_id, provider_id),
    check (provider_type in ('PAYMENT', 'GAME')),
    check (state in ('CLOSED', 'OPEN', 'HALF_OPEN')),
    check (failure_threshold > 0),
    check (cooldown_seconds >= 0),
    check (server_version >= 0)
);

create index ix_provider_circuit_breaker_state
    on admin_provider_circuit_breaker (tenant_id, state);

create table admin_provider_circuit_breaker_result (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    provider_id varchar(128) not null,
    provider_type varchar(32) not null,
    query_fingerprint varchar(512) not null,
    evidence_reference varchar(128) not null,
    state varchar(32) not null,
    failure_threshold int not null,
    cooldown_seconds bigint not null,
    incident_reference varchar(128),
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    foreign key (tenant_id, provider_id) references admin_provider_circuit_breaker(tenant_id, provider_id),
    check (provider_type in ('PAYMENT', 'GAME')),
    check (state in ('CLOSED', 'OPEN', 'HALF_OPEN')),
    check (failure_threshold > 0),
    check (cooldown_seconds >= 0),
    check (server_version >= 0)
);
