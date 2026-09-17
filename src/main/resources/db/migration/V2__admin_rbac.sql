create table admin_authorization_decision (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    resource_owner_id varchar(128) not null,
    permission varchar(64) not null,
    state varchar(16) not null,
    server_version bigint not null,
    decided_at timestamptz not null,
    expires_at timestamptz not null,
    break_glass boolean not null default false,
    idempotency_key varchar(128) not null,
    request_fingerprint varchar(512) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    check (state in ('ALLOWED', 'DENIED')),
    check (server_version >= 1),
    check (expires_at > decided_at)
);

create index admin_authorization_owner_idx
    on admin_authorization_decision (tenant_id, resource_owner_id, decided_at);
