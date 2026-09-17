create table admin_mfa_authentication (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    principal_id varchar(128) not null,
    session_id varchar(128) not null,
    state varchar(32) not null,
    server_version bigint not null,
    authenticated_at timestamptz not null,
    expires_at timestamptz not null,
    idempotency_key varchar(128) not null,
    request_fingerprint varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    check (state in ('AUTHENTICATED', 'DENIED', 'PENDING')),
    check (expires_at > authenticated_at)
);

create index admin_mfa_authentication_owner_idx
    on admin_mfa_authentication (tenant_id, principal_id, authenticated_at);

create table admin_audit_event (
    event_id uuid primary key,
    result_id uuid not null references admin_mfa_authentication(result_id),
    tenant_id varchar(128) not null,
    event_type varchar(64) not null,
    occurred_at timestamptz not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    redacted_details jsonb not null
);

create table admin_outbox_event (
    event_id uuid primary key,
    result_id uuid not null references admin_mfa_authentication(result_id),
    tenant_id varchar(128) not null,
    event_type varchar(64) not null,
    created_at timestamptz not null,
    published_at timestamptz null,
    payload jsonb not null
);
