create table admin_player_profile_search (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    query_fingerprint varchar(512) not null,
    access_reason varchar(64) not null,
    state varchar(16) not null,
    result_count integer not null,
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    check (state in ('FOUND', 'EMPTY')),
    check (result_count >= 0 and result_count <= 20),
    check (server_version >= 1)
);

create index admin_player_profile_search_scope_idx
    on admin_player_profile_search (tenant_id, occurred_at);
