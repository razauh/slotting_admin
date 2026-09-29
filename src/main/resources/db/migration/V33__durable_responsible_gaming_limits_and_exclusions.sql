-- V33: Durable Responsible Gaming Limits, Usages, Exclusions, and Idempotency (TC-029 / AND-004, BE-002, BE-024)

create table if not exists rg_limit_configs (
    limit_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id varchar(128) not null,
    limit_type varchar(64) not null,
    period varchar(32) not null check (period in ('DAILY', 'WEEKLY', 'MONTHLY', 'PER_SESSION')),
    limit_value_minor bigint not null check (limit_value_minor > 0),
    pending_increase_value_minor bigint null,
    pending_increase_effective_at timestamptz null,
    timezone varchar(64) not null default 'UTC',
    product_scope varchar(64) not null default 'ALL_PRODUCTS',
    active boolean not null default true,
    version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, player_id, limit_type)
);

create index if not exists ix_rg_limit_configs_player
    on rg_limit_configs (tenant_id, player_id);

create table if not exists rg_limit_usages (
    usage_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id varchar(128) not null,
    limit_type varchar(64) not null,
    period varchar(32) not null check (period in ('DAILY', 'WEEKLY', 'MONTHLY', 'PER_SESSION')),
    period_start timestamptz not null,
    period_end timestamptz not null,
    timezone varchar(64) not null default 'UTC',
    consumed_minor bigint not null default 0 check (consumed_minor >= 0),
    version bigint not null default 1,
    updated_at timestamptz not null default now(),
    unique (tenant_id, player_id, limit_type, period_start)
);

create index if not exists ix_rg_limit_usages_player
    on rg_limit_usages (tenant_id, player_id, limit_type, period_start);

create table if not exists rg_exclusions (
    exclusion_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id varchar(128) not null,
    exclusion_type varchar(64) not null check (exclusion_type in ('COOL_OFF', 'SELF_EXCLUSION_DEFINITE', 'SELF_EXCLUSION_PERMANENT')),
    status varchar(32) not null check (status in ('ACTIVE', 'EXPIRED', 'REVOKED')),
    effective_from timestamptz not null,
    expires_at timestamptz null,
    reason varchar(512) not null,
    requested_by varchar(128) not null,
    evidence_reference varchar(256) not null,
    version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists ix_rg_exclusions_player
    on rg_exclusions (tenant_id, player_id, status, effective_from, expires_at);

create table if not exists rg_idempotency (
    tenant_id varchar(128) not null,
    idempotency_key varchar(128) not null,
    request_fingerprint varchar(128) not null,
    result_json text not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, idempotency_key)
);
