-- V29: Outcome-bound fairness evidence and independent verification authority (TC-022 / BE-006)

create table if not exists game_fairness_commitment (
    commitment_id uuid primary key,
    tenant_id varchar(128) not null,
    game_id varchar(64) not null,
    round_id varchar(128) not null,
    authority_type varchar(32) not null check (authority_type in ('INTERNAL_HMAC_SHA256', 'EXTERNAL_CERTIFIED_PROVIDER')),
    algorithm_version varchar(32) not null default '1.0.0',
    rules_version varchar(32) not null default '1.0.0',
    commitment_hash varchar(128) not null check (length(commitment_hash) = 64),
    public_salt varchar(128) not null,
    encrypted_secret_seed text not null,
    committed_at timestamptz not null default now(),
    first_bet_accepted_at timestamptz null,
    status varchar(32) not null check (status in ('COMMITTED', 'BETTING_ACTIVE', 'LOCKED', 'REVEALED', 'INVALIDATED')),
    server_version bigint not null default 1 check (server_version >= 1),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, game_id, round_id),
    foreign key (tenant_id, game_id, round_id) references game_authoritative_round(tenant_id, game_id, round_id)
);

create index if not exists ix_fairness_commitment_status
    on game_fairness_commitment (tenant_id, game_id, status);

create table if not exists game_fairness_reveal (
    reveal_id uuid primary key,
    commitment_id uuid not null references game_fairness_commitment(commitment_id),
    tenant_id varchar(128) not null,
    game_id varchar(64) not null,
    round_id varchar(128) not null,
    revealed_secret_seed varchar(128) not null check (length(revealed_secret_seed) = 64),
    derived_multiplier numeric(12, 4) not null check (derived_multiplier >= 1.0000),
    revealed_at timestamptz not null default now(),
    verification_status varchar(32) not null check (verification_status in ('VERIFIED', 'FAILED', 'TAMPERED', 'PENDING_AUDIT')),
    verification_error text null,
    evidence_reference varchar(255) not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, commitment_id),
    unique (tenant_id, game_id, round_id)
);

create index if not exists ix_fairness_reveal_round
    on game_fairness_reveal (tenant_id, game_id, round_id, verification_status);

create table if not exists game_fairness_audit (
    audit_id uuid primary key,
    tenant_id varchar(128) not null,
    round_id varchar(128) not null,
    action varchar(64) not null,
    actor varchar(128) not null,
    detail text not null,
    occurred_at timestamptz not null default now()
);

create index if not exists ix_fairness_audit_round
    on game_fairness_audit (tenant_id, round_id, occurred_at);
