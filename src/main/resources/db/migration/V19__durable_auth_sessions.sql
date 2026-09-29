-- V19: Durable Authentication, Session, Refresh, and MFA Authority (TC-004)

create table player_credential (
    player_id uuid primary key,
    tenant_id varchar(128) not null,
    identifier varchar(255) not null,
    password_hash varchar(255) not null,
    password_algo varchar(32) not null, -- 'pbkdf2_sha256', 'sha256_legacy'
    password_salt varchar(128) not null,
    iterations int not null,
    status varchar(32) not null default 'ACTIVE',
    version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, identifier)
);

create table auth_challenge (
    challenge_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    purpose varchar(64) not null, -- 'REGISTRATION_VERIFY', 'LOGIN_MFA', 'PASSWORD_RESET', 'WITHDRAWAL_STEP_UP'
    code_hash varchar(128) not null,
    salt varchar(128) not null,
    attempts_remaining int not null default 3,
    max_attempts int not null default 3,
    expires_at timestamptz not null,
    consumed_at timestamptz null,
    created_at timestamptz not null default now()
);

create index auth_challenge_lookup_idx on auth_challenge(tenant_id, player_id, purpose, expires_at);

create table player_session (
    session_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    state varchar(32) not null default 'ACTIVE', -- 'ACTIVE', 'TERMINATED', 'EXPIRED'
    device_fingerprint varchar(255) null,
    ip_address varchar(64) not null default '127.0.0.1',
    user_agent varchar(255) not null default 'Unknown',
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    terminated_at timestamptz null,
    version bigint not null default 1
);

create index player_session_owner_idx on player_session(tenant_id, player_id, state);

create table token_family (
    family_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    session_id uuid not null references player_session(session_id),
    is_revoked boolean not null default false,
    revocation_reason varchar(64) null, -- 'LOGOUT', 'ROTATED_REUSE_DETECTED', 'SECURITY_POLICY'
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    version bigint not null default 1
);

create index token_family_owner_idx on token_family(tenant_id, player_id);

create table refresh_token_record (
    token_id uuid primary key,
    family_id uuid not null references token_family(family_id),
    token_hash varchar(128) not null unique,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    parent_token_hash varchar(128) null,
    status varchar(32) not null default 'ACTIVE', -- 'ACTIVE', 'ROTATED', 'REVOKED', 'EXPIRED'
    issued_at timestamptz not null default now(),
    expires_at timestamptz not null,
    rotated_at timestamptz null,
    revoked_at timestamptz null
);

create index refresh_token_hash_idx on refresh_token_record(tenant_id, token_hash);

create table authorization_code_session (
    code varchar(128) primary key,
    code_challenge varchar(128) not null,
    code_challenge_method varchar(32) not null default 'S256',
    state varchar(128) not null,
    nonce varchar(128) null,
    redirect_uri varchar(255) not null,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    expires_at timestamptz not null,
    consumed boolean not null default false,
    consumed_at timestamptz null,
    created_at timestamptz not null default now()
);
