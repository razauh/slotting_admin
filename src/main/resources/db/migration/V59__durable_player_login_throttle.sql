create table player_login_attempt (
    tenant_id varchar(128) not null,
    subject_key varchar(64) not null,
    attempt_count integer not null check (attempt_count > 0),
    expires_at timestamptz not null,
    primary key (tenant_id, subject_key)
);

create table player_login_lockout (
    tenant_id varchar(128) not null,
    account_key varchar(64) not null,
    locked_until timestamptz not null,
    primary key (tenant_id, account_key)
);
