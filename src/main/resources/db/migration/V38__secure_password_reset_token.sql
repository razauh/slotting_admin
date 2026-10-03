create table password_reset_token (
    id uuid primary key,
    player_id uuid not null,
    tenant_id varchar(128) not null default 'default',
    token_digest varchar(128) not null unique,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    used_at timestamptz null,
    revoked_at timestamptz null,
    request_correlation_id varchar(128) not null,
    ip_address varchar(64) null,
    user_agent varchar(255) null
);

create index idx_pwd_reset_digest on password_reset_token(token_digest);
create index idx_pwd_reset_player on password_reset_token(tenant_id, player_id, expires_at);
create index idx_pwd_reset_active on password_reset_token(tenant_id, player_id);
