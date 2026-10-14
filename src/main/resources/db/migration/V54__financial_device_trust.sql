create table trusted_player_device (
    tenant_id varchar(128) not null,
    player_id uuid not null,
    device_hash char(64) not null,
    device_cluster_hash char(64) not null,
    trust_state varchar(16) not null,
    created_at timestamptz not null,
    verified_at timestamptz,
    last_seen_at timestamptz not null,
    revoked_at timestamptz,
    primary key (tenant_id, player_id, device_hash),
    check (trust_state in ('PENDING', 'PENDING_REVIEW', 'VERIFIED', 'DENIED', 'REVOKED')),
    check ((trust_state = 'VERIFIED' and verified_at is not null) or trust_state <> 'VERIFIED')
);

create index trusted_player_device_cap_idx on trusted_player_device(tenant_id, player_id, trust_state, verified_at);
create index trusted_player_device_cluster_idx on trusted_player_device(tenant_id, device_cluster_hash, trust_state);

create table player_device_travel_event (
    event_id bigserial primary key,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    device_hash char(64) not null,
    ip_hash char(64) not null,
    latitude double precision not null,
    longitude double precision not null,
    observed_at timestamptz not null,
    check (latitude between -90 and 90),
    check (longitude between -180 and 180)
);

create index player_device_travel_recent_idx on player_device_travel_event(tenant_id, player_id, observed_at desc);

create table trusted_player_device_audit (
    audit_id bigserial primary key,
    tenant_id varchar(128) not null,
    player_id uuid not null,
    device_hash char(64) not null,
    event_type varchar(40) not null,
    reason varchar(64) not null,
    occurred_at timestamptz not null
);

create index trusted_player_device_audit_owner_idx on trusted_player_device_audit(tenant_id, player_id, occurred_at desc);
