create table registration_risk_signal (
    tenant_id varchar(128) not null,
    player_id uuid not null references player_credential(player_id),
    device_hash char(64),
    ip_hash char(64),
    created_at timestamptz not null,
    primary key (tenant_id, player_id)
);

create index registration_risk_device_window_idx on registration_risk_signal(tenant_id, device_hash, created_at desc) where device_hash is not null;
create index registration_risk_ip_window_idx on registration_risk_signal(tenant_id, ip_hash, created_at desc) where ip_hash is not null;

create table registration_risk_review (
    tenant_id varchar(128) not null,
    player_id uuid not null references player_credential(player_id),
    identifier varchar(255) not null,
    reason varchar(64) not null,
    state varchar(16) not null,
    created_at timestamptz not null,
    cleared_at timestamptz,
    reviewer_id varchar(128),
    reviewer_reason varchar(500),
    primary key (tenant_id, player_id),
    check (state in ('OPEN', 'CLEARED')),
    check ((state = 'OPEN' and cleared_at is null and reviewer_id is null) or (state = 'CLEARED' and cleared_at is not null and reviewer_id is not null))
);

create index registration_risk_review_queue_idx on registration_risk_review(tenant_id, created_at) where state = 'OPEN';

create table registration_risk_review_audit (
    audit_id bigserial primary key,
    tenant_id varchar(128) not null,
    player_id uuid not null references player_credential(player_id),
    event_type varchar(16) not null,
    reviewer_id varchar(128),
    reason varchar(500) not null,
    occurred_at timestamptz not null,
    check (event_type in ('HELD', 'CLEARED'))
);

create index registration_risk_audit_player_idx on registration_risk_review_audit(tenant_id, player_id, occurred_at);
