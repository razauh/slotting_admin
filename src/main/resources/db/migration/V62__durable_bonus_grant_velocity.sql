create table admin_bonus_grant_velocity (
    event_id uuid primary key default gen_random_uuid(),
    tenant_id text not null,
    player_id uuid not null,
    admin_id text not null,
    amount_minor_units bigint not null check (amount_minor_units > 0),
    created_at timestamptz not null
);

create index admin_bonus_grant_velocity_player_window_idx
    on admin_bonus_grant_velocity (tenant_id, player_id, created_at desc);

create index admin_bonus_grant_velocity_admin_window_idx
    on admin_bonus_grant_velocity (tenant_id, admin_id, created_at desc);
