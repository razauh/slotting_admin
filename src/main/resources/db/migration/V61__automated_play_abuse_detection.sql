create table play_cashout_detection_event (
    event_id uuid primary key,
    tenant_id varchar(128) not null,
    player_id varchar(128) not null,
    game_id varchar(128) not null,
    round_id varchar(128) not null,
    hand_id varchar(128) not null,
    occurred_at timestamptz not null
);

create index play_cashout_detection_player_time_idx
    on play_cashout_detection_event (tenant_id, player_id, occurred_at desc);

create index play_cashout_detection_round_time_idx
    on play_cashout_detection_event (tenant_id, game_id, round_id, occurred_at desc);

create table player_account_link (
    tenant_id varchar(128) not null,
    player_id varchar(128) not null,
    linked_player_id varchar(128) not null,
    created_at timestamptz not null,
    primary key (tenant_id, player_id, linked_player_id),
    check (player_id <> linked_player_id)
);

create table play_abuse_alert (
    tenant_id varchar(128) not null,
    case_reference varchar(256) not null,
    player_id varchar(128) not null,
    rule_code varchar(64) not null,
    linked_player_references text not null,
    window_start timestamptz not null,
    created_at timestamptz not null,
    session_flagged boolean not null,
    primary key (tenant_id, case_reference)
);
