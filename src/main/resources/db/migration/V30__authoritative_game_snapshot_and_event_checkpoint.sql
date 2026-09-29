-- V30: Authoritative game snapshot sequence checkpoint and event journal (TC-023 / BE-005, XREP-001, XREP-003)

create table if not exists game_socket_sequence_checkpoint (
    tenant_id varchar(128) not null,
    game_id varchar(64) not null,
    last_sequence_id bigint not null default 0 check (last_sequence_id >= 0),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, game_id)
);

create table if not exists game_event_journal (
    event_id uuid primary key,
    tenant_id varchar(128) not null,
    game_id varchar(64) not null,
    round_id varchar(128) not null,
    sequence_id bigint not null check (sequence_id >= 1),
    event_name varchar(64) not null,
    payload_json text not null,
    target_scope varchar(32) not null check (target_scope in ('BROADCAST', 'ROOM_TENANT', 'ROOM_PLAYER')),
    target_owner_id varchar(128) null,
    timestamp_millis bigint not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, game_id, sequence_id)
);

create index if not exists ix_game_event_journal_lookup
    on game_event_journal (tenant_id, game_id, target_scope, target_owner_id, sequence_id);
