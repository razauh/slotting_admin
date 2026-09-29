-- V28: Durable game wager reservation and once-only settlement authority (TC-021 / BE-004, BE-024)

create table if not exists game_authoritative_round (
    tenant_id varchar(128) not null,
    game_id varchar(64) not null,
    round_id varchar(128) not null,
    phase varchar(32) not null check (phase in ('SCHEDULED', 'BET_COUNTDOWN', 'FLYING', 'CRASHED', 'CLOSED')),
    round_version bigint not null default 1 check (round_version >= 1),
    current_multiplier numeric(12, 4) not null default 1.0000 check (current_multiplier >= 1.0000),
    crash_multiplier numeric(12, 4) null check (crash_multiplier is null or crash_multiplier >= 1.0000),
    started_at timestamptz not null default now(),
    crashed_at timestamptz null,
    closed_at timestamptz null,
    server_time timestamptz not null default now(),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, game_id, round_id)
);

create index if not exists ix_game_round_phase
    on game_authoritative_round (tenant_id, game_id, phase);

create table if not exists game_accepted_bet (
    bet_id uuid primary key,
    tenant_id varchar(128) not null,
    owner_id varchar(128) not null,
    game_id varchar(64) not null,
    round_id varchar(128) not null,
    hand_id varchar(64) not null,
    wager_minor_units bigint not null check (wager_minor_units > 0),
    currency_code varchar(3) not null,
    reservation_id uuid not null,
    ledger_reservation_ref varchar(128) not null,
    status varchar(32) not null check (status in ('ACCEPTED', 'CANCELLED', 'CASHED_OUT', 'LOST')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, game_id, round_id, owner_id, hand_id)
);

create index if not exists ix_game_bet_round
    on game_accepted_bet (tenant_id, game_id, round_id, status);

create table if not exists game_bet_settlement (
    settlement_id uuid primary key,
    tenant_id varchar(128) not null,
    bet_id uuid not null references game_accepted_bet(bet_id),
    owner_id varchar(128) not null,
    game_id varchar(64) not null,
    round_id varchar(128) not null,
    hand_id varchar(64) not null,
    outcome varchar(32) not null check (outcome in ('REFUND_CANCEL', 'PAYOUT_CASH_OUT', 'LOSS_CRASH')),
    multiplier numeric(12, 4) not null check (multiplier >= 0),
    payout_minor_units bigint not null check (payout_minor_units >= 0),
    ledger_settlement_ref varchar(128) null,
    settled_at timestamptz not null default now(),
    evidence_reference varchar(255) not null,
    unique (tenant_id, bet_id)
);

create index if not exists ix_game_settlement_round
    on game_bet_settlement (tenant_id, game_id, round_id);

create table if not exists game_command_receipt (
    receipt_id uuid primary key,
    tenant_id varchar(128) not null,
    owner_id varchar(128) not null,
    game_id varchar(64) not null,
    command_id varchar(128) not null,
    round_id varchar(128) not null,
    hand_id varchar(64) not null,
    action varchar(32) not null check (action in ('PLACE_BET', 'CANCEL_BET', 'CASH_OUT')),
    status varchar(32) not null check (status in ('ACCEPTED', 'REJECTED', 'DUPLICATE', 'ALREADY_PROCESSED')),
    fingerprint varchar(128) not null,
    response_json text not null,
    causation_id varchar(128) not null,
    correlation_id varchar(128) not null,
    server_sequence_id bigint not null,
    round_version bigint not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, command_id)
);

create index if not exists ix_game_command_round_cmd
    on game_command_receipt (tenant_id, round_id, command_id);

create table if not exists game_cumulative_player_limit (
    tenant_id varchar(128) not null,
    player_id varchar(128) not null,
    currency_code varchar(3) not null,
    daily_date varchar(10) not null,
    accumulated_wager_minor bigint not null default 0 check (accumulated_wager_minor >= 0),
    accumulated_loss_minor bigint not null default 0 check (accumulated_loss_minor >= 0),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, player_id, currency_code, daily_date)
);
