create table if not exists lifecycle_attempt_journal (
    attempt_id uuid primary key,
    tenant_id text not null,
    game_id text not null,
    round_id text null,
    attempt_number bigint not null,
    stage text not null,
    owner_id text null,
    lease_epoch bigint null,
    status text not null,
    error_type text null,
    error_message text null,
    started_at timestamptz not null,
    finished_at timestamptz null,
    event_sequence bigint null,
    settlement_reference text null,
    created_at timestamptz not null default now(),
    constraint ck_lifecycle_attempt_status check (status in ('STARTED', 'COMPLETED', 'FAILED')),
    constraint ux_lifecycle_attempt_identity unique (tenant_id, game_id, round_id, attempt_number)
);

create index if not exists ix_lifecycle_attempt_lookup on lifecycle_attempt_journal (tenant_id, game_id, round_id, attempt_number desc);
