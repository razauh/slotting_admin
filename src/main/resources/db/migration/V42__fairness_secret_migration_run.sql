create table if not exists fairness_secret_migration_run (
    run_id uuid primary key,
    tenant_id varchar(128) null,
    started_at timestamptz not null default now(),
    finished_at timestamptz null,
    status varchar(32) not null check (status in ('RUNNING', 'COMPLETED', 'FAILED')),
    processed_count integer not null default 0 check (processed_count >= 0),
    encrypted_count integer not null default 0 check (encrypted_count >= 0),
    skipped_count integer not null default 0 check (skipped_count >= 0),
    failure_count integer not null default 0 check (failure_count >= 0),
    remaining_count integer not null default 0 check (remaining_count >= 0),
    detail text null
);

create index if not exists ix_fairness_migration_run_tenant
    on fairness_secret_migration_run (tenant_id, started_at);
