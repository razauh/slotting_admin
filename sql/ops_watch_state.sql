create table if not exists public.ops_watch_state (
    id integer primary key check (id = 1),
    last_daily_run_utc timestamptz null,
    last_weekly_run_utc timestamptz null,
    updated_utc timestamptz not null default now()
);

insert into public.ops_watch_state (id) values (1) on conflict (id) do nothing;

revoke all on public.ops_watch_state from anon, authenticated;
