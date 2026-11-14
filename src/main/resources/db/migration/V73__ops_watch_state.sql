create table if not exists public.ops_watch_state (
    id integer primary key check (id = 1),
    last_daily_run_utc timestamptz null,
    last_weekly_run_utc timestamptz null,
    updated_utc timestamptz not null default now()
);

insert into public.ops_watch_state (id) values (1) on conflict (id) do nothing;

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.ops_watch_state from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.ops_watch_state from authenticated'; end if;
end $$;
