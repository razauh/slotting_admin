create table if not exists public.ops_notices (
    id uuid primary key default gen_random_uuid(),
    cause text not null unique,
    class_tag text not null,
    severity text not null check (severity in ('CRITICAL', 'WARNING', 'INFO')),
    notice_text text not null,
    created_utc timestamptz not null default now(),
    acknowledged_utc timestamptz null,
    acknowledged_by text null
);

create index if not exists ops_notices_severity_created_idx
    on public.ops_notices (severity, created_utc desc);

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.ops_notices from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.ops_notices from authenticated'; end if;
end $$;

create table if not exists public.ops_decisions (
    item_name text primary key,
    owner text null,
    status text not null default 'UNSCHEDULED' check (status in ('UNSCHEDULED', 'SCHEDULED', 'OVERDUE')),
    due_date date null,
    reopen_trigger text not null,
    updated_utc timestamptz not null default now()
);

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.ops_decisions from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.ops_decisions from authenticated'; end if;
end $$;

insert into public.ops_decisions (item_name, owner, status, due_date, reopen_trigger) values
    ('JWT_KEYS_TIMELINE', null, 'UNSCHEDULED', null, 'platform JWT secret rotation announced or edge rejection observed'),
    ('REALTIME_PAYLOAD_SCOPE', null, 'UNSCHEDULED', null, 'payload policy review requested before enabling hints'),
    ('KILLSWITCH_RUNTIME_TOGGLE', null, 'UNSCHEDULED', null, 'runtime admin toggle required for incident response'),
    ('TC16_EXPOSURE_FINAL', null, 'UNSCHEDULED', null, 'exposure surface changes or dashboard drift detected'),
    ('TC38_PLATFORM_FLIP', null, 'UNSCHEDULED', null, 'real production cutover environment exists')
on conflict (item_name) do nothing;
