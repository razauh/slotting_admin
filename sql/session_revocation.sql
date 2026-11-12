create schema if not exists api;

create table if not exists public.bridge_session_revocations (
    session_id uuid primary key,
    tenant_id text not null,
    revoked_at timestamptz not null default now(),
    reason text not null
);

create index if not exists bridge_session_revocations_tenant_idx
    on public.bridge_session_revocations (tenant_id);

revoke all on table public.bridge_session_revocations from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.bridge_session_revocations from anon'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.bridge_session_revocations from authenticated'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'slotting_read') then execute 'revoke all on public.bridge_session_revocations from slotting_read'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'slotting_app') then execute 'grant select, insert, update, delete on public.bridge_session_revocations to slotting_app'; end if;
end $$;

create or replace function api.session_is_active()
returns boolean
language plpgsql
stable
security definer
set search_path = public, api, auth
as $$
declare
    claim_session_id text;
begin
    claim_session_id := nullif(auth.jwt() ->> 'session_id', '');
    if claim_session_id is null then
        return true;
    end if;
    begin
        return not exists (
            select 1
            from public.bridge_session_revocations r
            where r.session_id = claim_session_id::uuid
        );
    exception when others then
        return false;
    end;
end
$$;

revoke all on function api.session_is_active() from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'grant execute on function api.session_is_active() to authenticated'; end if;
  if exists (select 1 from pg_roles where rolname = 'slotting_app') then execute 'grant execute on function api.session_is_active() to slotting_app'; end if;
  if exists (select 1 from pg_roles where rolname = 'slotting_read') then execute 'grant execute on function api.session_is_active() to slotting_read'; end if;
end $$;

do $$ begin
  if to_regclass('public.rg_limit_configs') is not null then
    execute $v$
create or replace view api.player_rg_limits
with (security_invoker = false)
as
select
    limit_id,
    tenant_id,
    player_id,
    limit_type,
    period,
    limit_value_minor,
    pending_increase_value_minor,
    pending_increase_effective_at,
    timezone,
    product_scope,
    active,
    version,
    created_at,
    updated_at
from public.rg_limit_configs
where tenant_id::text = api.current_tenant_id()
  and player_id::text = api.current_player_id()
  and api.session_is_active()
$v$;
  else
    raise notice 'rg_limit_configs absent; skipping api.player_rg_limits view';
  end if;
end $$;

do $$ begin
  if to_regclass('api.player_rg_limits') is not null then execute 'revoke all on api.player_rg_limits from public'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on api.player_rg_limits from anon'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on api.player_rg_limits from authenticated'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'slotting_read') then execute 'grant select on api.player_rg_limits to slotting_read'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'grant select on api.player_rg_limits to authenticated'; end if;
end $$;

do $$
declare
    policy_record record;
    policy_qual text;
begin
    for policy_record in
        select schemaname, tablename, policyname, qual
        from pg_policies
        where schemaname = 'public'
          and policyname = 'tc6_player_scope_select'
        order by tablename
    loop
        policy_qual := policy_record.qual;
        if policy_qual is null then
            raise exception 'tc6_player_scope_select on %.% has no USING expression',
                policy_record.schemaname, policy_record.tablename;
        end if;
        if policy_qual like '%api.session_is_active()%' then
            continue;
        end if;
        execute format(
            'drop policy if exists %I on %I.%I',
            policy_record.policyname,
            policy_record.schemaname,
            policy_record.tablename
        );
        execute format(
            'create policy %I on %I.%I for select to authenticated using ((%s) and api.session_is_active())',
            policy_record.policyname,
            policy_record.schemaname,
            policy_record.tablename,
            policy_qual
        );
    end loop;

    if (select count(*) from pg_policies where schemaname = 'public' and policyname = 'tc6_backend_all') > 0 then
        if (select count(*) from pg_policies where schemaname = 'public' and policyname = 'tc6_backend_all') <> 147 then
            raise exception 'Expected 147 tc6_backend_all policies, found %',
                (select count(*) from pg_policies where schemaname = 'public' and policyname = 'tc6_backend_all');
        end if;

        if (select count(*) from pg_policies where schemaname = 'public' and policyname = 'tc6_player_scope_select') <> 144 then
            raise exception 'Expected 144 tc6_player_scope_select policies, found %',
                (select count(*) from pg_policies where schemaname = 'public' and policyname = 'tc6_player_scope_select');
        end if;
    else
        raise notice 'base policies absent; skipping session_revocation policy count assertions';
    end if;
end
$$;
