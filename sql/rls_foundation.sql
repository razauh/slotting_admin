create schema if not exists api;

create or replace function api.current_tenant_id()
returns text
language sql
stable
as $$
    select coalesce(
        nullif(auth.jwt() ->> 'tenant_id', ''),
        nullif(auth.jwt() -> 'app_metadata' ->> 'tenant_id', '')
    )
$$;

create or replace function api.current_player_id()
returns text
language sql
stable
as $$
    select nullif(auth.uid()::text, '')
$$;

revoke all on function api.current_tenant_id() from public;
revoke all on function api.current_player_id() from public;
grant execute on function api.current_tenant_id() to authenticated, slotting_app, slotting_read;
grant execute on function api.current_player_id() to authenticated, slotting_app, slotting_read;
grant usage on schema api to authenticated, slotting_app, slotting_read;

do $$
declare
    table_record record;
    has_tenant boolean;
    has_player boolean;
    expression text;
begin
    for table_record in
        select c.oid, n.nspname, c.relname
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind = 'r'
        order by c.relname
    loop
        select exists (
            select 1 from pg_attribute a
            where a.attrelid = table_record.oid
              and a.attname = 'tenant_id'
              and a.attnum > 0
              and not a.attisdropped
        ) into has_tenant;

        select exists (
            select 1 from pg_attribute a
            where a.attrelid = table_record.oid
              and a.attname = 'player_id'
              and a.attnum > 0
              and not a.attisdropped
        ) into has_player;

        execute format(
            'alter table %I.%I enable row level security',
            table_record.nspname,
            table_record.relname
        );

        if not exists (
            select 1 from pg_policies
            where schemaname = 'public'
              and tablename = table_record.relname
              and policyname = 'tc6_backend_all'
        ) then
            execute format(
                'create policy tc6_backend_all on %I.%I for all to slotting_app using (true) with check (true)',
                table_record.nspname,
                table_record.relname
            );
        end if;

        if has_tenant and has_player then
            expression := 'tenant_id::text = api.current_tenant_id() and player_id::text = api.current_player_id()';
        elsif has_tenant then
            expression := 'tenant_id::text = api.current_tenant_id()';
        elsif has_player then
            expression := 'player_id::text = api.current_player_id()';
        else
            expression := null;
        end if;

        if expression is not null and not exists (
            select 1 from pg_policies
            where schemaname = 'public'
              and tablename = table_record.relname
              and policyname = 'tc6_player_scope_select'
        ) then
            execute format(
                'create policy tc6_player_scope_select on %I.%I for select to authenticated using (%s)',
                table_record.nspname,
                table_record.relname,
                expression
            );
        end if;
    end loop;
end
$$;
