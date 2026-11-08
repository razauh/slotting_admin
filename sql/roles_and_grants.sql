do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'slotting_app') then
        create role slotting_app login nosuperuser nobypassrls nocreatedb nocreaterole;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'slotting_read') then
        create role slotting_read login nosuperuser nobypassrls nocreatedb nocreaterole;
    end if;
    if exists (select 1 from pg_roles where rolname = 'slotting_app' and (rolsuper or rolbypassrls or rolcreatedb or rolcreaterole)) then
        raise exception 'slotting_app has elevated attributes';
    end if;
    if exists (select 1 from pg_roles where rolname = 'slotting_read' and (rolsuper or rolbypassrls or rolcreatedb or rolcreaterole)) then
        raise exception 'slotting_read has elevated attributes';
    end if;
end
$$;

grant slotting_app to postgres;
grant slotting_read to postgres;

revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
revoke all on all functions in schema public from anon, authenticated;

alter default privileges for role postgres in schema public revoke all on tables from anon, authenticated;
alter default privileges for role postgres in schema public revoke all on sequences from anon, authenticated;
alter default privileges for role postgres in schema public revoke all on functions from anon, authenticated;

grant usage on schema public to slotting_app;
grant select, insert, update, delete on all tables in schema public to slotting_app;
grant usage, select, update on all sequences in schema public to slotting_app;
grant execute on all functions in schema public to slotting_app;

alter default privileges for role postgres in schema public grant select, insert, update, delete on tables to slotting_app;
alter default privileges for role postgres in schema public grant usage, select, update on sequences to slotting_app;
alter default privileges for role postgres in schema public grant execute on functions to slotting_app;
