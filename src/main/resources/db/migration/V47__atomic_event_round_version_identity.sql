alter table game_event_journal add column if not exists round_version bigint;

do $$
declare
    missing_ids text;
    duplicate_ids text;
begin
    select string_agg(event_id::text, ',' order by event_id)
    into missing_ids
    from game_event_journal
    where payload_json::jsonb ->> 'roundVersion' is null
       or (payload_json::jsonb ->> 'roundVersion') !~ '^[1-9][0-9]*$';

    if missing_ids is not null then
        raise exception 'V47 event identity pre-check failed: missing or invalid roundVersion event_ids=%', missing_ids;
    end if;

    update game_event_journal
       set round_version = (payload_json::jsonb ->> 'roundVersion')::bigint
     where round_version is null;

    select string_agg(event_id::text, ',' order by event_id)
    into duplicate_ids
    from (
        select min(event_id) as event_id
        from game_event_journal
        group by tenant_id, game_id, round_id, round_version, event_name
        having count(*) > 1
    ) duplicates;

    if duplicate_ids is not null then
        raise exception 'V47 event identity pre-check failed: duplicate event_ids=%', duplicate_ids;
    end if;
end $$;

alter table game_event_journal alter column round_version set not null;
alter table game_event_journal add constraint ck_game_event_journal_round_version_positive check (round_version >= 1);
create unique index ux_game_event_journal_round_identity
    on game_event_journal (tenant_id, game_id, round_id, round_version, event_name);
