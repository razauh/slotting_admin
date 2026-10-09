alter table game_fairness_audit add column if not exists game_id varchar(64) null;
alter table game_fairness_audit add column if not exists commitment_id uuid null;
alter table game_fairness_audit add column if not exists event_key varchar(64) null;

do $$
declare
    dup_count integer;
    dup_diag text;
begin
    select count(*), string_agg(tenant_id || '/' || game_id || '/' || round_id || ' count=' || cnt, '; ')
    into dup_count, dup_diag
    from (
        select tenant_id, game_id, round_id, count(*) as cnt
        from game_fairness_reveal
        group by tenant_id, game_id, round_id
        having count(*) > 1
    ) d;

    if dup_count > 0 then
        raise exception 'Duplicate fairness reveal evidence detected for % (conflict groups: %); resolve before migration', dup_diag, dup_count;
    end if;
end $$;

create unique index if not exists ux_fairness_audit_event_key
    on game_fairness_audit (tenant_id, round_id, event_key)
    where event_key is not null;
