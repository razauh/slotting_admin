do $$
declare
    dup_count integer;
    dup_diag text;
    ambiguous_count integer;
    ambiguous_diag text;
begin
    select count(*), string_agg(tenant_id || '/' || round_id, '; ')
    into ambiguous_count, ambiguous_diag
    from (
        select a.tenant_id, a.round_id
        from game_fairness_audit a
        where a.action = 'ROUND_OUTCOME_REVEALED_AND_VERIFIED'
          and a.commitment_id is null
        group by a.tenant_id, a.round_id
        having (
            select count(*)
            from game_fairness_commitment c
            where c.tenant_id = a.tenant_id and c.round_id = a.round_id
        ) <> 1
    ) x;

    if ambiguous_count > 0 then
        raise exception 'Ambiguous legacy fairness audit mapping for % tenant/round identities: %; resolve before migration', ambiguous_count, ambiguous_diag;
    end if;

    select count(*), string_agg(commitment_id::text || ' count=' || cnt, '; ')
    into dup_count, dup_diag
    from (
        select c.commitment_id, count(*) as cnt
        from game_fairness_audit a
        join game_fairness_commitment c
          on c.tenant_id = a.tenant_id and c.round_id = a.round_id
        where a.action = 'ROUND_OUTCOME_REVEALED_AND_VERIFIED'
          and a.commitment_id is null
        group by c.commitment_id
        having count(*) > 1
    ) d;

    if dup_count > 0 then
        raise exception 'Duplicate legacy fairness reveal audits detected for % (groups: %); resolve before migration', dup_count, dup_diag;
    end if;

    select count(*), string_agg(commitment_id::text || '/' || event_key || ' count=' || cnt, '; ')
    into dup_count, dup_diag
    from (
        select commitment_id, event_key, count(*) as cnt
        from game_fairness_audit
        where commitment_id is not null and event_key is not null
        group by commitment_id, event_key
        having count(*) > 1
    ) d;

    if dup_count > 0 then
        raise exception 'Duplicate canonical fairness audit identities detected for % (groups: %); resolve before migration', dup_count, dup_diag;
    end if;
end $$;

drop index if exists ux_fairness_audit_event_key;

create unique index if not exists ux_fairness_audit_commitment_event
    on game_fairness_audit (tenant_id, commitment_id, event_key)
    where event_key is not null and commitment_id is not null;
