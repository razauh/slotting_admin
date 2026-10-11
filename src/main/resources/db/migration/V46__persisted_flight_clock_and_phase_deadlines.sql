alter table game_authoritative_round
    add column if not exists flying_at timestamptz null,
    add column if not exists phase_started_at timestamptz null,
    add column if not exists phase_deadline_at timestamptz null;

do $$
declare
    conflict_count integer;
    conflict_diag text;
begin
    select count(*), string_agg(tenant_id || '/' || game_id || '/' || round_id || ' phase=' || phase ||
        ' flying_at=' || coalesce(flying_at::text, 'NULL') ||
        ' phase_started_at=' || coalesce(phase_started_at::text, 'NULL') ||
        ' phase_deadline_at=' || coalesce(phase_deadline_at::text, 'NULL'), '; ')
    into conflict_count, conflict_diag
    from game_authoritative_round
    where phase <> 'CLOSED'
      and (
        (phase = 'FLYING' and flying_at is null)
        or (phase <> 'CLOSED' and phase_started_at is null)
        or (phase = 'BET_COUNTDOWN' and phase_deadline_at is null)
        or (phase <> 'FLYING' and flying_at is not null)
        or (phase_deadline_at is not null and phase_started_at is not null and phase_deadline_at <= phase_started_at)
        or (flying_at is not null and phase_started_at is not null and flying_at < phase_started_at)
      );

    if conflict_count > 0 then
        raise exception 'V46 blocked: % non-CLOSED rounds have missing or contradictory phase timestamps. Conflicts: %', conflict_count, conflict_diag;
    end if;
end $$;

create index if not exists ix_game_round_flying_at
    on game_authoritative_round (tenant_id, game_id, flying_at)
    where flying_at is not null;

create index if not exists ix_game_round_phase_deadline
    on game_authoritative_round (tenant_id, game_id, phase_deadline_at)
    where phase_deadline_at is not null;
