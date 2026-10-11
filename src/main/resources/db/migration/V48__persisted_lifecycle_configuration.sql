alter table game_authoritative_round
    add column if not exists config_fingerprint text null,
    add column if not exists scheduled_millis bigint null,
    add column if not exists betting_millis bigint null,
    add column if not exists closed_millis bigint null,
    add column if not exists tick_millis bigint null,
    add column if not exists multiplier_step numeric(20,8) null,
    add column if not exists rules_version text null,
    add column if not exists algorithm_version text null,
    add column if not exists public_salt text null;

do $$
declare
    conflict_count integer;
    conflict_diag text;
begin
    select count(*), string_agg(tenant_id || '/' || game_id || '/' || round_id || ' phase=' || phase, '; ')
    into conflict_count, conflict_diag
    from game_authoritative_round
    where phase <> 'CLOSED'
      and (
        config_fingerprint is null
        or scheduled_millis is null
        or betting_millis is null
        or closed_millis is null
        or tick_millis is null
        or multiplier_step is null
        or rules_version is null
        or algorithm_version is null
        or public_salt is null
      );

    if conflict_count > 0 then
        raise exception 'V48 blocked: % in-flight rounds lack lifecycle configuration identities. Conflicts: %', conflict_count, conflict_diag;
    end if;
end $$;

create index if not exists ix_game_round_config_fingerprint
    on game_authoritative_round (tenant_id, game_id, config_fingerprint)
    where config_fingerprint is not null;
