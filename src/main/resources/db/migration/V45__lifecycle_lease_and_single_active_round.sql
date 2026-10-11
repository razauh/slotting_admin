do $$
declare
    dup_count integer;
    dup_diag text;
begin
    select count(*), string_agg(tenant_id || '/' || game_id || ' count=' || cnt || ' rounds=[' || round_ids || ']', '; ')
    into dup_count, dup_diag
    from (
        select tenant_id, game_id, count(*) as cnt, string_agg(round_id, ', ' order by round_id) as round_ids
        from game_authoritative_round
        where phase <> 'CLOSED'
        group by tenant_id, game_id
        having count(*) > 1
    ) d;

    if dup_count > 0 then
        raise exception 'Duplicate active rounds detected: % (total conflict groups: %)', dup_diag, dup_count;
    end if;
end $$;

create table if not exists game_lifecycle_lease (
    tenant_id varchar(128) not null,
    game_id varchar(64) not null,
    owner_id varchar(128) not null,
    epoch bigint not null default 1 check (epoch >= 1),
    lease_expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, game_id)
);

create index if not exists ix_game_lifecycle_lease_expiry
    on game_lifecycle_lease (tenant_id, game_id, lease_expires_at);

create unique index if not exists ux_game_authoritative_round_active
    on game_authoritative_round (tenant_id, game_id)
    where phase <> 'CLOSED';
