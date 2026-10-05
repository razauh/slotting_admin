do $$
declare
    dup_count integer;
    dup_diag text;
begin
    select count(*), string_agg(tenant_id || '/' || server_sequence_id || ' count=' || cnt, '; ')
    into dup_count, dup_diag
    from (
        select tenant_id, server_sequence_id, count(*) as cnt
        from game_command_receipt
        group by tenant_id, server_sequence_id
        having count(*) > 1
    ) d;

    if dup_count > 0 then
        raise exception 'Duplicate command sequence detected: % (total conflict groups: %)', dup_diag, dup_count;
    end if;
end $$;

create table if not exists game_command_sequence (
    tenant_id varchar(128) primary key,
    last_sequence_id bigint not null default 0 check (last_sequence_id >= 0),
    updated_at timestamptz not null default now()
);

insert into game_command_sequence (tenant_id, last_sequence_id, updated_at)
select tenant_id, coalesce(max(server_sequence_id), 0), now()
from game_command_receipt
group by tenant_id
on conflict (tenant_id) do update
set last_sequence_id = excluded.last_sequence_id, updated_at = now();

create unique index if not exists ix_game_command_receipt_tenant_seq
    on game_command_receipt (tenant_id, server_sequence_id);
