do $$
declare
    constraint_name text;
begin
    for constraint_name in
        select conname
        from pg_constraint
        where conrelid = 'game_command_receipt'::regclass
          and contype = 'c'
          and pg_get_constraintdef(oid) ilike '%status%'
    loop
        execute format('alter table game_command_receipt drop constraint %I', constraint_name);
    end loop;

    if not exists (
        select 1 from pg_constraint
        where conrelid = 'game_command_receipt'::regclass
          and conname = 'game_command_receipt_status_check'
    ) then
        alter table game_command_receipt
            add constraint game_command_receipt_status_check
            check (status in ('PENDING', 'ACCEPTED', 'REJECTED', 'DUPLICATE', 'ALREADY_PROCESSED'));
    end if;
end $$;

alter table game_command_receipt alter column response_json drop not null;
alter table game_command_receipt alter column server_sequence_id drop not null;

create or replace function assert_no_pending_game_command_receipt()
returns trigger
language plpgsql
as $$
begin
    if exists (select 1 from game_command_receipt where status = 'PENDING') then
        raise exception 'Uncompleted pending command receipt cannot commit: tenant=% command=%',
            new.tenant_id, new.command_id;
    end if;
    return new;
end $$;

drop trigger if exists trg_game_command_receipt_no_pending on game_command_receipt;

create constraint trigger trg_game_command_receipt_no_pending
    after insert or update on game_command_receipt
    deferrable initially deferred
    for each row
    execute function assert_no_pending_game_command_receipt();
