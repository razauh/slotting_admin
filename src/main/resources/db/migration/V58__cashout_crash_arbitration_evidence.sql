alter table game_bet_settlement
    add column receive_time timestamptz;

alter table game_bet_settlement
    add column crash_time timestamptz;

update game_bet_settlement
set receive_time = settled_at
where receive_time is null;

alter table game_bet_settlement
    alter column receive_time set not null;
