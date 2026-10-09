alter table if exists game_fairness_commitment
    add column if not exists secret_nonce text null;

alter table if exists game_fairness_commitment
    add column if not exists secret_key_id varchar(128) null;

alter table if exists game_fairness_commitment
    add column if not exists secret_key_version integer null;

alter table if exists game_fairness_commitment
    add column if not exists secret_format_version integer null;
