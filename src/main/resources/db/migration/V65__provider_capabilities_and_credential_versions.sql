alter table admin_payment_provider_config add column if not exists environment varchar(32) not null default 'SANDBOX';
alter table admin_payment_provider_config add column if not exists wallet_currencies varchar(128) not null default 'PKR';
alter table admin_payment_provider_config add column if not exists settlement_currencies varchar(128) not null default 'PKR';
alter table admin_payment_provider_config add column if not exists supported_operations varchar(512) not null default 'DEPOSIT';
alter table admin_payment_provider_config add column if not exists capability_version bigint not null default 1;
alter table admin_payment_provider_config add column if not exists setup_status varchar(32) not null default 'DISABLED';
alter table admin_payment_provider_config add column if not exists permitted_use_approved boolean not null default false;
alter table admin_payment_provider_config add column if not exists technical_verification_approved boolean not null default false;
alter table admin_payment_provider_config add column if not exists external_evidence_reference varchar(256);
alter table admin_payment_provider_config add column if not exists reviewer varchar(128);
alter table admin_payment_provider_config add column if not exists credential_version bigint not null default 0;
alter table admin_payment_provider_config add column if not exists last_probe_status varchar(32);
alter table admin_payment_provider_config add column if not exists last_probe_at timestamptz;

create table if not exists admin_provider_credentials_kms_versions (
    tenant_id varchar(128) not null,
    provider_id varchar(128) not null,
    credential_version bigint not null,
    secret_key_alias varchar(128) not null,
    key_version integer not null,
    ciphertext_base64 text not null,
    status varchar(32) not null,
    created_at timestamptz not null,
    activated_at timestamptz,
    retired_at timestamptz,
    primary key (tenant_id, provider_id, credential_version),
    check (credential_version > 0),
    check (key_version > 0),
    check (status in ('ACTIVE', 'RETIRED', 'REVOKED'))
);
