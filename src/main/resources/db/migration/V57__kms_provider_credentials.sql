create table admin_provider_credentials_kms (
    tenant_id varchar(128) not null,
    provider_id varchar(128) not null,
    secret_key_alias varchar(128) not null,
    key_version integer not null,
    ciphertext_base64 text not null,
    updated_at timestamptz not null,
    primary key (tenant_id, provider_id),
    check (key_version > 0)
);
