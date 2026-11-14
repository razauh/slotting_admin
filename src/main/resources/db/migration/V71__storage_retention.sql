create table if not exists public.storage_retention (
    retention_id uuid primary key default gen_random_uuid(),
    bucket_id text not null,
    object_path text not null,
    tenant_id text not null,
    player_id text not null,
    checksum_sha256 text not null,
    created_at timestamptz not null default now(),
    retention_expires_at timestamptz not null,
    legal_hold boolean not null default false,
    constraint storage_retention_object_key unique (bucket_id, object_path)
);

create index if not exists ix_storage_retention_expiry
    on public.storage_retention (retention_expires_at)
    where legal_hold = false;

grant select, insert, update, delete on public.storage_retention to slotting_app;
