insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
    ('player-documents', 'player-documents', false, 10485760, array['application/pdf', 'image/png', 'image/jpeg']),
    ('payment-proofs', 'payment-proofs', false, 10485760, array['application/pdf', 'image/png', 'image/jpeg'])
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists tc19_player_scope_select on storage.objects;
create policy tc19_player_scope_select on storage.objects
for select to authenticated
using (
    bucket_id in ('player-documents', 'payment-proofs')
    and (storage.foldername(name))[1] = (select auth.jwt() ->> 'tenant_id')
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'player_id')
);

drop policy if exists tc19_player_scope_insert on storage.objects;
create policy tc19_player_scope_insert on storage.objects
for insert to authenticated
with check (
    bucket_id in ('player-documents', 'payment-proofs')
    and (storage.foldername(name))[1] = (select auth.jwt() ->> 'tenant_id')
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'player_id')
);

drop policy if exists tc19_player_scope_update on storage.objects;
create policy tc19_player_scope_update on storage.objects
for update to authenticated
using (
    bucket_id in ('player-documents', 'payment-proofs')
    and (storage.foldername(name))[1] = (select auth.jwt() ->> 'tenant_id')
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'player_id')
)
with check (
    bucket_id in ('player-documents', 'payment-proofs')
    and (storage.foldername(name))[1] = (select auth.jwt() ->> 'tenant_id')
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'player_id')
);

drop policy if exists tc19_player_scope_delete on storage.objects;
create policy tc19_player_scope_delete on storage.objects
for delete to authenticated
using (
    bucket_id in ('player-documents', 'payment-proofs')
    and (storage.foldername(name))[1] = (select auth.jwt() ->> 'tenant_id')
    and (storage.foldername(name))[2] = (select auth.jwt() ->> 'player_id')
);
