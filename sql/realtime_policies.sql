drop policy if exists tc22_player_channel_read on realtime.messages;
create policy tc22_player_channel_read on realtime.messages
for select to authenticated
using (
    realtime.topic() = 'tenant:' || (select auth.jwt() ->> 'tenant_id') || ':player:' || (select auth.jwt() ->> 'player_id')
);

drop policy if exists tc22_player_channel_write on realtime.messages;
create policy tc22_player_channel_write on realtime.messages
for insert to authenticated
with check (
    realtime.topic() = 'tenant:' || (select auth.jwt() ->> 'tenant_id') || ':player:' || (select auth.jwt() ->> 'player_id')
);
