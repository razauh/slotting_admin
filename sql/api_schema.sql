create schema if not exists api;

create or replace view api.player_rg_limits
with (security_invoker = false)
as
select
    limit_id,
    tenant_id,
    player_id,
    limit_type,
    period,
    limit_value_minor,
    pending_increase_value_minor,
    pending_increase_effective_at,
    timezone,
    product_scope,
    active,
    version,
    created_at,
    updated_at
from public.rg_limit_configs
where tenant_id::text = api.current_tenant_id()
  and player_id::text = api.current_player_id();

revoke all on api.player_rg_limits from public;
revoke all on api.player_rg_limits from anon;
revoke all on api.player_rg_limits from authenticated;
grant usage on schema api to slotting_read;
grant select on api.player_rg_limits to slotting_read, authenticated;
