create table if not exists public.payout_requests (
    id uuid primary key default gen_random_uuid(),
    tenant_id text not null,
    player_id text not null,
    amount_usd numeric(14, 2) not null check (amount_usd > 0),
    fee_usd numeric(14, 2) not null,
    net_usd numeric(14, 2) not null,
    payout_rate_pkr_per_usd numeric(14, 4) not null,
    payout_pkr numeric(14, 2) not null,
    dest_type text not null check (dest_type in ('BANK', 'RAAST', 'EASYPAISA', 'JAZZCASH')),
    dest_account_title text not null,
    dest_account_number text not null,
    status text not null default 'PENDING' check (status in ('PENDING', 'APPROVED_FUNDS_LOCKED', 'PAID', 'REJECTED')),
    reject_reason text null,
    receipt_object text null,
    requested_utc timestamptz not null default now(),
    locked_utc timestamptz null,
    paid_utc timestamptz null,
    rejected_utc timestamptz null,
    locked_by text null,
    paid_by text null,
    created_utc timestamptz not null default now()
);

create index if not exists payout_requests_player_status_idx
    on public.payout_requests (tenant_id, player_id, status);

create unique index if not exists payout_requests_single_paid_idx
    on public.payout_requests (id) where status = 'PAID';

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.payout_requests from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.payout_requests from authenticated'; end if;
end $$;
