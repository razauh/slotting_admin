create table if not exists public.funding_accounts (
    id uuid primary key default gen_random_uuid(),
    tenant_id text not null,
    type text not null check (type in ('BANK', 'RAAST', 'EASYPAISA', 'JAZZCASH')),
    account_title text not null,
    account_number text not null,
    instructions text null,
    visible boolean not null default true,
    sort_order integer not null default 0,
    created_utc timestamptz not null default now(),
    updated_utc timestamptz not null default now()
);

create index if not exists funding_accounts_tenant_idx
    on public.funding_accounts (tenant_id, visible, sort_order);

create table if not exists public.deposit_submissions (
    id uuid primary key default gen_random_uuid(),
    tenant_id text not null,
    player_id text not null,
    funding_account_id uuid not null references public.funding_accounts (id),
    amount_pkr numeric(14, 2) not null check (amount_pkr > 0),
    transfer_reference text not null,
    transferred_utc timestamptz not null,
    receipt_object text not null,
    status text not null default 'SUBMITTED' check (status in ('SUBMITTED', 'APPROVED', 'REJECTED')),
    reject_reason text null,
    rate_applied numeric(14, 4) null,
    amount_usd numeric(14, 2) null,
    approved_by text null,
    approved_utc timestamptz null,
    created_utc timestamptz not null default now()
);

create index if not exists deposit_submissions_player_idx
    on public.deposit_submissions (tenant_id, player_id, status);

create unique index if not exists deposit_submissions_single_approval_idx
    on public.deposit_submissions (id) where status = 'APPROVED';

create table if not exists public.manual_rails_settings (
    id integer primary key check (id = 1),
    deposit_rate_pkr_per_usd numeric(14, 4) not null,
    payout_rate_pkr_per_usd numeric(14, 4) not null,
    withdrawal_fee_percent numeric(5, 2) not null default 0 check (withdrawal_fee_percent between 0 and 100),
    payout_sla_working_days integer not null default 7,
    updated_by text null,
    updated_utc timestamptz not null default now()
);

insert into public.manual_rails_settings (id, deposit_rate_pkr_per_usd, payout_rate_pkr_per_usd, withdrawal_fee_percent, payout_sla_working_days)
values (1, 1.0000, 1.0000, 0.00, 7)
on conflict (id) do nothing;

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.funding_accounts from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.funding_accounts from authenticated'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.deposit_submissions from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.deposit_submissions from authenticated'; end if;
end $$;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then execute 'revoke all on public.manual_rails_settings from anon'; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then execute 'revoke all on public.manual_rails_settings from authenticated'; end if;
end $$;
