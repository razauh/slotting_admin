-- V31: Distinct server restriction sources, scopes, and policy matrix evaluations (TC-026 / BE-008, BE-009)

create table if not exists server_restrictions (
    restriction_id uuid primary key,
    tenant_id varchar(128) not null,
    subject_reference varchar(128) not null,
    source varchar(64) not null check (source in ('ADMINISTRATIVE_BAN', 'FRAUD_SECURITY', 'RESPONSIBLE_GAMING', 'KYC_AML', 'PROVIDER_RESTRICTION', 'ACCOUNT_CLOSURE')),
    reason_code varchar(128) not null,
    safe_user_message varchar(512) not null,
    scope_type varchar(32) not null check (scope_type in ('WHOLE_ACCOUNT', 'PROVIDER_SCOPED', 'SURFACE_SCOPED')),
    scope_provider_id varchar(128) null,
    scope_category varchar(32) null,
    scope_surface varchar(128) null,
    effective_from timestamptz not null,
    expires_at timestamptz null,
    evidence_reference varchar(256) not null,
    rule_version bigint not null default 1,
    issuer varchar(128) not null,
    active boolean not null default true,
    revoked_at timestamptz null,
    revoked_by varchar(128) null,
    created_at timestamptz not null default now()
);

create index if not exists ix_server_restrictions_subject
    on server_restrictions (tenant_id, subject_reference, active, effective_from, expires_at);

create table if not exists server_restriction_evaluations (
    decision_id uuid primary key,
    tenant_id varchar(128) not null,
    subject_reference varchar(128) not null,
    operation varchar(64) not null,
    composite_access varchar(32) not null check (composite_access in ('ALLOW', 'STEP_UP', 'DENY')),
    financial_disposition varchar(32) not null check (financial_disposition in ('NONE', 'HOLD', 'CANCEL', 'REFUND', 'COMPLETE', 'PAYOUT')),
    contributing_restrictions text not null,
    policy_version bigint not null default 1,
    evaluated_at timestamptz not null default now()
);

create index if not exists ix_restriction_evaluations_subject
    on server_restriction_evaluations (tenant_id, subject_reference, evaluated_at);
