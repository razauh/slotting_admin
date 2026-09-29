-- V20: Durable Dual Control Approval Authority (TC-006 / BE-013)

create table dual_control_proposal (
    proposal_id uuid primary key,
    tenant_id varchar(128) not null,
    operation_id varchar(128) not null,
    operation_type varchar(64) not null,
    resource_reference varchar(255) not null,
    payload_digest varchar(128) not null,
    required_permission varchar(64) not null,
    target_version bigint not null,
    status varchar(32) not null default 'PENDING_CHECKER',
    maker_principal_id varchar(128) not null,
    maker_session_id varchar(128) not null,
    maker_roles varchar(255) not null,
    maker_mfa_verified boolean not null default true,
    proposed_at timestamptz not null default now(),
    expires_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    notes text null,
    version bigint not null default 1,
    unique (tenant_id, operation_id),
    unique (tenant_id, idempotency_key)
);

create index dual_control_proposal_lookup_idx on dual_control_proposal(tenant_id, status, operation_id);

create table dual_control_receipt (
    receipt_id uuid primary key,
    proposal_id uuid not null references dual_control_proposal(proposal_id),
    tenant_id varchar(128) not null,
    operation_id varchar(128) not null,
    operation_type varchar(64) not null,
    resource_reference varchar(255) not null,
    payload_digest varchar(128) not null,
    required_permission varchar(64) not null,
    target_version bigint not null,
    status varchar(32) not null,
    maker_principal_id varchar(128) not null,
    checker_principal_id varchar(128) not null,
    checker_session_id varchar(128) not null,
    checker_roles varchar(255) not null,
    checker_mfa_verified boolean not null default true,
    decided_at timestamptz not null default now(),
    expires_at timestamptz not null,
    evidence_reference varchar(255) not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    notes text null,
    check (checker_principal_id <> maker_principal_id),
    unique (tenant_id, operation_id),
    unique (tenant_id, idempotency_key)
);

create index dual_control_receipt_lookup_idx on dual_control_receipt(tenant_id, operation_id, status);
