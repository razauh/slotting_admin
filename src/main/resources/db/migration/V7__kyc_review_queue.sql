create table admin_kyc_review_queue (
    tenant_id varchar(128) not null,
    case_reference varchar(128) not null,
    state varchar(16) not null,
    claimed_by varchar(128),
    claim_expires_at timestamptz,
    server_version bigint not null default 0,
    updated_at timestamptz not null,
    primary key (tenant_id, case_reference),
    check (state in ('QUEUED','CLAIMED','APPROVED','REJECTED')),
    check (server_version >= 0),
    check ((state = 'CLAIMED' and claimed_by is not null and claim_expires_at is not null) or (state <> 'CLAIMED' and claimed_by is null and claim_expires_at is null))
);
create index ix_kyc_review_queue_state on admin_kyc_review_queue(tenant_id, state, claim_expires_at);
create table admin_kyc_review_result (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    case_reference varchar(128) not null,
    query_fingerprint varchar(128) not null,
    reason_code varchar(32) not null,
    state varchar(16) not null,
    claimed_by varchar(128),
    second_approver_id varchar(128),
    claim_expires_at timestamptz,
    server_version bigint not null,
    occurred_at timestamptz not null,
    idempotency_key varchar(128) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, idempotency_key),
    foreign key (tenant_id, case_reference) references admin_kyc_review_queue(tenant_id, case_reference),
    check (state in ('QUEUED','CLAIMED','APPROVED','REJECTED')),
    check (server_version >= 0)
);
