-- V25: Authoritative withdrawal quote, request, step-up, and approval binding (TC-014 / BE-010, BE-011)

-- 1. Verified payout destinations
CREATE TABLE IF NOT EXISTS admin_payout_destination (
    destination_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL,
    payment_method VARCHAR(64) NOT NULL,
    destination_reference VARCHAR(256) NOT NULL,
    account_holder_name VARCHAR(256) NOT NULL,
    verification_method VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    rejection_reason TEXT,
    verification_evidence_reference VARCHAR(256),
    idempotency_key VARCHAR(128) NOT NULL,
    server_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_payout_dest_tenant_idemp UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT uk_payout_dest_ref UNIQUE (tenant_id, owner_id, payment_method, destination_reference)
);

CREATE INDEX IF NOT EXISTS idx_payout_dest_owner
    ON admin_payout_destination (tenant_id, owner_id, status);

-- 2. One-time bound step-up assertions
CREATE TABLE IF NOT EXISTS admin_withdrawal_step_up_assertion (
    assertion_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL,
    session_id VARCHAR(128) NOT NULL,
    destination_reference VARCHAR(256) NOT NULL,
    gross_amount_minor_units BIGINT NOT NULL,
    currency VARCHAR(12) NOT NULL,
    method_id VARCHAR(64) NOT NULL,
    operation_type VARCHAR(64) NOT NULL DEFAULT 'WITHDRAWAL',
    bound_digest VARCHAR(64) NOT NULL,
    token VARCHAR(128) NOT NULL UNIQUE,
    is_consumed BOOLEAN NOT NULL DEFAULT FALSE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_step_up_token
    ON admin_withdrawal_step_up_assertion (tenant_id, token);

-- 3. Authoritative withdrawal quotes
CREATE TABLE IF NOT EXISTS admin_withdrawal_quote (
    quote_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL,
    currency VARCHAR(12) NOT NULL,
    method_id VARCHAR(64) NOT NULL,
    destination_reference VARCHAR(256) NOT NULL,
    gross_amount_minor_units BIGINT NOT NULL,
    fixed_fee_minor_units BIGINT NOT NULL DEFAULT 0,
    percentage_fee_bps BIGINT NOT NULL DEFAULT 0,
    total_fee_minor_units BIGINT NOT NULL DEFAULT 0,
    net_payout_minor_units BIGINT NOT NULL,
    step_up_required BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL,
    quoted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    idempotency_key VARCHAR(128) NOT NULL,
    server_version BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT uk_withdrawal_quote_idemp UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_withdrawal_quote_lookup
    ON admin_withdrawal_quote (tenant_id, quote_id);

-- 4. Authoritative withdrawal requests with immutable digest and review state
CREATE TABLE IF NOT EXISTS admin_authoritative_withdrawal_request (
    request_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL,
    quote_id UUID NOT NULL,
    reservation_id UUID NOT NULL,
    method_id VARCHAR(64) NOT NULL,
    destination_reference VARCHAR(256) NOT NULL,
    gross_amount_minor_units BIGINT NOT NULL,
    fee_minor_units BIGINT NOT NULL,
    net_payout_amount_minor_units BIGINT NOT NULL,
    currency VARCHAR(12) NOT NULL,
    step_up_assertion_id UUID,
    immutable_digest VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    review_state VARCHAR(32) NOT NULL DEFAULT 'QUEUED',
    denial_reason_code VARCHAR(64),
    denial_message TEXT,
    dual_control_receipt_id UUID,
    idempotency_key VARCHAR(128) NOT NULL,
    server_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_auth_withdrawal_request_idemp UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_auth_withdrawal_request_lookup
    ON admin_authoritative_withdrawal_request (tenant_id, request_id);

CREATE INDEX IF NOT EXISTS idx_auth_withdrawal_review_state
    ON admin_authoritative_withdrawal_request (tenant_id, review_state);

-- 5. Authoritative fund reservations
CREATE TABLE IF NOT EXISTS admin_authoritative_withdrawal_reservation (
    reservation_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    owner_id UUID NOT NULL,
    request_id UUID NOT NULL,
    amount_minor_units BIGINT NOT NULL,
    currency VARCHAR(12) NOT NULL,
    status VARCHAR(32) NOT NULL,
    ledger_journal_reference VARCHAR(128),
    server_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_withdrawal_reservation_owner
    ON admin_authoritative_withdrawal_reservation (tenant_id, owner_id, status);
