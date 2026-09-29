-- V26: Durable payout dispatch intent, recoverable worker, and reconciliation (TC-015 / BE-007)

CREATE TABLE IF NOT EXISTS admin_payout_dispatch_intent (
    intent_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    request_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    reservation_id UUID NOT NULL,
    method_id VARCHAR(64) NOT NULL,
    provider_id VARCHAR(64) NOT NULL,
    destination_reference VARCHAR(256) NOT NULL,
    gross_amount_minor_units BIGINT NOT NULL,
    fee_minor_units BIGINT NOT NULL,
    net_payout_amount_minor_units BIGINT NOT NULL,
    currency VARCHAR(12) NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    provider_reference VARCHAR(128),
    status VARCHAR(32) NOT NULL,
    lease_worker_id VARCHAR(128),
    lease_expires_at TIMESTAMPTZ,
    attempt_count INT NOT NULL DEFAULT 0,
    ledger_transaction_reference VARCHAR(128),
    failure_reason TEXT,
    server_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_payout_dispatch_tenant_idemp UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT uk_payout_dispatch_request UNIQUE (tenant_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_payout_dispatch_status_lease
    ON admin_payout_dispatch_intent (tenant_id, status, lease_expires_at);

CREATE TABLE IF NOT EXISTS admin_payout_reconciliation_audit (
    audit_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    intent_id UUID NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    previous_status VARCHAR(32) NOT NULL,
    new_status VARCHAR(32) NOT NULL,
    operator_id VARCHAR(128) NOT NULL,
    notes TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payout_reconciliation_audit_intent
    ON admin_payout_reconciliation_audit (tenant_id, intent_id, occurred_at);
