-- TC-033: Operation-bound attestation challenges, durable single-use nonces, and replay protection

CREATE TABLE IF NOT EXISTS operation_attestation_challenges (
    challenge_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(128) NOT NULL,
    session_id VARCHAR(128) NOT NULL,
    operation VARCHAR(32) NOT NULL,
    nonce_value VARCHAR(128) NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_at TIMESTAMPTZ,
    consumed_by_operation_ref VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attestation_challenges_lookup
    ON operation_attestation_challenges (tenant_id, nonce_value);

CREATE INDEX IF NOT EXISTS idx_attestation_challenges_active
    ON operation_attestation_challenges (tenant_id, user_id, session_id, operation, consumed);

CREATE INDEX IF NOT EXISTS idx_attestation_challenges_expiry
    ON operation_attestation_challenges (expires_at);

CREATE TABLE IF NOT EXISTS operation_attestation_audits (
    audit_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(128) NOT NULL,
    session_id VARCHAR(128) NOT NULL,
    operation VARCHAR(32) NOT NULL,
    nonce_value VARCHAR(128) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    reason VARCHAR(64) NOT NULL,
    app_package_name VARCHAR(128),
    app_version_code BIGINT,
    client_reported_fingerprint VARCHAR(128),
    occurred_at TIMESTAMPTZ NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    evidence_reference VARCHAR(128) NOT NULL,
    details_redacted TEXT,
    CONSTRAINT uq_attestation_audits_tenant_idem UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_attestation_audits_user
    ON operation_attestation_audits (tenant_id, user_id, occurred_at);
