ALTER TABLE admin_deposit_intent RENAME COLUMN currency_code TO currency;
ALTER TABLE admin_deposit_intent ADD COLUMN request_fingerprint varchar(128) NOT NULL DEFAULT '';
ALTER TABLE admin_deposit_intent ADD COLUMN redirect_url text;
ALTER TABLE admin_deposit_intent ADD COLUMN client_secret text;
ALTER TABLE admin_deposit_intent ALTER COLUMN correlation_id SET DEFAULT 'deposit-workflow';
ALTER TABLE admin_deposit_intent ALTER COLUMN causation_id SET DEFAULT 'deposit-workflow';
ALTER TABLE admin_deposit_intent DROP CONSTRAINT IF EXISTS admin_deposit_intent_status_check;
ALTER TABLE admin_deposit_intent
    ADD CONSTRAINT ck_admin_deposit_intent_status
    CHECK (status IN ('CREATED', 'DISPATCH_PENDING', 'PROVIDER_PENDING', 'SETTLED', 'FAILED', 'QUARANTINED', 'EXPIRED', 'AMBIGUOUS_RECONCILING'));

DROP INDEX IF EXISTS ix_deposit_inbox_processed;
ALTER TABLE admin_deposit_inbox RENAME COLUMN event_id TO inbox_id;
ALTER TABLE admin_deposit_inbox RENAME COLUMN signature_valid TO signature_verified;
ALTER TABLE admin_deposit_inbox ADD COLUMN status varchar(32) NOT NULL DEFAULT 'RECEIVED';
UPDATE admin_deposit_inbox SET status = CASE WHEN processed THEN 'PROCESSED' ELSE 'RECEIVED' END;
ALTER TABLE admin_deposit_inbox DROP COLUMN processed;
CREATE INDEX ix_deposit_inbox_processed ON admin_deposit_inbox (tenant_id, status, received_at);

ALTER TABLE admin_deposit_reconciliation RENAME COLUMN status_before TO previous_status;
ALTER TABLE admin_deposit_reconciliation RENAME COLUMN status_after TO new_status;
ALTER TABLE admin_deposit_reconciliation RENAME COLUMN reconciled_by TO performed_by;
ALTER TABLE admin_deposit_reconciliation RENAME COLUMN reconciled_at TO occurred_at;
ALTER TABLE admin_deposit_reconciliation RENAME COLUMN evidence TO notes;
ALTER TABLE admin_deposit_reconciliation ADD COLUMN action_type varchar(128) NOT NULL DEFAULT 'RECONCILIATION';
