ALTER TABLE fraud_cases
    ALTER COLUMN risk_decision_refs_json TYPE JSONB USING risk_decision_refs_json::jsonb,
    ALTER COLUMN detected_reasons_json TYPE JSONB USING detected_reasons_json::jsonb,
    ALTER COLUMN admin_notes_json TYPE JSONB USING admin_notes_json::jsonb;

ALTER TABLE fraud_cases
    ADD CONSTRAINT ck_fraud_cases_state
        CHECK (state IN ('OPEN', 'CLAIMED', 'EVIDENCE_REQUESTED', 'ESCALATED', 'DISPOSED_RESTRICTED', 'DISPOSED_CLEARED')),
    ADD CONSTRAINT ck_fraud_cases_severity
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    ADD CONSTRAINT ck_fraud_cases_risk_refs_array
        CHECK (jsonb_typeof(risk_decision_refs_json) = 'array'),
    ADD CONSTRAINT ck_fraud_cases_detected_reasons_array
        CHECK (jsonb_typeof(detected_reasons_json) = 'array'),
    ADD CONSTRAINT ck_fraud_cases_admin_notes_array
        CHECK (admin_notes_json IS NULL OR jsonb_typeof(admin_notes_json) = 'array');

ALTER TABLE fraud_case_actions
    ADD CONSTRAINT ck_fraud_case_actions_action
        CHECK (action IN ('CLAIM', 'RELEASE', 'REQUEST_EVIDENCE', 'ESCALATE', 'CONFIRM_RESTRICTION', 'DISPOSE_CLEAR')),
    ADD CONSTRAINT ck_fraud_case_actions_from_state
        CHECK (from_state IN ('OPEN', 'CLAIMED', 'EVIDENCE_REQUESTED', 'ESCALATED', 'DISPOSED_RESTRICTED', 'DISPOSED_CLEARED')),
    ADD CONSTRAINT ck_fraud_case_actions_to_state
        CHECK (to_state IN ('OPEN', 'CLAIMED', 'EVIDENCE_REQUESTED', 'ESCALATED', 'DISPOSED_RESTRICTED', 'DISPOSED_CLEARED'));

CREATE UNIQUE INDEX uq_fraud_cases_tenant_case_id
    ON fraud_cases (tenant_id, case_id);

ALTER TABLE fraud_case_actions
    ADD CONSTRAINT fk_fraud_case_actions_case
        FOREIGN KEY (tenant_id, case_id)
        REFERENCES fraud_cases (tenant_id, case_id)
        ON DELETE RESTRICT NOT VALID;

ALTER TABLE fraud_case_actions
    VALIDATE CONSTRAINT fk_fraud_case_actions_case;

CREATE INDEX idx_fraud_cases_risk_refs_gin
    ON fraud_cases USING GIN (risk_decision_refs_json);

CREATE INDEX idx_fraud_cases_detected_reasons_gin
    ON fraud_cases USING GIN (detected_reasons_json);

CREATE INDEX idx_fraud_cases_admin_notes_gin
    ON fraud_cases USING GIN (admin_notes_json);
