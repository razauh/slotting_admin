-- TC-034: Authoritative analytics facts, incremental daily projections, and unique players tracking

CREATE TABLE IF NOT EXISTS analytics_facts (
    fact_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    fact_type VARCHAR(64) NOT NULL,
    source_event_id VARCHAR(128) NOT NULL,
    source_event_type VARCHAR(64) NOT NULL,
    user_id VARCHAR(128),
    session_id VARCHAR(128),
    game_id VARCHAR(64),
    provider_id VARCHAR(64),
    currency VARCHAR(8),
    amount_minor BIGINT,
    payout_minor BIGINT,
    status VARCHAR(32) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(128) NOT NULL,
    metadata_json TEXT,
    CONSTRAINT uq_analytics_facts_tenant_source UNIQUE (tenant_id, source_event_id)
);

CREATE INDEX IF NOT EXISTS idx_analytics_facts_tenant_time
    ON analytics_facts (tenant_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_analytics_facts_tenant_type
    ON analytics_facts (tenant_id, fact_type, occurred_at);

CREATE INDEX IF NOT EXISTS idx_analytics_facts_user
    ON analytics_facts (tenant_id, user_id, occurred_at);

CREATE TABLE IF NOT EXISTS analytics_daily_projections (
    projection_id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    date_bucket DATE NOT NULL,
    currency VARCHAR(8) NOT NULL,
    dimension_type VARCHAR(32) NOT NULL DEFAULT 'OVERALL',
    dimension_value VARCHAR(64) NOT NULL DEFAULT 'ALL',
    total_wagers_minor BIGINT NOT NULL DEFAULT 0,
    wager_count BIGINT NOT NULL DEFAULT 0,
    total_payouts_minor BIGINT NOT NULL DEFAULT 0,
    payout_count BIGINT NOT NULL DEFAULT 0,
    ggr_minor BIGINT NOT NULL DEFAULT 0,
    total_deposits_minor BIGINT NOT NULL DEFAULT 0,
    deposit_count BIGINT NOT NULL DEFAULT 0,
    total_withdrawals_completed_minor BIGINT NOT NULL DEFAULT 0,
    withdrawal_completed_count BIGINT NOT NULL DEFAULT 0,
    withdrawal_rejected_count BIGINT NOT NULL DEFAULT 0,
    active_players_count BIGINT NOT NULL DEFAULT 0,
    new_registrations_count BIGINT NOT NULL DEFAULT 0,
    auth_failures_count BIGINT NOT NULL DEFAULT 0,
    restrictions_placed_count BIGINT NOT NULL DEFAULT 0,
    reconciliation_exceptions_count BIGINT NOT NULL DEFAULT 0,
    chargebacks_unsupported_marker BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 1,
    last_processed_fact_time TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_analytics_daily_proj UNIQUE (tenant_id, date_bucket, currency, dimension_type, dimension_value)
);

CREATE INDEX IF NOT EXISTS idx_analytics_daily_lookup
    ON analytics_daily_projections (tenant_id, date_bucket, currency);

CREATE TABLE IF NOT EXISTS analytics_unique_players (
    tenant_id VARCHAR(64) NOT NULL,
    date_bucket DATE NOT NULL,
    user_id VARCHAR(128) NOT NULL,
    first_activity_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, date_bucket, user_id)
);

CREATE INDEX IF NOT EXISTS idx_analytics_unique_players_lookup
    ON analytics_unique_players (tenant_id, date_bucket);
