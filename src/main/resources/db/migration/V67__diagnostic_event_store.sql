create table if not exists diagnostic_event (
    tenant_id varchar(128) not null,
    event_id uuid not null,
    payload_digest char(64) not null,
    schema_version integer not null,
    occurred_at timestamptz not null,
    server_received_at timestamptz not null,
    event_type varchar(128) not null,
    severity varchar(32) not null,
    source_app varchar(64) not null,
    component varchar(128) not null,
    environment varchar(64) not null,
    correlation_id varchar(128) not null,
    payload_json jsonb not null,
    delivery_state varchar(32) not null,
    attempt_count integer not null default 0,
    next_attempt_at timestamptz,
    last_error varchar(512),
    sent_at timestamptz,
    sink_receipt_id varchar(256),
    created_at timestamptz not null,
    primary key (tenant_id, event_id)
);

create index if not exists diagnostic_event_pending_idx
    on diagnostic_event (delivery_state, next_attempt_at, created_at);

create index if not exists diagnostic_event_received_idx
    on diagnostic_event (tenant_id, server_received_at);
