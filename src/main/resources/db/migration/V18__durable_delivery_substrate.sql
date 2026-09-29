-- TC-002 durable, provider-neutral event delivery substrate.
-- Payloads are redacted envelopes; raw credentials, tokens, signatures, and
-- full payment payloads must never be written here.

create table admin_event_envelope (
    event_id uuid primary key,
    tenant_id varchar(128) not null,
    aggregate_type varchar(128) not null,
    aggregate_id varchar(256) not null,
    operation_id uuid not null,
    event_type varchar(128) not null,
    schema_version integer not null,
    occurred_at timestamptz not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    redacted_payload jsonb not null,
    payload_sha256 varchar(64),
    created_at timestamptz not null,
    check (schema_version > 0),
    check (redacted_payload <> '{}'::jsonb),
    unique (tenant_id, event_id)
);

create index admin_event_envelope_tenant_time_idx
    on admin_event_envelope (tenant_id, occurred_at);

create table admin_outbox_delivery (
    event_id uuid primary key references admin_event_envelope(event_id),
    tenant_id varchar(128) not null,
    topic varchar(256) not null,
    status varchar(32) not null default 'PENDING',
    retry_count integer not null default 0,
    max_retries integer not null default 5,
    next_attempt_at timestamptz not null,
    created_at timestamptz not null,
    lease_owner varchar(128),
    lease_expires_at timestamptz,
    last_error varchar(512),
    published_at timestamptz,
    version bigint not null default 1,
    check (status in ('PENDING', 'LEASED', 'PUBLISHED', 'QUARANTINED')),
    check (retry_count >= 0 and max_retries > 0),
    check (version > 0),
    check ((status = 'LEASED' and lease_owner is not null and lease_expires_at is not null)
        or status <> 'LEASED')
);

create index admin_outbox_delivery_claim_idx
    on admin_outbox_delivery (tenant_id, status, next_attempt_at, created_at);

create table admin_inbox_consumer (
    tenant_id varchar(128) not null,
    event_id uuid not null references admin_event_envelope(event_id),
    consumer_name varchar(128) not null,
    status varchar(32) not null default 'RECEIVED',
    attempt_count integer not null default 0,
    lease_owner varchar(128),
    lease_expires_at timestamptz,
    domain_effect_key varchar(256) not null,
    processed_at timestamptz,
    last_error varchar(512),
    version bigint not null default 1,
    primary key (tenant_id, event_id, consumer_name),
    check (status in ('RECEIVED', 'PROCESSING', 'PROCESSED', 'FAILED', 'QUARANTINED')),
    check (attempt_count >= 0),
    check ((status = 'PROCESSING' and lease_owner is not null and lease_expires_at is not null)
        or status <> 'PROCESSING')
);

create index admin_inbox_consumer_claim_idx
    on admin_inbox_consumer (tenant_id, consumer_name, status, lease_expires_at);

create table admin_delivery_attempt (
    attempt_id uuid primary key,
    tenant_id varchar(128) not null,
    event_id uuid not null references admin_event_envelope(event_id),
    consumer_name varchar(128),
    attempt_number integer not null,
    worker_id varchar(128) not null,
    status varchar(32) not null,
    started_at timestamptz not null,
    finished_at timestamptz,
    error_type varchar(128),
    error_detail varchar(512),
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    unique (tenant_id, event_id, consumer_name, attempt_number),
    check (status in ('CLAIMED', 'SENT', 'ACKNOWLEDGED', 'FAILED', 'EXPIRED', 'QUARANTINED'))
);

create table admin_delivery_dead_letter (
    dead_letter_id uuid primary key,
    tenant_id varchar(128) not null,
    event_id uuid not null references admin_event_envelope(event_id),
    consumer_name varchar(128),
    reason varchar(64) not null,
    failure_detail varchar(512) not null,
    quarantined_at timestamptz not null,
    replayed_at timestamptz,
    replayed_by varchar(128),
    replay_correlation_id varchar(128),
    version bigint not null default 1,
    unique (tenant_id, event_id, consumer_name),
    check (version > 0)
);

create index admin_delivery_dlq_tenant_time_idx
    on admin_delivery_dead_letter (tenant_id, quarantined_at);

create table admin_delivery_replay (
    tenant_id varchar(128) not null,
    idempotency_key varchar(128) not null,
    fingerprint varchar(64) not null,
    result_id uuid not null,
    event_id uuid not null references admin_event_envelope(event_id),
    replayed_by varchar(128) not null,
    replayed_at timestamptz not null,
    status varchar(32) not null,
    evidence_reference varchar(256) not null,
    correlation_id varchar(128) not null,
    causation_id varchar(128) not null,
    primary key (tenant_id, idempotency_key)
);

-- Existing authoritative stores already insert admin_outbox_event in their
-- originating transaction. Bridge that released table into the durable
-- envelope/lease tables without changing their transaction boundary.
create or replace function admin_bridge_legacy_outbox_event()
returns trigger
language plpgsql
as $$
declare
    audit_row record;
begin
    select correlation_id, causation_id, occurred_at
      into audit_row
      from admin_audit_event
     where result_id = new.result_id
     order by occurred_at desc
     limit 1;

    insert into admin_event_envelope(
        event_id, tenant_id, aggregate_type, aggregate_id, operation_id, event_type,
        schema_version, occurred_at, correlation_id, causation_id, redacted_payload,
        payload_sha256, created_at
    ) values (
        new.event_id, new.tenant_id, 'ADMIN_OPERATION', new.result_id::text, new.result_id,
        new.event_type, 1, coalesce(audit_row.occurred_at, new.created_at),
        coalesce(audit_row.correlation_id, 'legacy-' || new.event_id::text),
        coalesce(audit_row.causation_id, 'legacy-' || new.event_id::text),
        case when new.payload = '{}'::jsonb
             then jsonb_build_object('legacyPayload', 'redacted', 'eventId', new.event_id::text, 'payloadWasEmpty', true)
             else new.payload end,
        null, new.created_at
    ) on conflict (event_id) do nothing;

    insert into admin_outbox_delivery(
        event_id, tenant_id, topic, status, retry_count, max_retries, next_attempt_at, created_at, version
    ) values (
        new.event_id, new.tenant_id, new.event_type, 'PENDING', 0, 5, new.created_at, new.created_at, 1
    ) on conflict (event_id) do nothing;
    return new;
end;
$$;

create trigger admin_outbox_event_durable_bridge
after insert on admin_outbox_event
for each row execute function admin_bridge_legacy_outbox_event();

insert into admin_event_envelope(
    event_id, tenant_id, aggregate_type, aggregate_id, operation_id, event_type,
    schema_version, occurred_at, correlation_id, causation_id, redacted_payload,
    payload_sha256, created_at
)
select o.event_id, o.tenant_id, 'ADMIN_OPERATION', o.result_id::text, o.result_id,
       o.event_type, 1, o.created_at,
       coalesce(a.correlation_id, 'legacy-' || o.event_id::text),
       coalesce(a.causation_id, 'legacy-' || o.event_id::text),
       case when o.payload = '{}'::jsonb
            then jsonb_build_object('legacyPayload', 'redacted', 'eventId', o.event_id::text, 'payloadWasEmpty', true)
            else o.payload end,
       null, o.created_at
  from admin_outbox_event o
  left join lateral (
      select correlation_id, causation_id
        from admin_audit_event
       where result_id = o.result_id
       order by occurred_at desc
       limit 1
  ) a on true
 where not exists (select 1 from admin_event_envelope e where e.event_id = o.event_id);

insert into admin_outbox_delivery(
    event_id, tenant_id, topic, status, retry_count, max_retries, next_attempt_at, created_at, version
)
select event_id, tenant_id, event_type, 'PENDING', 0, 5, created_at, created_at, 1
  from admin_outbox_event
 where not exists (select 1 from admin_outbox_delivery d where d.event_id = admin_outbox_event.event_id);
