create table admin_operation (
    result_id uuid primary key,
    tenant_id varchar(128) not null,
    operation_type varchar(64) not null,
    created_at timestamptz not null
);

insert into admin_operation(result_id, tenant_id, operation_type, created_at)
select result_id, tenant_id, 'ADMIN_MFA_AUTHENTICATION', authenticated_at
from admin_mfa_authentication
on conflict (result_id) do nothing;

insert into admin_operation(result_id, tenant_id, operation_type, created_at)
select result_id, tenant_id, 'ADMIN_AUTHORIZATION', decided_at
from admin_authorization_decision
on conflict (result_id) do nothing;

insert into admin_operation(result_id, tenant_id, operation_type, created_at)
select result_id, tenant_id, 'PLAYER_PROFILE_SEARCH', occurred_at
from admin_player_profile_search
on conflict (result_id) do nothing;

alter table admin_audit_event drop constraint if exists admin_audit_event_result_id_fkey;
alter table admin_outbox_event drop constraint if exists admin_outbox_event_result_id_fkey;

alter table admin_audit_event
    add constraint admin_audit_event_operation_fk foreign key (result_id) references admin_operation(result_id);
alter table admin_outbox_event
    add constraint admin_outbox_event_operation_fk foreign key (result_id) references admin_operation(result_id);

create index admin_operation_tenant_time_idx
    on admin_operation (tenant_id, created_at);
