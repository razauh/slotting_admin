alter table admin_mfa_authentication
    add column approver_id varchar(128);

create index admin_mfa_break_glass_approver_idx
    on admin_mfa_authentication (tenant_id, approver_id, authenticated_at)
    where approver_id is not null;
