alter table admin_mfa_authentication
    add column roles varchar(255) not null default '';
