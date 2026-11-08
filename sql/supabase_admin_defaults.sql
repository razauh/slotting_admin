alter default privileges for role supabase_admin in schema public revoke all on tables from anon, authenticated;
alter default privileges for role supabase_admin in schema public revoke all on sequences from anon, authenticated;
alter default privileges for role supabase_admin in schema public revoke all on functions from anon, authenticated;
