select setval('public.player_device_travel_event_event_id_seq', coalesce((select max(event_id) from public.player_device_travel_event), 0) + 1, false);
select setval('public.registration_risk_review_audit_audit_id_seq', coalesce((select max(audit_id) from public.registration_risk_review_audit), 0) + 1, false);
select setval('public.request_abuse_quarantine_audit_audit_id_seq', coalesce((select max(audit_id) from public.request_abuse_quarantine_audit), 0) + 1, false);
select setval('public.trusted_player_device_audit_audit_id_seq', coalesce((select max(audit_id) from public.trusted_player_device_audit), 0) + 1, false);
