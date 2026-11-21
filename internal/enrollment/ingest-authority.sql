WITH allowed(rel, r, i, u) AS (VALUES
 ('identity_clock','id second','',''),
 ('identity_telemetry_clock','id second','','second'),
 ('identity_accounts','owner enabled device_limit valid_until grant_hash','','lock_guard'),
 ('identity_devices','id owner jkt active','','ingest_lock_guard'),
 ('identity_sessions','id device access_hash nonce access_until refresh_until generation active','','ingest_lock_guard'),
 ('identity_replays','','jkt jti expires',''),
 ('identity_telemetry_events','','device event_id session_id build policy_revision algorithm_revision received_at_ms observed_at_ms elapsed_ms network_epoch kind code mode path_id duration_ms',''),
 ('identity_telemetry_windows','device period used','device period used','used')
), relations AS (
 SELECT c.oid,a.rel,a.r,a.i,a.u FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace AND n.nspname='public'
 LEFT JOIN allowed a ON c.relname=a.rel WHERE c.relkind IN ('r','p','v','m','f')
)
SELECT session_user=current_user AND current_user='syn443_telemetry_ingest'
 AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user AND r.rolcanlogin
   AND NOT (r.rolsuper OR r.rolinherit OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication)
   AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid))
 AND NOT has_schema_privilege(current_user,'public','CREATE')
 AND (SELECT count(rel) FROM relations)=(SELECT count(*) FROM allowed)
 AND NOT EXISTS (SELECT 1 FROM relations t WHERE has_table_privilege(current_user,t.oid,'DELETE,TRUNCATE,TRIGGER'))
 AND NOT EXISTS (
   SELECT 1 FROM relations t JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
   WHERE has_column_privilege(current_user,t.oid,a.attnum,'SELECT')<>(a.attname::text=ANY(string_to_array(coalesce(t.r,''),' ')))
      OR has_column_privilege(current_user,t.oid,a.attnum,'INSERT')<>(a.attname::text=ANY(string_to_array(coalesce(t.i,''),' ')))
      OR has_column_privilege(current_user,t.oid,a.attnum,'UPDATE')<>(a.attname::text=ANY(string_to_array(coalesce(t.u,''),' ')))
      OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')
 )
