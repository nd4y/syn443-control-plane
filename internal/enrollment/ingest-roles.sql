-- Apply as the schema owner after creating the independent NOINHERIT login.
GRANT USAGE ON SCHEMA public TO syn443_telemetry_ingest;
GRANT SELECT(id,second) ON identity_clock TO syn443_telemetry_ingest;
GRANT SELECT(id,second),UPDATE(second) ON identity_telemetry_clock TO syn443_telemetry_ingest;
GRANT SELECT(owner,enabled,device_limit,valid_until,grant_hash),UPDATE(lock_guard) ON identity_accounts TO syn443_telemetry_ingest;
GRANT SELECT(id,owner,jkt,active),UPDATE(ingest_lock_guard) ON identity_devices TO syn443_telemetry_ingest;
GRANT SELECT(id,device,access_hash,nonce,access_until,refresh_until,generation,active),UPDATE(ingest_lock_guard) ON identity_sessions TO syn443_telemetry_ingest;
GRANT INSERT(jkt,jti,expires) ON identity_replays TO syn443_telemetry_ingest;
GRANT INSERT(device,event_id,session_id,build,policy_revision,algorithm_revision,received_at_ms,observed_at_ms,elapsed_ms,network_epoch,kind,code,mode,path_id,duration_ms) ON identity_telemetry_events TO syn443_telemetry_ingest;
GRANT SELECT(device,period,used),INSERT(device,period,used),UPDATE(used) ON identity_telemetry_windows TO syn443_telemetry_ingest;
