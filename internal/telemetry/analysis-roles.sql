-- Apply as the schema owner to the dedicated, non-inheriting analysis role.
-- This worker has no account, pseudonym, path, or authentication fields.
GRANT USAGE ON SCHEMA public TO syn443_telemetry_analysis;
GRANT SELECT(received_at_ms,kind,code,mode,duration_ms) ON identity_telemetry_events TO syn443_telemetry_analysis;
GRANT SELECT ON identity_telemetry_analysis_events TO syn443_telemetry_analysis;
GRANT SELECT,INSERT,DELETE ON identity_telemetry_hourly TO syn443_telemetry_analysis;
