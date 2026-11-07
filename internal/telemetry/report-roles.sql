-- Separate read-only analyst role. It has no access to individual events.
GRANT USAGE ON SCHEMA public TO syn443_telemetry_reader;
GRANT SELECT ON identity_telemetry_hourly TO syn443_telemetry_reader;
