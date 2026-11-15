-- Optional telemetry retention role. Apply as migration owner after creating
-- syn443_telemetry_retention as a separate NOINHERIT, NOBYPASSRLS LOGIN role.
GRANT USAGE ON SCHEMA public TO syn443_telemetry_retention;
GRANT SELECT(device,event_id,received_at_ms),DELETE ON identity_telemetry_events TO syn443_telemetry_retention;
GRANT SELECT(device,period),DELETE ON identity_telemetry_windows TO syn443_telemetry_retention;
GRANT SELECT(hour_start_ms),DELETE ON identity_telemetry_hourly TO syn443_telemetry_retention;
