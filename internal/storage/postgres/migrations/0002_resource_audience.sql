-- RFC 8707 resource indicators. clients.resources lists the resources a client
-- may request (JSON array text); the audience columns carry the validated
-- resource from the artifact that outlives the request. '' means none was
-- recorded (rows written before this migration).
ALTER TABLE clients ADD COLUMN resources text NOT NULL DEFAULT '[]';
ALTER TABLE auth_codes ADD COLUMN audience text NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN audience text NOT NULL DEFAULT '';
ALTER TABLE device_codes ADD COLUMN audience text NOT NULL DEFAULT '';
ALTER TABLE pushed_requests ADD COLUMN audience text NOT NULL DEFAULT '';
