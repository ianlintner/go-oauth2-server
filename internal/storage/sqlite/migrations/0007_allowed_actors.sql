-- RFC 8693 token exchange. clients.allowed_actors lists the client IDs allowed
-- to act for, or exchange tokens issued to, this client (JSON array).
ALTER TABLE clients ADD COLUMN allowed_actors TEXT NOT NULL DEFAULT '[]';
