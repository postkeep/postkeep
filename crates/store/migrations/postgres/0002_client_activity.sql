-- When a client last obtained tokens, so unused registrations can expire.
ALTER TABLE oauth_clients ADD COLUMN last_used_at BIGINT;

CREATE INDEX oauth_clients_activity ON oauth_clients (last_used_at, created_at);
CREATE INDEX grants_client ON grants (client_id);
CREATE INDEX authorization_requests_expiry ON authorization_requests (expires_at);
CREATE INDEX authorization_codes_expiry ON authorization_codes (expires_at);
CREATE INDEX access_tokens_expiry ON access_tokens (expires_at);
CREATE INDEX refresh_tokens_expiry ON refresh_tokens (expires_at);
