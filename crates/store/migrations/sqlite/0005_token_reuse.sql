-- Replay detection (RFC 9700 section 4.14.2, OAuth 2.1 section 4.1.3).
--
-- A rotated refresh token is kept, marked used, until it expires. Presenting
-- it again means two parties hold the grant's tokens, so the grant is
-- revoked.
ALTER TABLE refresh_tokens ADD COLUMN used_at BIGINT;

-- A redeemed authorization code is kept, marked used and linked to the
-- grant it created, until it expires. Redeeming it again revokes that
-- grant; `replayed` also stops a grant still being created from it.
ALTER TABLE authorization_codes ADD COLUMN used_at BIGINT;
ALTER TABLE authorization_codes ADD COLUMN grant_id TEXT;
ALTER TABLE authorization_codes ADD COLUMN replayed BIGINT NOT NULL DEFAULT 0;
