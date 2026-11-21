-- When the mail server last rejected an IMAP account's stored password, in
-- Unix seconds; NULL until it does, and again once a new password is stored or
-- a login with the stored one works. Nullable and additive.
ALTER TABLE accounts ADD COLUMN password_rejected_at BIGINT;
