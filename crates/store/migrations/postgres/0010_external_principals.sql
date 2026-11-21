-- External principals. A grant or an authorization code is for exactly one
-- subject: a mailbox account, or a principal, an opaque string that an
-- embedding's sign-in hook approved.
ALTER TABLE grants ALTER COLUMN account_id DROP NOT NULL;
ALTER TABLE grants ADD COLUMN principal TEXT;
ALTER TABLE grants ADD CONSTRAINT grants_one_subject
    CHECK ((account_id IS NULL) <> (principal IS NULL));
CREATE INDEX grants_principal ON grants (principal) WHERE principal IS NOT NULL;

ALTER TABLE authorization_codes ALTER COLUMN account_id DROP NOT NULL;
ALTER TABLE authorization_codes ADD COLUMN principal TEXT;
ALTER TABLE authorization_codes ADD CONSTRAINT authorization_codes_one_subject
    CHECK ((account_id IS NULL) <> (principal IS NULL));
