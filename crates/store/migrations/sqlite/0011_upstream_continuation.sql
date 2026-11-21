-- Microsoft or Google sign-ins that an embedding starts to add a mailbox to
-- one of its tenants (purpose 'continue'): the tenant, and the embedding's
-- continuation, encrypted like the request ID. Both stay NULL for the other
-- purposes, so existing rows stay readable.
ALTER TABLE upstream_requests ADD COLUMN tenant TEXT;
ALTER TABLE upstream_requests ADD COLUMN continuation_ciphertext TEXT;
