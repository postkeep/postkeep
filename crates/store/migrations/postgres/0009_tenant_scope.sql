-- Tenant scope. Every account belongs to a tenant, an opaque string that an
-- embedding chooses; this server alone only ever uses 'default'.
-- Addresses and provider identities are unique per tenant, so two tenants
-- can each connect the same mailbox.
ALTER TABLE accounts ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
ALTER TABLE accounts DROP CONSTRAINT accounts_email_key;
DROP INDEX accounts_provider_subject;
CREATE UNIQUE INDEX accounts_tenant_email ON accounts (tenant, email);
CREATE UNIQUE INDEX accounts_tenant_provider_subject ON accounts (tenant, provider, subject);
