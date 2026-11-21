-- Tenant scope. Every account belongs to a tenant, an opaque string that an
-- embedding chooses; this server alone only ever uses 'default'.
-- SQLite keeps the global unique email and (provider, subject): a SQLite
-- server holds one tenant, so an address can be connected only once. The
-- per-tenant indexes match PostgreSQL's, so the same upserts work on both.
ALTER TABLE accounts ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
CREATE UNIQUE INDEX accounts_tenant_email ON accounts (tenant, email);
CREATE UNIQUE INDEX accounts_tenant_provider_subject ON accounts (tenant, provider, subject);
