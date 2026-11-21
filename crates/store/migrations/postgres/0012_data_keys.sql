-- Data keys: each tenant's 32-byte keys, numbered by version, stored only
-- wrapped by a key encryption key (KEK). provider, kek_id and kek_version
-- name the KEK that wrapped a key; wrapped is the key wrapper's opaque
-- output in base64url. A new table only, so existing rows are unchanged.
CREATE TABLE data_keys (
    tenant TEXT NOT NULL,
    version BIGINT NOT NULL,
    provider TEXT NOT NULL,
    kek_id TEXT NOT NULL,
    kek_version BIGINT NOT NULL,
    wrapped TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (tenant, version)
);
