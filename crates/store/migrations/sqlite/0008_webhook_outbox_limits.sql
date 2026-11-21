-- Per-account outbox limits. NULL means the server default
-- (POSTKEEP_WEBHOOK_OUTBOX_RETENTION and POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS).
-- Retention is seconds. The event cap counts every kept event, delivered or
-- not. The columns are nullable and additive so existing rows stay readable.
ALTER TABLE webhooks ADD COLUMN outbox_retention_secs BIGINT;
ALTER TABLE webhooks ADD COLUMN outbox_max_events BIGINT;
