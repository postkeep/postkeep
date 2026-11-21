-- Webhook filter rules, one row each, so that when a mailbox has more rules
-- than its limit allows the oldest stay active. action, field and kind are
-- plain text that the caller checks; the pattern can hold personal data and
-- is encrypted. seq is one more than the largest in the mailbox when the rule
-- is added, and orders rules added in the same second. Every add or remove
-- counts in webhooks.filter_rules_version.
CREATE TABLE webhook_filter_rules (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    added_at BIGINT NOT NULL,
    action TEXT NOT NULL,
    field TEXT NOT NULL,
    kind TEXT NOT NULL,
    pattern_ciphertext TEXT NOT NULL,
    UNIQUE (account_id, seq)
);

ALTER TABLE webhooks ADD COLUMN filter_rules_version BIGINT NOT NULL DEFAULT 0;
