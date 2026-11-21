-- Whether a webhook filter rule is on (1) or turned off (0). A rule that is
-- off judges nothing, but keeps its place and counts toward the mailbox's
-- limit. Rules stored before this, and rules an earlier version adds, are on.
ALTER TABLE webhook_filter_rules ADD COLUMN enabled BIGINT NOT NULL DEFAULT 1;
