-- A webhook that fails repeatedly is paused, not turned off. `paused_at` is
-- the Unix time the pause began; NULL while it is delivering or the user
-- turned it off. The watcher keeps running and recording events. The column
-- is nullable and additive so existing rows stay readable.
ALTER TABLE webhooks ADD COLUMN paused_at BIGINT;

-- Rows an older version turned off after repeated failures (it stored a
-- reason) start watching again, paused, from the cursor they already had.
-- Rows the user turned off have no reason and stay off.
UPDATE webhooks
SET enabled = 1,
    paused_at = COALESCE(last_attempt_at, updated_at),
    disabled_reason = NULL
WHERE enabled = 0 AND disabled_reason IS NOT NULL;
