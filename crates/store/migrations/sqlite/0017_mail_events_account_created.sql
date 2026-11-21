-- An account's events by age, so that the periodic purge finds each
-- outbox's oldest event, and deletes those past its retention, without
-- reading every account's events.
CREATE INDEX mail_events_account_created ON mail_events (account_id, created_at);
