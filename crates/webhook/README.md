# postkeep-webhook

Webhook delivery for [postkeep](../../README.md):

- `WebhookUrl` and `AuthHeader` validate what a user enters: `https` only,
  no credentials in the URL, no literal private addresses or local names,
  no reserved or CR/LF-injected headers.
- `Deliverer` is a small hyper + rustls client. It resolves the host,
  refuses it if any address is not globally routable (loopback, private,
  CGNAT, link-local and cloud metadata, unique local IPv6, multicast,
  documentation ranges, and IPv6 forms embedding such IPv4 addresses), then
  connects to the vetted address itself so DNS rebinding can't redirect it.
  Redirects are never followed and each attempt is capped at 10 seconds.
- `sign` produces and verifies `X-Signature-256: sha256=<hex>` over
  `"{timestamp}.{body}"`.
- `deliver` retries network errors, `5xx`, `408` and `429` after 2 s, 10 s
  and 60 s. Repeated failures pause the webhook in the server (it stays
  enabled and retries slowly); they do not turn it off.
- `filter` judges each new message by its mailbox's filter rules (`Rule`,
  `CompiledRules`): allow and block rules on the sender, its domain, the
  recipients or the subject
  ([`docs/webhooks.md`](../../docs/webhooks.md#filter-rules)).

How long events are kept, and how many, is set per account: 7 days and
1000 events by default, up to 30 days and 10000. Both limits count
delivered and undelivered events. The receiver's documentation, including
the outbox, is in [`docs/webhooks.md`](../../docs/webhooks.md).
