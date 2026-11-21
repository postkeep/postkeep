# Recorded Microsoft Graph responses

Responses and notifications that the Graph watcher tests replay through a
mock server (`src/watch/graph_fixtures.rs`). Each follows a shape that
Microsoft documents on Microsoft Learn; ids, times, addresses and subjects
are made up. The tests replace `https://graph.microsoft.com/v1.0/` with the
mock server's address, so every `@odata.nextLink` stays on the endpoint the
server talks to, as it does at Graph.

| File | Status | Shape from (Microsoft Learn) |
| --- | --- | --- |
| `inbox-page-1.json`, `inbox-page-2.json` | 200 | "List messages": messages with `$select`, the first page with an `@odata.nextLink` that repeats the query and adds `$skip` |
| `throttled.json` | 429 with `Retry-After: 10` | "Microsoft Graph throttling guidance", the sample response |
| `unavailable.json` | 503 with `Retry-After: 5` | "Microsoft Graph error responses and resource types": the error resource, code `serviceNotAvailable` |
| `lifecycle-reauthorization-required.json`, `lifecycle-subscription-removed.json`, `lifecycle-missed.json` | sent to the lifecycle URL | "Reduce missing change notifications and removed subscriptions": the lifecycle notification structure |
| `subscription-conflict.json` | 409 | the error resource |
| `subscriptions-page-1.json`, `subscriptions-page-2.json` | 200 | "List subscriptions", where `clientState` is never returned, the first page with an `@odata.nextLink` |
| `subscription-created.json` | 201 | "Create subscription" |

Graph's error messages are not stable, so the server acts on the status
and, where it matters, the error code, never on the message. Microsoft's
Dev Proxy can simulate throttling against a real tenant locally; these
files are what CI runs.
