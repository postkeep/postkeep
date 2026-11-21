# New-mail webhooks

postkeep can POST a small JSON event to a URL of your choice when new
mail arrives in your Inbox. Webhooks are opt-in per account: sign in at
`/account` on your server, switch the "Webhook" section On,
fill it in and press Save. Once it is saved, "Send test event" saves
any changes and sends one sample event right away.

Operators can turn the feature off with `POSTKEEP_WEBHOOKS=false`.
Watchers only run while the server does, so platforms that stop idle
instances must keep one running; see
[deployment](deployment.md#new-mail-webhooks).

## How new mail is detected

| Account | How postkeep learns about new mail |
| ------- | ---------------------------------- |
| iCloud, Fastmail, Yahoo, Gmail with an app password, custom IMAP | An IMAP `IDLE` connection to the Inbox, or a 60-second poll when the server has no IDLE |
| Outlook (Microsoft) | A Microsoft Graph change-notification subscription; Graph calls `POST /push/microsoft` (and `/push/microsoft/lifecycle`) on your server |
| Gmail with Sign in with Google | Gmail `users.watch` through Google Cloud Pub/Sub; a push subscription calls `POST /push/google` on your server |

A Gmail account connected with an app password is an IMAP account, so the
first row applies to it. Elsewhere on this page, Gmail means Sign in with
Google.

Outlook and Gmail need sign-in with that provider configured, and Gmail
additionally needs a Pub/Sub topic and push subscription; see
the [Outlook](providers/microsoft.md#5-new-mail-webhooks) and [Gmail](providers/google.md#5-new-mail-webhooks-cloud-pubsub) guides. A
notification from Microsoft or Google is only a hint. postkeep then reads
mail added since the last event it recorded, and retries of one event keep
the same `X-Webhook-Id`. Graph does not promise to deliver every
notification, so postkeep also reads the Outlook Inbox every 15 minutes
without one. If the stored Gmail history has expired or paging
is cut off, postkeep lists at most one page of 50 Inbox messages and then
moves to the current history id, so older messages past that page are not
reported. An IMAP backlog is read oldest first in chunks of at most 50
messages, each one event unless the [filter rules](#filter-rules) let none
of it through, before the watcher goes back to waiting for new mail.
A gap in `X-Webhook-Sequence` means events were dropped.

An Outlook or Gmail catch-up that fails because the provider or the database
is briefly unavailable (a timeout, a transport error, HTTP 408, 429 or 5xx,
a Gmail 403 whose reason is `userRateLimitExceeded` or `rateLimitExceeded`,
a token refresh that may succeed later, or any database error) is retried
with a doubling backoff, from 5 seconds up to 5 minutes. Retries stop on
shutdown, when the user has turned the webhook off, when it is missing or
its settings can't be read, when the account is removed or no longer
allowed, when the sign-in is no longer valid, and on any other failure. A
pause after failed deliveries does not stop this catch-up, and it does not
stop renewal: the watcher keeps its slot, Gmail `users.watch` and the Graph
subscription keep renewing on their usual schedule, and new mail is
recorded. A pause does not call the provider more often. Mail recorded
while paused is not delivered before the next pause retry. A new
notification during a failed catch-up runs the next read immediately.
Turning the webhook off stops the watcher and the provider watch.

An IMAP watcher stops when the mail server rejects the stored password three
times in a row, 15 minutes apart; the webhook stays enabled. A tool call whose
IMAP login is rejected is recorded too. The status is then `needs_password`,
new-mail delivery may have stopped, and the account page shows a notice. A new
app password, entered on the account page or at sign-in, clears the record and
gives the watcher three tries. Any other change, or a restart, gives it one. A
login that works clears the record, and when a tool's login does, a stopped
watcher starts again. A busy server or a dropped connection is not a rejection.

## Filter rules

Filter rules choose which new mail sends an event, so an agent wakes only
for the mail it wants. Agents list, add and remove them with
[`list_webhook_filters`](reference/tools.md#list_webhook_filters), [`add_webhook_filter`](reference/tools.md#add_webhook_filter) and [`remove_webhook_filter`](reference/tools.md#remove_webhook_filter).
The rules belong to the mailbox's webhook: the tools need a saved webhook,
and they apply to the signed-in mailbox. The rules stay when the webhook is
turned off or its URL changes, and go when the account's data is deleted.
The account page (`/account`) lists them, oldest first, and shows whether each
is on, off or past the limit, or why it holds the mail (see
[Unreadable rules](#unreadable-rules)). A person can add rules, change one,
turn each on or off, or remove one or all of them, there. An add or a change there is
checked as the tool checks an add.

### How rules combine

1. With no active rules, every new message sends an event.
2. Once there is an active `allow` rule, a message must match one of them.
3. A message that matches an active `block` rule sends nothing: block wins.

So the first active `allow` rule silences all other mail. Add one only when
the agent should hear about nothing else.

### What a rule is

| Property | Value | Meaning |
| -------- | ----- | ------- |
| `action` | `allow` | Once the mailbox has an active allow rule, only mail that matches one sends an event. |
| `action` | `block` | Mail that matches never sends an event, whatever else matches. |
| `field` | `from` | The sender's address. |
| `field` | `from_domain` | The sender's domain: what follows the last `@`. |
| `field` | `to` | The addresses in To and Cc; the rule matches if any does. |
| `field` | `subject` | The decoded subject. |
| `kind` | `equals` | The whole text is the pattern. |
| `kind` | `contains` | The text contains the pattern. |
| `kind` | `domain` | The address's domain, or the domain itself, is the pattern or a subdomain of it. Takes a plain domain such as `example.com`; not for `subject`. |
| `kind` | `regex` | A regular expression in Rust syntax, without look-around or back-references. |

`pattern` is 1 to 512 bytes. The server sets each rule's `id` and
`added_at`, and adds it turned on (`enabled: true`). A rule turned off
(`enabled: false`) judges nothing. The tools can't turn rules on or off; a
person does that on the account page. A person can also change a rule's
`action`, `field`, `kind` and `pattern` there. It keeps its `id`, `added_at`
and place, stays on or off, and is checked with the rules that are on, as an
add is, even while it is off.

Matching ignores case, with Unicode folding. `regex` follows the
[Rust `regex` crate syntax](https://docs.rs/regex/latest/regex/#syntax). A
regex matches anywhere in the text unless it is anchored with `^` and `$`,
and `.` also matches a line break. The crate matches in time linear in the
text, so look-around and back-references are refused, with the parser's
message, which never repeats the pattern. What the sender controls is cut
before matching: a message is judged on the first 2 KiB of its subject, the
last 320 bytes of each address (the domain stays) and its first 100
recipients. A rule matches each field as it arrived, and in other forms too.
An allow rule also matches the field as `get_message` shows it: in an
address, invisible and control characters are written as visible escapes; in
the subject, invisible characters are left out, except those that emoji and
scripts need, and bidi controls and control characters other than whitespace
are written as escapes. A block rule also matches the field with invisible
characters and control characters left out: the subject keeps whitespace,
line and paragraph separators included, so that words stay apart, while an
address also drops line and paragraph separators and the control characters
that count as whitespace. An allow rule also matches the subject in that
form. Block rules skip the shown form, since its escapes are text the mail
does not hold, and allow rules skip an address with characters left out,
since that is another address. A match in any form counts.

For IMAP and Gmail mail, an allow rule judges the sender's address only when
the message has one `From` header and it holds the address exactly, alone or
after a name and between the header's only `<` and a `>` at its end, as in
`alice@example.com` or `Alice <alice@example.com>`, with one `@`, text before
and after it, and no space, control character or any of `"(),:;<>[\]` in the
address. For Outlook mail, it judges the address Microsoft gives only when
that address meets the same rule. Otherwise an allow rule judges the message
as one without a sender address. So a sender written as
`alice@example.com (Alice)`, with a quoted `<` in the name, with a comment
after the `>`, or with a quoted local part as in `"alice"@example.com` counts
as no sender for allow rules; an allow rule on `to` or `subject` still matches
such mail.

A block rule on `from` or `from_domain` judges the address read from the
header, and also each address found at an `@` in it: the `@` with the
characters an address may hold before it (letters, digits and
``.!#$%&'*+-/=?^_`{|}~``) and the domain after it (letters, digits, `-`, `_`
and dots), without the dots at its end. So `boss@example.com@example.net` is
also judged as `boss@example.com`, and `news@example.com.` as
`news@example.com`. When an allow rule would judge the message as one without
a sender address, a block rule also judges each address found at an `@` in
every `From` header, as it arrived and with invisible and control characters
left out. So a `from_domain` block rule for `example.com` matches
`<news@example.com> alice@example.net`. Addresses are also found as a mail app
may read them: with comments, the text in parentheses outside quoted strings,
left out, and with quoted strings unquoted. A sender that gives more than 100
addresses this way matches every block rule on `from` and `from_domain`.

| Goal | `action` | `field` | `kind` | `pattern` |
| ---- | -------- | ------- | ------ | --------- |
| Only mail from example.com and its subdomains | `allow` | `from_domain` | `domain` | `example.com` |
| Nothing from one newsletter | `block` | `from` | `equals` | `news@example.com` |
| Only subjects that start with `[ticket]` | `allow` | `subject` | `regex` | `^\[ticket\]` |

### Limits

An add, or a change on the account page, is refused when the pattern is
empty or longer than 512 bytes
(`the pattern must be 1 to 512 bytes`), when a `domain` rule looks at the
subject (`a domain rule cannot look at the subject`) or has no plain domain
(`a domain rule needs a plain domain such as example.com: no @, * or spaces, no dot at either end`),
when a `regex` is invalid (the parser's message), and when the mailbox's
rules would be too large to compile together
(`the rules of this mailbox are too large to compile; remove some or simplify them`).

Compiled patterns take at most about 4 MiB per action and field and about
10 MiB per mailbox. On top of that come the reverse automaton and, on each
thread that searches, a cache of up to 2 MiB per set (at most eight sets,
one per action and field). A mailbox's compiled rules are dropped at the
next lookup of any mailbox's rules once they have judged nothing for 10
minutes.

A mailbox counts its oldest rules, as many as `filter_rules_limit`. That is
[`POSTKEEP_WEBHOOK_FILTER_MAX_RULES`](configuration.md#new-mail-webhooks)
(1000 by default, from 0 to 2000), or the number an embedding gives the
mailbox. After the limit is lowered, the newer rules show `active: false`
and judge nothing until older ones are removed or the limit rises. Rules
turned off count toward the limit too, and keep their place, so turning one
off never makes a newer rule active. At the limit an add is refused with
`This mailbox may have at most N filter rules.` Removing always works.

### What happens to the mail

Each new message of a batch is judged. The event describes the newest one
that passes, and `count` is how many passed. If none passes, no event is
sent and the watcher moves on. Mail the rules keep out is neither stored
nor sent and takes no sequence number, so it leaves no gap in
`X-Webhook-Sequence`.

Outlook gets the recipients in the same request. Gmail, with at least one
active rule, makes one request per new message instead of one for the
newest.

Each add or change, each removal that removed something, and each rule
turned on or off restarts the mailbox's watcher: IMAP logs in again, and
Outlook and Gmail read what arrived meanwhile. A refused add, change or
turn-on, or a removal of nothing, changes nothing.

### Unreadable rules

Rules can't be read when an active rule has an action, field or kind this
version doesn't know (it was written by a newer version), or when this
server's keys can't decrypt the pattern of any rule, turned off or not (for
example, the master key changed and the previous one is not in
`POSTKEEP_PREVIOUS_MASTER_KEYS`). Rules that decrypt and parse but don't
compile together, for example after an upgrade changes how the `regex`
crate sizes them, count as unreadable too. The mailbox's
new mail then waits: no event is sent and nothing is skipped, within the
limits in [How new mail is detected](#how-new-mail-is-detected): a Gmail
history that expired meanwhile resyncs one page of 50. Delivering
everything would wake the agent for the mail the rules keep out, and
dropping it would lose webhook calls for good.

While the webhook is on (`active` or `paused`), the status is then
`rules_unreadable`, and its `message` names the cause and its fix;
`needs_password` and an `unreadable` webhook take precedence.
`filter_rules_unreadable` is true, and the server logs
`the filter rules have a name this version does not know; its mail waits`,
`the filter rules can't be decrypted; its mail waits` or
`the filter rules can't be compiled; its mail waits`.

The fix depends on the cause:

- Unknown names: `list_webhook_filters` and the account page show the
  rules as they were written, and the page marks each of them
  `Can't be read`. Run the version that wrote them again, or
  turn those rules off on the account page; there you can then change them
  to names this version knows. Removing them also works, there
  or with `remove_webhook_filter` (`all: true`); then add rules this version
  knows.
- Patterns that can't be decrypted: the list can't show them either and
  answers with the same message. Restore the key that wrote them in
  `POSTKEEP_PREVIOUS_MASTER_KEYS` (see
  [Rotating the master key](configuration.md#rotating-the-master-key)) and
  start the server again with it
  ([changing a setting](deployment.md#changing-a-setting)), since a stopped
  watcher starts again only on a change
  to the mailbox or a restart. Only if that key is gone, remove them all,
  on the account page or with `remove_webhook_filter` (`all: true`), and
  write the rules again from scratch.
- Rules that don't compile: the `message` names the oldest rule that's on
  and doesn't compile with the ones before it, and says whether it doesn't
  compile on its own or makes the rules too large together. The account
  page marks it `Doesn't compile`. Remove it, with `remove_webhook_filter`
  or on the account page, or turn it off there. If newer rules still don't
  fit, the status and the page then name the next one.

In each case, the watcher then starts and reports the mail that waited,
within the same limits: a Gmail history that expired meanwhile resyncs one
page of 50.

### Example: one-time codes

An agent waiting for a sign-in code can add an `allow` rule on `subject`
with kind `regex` and this pattern:

`(code|verification|verify|one-time|passcode|sign[- ]?in|log[- ]?in)`

An `allow` rule on `from_domain` for the sending service's domain is exact.
The subject rule misses codes sent under a neutral subject (such as "Your
account"), in other languages, or with words the pattern lacks. Remove the
rule once the code is in, or all other mail stays silent.

Filters decide what wakes the agent. They don't keep codes or reset links
from an agent that can read the mailbox; see the
[threat model](security/threat-model.md#assumptions-and-residual-risks).

Rules save the agent's tokens. The event is already small: it has no body,
and it carries the sender and subject only with "Include sender and
subject". The agent then searches for what it needs, so keep that setting
off unless the agent needs them before fetching.

## Request

```http
POST /your/path HTTP/1.1
Host: hooks.example.com
Content-Type: application/json
User-Agent: postkeep/<version>
X-Webhook-Id: 0b4e5c1e-3f7d-4f0e-9a43-5d7c0c8e2a11
X-Webhook-Event: new_mail
X-Webhook-Timestamp: 1791432724
X-Signature-256: sha256=5d0c…
Authorization: Bearer …            (only if you set an auth header)

{"event":"new_mail","account":"alice@example.com","folder":"INBOX",
 "id":"imap.4211.SU5CT1g.1789000000","uid":4211,"message_id":"<abc@example.com>","from":"Alice <alice@example.com>",
 "subject":"Lunch?","date":"2026-10-08T02:12:04+00:00","count":1}
```

## Payload

| Field | Type | Description |
| ----- | ---- | ----------- |
| `event` | string | Always `new_mail`. |
| `test` | boolean | `true` on test events sent from the account page (sample data). Absent otherwise. |
| `account` | string | The account's email address. |
| `folder` | string | The folder, currently always `INBOX`. |
| `id` | string | Opaque id of the newest new message that passed the [filter rules](#filter-rules), the same id the MCP tools take. |
| `uid` | integer | IMAP UID of the newest new message. Only present for IMAP accounts; prefer `id`. |
| `message_id` | string or null | Its `Message-ID` header. |
| `from` | string | Its `From` header. Only present when "Include sender and subject" is on. |
| `from_unclear` | boolean | `true` when the sender does not read as one address, alone or after a name: `from` is then its first `From` header whole, as sent, with `<`, `>` and their look-alikes as escapes, and a mail app may show another sender. Absent otherwise, and whenever `from` is absent. Outlook events take the sender's address from Microsoft Graph and never set it. |
| `subject` | string | Its subject. Only present when "Include sender and subject" is on. |
| `date` | string or null | Its `Date` header, RFC 3339. |
| `count` | integer | How many new messages this event covers that passed the filter rules (all of them when there are none): at most 50 for an IMAP event, an Outlook page, and a Gmail resync. An IMAP backlog larger than 50 is read in chunks of 50, oldest first, each one event, before the watcher waits for more mail. A Gmail history catch-up can cover more than 50 in one event. Messages arriving within a few seconds of each other are batched into one event describing the newest of that batch that passed. An Outlook burst larger than one page of 50 is read a page at a time, each page one event, without waiting for another notification. A chunk or page where no message passes sends no event. |

"Include sender and subject" is applied when the event is sent. Turning it
off removes `from`, `from_unclear` and `subject` from events already
queued. Turning it on does not add them to events that were recorded
without them.

The event never contains message bodies. Unknown fields may be added later;
ignore them.

## Headers

| Header | Description |
| ------ | ----------- |
| `X-Webhook-Id` | Unique per event and the same across retries. Use it to drop duplicates. |
| `X-Webhook-Sequence` | The event's number in the account's stream, starting at 1 and increasing by one per event. A gap means events were dropped (for example after the webhook was re-enabled); test deliveries have none. |
| `X-Webhook-Event` | `new_mail`. |
| `X-Webhook-Timestamp` | Unix time (seconds) the event was signed. |
| `X-Signature-256` | `sha256=` and the lowercase hex HMAC-SHA256, if signing is on. |
| your auth header | The name and value you entered, such as `Authorization: Bearer …`. Reserved names (`Host`, `Content-Type`, `X-Webhook-*`, …) can't be used. |

## Verifying the signature

The signature is HMAC-SHA256, keyed with the whole signing secret (including
the `whsec_` prefix), over the timestamp, a dot and the raw body:

```text
signature = hex(HMAC_SHA256(secret, "{X-Webhook-Timestamp}.{raw body}"))
```

Compare in constant time against the `X-Signature-256` value without its
`sha256=` prefix, and reject timestamps more than five minutes away from
your clock to limit replays. Always verify the raw bytes you received, not
re-serialized JSON.

Python:

```python
import hashlib, hmac, time

def verify(secret: str, headers, body: bytes) -> bool:
    timestamp = headers["X-Webhook-Timestamp"]
    if abs(time.time() - int(timestamp)) > 300:
        return False
    expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    received = headers.get("X-Signature-256", "").removeprefix("sha256=")
    return hmac.compare_digest(expected, received)
```

Node.js:

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verify(secret, headers, rawBody) {
  const timestamp = headers["x-webhook-timestamp"];
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const expected = createHmac("sha256", secret).update(`${timestamp}.`).update(rawBody).digest();
  const received = Buffer.from((headers["x-signature-256"] || "").replace(/^sha256=/, ""), "hex");
  return received.length === expected.length && timingSafeEqual(received, expected);
}
```

Rotating the secret on the account page invalidates the old one at once.

## Delivery and retries

- Answer with any `2xx` status within 10 seconds. The response body is
  ignored.
- Network errors, timeouts, `5xx`, `408` and `429` are retried after 2 s,
  10 s and 60 s (four attempts in total).
- Redirects are **not** followed and count as a failure, as do other `4xx`
  statuses. Point the webhook at the final URL.

A webhook is `active` (enabled and delivering), `paused` (enabled, backing
off after failures), or `disabled` (the user turned it off). It can also be
`unreadable` (saved, but no configured key can decrypt it),
`rules_unreadable` (its [filter rules](#unreadable-rules) can't be read or
compiled, so new mail waits), not configured,
or unavailable when the operator set `POSTKEEP_WEBHOOKS=false`. While a
rejected password is on record it is `needs_password` instead.

- After 10 real deliveries in a row fail, the webhook is **paused**, not
  turned off. It stays enabled. The account page shows a Paused status with
  the last error, the last success, and the next retry time. While paused,
  the oldest pending event is tried about once an hour
  (`POSTKEEP_WEBHOOK_RETRY_INTERVAL`, 3600 seconds by default, from 1 to
  86400). New mail does not start an extra attempt on every message. The
  watcher keeps running and recording into the same queue, so mail that
  arrives during the outage is delivered after recovery. The account keeps
  its `POSTKEEP_WEBHOOK_MAX_WATCHERS` slot. IMAP keeps its connection.
  Gmail `users.watch` and the Graph subscription keep renewing on their
  usual schedule (about once a day, or a day before the Graph subscription
  expires). A pause does not shorten that schedule or call the provider
  more often. A push while paused records the new mail and does not
  deliver it before the next slot. If nothing is
  pending, nothing is probed; the next recorded event is tried at the next
  slot. A restart, saving the settings, turning it back on, a successful
  test, or signing in again may try once immediately. After that attempt
  the hourly cadence resumes. A test does not count toward the 10 failures,
  and a test success does not clear the pause. The first
  successful real delivery clears the pause, resets the failure count, and
  the rest of the backlog is then sent promptly, in order, with the
  original `X-Webhook-Id` and `X-Webhook-Sequence`. Turning the webhook off
  on the account page, or with [`set_webhook_enabled`](reference/tools.md#set_webhook_enabled), stops the watcher
  promptly and frees the slot. Gmail is stopped with `users.stop`. The
  Graph subscription is deleted; if that delete fails, the local record is
  kept and the next time the webhook is turned on the subscription is
  renewed or deleted instead of duplicated. There is then no watcher, no
  renewal, and no automatic recovery. Repeated failures never turn a
  webhook off. A pause never becomes that off state by itself.
- Every event is stored (encrypted) before it is sent and numbered per
  account; the number is sent as `X-Webhook-Sequence`. An event that still
  fails after the short retries is kept and sent again later, first after a
  minute and then with a doubling delay capped at the same interval (one
  hour by default), and the events after it wait so the receiver always
  gets them in order. By default events are kept for 7 days, and at most
  1000 per account. Both limits count every kept event, delivered or not:
  a delivered event stays so it can be sent again. Each account can raise
  them, up to 30 days and 10000 events, with
  [`set_webhook_outbox_limits`](reference/tools.md#set_webhook_outbox_limits).
  The account page shows the effective limits and does not edit them.
  `POSTKEEP_WEBHOOK_OUTBOX_RETENTION` (604800 seconds) and
  `POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS` (1000) are the server defaults.
  `POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION` (2592000 seconds, 30 days) and
  `POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT` (10000) are ceilings an
  account cannot pass. The shortest retention is 1 hour and the smallest
  cap is 1 event. An event is a small encrypted JSON payload, about 1 KB
  on disk, so the default is about 1 MB per account and the ceiling about
  10 MB. One hundred accounts at the ceiling is about 1 GB. The event cap
  is what protects the disk: a busy inbox reaches it before the retention
  clock does. Thirty days covers a receiver that stays down for a few
  weeks while the hourly pause retry is still running. Lowering a limit
  deletes the oldest kept events immediately, including ones that were not
  delivered yet. `last_sequence`, `delivered_sequence` and the watch cursor
  do not move backwards, so a gap in `X-Webhook-Sequence` is an event that
  was dropped. If an operator later lowers a ceiling, a stored override
  above it is limited to the new ceiling when events are pruned, and the
  status still reports that value as an account override. Setting a value
  outside the current range is rejected and the error names the allowed
  range. The stored value stays as it was.

> [!TIP]
> A retry after a lost response can repeat an event, so deduplicate on
> `X-Webhook-Id`, which stays the same for every attempt at one event.
> Mail that arrives while the server is stopped is reported when it starts
> again, within the limits in [How new mail is detected](#how-new-mail-is-detected):
> an IMAP backlog is read in chunks of at most 50, oldest first, and a Gmail
> resync lists one page of 50 and then moves to the current history id.

- Turning the webhook back on, or changing its URL, skips the events not
  delivered yet, so a new receiver only sees new mail. Saving a paused
  webhook, still on, with the same URL keeps them: that save clears the
  pause and retries them promptly.
- A server upgraded from a version that turned webhooks off after repeated
  failures pauses those webhooks instead and starts watching again from the
  cursor they already had. Mail that arrived in the Inbox since then is
  reported with the same batching as any other catch-up, still bounded by
  that account's outbox limits (7 days and 1000 events by default, up to
  30 days and 10000). An IMAP backlog is read in chunks of at most 50
  messages, oldest first, and an Outlook catch-up a page of at most 50 at a
  time, each one event when a message in it passes the filter rules. A Gmail account whose stored history id is still valid
  reports every Inbox addition in that history as one event, so `count` can
  be higher than 50 (100 additions is one event with `count` 100). If that
  Gmail history has expired, or history paging is cut off, Gmail lists at
  most one page of 50 Inbox messages and then moves to the current history
  id, so older messages past that page are not reported. A webhook the user
  turned off stays off.
- Existing mail is never reported: watching starts at the newest message
  when the webhook is first enabled, and again if the Inbox's `UIDVALIDITY`
  changes.

[`get_webhook_status`](reference/tools.md#get_webhook_status) and
[`set_webhook_enabled`](reference/tools.md#set_webhook_enabled)
report and turn delivery on or off for the signed-in account.
[`set_webhook_outbox_limits`](reference/tools.md#set_webhook_outbox_limits)
sets how long that account keeps events and how many. Omit a field to leave it
unchanged. JSON null or the string `default` stores the server default
for that field. `reset` true stores the server default for both and
ignores the other fields. `retention` is a whole number of seconds or a
duration such as `36h`, `30d` or `90m`. A value below 1 hour or 1 event,
or above the server's ceiling, is rejected and the error names the
allowed range. The stored value stays as it was. Lowering a limit deletes
the oldest kept events immediately, including ones that were not
delivered, and the result includes `events_pruned` (how many were deleted)
plus the same status fields as `get_webhook_status`. The tool needs a
webhook saved on the account page (`/account`). It works while the webhook
is paused or turned off. The account page shows the effective limits and
does not edit them. All three tools return the URL's host only, never the
full URL, the signing secret, the auth header, or any ciphertext, and
they cannot change the endpoint or its secrets. Set those on the account
page. All three also report the mailbox's filter rules:
`filter_rules_active`, `filter_rules_disabled`, `filter_rules_limit` and
`filter_rules_unreadable` (see [Filter rules](#filter-rules)). When the saved settings can't be decrypted, the status is
`unreadable` and its `message` asks for the URL and auth header to be
entered again on the account page. The host, the last error and the pause
schedule are left out, because they cannot be checked without those
secrets. The outbox limits are still reported: those columns are stored
in the clear. Turning that webhook on is refused, because the watcher
cannot use it; turning it off still works. `set_webhook_outbox_limits`
still works on an unreadable row.

## Which URLs are allowed

To keep the server from being used to reach internal systems (SSRF):

- The URL must be `https`, with a certificate valid for its host, and must
  not contain a user name or password.
- The host must not be, or resolve to, a private, loopback, link-local,
  carrier-grade NAT, multicast, documentation or reserved address. Cloud
  metadata (`169.254.169.254`, `fd00:ec2::254`), unique local IPv6 (such as
  Fly.io's `fdaa::/16` private network) and IPv6 forms embedding such IPv4
  addresses are refused too. If any address a name resolves to is blocked,
  the name is refused.
- Names like `localhost`, `*.local`, `*.internal` and single-label names
  are refused.
- The connection goes to the address that was checked, so a second DNS
  answer can't redirect it.
