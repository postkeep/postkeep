# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-11-21

### Breaking changes

- *(mcp)* [**breaking**] forward a message with its attachments
- *(mcp)* [**breaking**] attach files to new mail, replies and drafts
- *(mcp)* [**breaking**] act on a search's matches without listing their ids
- *(mcp)* [**breaking**] act on up to 1,000 messages in one call
- *(mcp)* [**breaking**] hold a send for the user's yes where the embedding asks
- *(actions)* [**breaking**] say per message what a dry run, a change and a repeat find
- *(imap)* [**breaking**] check each listed message against the search's header filters
- *(search)* [**breaking**] make every filter hold for a search and its selection
- *(mail)* [**breaking**] have replies name recipients when the Reply-To, To or Cc does not read as addresses
- *(server)* [**breaking**] show a sender that does not read as one address whole, and have replies to it name recipients
- *(server)* [**breaking**] refuse tool arguments that a tool does not take, naming them
- [**breaking**] check message ids against the folder's UIDVALIDITY

### Added

- *(mail)* send large Outlook messages through a draft
- *(mail)* send large Gmail messages through Gmail's upload route
- *(mail)* move, flag and trash many IMAP messages per command
- *(mcp)* add tool titles and server metadata
- *(auth)* the usage hook hears how each tool call ended
- *(server)* an embedding can hand the server its listener
- *(site)* postkeep.dev in the v4 brand
- *(server)* let agents save drafts in IMAP mailboxes without sending them
- *(server)* let an embedding word what the webhook tools say about a problem
- *(server)* return In-Reply-To and References from get_message
- *(server)* download_attachment returns text as get_message does, and base64 on request
- *(auth)* an embedding's pages in place of the provider callback's own
- *(auth)* an embedding's page for the requests /authorize refuses
- *(server)* opt-in raw html bodies in get_message
- *(server)* download_attachment tool
- *(server)* links and images in markdown bodies
- *(mail)* attachment ids and attachment content
- *(server)* html-only mail bodies as markdown

### Documentation

- one page for the agent apps, one place for each mailbox fact
- *(site)* build the site's docs pages from docs/
- a short README that starts with a working HTTPS setup
- correct the crate pages and the one-line descriptions
- the README and repository images in the v4 brand
- say how get_message joins the parts a mail app shows, in the tools reference

### Fixed

- *(auth)* let a refresh token presented again within 30 seconds rotate instead of revoking the grant
- say webhook where the tools and the account page said alert
- *(mcp)* make destructive hints explicit
- *(deps)* update rmcp to 3.9.0 and ignore the advisories with no released fix
- *(mail)* read fewer sender forms as one address and judge more in filter rules
- *(server)* end a failed watcher run quietly when its account is gone
- *(server)* end a watch renewal quietly when its account's deletion commits first
- *(watch)* judge every address a mail app may show as the sender in block rules
- *(watch)* judge From in allow rules only when it is one address, alone or after a name
- *(server)* make Gmail search results show the date that since, before and the order use
- *(server)* keep bold and italic in get_message's Markdown
- *(server)* always write get_message's reply_to and search_messages' total_is_estimate
- *(watch)* delete an account's Graph subscription or Gmail watch before the account is deleted
- *(server)* list Outlook mail whose sender has no address, and stop advising a new sign-in for Gmail's daily limit
- *(watch)* harden graph recipient parsing, resume imap only forward, and back off after refused starts
- *(server)* count the lowest font size past the depth browsers nest to in get_message's Markdown
- *(server)* keep moved-text bounds through closed markers and tables in get_message's Markdown
- *(watch)* store a first start's outlook and gmail position only over the one read
- *(watch)* store outlook resume-link bookkeeping only over the position the run read
- *(server)* copy formatting elements back at spaces where the open elements are unknown and at no-break spaces in get_message's Markdown
- *(server)* treat Gmail's 403 rate limits as transient
- *(mail)* withhold text that mail apps may convert otherwise
- *(server)* count the ex sizes of copied formatting elements where they land in get_message's Markdown
- *(mail)* withhold parts whose boundary or charset a mail client may read differently
- *(server)* report filter rules that don't compile as rules_unreadable, with a fix for each cause
- *(mail)* read Content-Transfer-Encoding and the related start as mail clients do
- *(mail)* refuse attachments from where a mail client may read the parts differently
- *(server)* set body_note when get_message's html body is empty
- *(mail)* refuse an attachment whose bytes changed when the parser read it as text
- write brackets and line breaks in display names as escapes, in Gmail events too
- *(server)* filter rules also match text without invisible characters, and allow rules as shown
- *(server)* join the parts a mail app shows besides the body into get_message's body
- *(mail)* read unknown transfer encodings as not decoded, and refuse attachments that did not decode
- *(server)* leave invisible Unicode characters out of message text and webhook events
- *(server)* end a mail's head where browsers do in get_message's Markdown
- *(server)* leave text that font shorthands or size adjustments make tiny out of get_message's Markdown
- *(server)* bound font sizes that misnested formatting elements move in get_message's Markdown
- *(server)* follow table parts and content moved out of tables for font sizes in get_message's Markdown
- *(server)* follow start tags and copied formatting elements for font sizes in get_message's Markdown
- *(server)* follow the elements browsers close for font sizes in get_message's Markdown
- *(server)* say in body_note why get_message's body is empty
- *(server)* leave text in tiny fonts out of get_message's Markdown
- *(server)* never give get_message the plain-text part in place of an HTML part
- *(mail)* read a text/markdown part as the body, not as an attachment
- *(server)* leave faint text out of get_message's Markdown
- *(server)* leave svg, math and select content out of get_message's Markdown
- *(server)* leave elements hidden by inline styles out of get_message's Markdown
- *(server)* leave hidden elements out of get_message's Markdown
- *(server)* read tags, raw text and entities in mail HTML as browsers do

### Maintenance

- *(watch)* wait on the event, not the clock, in the watcher tests
- *(watch)* wait for the watcher's decision before moving the paused clock
- *(server)* make the sign-in wait also wait for the outbox pumps
- *(server)* wait for sign-in watchers to stop in every test that then saves a webhook
- *(server)* wait for the sign-in's watcher to stop before saving a webhook
- *(server)* pin the Markdown of normal mail

### Performance

- *(store)* find the outboxes the purge prunes without reading every event

## 0.3.3 - 2026-10-21

Upgrading from 0.3.2 or earlier: 0.3.3 writes passwords, webhook secrets,
events, provider tokens and sign-ins in progress under data keys, and shortly
after its first start it moves every value that an earlier version stored to
a data key. Stop every instance of 0.3.2 or earlier, then start 0.3.3; do not
roll them one at a time, and do not go back to 0.3.2 once 0.3.3 has run: it
cannot open those values, and it stops at start on the migrations it does not
know. An image from `main` (`latest`, `main` or a commit hash) built from a
commit before the 0.3.3 release commit reports 0.3.2 too; Upgrading in
`docs/deployment.md` tells which of those already use data keys.

### Added

- *(server)* postkeep storage-level shows and raises the storage level
- *(store)* read and raise the storage level, and gate a newer format on it
- *(server)* count mail logins, sends, watchers and database connections
- *(server)* serve Prometheus metrics on a separate port
- *(server)* structured request logs with principal, tool and outcome
- *(store)* destroy a tenant's data keys
- *(store)* stop using the data keys of a destroyed tenant
- *(auth)* edit webhook filter rules on the account page
- *(auth)* add webhook filter rules on the account page
- *(auth)* turn each webhook filter rule on or off on the account page
- *(auth)* remove webhook filter rules on the account page
- *(auth)* list the webhook filter rules on the account page
- *(store)* change a filter rule in its place
- *(store)* turn a filter rule off and on
- *(server)* let agents list, add and remove webhook filter rules
- *(watch)* judge each new outlook and gmail message by the rules
- *(watch)* tell the person and the agent that the stored password was rejected
- *(watch)* judge each new IMAP message by the mailbox's rules
- *(store)* record the storage level and refuse to start above it
- *(mail)* add a Gmail preset for app passwords
- *(webhook)* judge a message by filter rules
- *(mail)* refuse a permanent delete where it only removes a label
- *(store)* keep webhook filter rules with each pattern encrypted
- *(server)* migrate stored values in the background
- *(mail)* leave the Sent copy to servers that file sent mail
- *(store)* move v1 values to data keys in the sweep
- *(store)* write sign-ins under data keys
- *(store)* write provider tokens under data keys
- *(store)* write event payloads under data keys
- *(store)* write passwords and webhook secrets under data keys
- *(store)* make a new data key when none of a tenant's can be unwrapped
- *(store)* re-wrap data keys when the wrapping key changes
- *(store)* read v2 ciphertexts of provider tokens and sign-ins
- *(store)* read v2 ciphertexts bound to tenant, column and row
- *(store)* envelope encryption with a pluggable key wrapper
- *(site)* docs pages with sidebar, pager and search
- *(auth)* explain admin-consent and unverified-publisher errors
- *(watch)* periodic Graph catch-up
- *(server)* enforce MCP Origin checks
- *(watch)* mailbox ownership hook for watchers and provider pushes
- *(server)* outbox ceilings from the usage hook
- *(server)* usage hook before tool calls and sends
- *(auth)* usage hook before a sign-in adds a mailbox
- *(server)* let an embedding turn down tool calls before they run
- *(server)* an embedding's own tools on the MCP endpoint
- *(auth)* upstream sign-in with a continuation hook
- *(auth)* sign-in hook for an embedding's own resources
- *(auth)* let embedding resolvers take this server's access tokens
- *(store)* external principals on OAuth grants and codes
- *(server)* resources under a path prefix, and resolvers see the resource
- *(server)* let an embedding open the store and share its pool
- *(server)* readiness endpoint and drain on shutdown
- *(server)* mailbox selector for principals with several mailboxes
- *(store)* tenant scope for mailbox records
- *(server)* per-request resource metadata and wildcard allowed hosts
- *(auth)* pluggable principal resolver for the MCP endpoint
- *(cli)* add a migrate subcommand for release commands
- *(store)* configurable database pool and connection lifetimes
- *(auth)* accept OAuth Client ID Metadata Documents

### Changed

- *(store)* describe each swept column by its slot, tenant and row key
- *(store)* return the wrapping key from KeyWrapper::wrap
- *(store)* per-backend migrators with a shared 0001-0008 prefix
- *(server)* split serve() into a reusable ServerBuilder

### Documentation

- name Gmail with an app password wherever providers are listed
- sweep the master-key wording for data keys
- webhook filter rules
- embedding postkeep and its extension points
- update the README banner and OG card to the new hero text
- sweep README, docs and metadata for the new brand and GitLab host

### Fixed

- *(deps)* update rustls-webpki and webpki-roots for RUSTSEC-2026-0381 and 0382
- *(deps)* update rustls to 0.23.46 for RUSTSEC-2026-0346 to 0349
- *(watch)* stop watching after the mail server rejects the password
- *(mail)* treat a temporary login refusal as temporary
- *(server)* keep info log lines on PostgreSQL
- *(watch)* hold an event that cannot be opened before skipping it
- *(store)* tell a value in a newer format from an unreadable one
- *(store)* open a sign-in before removing it
- *(auth)* link the admin-consent guide on postkeep.dev
- *(store)* make the rollback helper visible to clippy
- *(store)* roll back sqlite writes before the caller continues
- *(store)* compare-and-set for Graph and Gmail watch positions

### Maintenance

- *(mail)* give each GreenMail test a mailbox of its own and wait for delivery
- *(mail)* check Gmail over IMAP with an app password against a live account
- *(server)* read the counts that a start with previous keys logs
- *(store)* cover the sweep on upgraded databases, in pages and across a crash
- *(store)* cover the sweep against writers, a second sweep and a failing wrapper
- publish the image only when its build inputs change
- *(store)* build previous-key and unreadable values from fixed v1 text
- remove the name-guard job and crate
- *(graph)* recorded fixtures for paging, throttling and lifecycle
- also publish latest on every merge to main
- *(server)* builder cases for default pages and per-request resources
- *(server)* default-build parity with the pinned surface
- *(server)* extension contract suite for every hook
- stamp the release tag version into the image
- run on the ephemeral runner and isolate the idle stop test
- make the test job pass on the runners and always upload its report
- add the name guard for merge requests, new commits and artifacts
- *(server)* pin the 12 tools, their schemas and annotations

### Performance

- *(store)* leave values under data keys unread in the sweep

## 0.3.2 - 2026-10-09

### Added

- *(webhooks)* make outbox limits a per-account setting with MCP controls (#88)

### Documentation

- *(deployment)* pin the example image tag to 0.3.1 (#86)

### Fixed

- *(auth)* show when the email domain overrides the picked mail provider (#87)

## 0.3.1 - 2026-10-09

### Added

- *(webhooks)* recover automatically and add MCP webhook controls (#85)

### Documentation

- add the 0.3.0 database upgrade note and correct stale examples and help strings (#81)

### Fixed

- *(watch)* address audit round 8 findings in graph subscription lifecycle and cleanup (#82)
- *(auth)* address audit round 7 findings in account recovery, code exchange and session rotation (#79)
- *(watch)* address audit round 7 findings in watcher replacement and outlook search paging (#78)

## 0.3.0 - 2026-10-08

Upgrading from 0.2.x with the default SQLite path: 0.3.0 looks for
`postkeep.db` instead of `icloud-mail-mcp.db`, so rename the existing file
to `postkeep.db` (in the image, `/data/postkeep.db`) or point
`POSTKEEP_DATABASE_URL` at it before starting. Account-page users sign in
again once. If 0.3.0 has already started and created an empty
`postkeep.db`, stop it and replace that file with your old one.

### Changed

- *(config)* [**breaking**] read only POSTKEEP_* environment variables (#72)

### Fixed

- *(watch)* address audit round 6 findings in gmail history labels and watcher replacement (#75)
- *(auth)* address audit round 6 findings in authorize form origin and sign-in limit docs (#73)

## 0.2.2 - 2026-10-08

### Documentation

- *(site)* correct accuracy issues from the marketing review (#65)
- *(site)* add the visual hero landing page (#57)
- *(providers)* explain publishing the Google app to stop weekly re-sign-in (#55)

### Fixed

- *(watch)* address audit round 5 findings in imap backlog expunge and catch-up retries (#69)
- *(server)* address audit round 4 findings in outlook search, watcher allow-list and imap backlog (#67)
- *(server)* address audit round 3 findings in html conversion, push keys, graph reauthorization and key rotation (#64)
- *(watch)* address audit round 2 findings in catch-up, coalescing and the outbox (#61)
- *(security)* address audit round 2 findings in redirects, sign-in, tokens and logging (#60)
- *(watch)* address audit round 1 findings in provider watchers and refresh (#59)
- *(security)* address audit round 1 findings in auth, logging and webhook delivery (#58)

## 0.2.1 - 2026-10-08

### Documentation

- *(providers)* set up Outlook and Gmail sign-in and push (#50)

### Fixed

- *(security)* harden provider sign-in and push from the Phase 2 review (#52)

## 0.2.0 - 2026-10-08

The first release as **postkeep** (formerly icloud-mail-mcp). Upgrading from
0.1.0 keeps every account, connected app, token, account-page session and
webhook: the database file, cookie names, encryption contexts and token
formats are unchanged, and the old `ICLOUD_MAIL_MCP_*` variables still work.

### Breaking changes

- The project, crates, binary and image are renamed to postkeep. The image is
  now named `postkeep`, and `POSTKEEP_*` is the canonical
  environment prefix; the `ICLOUD_MAIL_MCP_*` names are read as fallbacks
  and log a warning (#28)
- postkeep is now licensed under MIT only, no longer under MIT OR Apache-2.0
  (#46)
- MCP tools address messages by an opaque `id`. IMAP accounts still accept
  and return `folder` + `uid`, so existing clients keep working
  (#38)

### Added

- *(gmail)* read, label and send Gmail through the Gmail API (#42)
- *(graph)* read, organize and send Outlook mail through Microsoft Graph (#41)
- *(auth)* sign in with Microsoft and Google (#40)
- *(upstream)* add the Microsoft and Google OAuth client with token refresh (#39)
- *(graph)* push new Outlook mail through Graph change notifications (#45)
- *(gmail)* push new Gmail mail through Pub/Sub watch notifications (#47)
- *(webhook)* deliver new-mail events in order through a durable outbox, with an `X-Webhook-Sequence` cursor (#43)
- *(auth)* redesign the account page with per-app revoke and password update (#36)
- *(auth)* redesign the sign-in and message pages (#34)
- Fastmail and Yahoo Mail IMAP presets with a provider picker, alongside an optional operator-configured IMAP server (#31)
- *(store)* add provider accounts, upstream tokens, push state and the event outbox (#29)

### Changed

- *(server)* address messages by opaque ids behind a mailbox abstraction (#38)
- [**breaking**] rename the project to postkeep (#28)
- [**breaking**] relicense under MIT only (#46)

### Notes

- Outlook and Gmail need an Entra app registration or a Google Cloud OAuth
  client (`POSTKEEP_MICROSOFT_*`, `POSTKEEP_GOOGLE_*`); without them postkeep
  offers IMAP sign-in only, as before. Gmail push alerts also need a Pub/Sub
  topic and push subscription (`POSTKEEP_GOOGLE_PUBSUB_*`). Step-by-step
  console guides and the Phase 2 security review land after this release.
- Rolling back to 0.1.0 needs the database backup taken before upgrading:
  0.2.0 applies a schema migration that 0.1.0 refuses to start with.

### Documentation

- add the landing page (#35)
- add postkeep brand assets (#32)

### Maintenance

- *(release)* stop looking up new library crates in the last release tag (#44)
- *(release)* bridge the v0.1.0 tag across the package rename (#30, #37)

## 0.1.0 - 2026-10-08

### Added

- *(server)* deliver opt-in new-mail webhooks per account (#19)
- *(webhook)* add SSRF-safe signed webhook delivery (#18)
- *(auth)* add an account page to disconnect apps and delete data (#17)
- *(mail)* watch a folder for new messages with IDLE (#16)
- *(store)* support master key rotation (#14)
- *(auth)* port the redesigned sign-in and message pages (#12)
- *(server)* add request timeouts, body, connection and concurrency limits (#11)
- *(auth)* add sign-in backoff, rate limits and client registration limits (#10)
- *(server)* add MCP server with mail tools over Streamable HTTP (#5)
- *(auth)* add OAuth 2.1 authorization server and sign-in page (#4)
- *(store)* add encrypted SQLite/PostgreSQL storage (#3)
- *(mail)* add the icloud-mail crate with IMAP and SMTP support, workspace tooling and CI

### Fixed

- *(auth)* refuse whitespace and control characters in redirect URIs (#24)
- *(server)* apply the email allow-list to new-mail watchers (#23)
- *(auth)* revoke grants on code or refresh token replay and stop open redirects (#21)
- *(mail)* infer folder roles by name when the server does not advertise them (#9)

### Performance

- *(server)* reuse idle IMAP sessions per account (#13)

### Documentation

- *(security)* add the October 2026 audit and threat model (#27)
- *(deploy)* add deployment guides and host-agnostic examples (#7)

### Maintenance

- *(deps)* bump tower-http from 0.6.11 to 0.7.1 (#26)
- *(ci)* pin actions and the runtime base image by digest (#22)
- *(fuzz)* add cargo-fuzz targets for untrusted input (#20)
- *(docker)* add the container image and release workflow (#6)
