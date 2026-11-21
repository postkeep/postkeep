# Gmail

postkeep connects a Gmail account in one of two ways:

- **With a Google app password**, over IMAP and SMTP. Your server needs
  nothing at Google: the `gmail` preset is offered by default
  ([mail providers](../configuration.md#mail-providers)). See
  [Connect with an app password](#connect-with-an-app-password).
- **With Sign in with Google**, through the Gmail API, once you register
  a Google Cloud OAuth client. See [Sign in with Google](#sign-in-with-google)
  and the numbered steps after it.

An address is connected one way at a time. To switch, delete it on
postkeep's account page, then connect it the other way.

## Connect with an app password

Google says "App passwords aren't recommended and are unnecessary in most
cases" and prefers Sign in with Google
([Google: Sign in with app passwords](https://support.google.com/accounts/answer/185833)).
If Google stops accepting them, switch to Sign in with Google.

1. Turn on [2-Step Verification](https://support.google.com/accounts/answer/185839)
   for the Google Account. App passwords need it.
2. Create an app password at
   [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
   Google may ask you to sign in again. Copy the password; if you lose
   it, create another.
3. On postkeep's sign-in page, enter the Gmail address and paste the
   16-character password. Spaces don't matter. For a Google Workspace
   address on your own domain, choose **Gmail** as the provider.

The app password option can be missing for an account whose 2-Step
Verification uses only security keys, an account with Advanced
Protection, and a work, school or other organization account
([Google](https://support.google.com/accounts/answer/185833)). A Google
Workspace account also needs its admin to turn IMAP on and to allow all
mail clients, not only OAuth ones, and the user to turn IMAP on in
Gmail's settings (Forwarding and POP/IMAP)
([Google: Turn POP & IMAP on or off](https://knowledge.workspace.google.com/admin/sync/turn-pop-and-imap-on-or-off-for-users)).
Personal accounts always have IMAP on
([Google](https://support.google.com/mail/answer/7126229)). An account
that can't use an app password can use Sign in with Google.

- **A new Google Account password revokes every app password**
  ([Google](https://support.google.com/accounts/answer/185833)). Gmail
  then rejects postkeep's sign-ins: the webhook status turns
  `needs_password`, and the new-mail watcher stops after three rejections
  ([webhooks](../webhooks.md#how-new-mail-is-detected)). Create a new app
  password and enter it on the account page.
- **Gmail saves sent mail itself**, so postkeep adds no copy to Sent,
  whatever `save_to_sent` says
  ([Google](https://support.google.com/mail/answer/78892)).
- **Deleting moves a message to Gmail's Trash**, which Gmail empties after
  30 days ([Google](https://support.google.com/mail/answer/7401)).
  If the message is already in Trash, the answer says so.
  `permanent` is refused: on Gmail it would only take the message out of
  one folder, and it would stay in All Mail
  ([Google](https://support.google.com/mail/answer/78892)).
- **Labels are IMAP folders**, Gmail's own under `[Gmail]/` or
  `[GoogleMail]/`
  ([Google](https://developers.google.com/workspace/gmail/imap/imap-extensions)).
  Message ids start with `imap.` and change when a message moves.
  New-mail webhooks watch the Inbox over IMAP, as for the other app
  passwords, with no Pub/Sub.
- **Connections.** Gmail ends a session after about 24 hours, and
  postkeep connects again
  ([Google](https://developers.google.com/workspace/gmail/imap/imap-smtp)).
  Google allows up to 15 email clients at a time and may then answer
  "Too many simultaneous connections"
  ([Google](https://support.google.com/mail/answer/7126229)). Each
  postkeep server process opens at most
  [`POSTKEEP_ACCOUNT_CONCURRENCY`](../configuration.md#request-limits)
  (4 by default) IMAP connections per account for tool calls, and while
  a webhook is on, its watcher holds one more.
- **Sending limits.** A personal account that sends more than 500
  messages a day, or one message to more than 500 recipients, can't send
  for 1 to 24 hours; work and school accounts have their own limits
  ([Google](https://support.google.com/mail/answer/22839)).
- **Google may send a security alert** for the first sign-in from your
  server ([Google](https://support.google.com/accounts/answer/2590353)).
- **Use one form of the address.** With dots added, or with
  `@googlemail.com` for `@gmail.com`, an address reaches the same mailbox
  ([Google](https://support.google.com/mail/answer/10313)), but postkeep
  and `POSTKEEP_ALLOWED_EMAILS` take it for another address.

## Sign in with Google

With a Google Cloud OAuth client, the sign-in page offers **Sign in with
Google**. postkeep then reads and sends mail through the Gmail API. Gmail
labels appear as folders (`INBOX`, `Sent`, `Trash`, `Spam`, `Starred`,
`All Mail` and your own labels). New-mail webhooks additionally need Cloud
Pub/Sub, set up in [step 5](#5-new-mail-webhooks-cloud-pubsub).

> [!IMPORTANT]
> **Gmail users must sign in again every 7 days until you publish the
> app.** For a personal or family server, one click fixes it: see
> [Stop the weekly re-sign-in: publish your app](#stop-the-weekly-re-sign-in-publish-your-app).

You need:

- a public HTTPS address for postkeep (`POSTKEEP_PUBLIC_URL`, for example
  `https://mail.example.com`);
- a Google account that can create Google Cloud projects (billing isn't
  needed for the Gmail API; Pub/Sub's free tier covers a personal server).

The steps below use `https://mail.example.com`; replace it with your own
`POSTKEEP_PUBLIC_URL`, exactly as you set it (no trailing slash).

## 1. Create a project and enable the APIs

1. Open the [Google Cloud console](https://console.cloud.google.com),
   open the project picker and select **New project**. Name it, for
   example, `postkeep`, and create it. Note its **Project ID** (shown in the
   project picker and on the dashboard); step 5 needs it.
2. Go to **APIs & Services** > **Library**, search for **Gmail API** and
   select **Enable**.
3. For new-mail webhooks, also enable **Cloud Pub/Sub API**.

## 2. Configure the Google Auth Platform

The consent screen settings live under **Google Auth Platform** (in the
console menu, or search for it). If the project has none yet, select
**Get started** and fill in the app name and support email.

1. **Branding**: app name (users see it, for example `postkeep`), user
   support email and developer contact email. For a production app, also
   add the home page, privacy policy link and your domain under
   **Authorized domains**.
2. **Audience**: choose the **user type**.
   - **Internal**: only if every user belongs to your Google Workspace
     organization. Internal apps need no verification. Not available for
     personal Gmail accounts.
   - **External**: everyone else. A new external app starts in
     **Testing**; add every Gmail address that will sign in under **Test
     users** (up to 100). Then
     [publish it](#stop-the-weekly-re-sign-in-publish-your-app).
3. **Data Access** > **Add or remove scopes**. Add these, then **Update**
   and **Save**:

| Scope | Type | Why |
| ----- | ---- | --- |
| `openid` | Non-sensitive | A stable account id |
| `https://www.googleapis.com/auth/gmail.modify` | Restricted | Read, search, label, archive and trash messages; create labels |
| `https://www.googleapis.com/auth/gmail.send` | Sensitive | Send and reply |

postkeep requests nothing else: not the full `https://mail.google.com/`
scope, so it can't permanently delete mail (deleting moves messages to
Trash, and the `permanent` option of the delete tool is refused for Gmail
accounts), and not `email` or `profile` (the address comes from the Gmail
profile).

## 3. Create the OAuth client

1. **Google Auth Platform** > **Clients** > **Create client**.
2. **Application type**: **Web application**. **Name**: `postkeep`.
3. **Authorized redirect URIs** > **Add URI**:
   `https://mail.example.com/oauth/google/callback`. It must match exactly:
   `https`, your host, this path, no trailing slash. No JavaScript origins
   are needed.
4. Select **Create** and copy the **Client ID** and **Client secret**.
   Copy the secret right away; the console may not show it again. If you
   lose it, add a new secret to the client, update postkeep, then disable
   the old one.

## 4. Configure postkeep

Set these on the server, as
[Changing a setting](../deployment.md#changing-a-setting) shows for your install:

```text
POSTKEEP_GOOGLE_CLIENT_ID=<Client ID>
POSTKEEP_GOOGLE_CLIENT_SECRET=<Client secret>
```

Once the server has started again, its log names the redirect URI it uses:

```
sign-in with Google enabled redirect_uri=https://mail.example.com/oauth/google/callback
```

The sign-in and account pages now show **Sign in with Google**. Google's
consent screen lets people untick permissions; postkeep refuses the
sign-in (and revokes the grant) unless Gmail access was granted. If you set
`POSTKEEP_ALLOWED_EMAILS`, list the Gmail addresses there too.

## Stop the weekly re-sign-in: publish your app

### Why tokens expire after 7 days

A new **External** app starts with the publishing status **Testing**.
For such an app Google issues refresh tokens that expire after 7 days,
unless the app asks only for name, email and profile, which postkeep
doesn't: it needs Gmail access
([Google: refresh token expiration](https://developers.google.com/identity/protocols/oauth2#expiration)).
When the token expires, postkeep can no longer reach the mailbox, marks the
account and shows "sign in again" on the account page. MCP tools fail for
that account until the user signs in with Google again.

Testing also limits sign-in to the test users you listed, at most 100
([Google: Manage App Audience](https://support.google.com/cloud/answer/15549945)).

### Publish the app (personal, family or small-team servers)

1. Open the [Google Cloud console](https://console.cloud.google.com) and
   select your postkeep project.
2. Go to **Google Auth Platform** > **Audience**.
3. Under **Publishing status** (it says *Testing*), select **Publish app**
   and confirm. The status changes to **In production**.

What changes:

- **No more 7-day expiry.** The weekly limit only applies to apps in
  Testing. Refresh tokens can still stop working for the usual reasons:
  the user revokes access, changes their Google password (tokens with Gmail
  scopes are revoked then), or the token goes unused for six months. In
  those cases postkeep asks the user to sign in again
  ([Google: refresh token expiration](https://developers.google.com/identity/protocols/oauth2#expiration)).
- **Anyone with a Google account can try to sign in**, not just test
  users. Keep `POSTKEEP_ALLOWED_EMAILS` set so postkeep only accepts the
  addresses you expect.
- **Users see "Google hasn't verified this app"** before the consent
  screen, because the app requests restricted and sensitive scopes without
  having been verified. To continue, they select **Advanced**, then **Go to
  <app name> (unsafe)**, and then approve the permissions as usual
  ([Google: Unverified apps](https://support.google.com/cloud/answer/7454865);
  the click-through is described in
  [Google's Device Access guide](https://developers.google.com/nest/device-access/authorize)).
  The warning is about trusting whoever runs the server, so only send
  people through it who trust you as the operator.
- **A cap of 100 users for the project's lifetime.** An app that shows the
  unverified screen can be authorized by at most 100 new users in total.
  The count can't be reset
  ([Google: OAuth user cap](https://support.google.com/cloud/answer/15549945)).

Running unverified like this is allowed for personal use. Google's
restricted-scope rules list "personal use" as an exception to
verification: you are the only user, "or your app is used by only a few
users, all of whom are known personally to you", who click through the
unverified app screen
([Google: exceptions to verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification#exceptions)).

### Then sign in once more

Publishing doesn't extend tokens that were issued while the app was in
Testing. Each existing Gmail user should sign in with Google once more
after you publish: open the account page and choose **Sign in with
Google**, or connect the MCP client again. The new token is issued by an
app in production and no longer expires after a week.

### When you need verification

Only if you want to:

- remove the "Google hasn't verified this app" screen,
- go beyond 100 users, or
- offer the server to the public.

`gmail.modify` is a **restricted** scope and `gmail.send` is
**sensitive**. Verifying restricted scopes means Google's brand
verification, then restricted-scope review, and, because postkeep's
server handles Gmail data, a security assessment by a Google-approved lab
under the App Defense Alliance's CASA framework. The assessment must be
repeated every 12 months. Plan for weeks of work and usually a fee
([Google: restricted scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification),
[security assessment](https://support.google.com/cloud/answer/13465431),
[annual recertification](https://support.google.com/cloud/answer/13463816)).

### Google Workspace organizations: choose Internal

If every user is in your Google Workspace (or Cloud Identity)
organization and the project belongs to that organization, set the user
type to **Internal** under **Google Auth Platform** > **Audience**.
Internal apps need no verification and show no unverified app warning.
They can't be used by accounts outside the organization or by personal
Gmail accounts. Your Workspace admin may first have to allow
internal apps to use restricted Gmail scopes (Admin console, **Security** >
**API controls**)
([Google: Manage App Audience](https://support.google.com/cloud/answer/15549945),
[Unverified apps](https://support.google.com/cloud/answer/7454865),
[exceptions to verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification#exceptions)).

### Summary

| Setup | Who can sign in | Consent screen | Weekly re-sign-in |
| ----- | --------------- | -------------- | ----------------- |
| External, Testing | Listed test users (up to 100) | Unverified app screen | **Yes**, every 7 days |
| External, In production, unverified | Anyone you allow; 100 users in total, ever | Unverified app screen (Advanced > Go to … (unsafe)) | No |
| External, In production, verified | Anyone you allow | Normal | No |
| Internal (Workspace) | Members of your organization | Normal | No |

## 5. New-mail webhooks (Cloud Pub/Sub)

Gmail doesn't call webhooks directly. It publishes a notification to a
Pub/Sub **topic** in your project, and a **push subscription** delivers it
to postkeep at `POST https://mail.example.com/push/google`, signed with a
Google OIDC token for a service account you choose. postkeep checks that
token's signature, issuer, audience, expiry and service account before
doing anything.

The topic must be in the **same project** as the OAuth client from step
3; Gmail refuses topics from other projects.

### In the console

1. **Create the topic.** **Pub/Sub** > **Topics** > **Create topic**.
   Topic ID: `postkeep-gmail`. Untick **Add a default subscription** and
   create it. Its full name is
   `projects/<PROJECT_ID>/topics/postkeep-gmail`.
2. **Let Gmail publish to it.** Open the topic > **Permissions** (or
   **Show info panel**) > **Add principal**. Principal:
   `gmail-api-push@system.gserviceaccount.com`. Role: **Pub/Sub
   Publisher**. Save.
3. **Create a service account for the push.** **IAM & Admin** > **Service
   accounts** > **Create service account**. Name: `postkeep-push`. It needs
   no roles; select **Done**. Its email is
   `postkeep-push@<PROJECT_ID>.iam.gserviceaccount.com`.
4. **Let Pub/Sub sign tokens for it.** **IAM & Admin** > **IAM**: tick
   **Include Google-provided role grants**, find the Pub/Sub service agent
   `service-<PROJECT_NUMBER>@gcp-sa-pubsub.iam.gserviceaccount.com`, and
   make sure it has the **Service Account Token Creator** role (edit it and
   add the role if not). The project number is on the project dashboard.
5. **Create the push subscription.** **Pub/Sub** > **Subscriptions** >
   **Create subscription**:
   - Subscription ID: `postkeep-gmail-push`
   - Topic: `projects/<PROJECT_ID>/topics/postkeep-gmail`
   - Delivery type: **Push**
   - Endpoint URL: `https://mail.example.com/push/google`
   - Tick **Enable authentication**, service account `postkeep-push`
   - Audience: `https://mail.example.com/push/google` (the same as the
     endpoint)
   - Retry policy: **Retry after exponential backoff delay**
   - Leave the rest as is and select **Create**.

   If creating it fails with "permission denied", your user needs the
   **Service Account User** role on `postkeep-push`.

### With gcloud

The same setup from a terminal (replace the first three values):

```sh
PROJECT_ID=my-project
PROJECT_NUMBER=123456789012
PUBLIC_URL=https://mail.example.com

gcloud services enable gmail.googleapis.com pubsub.googleapis.com --project "$PROJECT_ID"
gcloud pubsub topics create postkeep-gmail --project "$PROJECT_ID"
gcloud pubsub topics add-iam-policy-binding postkeep-gmail --project "$PROJECT_ID" \
  --member serviceAccount:gmail-api-push@system.gserviceaccount.com \
  --role roles/pubsub.publisher
gcloud iam service-accounts create postkeep-push --project "$PROJECT_ID"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:service-$PROJECT_NUMBER@gcp-sa-pubsub.iam.gserviceaccount.com" \
  --role roles/iam.serviceAccountTokenCreator
gcloud pubsub subscriptions create postkeep-gmail-push --project "$PROJECT_ID" \
  --topic postkeep-gmail \
  --push-endpoint "$PUBLIC_URL/push/google" \
  --push-auth-service-account "postkeep-push@$PROJECT_ID.iam.gserviceaccount.com" \
  --push-auth-token-audience "$PUBLIC_URL/push/google"
```

### Tell postkeep

Set these on the server, as
[Changing a setting](../deployment.md#changing-a-setting) shows for your install:

```text
POSTKEEP_GOOGLE_PUBSUB_TOPIC=projects/<PROJECT_ID>/topics/postkeep-gmail
POSTKEEP_GOOGLE_PUBSUB_SERVICE_ACCOUNT=postkeep-push@<PROJECT_ID>.iam.gserviceaccount.com
# Only if you set a different audience on the subscription:
# POSTKEEP_GOOGLE_PUBSUB_AUDIENCE=https://mail.example.com/push/google
```

Once the server has started again, its log shows
`Gmail push through Pub/Sub enabled`.
When a user turns on the webhook for a Gmail account, postkeep calls
Gmail's `users.watch` for the Inbox and renews it every day (a watch
lapses after 7 days). Each push only tells postkeep to look: it then reads
the mailbox history since the last event it recorded, so replayed or
duplicated pushes can't produce duplicate events, and if the stored
history has expired it resyncs from the newest message it already
reported.

## Disconnecting

Where to remove postkeep's access at Google, both ways:
[Disconnect](../clients.md#disconnect).

## Troubleshooting

| Message | Cause |
| ------- | ----- |
| `Gmail didn't accept that address and password` on the sign-in page | The app password is wrong or was revoked (a new Google Account password revokes them all), the wrong provider was chosen (for an address on a custom domain, the provider picked is used, and the message names it), or more than 15 mail clients are connected. For a Workspace account, also check with the admin that IMAP is on for all mail clients, and that IMAP is on in the user's Gmail settings |
| The webhook status is `needs_password` | Google rejected the stored app password; create a new one and enter it on the account page |
| `Error 400: redirect_uri_mismatch` | The client's redirect URI differs from `{POSTKEEP_PUBLIC_URL}/oauth/google/callback` |
| `Error 403: access_denied` ("has not completed the Google verification process") | The app is in Testing and the address isn't a test user |
| `invalid_client` | Wrong client secret, or the secret was disabled |
| The account page asks to sign in again every week | The app is in Testing; [publish it](#stop-the-weekly-re-sign-in-publish-your-app), then sign in once more |
| No webhook events for Gmail with Sign in with Google | Check the topic permission for `gmail-api-push@system.gserviceaccount.com`, the subscription's endpoint, service account and audience, and postkeep's log: a `refused a Pub/Sub push` line names the claim that didn't match |
| `Gmail push needs Google sign-in and POSTKEEP_GOOGLE_PUBSUB_TOPIC` in the log | Set the variables from [step 5](#tell-postkeep) |
| `Invalid topicName` from Gmail | The topic is in another project than the OAuth client, or its name is misspelled |
