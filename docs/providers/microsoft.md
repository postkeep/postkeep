# Outlook

With a Microsoft Entra app registration, the sign-in page offers **Sign in
with Microsoft**. It works for personal Microsoft accounts (Outlook.com,
Hotmail, Live) and for Microsoft 365 work or school accounts. postkeep then
reads and sends mail through Microsoft Graph, and new-mail webhooks use
Graph change notifications. No app passwords are involved.

You need:

- a public HTTPS address for postkeep (`POSTKEEP_PUBLIC_URL`, for example
  `https://mail.example.com`);
- an account that can open the Microsoft Entra admin center. Any
  Microsoft 365 business account works; with a personal account, sign up
  for a free Azure account first, which creates a directory for you.

The steps below use `https://mail.example.com`; replace it with your own
`POSTKEEP_PUBLIC_URL`, exactly as you set it (no trailing slash).

> [!IMPORTANT]
> **The client secret expires, and then every Outlook account stops
> working.** Entra client secrets last at most 24 months (Microsoft
> recommends less than 12). When the secret expires, sign-ins and token
> refreshes fail with `AADSTS7000222` until you create a new one. Set a
> calendar reminder when you create it; see
> [step 2](#2-create-a-client-secret) for the rotation steps.
>
> Microsoft's refresh tokens last 90 days and are replaced by a fresh one
> each time postkeep uses them, so only an account left unused for 90 days
> needs to sign in again
> ([Microsoft: refresh token lifetime](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens#token-lifetime)).

## 1. Register the app

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com)
   and sign in. You need at least the *Application Developer* role.
2. Go to **Entra ID** > **App registrations** and select **New
   registration**.
3. **Name**: `postkeep` (users see it on the consent screen).
4. **Supported account types**: choose **Any Entra ID Tenant + Personal
   Microsoft accounts** (shown as *Accounts in any organizational directory
   and personal Microsoft accounts* in older versions of the page).
   postkeep signs in through Microsoft's `common` endpoint, which needs
   this option.
5. **Redirect URI**: platform **Web**, URI
   `https://mail.example.com/oauth/microsoft/callback`. It must match
   exactly: `https`, your host, this path, no trailing slash, no query.
6. Select **Register**. On the app's **Overview** page, copy the
   **Application (client) ID**.

## 2. Create a client secret

1. In the app, open **Certificates & secrets** > **Client secrets** > **New
   client secret**.
2. Enter a description such as `postkeep`, pick an expiry (at most 24
   months; Microsoft recommends less than 12, see
   [add credentials](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials)),
   and select **Add**.
3. Copy the secret's **Value** right away; it is shown only once. (The
   *Secret ID* next to it is not the secret.)
4. **Put a reminder in your calendar a few weeks before it expires.** The
   expiry date is listed under **Client secrets**. To rotate: create a new
   secret, set it as `POSTKEEP_MICROSOFT_CLIENT_SECRET`
   ([changing a setting](../deployment.md#changing-a-setting)), then delete
   the old secret. When a secret expires, sign-ins and token refreshes fail
   until you replace it; users don't need to sign in again once the new
   secret is in place.

## 3. API permissions

postkeep asks for its permissions when a user signs in, so personal
accounts work without this step. List them anyway if work or school
accounts will sign in: an administrator who approves postkeep in the
Entra admin center approves the permissions listed here (see
[Microsoft admin consent](microsoft-admin-consent.md)).

1. Open **API permissions** > **Add a permission** > **Microsoft Graph** >
   **Delegated permissions**.
2. Add `Mail.ReadWrite`, `Mail.Send` and `offline_access`. `User.Read` is
   usually already listed; keep it.
3. Remove any other permission. postkeep requests exactly these four:

| Permission | Why |
| ---------- | --- |
| `Mail.ReadWrite` | Read, search, flag, move and delete messages; create folders |
| `Mail.Send` | Send and reply |
| `offline_access` | A refresh token, so the connection survives without signing in again |
| `User.Read` | The account's address, a stable account id, and stable ids for the messages a search finds |

Do not add application permissions. postkeep only ever acts as the
signed-in user.

## 4. Configure postkeep

Set these on the server, as
[Changing a setting](../deployment.md#changing-a-setting) shows for your install:

```text
POSTKEEP_MICROSOFT_CLIENT_ID=<Application (client) ID>
POSTKEEP_MICROSOFT_CLIENT_SECRET=<client secret Value>
```

Once the server has started again, its log names the redirect URI it uses:

```
sign-in with Microsoft enabled redirect_uri=https://mail.example.com/oauth/microsoft/callback
```

The sign-in and account pages now show **Sign in with Microsoft**. If you
set `POSTKEEP_ALLOWED_EMAILS`, list the Outlook addresses there too.

## 5. New-mail webhooks

Nothing more to set up. When a user turns on the webhook for an Outlook
account, postkeep creates a Graph subscription for new Inbox messages.
Graph then calls:

| Endpoint | Purpose |
| -------- | ------- |
| `POST https://mail.example.com/push/microsoft` | Change notifications |
| `POST https://mail.example.com/push/microsoft/lifecycle` | Lifecycle notifications (reauthorization, removed subscription, missed notifications) |

Requirements:

- Microsoft must reach those URLs over HTTPS with a publicly trusted
  certificate. If a firewall or proxy only allows certain sources, allow
  Microsoft Graph's notification traffic or webhooks won't arrive.
- Graph validates the URL when the subscription is created and expects
  the answer within 10 seconds; postkeep answers straight away.

Subscriptions for Outlook messages last at most 10,080 minutes (7 days).
postkeep renews each one a day before it expires, and recreates it if
Graph removes it. Deleting an account on postkeep's account page deletes
its subscription at Microsoft first; one that Graph fails to delete lapses
within 7 days, and postkeep ignores its notifications in the meantime.

Each notification only tells postkeep to look, so a forged, replayed or
repeated one adds no event; each subscription's `clientState` secret is
checked first. Graph doesn't promise every notification, so while the
webhook is on postkeep also lists the Inbox every 15 minutes.

## Publisher verification

Microsoft labels apps without a verified publisher as **unverified** on
the consent screen. What that means depends on who signs in:

- **Personal Microsoft accounts** (Outlook.com, Hotmail, Live) see the
  label but can consent.
- **Work or school accounts in your own directory** are not affected.
- **Work or school accounts in other organizations**: for multitenant apps
  registered after November 8, 2020, Microsoft's default consent policy
  doesn't let users consent to an unverified app that asks for more than
  basic sign-in and profile access. postkeep asks for mail access, so
  those users see "Need admin approval" and an administrator of their
  organization has to grant consent (or allow it through an admin consent
  workflow); [Microsoft admin consent](microsoft-admin-consent.md) shows how.
  Organizations can also block user consent entirely.

To remove the label, complete
[publisher verification](https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview):
you need a Microsoft AI Cloud Partner Program (formerly MPN) account for a
business, a work account in the directory that owns the app, and a
verified publisher domain. Apps registered with a personal Microsoft
account can't be verified. For a server used by you, your family or your
own organization, verification is usually unnecessary.

## Disconnecting

Deleting an Outlook account on postkeep's account page deletes its stored
tokens. Microsoft offers apps no endpoint to revoke a grant, so remove
postkeep's access there too: [Disconnect](../clients.md#disconnect).

## Troubleshooting

| Message | Cause |
| ------- | ----- |
| `AADSTS50011` (redirect URI mismatch) | The redirect URI in the app registration differs from `{POSTKEEP_PUBLIC_URL}/oauth/microsoft/callback` (check `https`, host, trailing slash) |
| `AADSTS7000215` (invalid client secret) | The secret's *Secret ID* was used instead of its *Value*, or the value was mistyped |
| `AADSTS7000222` (expired client secret); every Outlook account fails at once | Create a new secret and update `POSTKEEP_MICROSOFT_CLIENT_SECRET` ([step 2](#2-create-a-client-secret)); users don't need to sign in again |
| `AADSTS50194` or `AADSTS50020` ("not configured as a multi-tenant application", "does not exist in tenant") | The app was registered for one directory only; recreate it with **Any Entra ID Tenant + Personal Microsoft accounts** |
| "Need admin approval" | An administrator has to approve postkeep for the organization; see [Microsoft admin consent](microsoft-admin-consent.md) and [publisher verification](#publisher-verification) |
| "Your organization has to approve postkeep" | Microsoft answered that an administrator has to approve the app (`AADSTS90094`, `AADSTS65001` or `consent_required`), or that a reviewer decides on the request (`AADSTS90095`); see [Microsoft admin consent](microsoft-admin-consent.md) |
| "Not approved", after the admin consent link | Microsoft recorded no approval, for example because the administrator declined. Try again with one of the roles named in [Microsoft admin consent](microsoft-admin-consent.md) |
| "This Microsoft account has no mailbox postkeep can reach" | The account has no Exchange Online mailbox (for example a work account without an Exchange license, or a mailbox hosted on-premises). postkeep only trusts the address of a real mailbox |
| The account page asks to sign in again | Microsoft rejected the refresh token (revoked consent, an administrator reset the password or revoked sessions, or 90 days without use); sign in with Microsoft again |
