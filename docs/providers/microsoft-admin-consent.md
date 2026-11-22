# Microsoft admin consent

Some Microsoft 365 organizations let only an administrator approve apps
that read mail. When someone there signs in with Microsoft, Microsoft shows
**Need admin approval** instead of its consent screen, and postkeep answers
"Your organization has to approve postkeep". This page is for the
administrator who approves it.

Personal Microsoft accounts (Outlook.com, Hotmail, Live) never need this:
each person consents for themselves.

## Why an administrator has to approve

Microsoft asks for an administrator when:

- the organization turned off user consent, or allows it only for apps
  from verified publishers;
- the app has no verified publisher and was registered in another
  organization (see [publisher verification](microsoft.md#publisher-verification));
- the organization requires users to be assigned to the app. Such an app
  always needs an administrator's consent.

## What postkeep asks for

Delegated Microsoft Graph permissions only. postkeep acts as the person who
signed in, and only after they sign in; it asks for no application
permissions, so approving it gives it no access to the mailbox of anyone
who never signs in.

| Permission | Why |
| ---------- | --- |
| `Mail.ReadWrite` | Read, search, flag, move and delete messages; create folders |
| `Mail.Send` | Send and reply |
| `offline_access` | A refresh token, so the connection survives without signing in again |
| `User.Read` | The account's address, a stable account id, and stable ids for the messages a search finds |

You need at least the **Cloud Application Administrator** role (an
Application Administrator or a Privileged Role Administrator also can).

## Approve with the admin consent link

This works even if nobody in the organization has signed in to postkeep
yet. Open this address, on one line, and sign in as an administrator:

```text
https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?client_id={client-id}&redirect_uri={server}/oauth/microsoft/callback&scope=offline_access%20https://graph.microsoft.com/User.Read%20https://graph.microsoft.com/Mail.ReadWrite%20https://graph.microsoft.com/Mail.Send
```

- `{tenant}`: your organization's tenant ID, or one of its verified
  domains such as `example.com`. `organizations` also works and uses the
  organization of the account you sign in with.
- `{client-id}`: the app's **Application (client) ID**. On a server you run
  it is `POSTKEEP_MICROSOFT_CLIENT_ID`; otherwise ask the server's
  operator.
- `{server}`: the server's address (`POSTKEEP_PUBLIC_URL`), for example
  `https://mail.example.com`.

Microsoft lists the four permissions and asks you to accept them for the
whole organization. It then sends you back to postkeep, which shows
**Approved at Microsoft**, or **Not approved** if you declined. People in
the organization can now sign in with Microsoft.

## Approve in the Microsoft Entra admin center

Once someone in the organization has consented to postkeep, or it was
approved before, it is listed as an enterprise app:

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com) and
   go to **Entra ID** > **Enterprise apps** > **All applications**.
2. Search for the app's name (`postkeep`, or the name the operator chose)
   and select it.
3. Under **Security**, select **Permissions**, review them, and select
   **Grant admin consent**.

This approves the permissions listed in the app's registration, so it
covers all four only if the operator listed them
([step 3 of the Outlook guide](microsoft.md#3-api-permissions)). The admin
consent link names them itself.

If the app is registered in your own directory, you can also approve it
from **Entra ID** > **App registrations** > the app > **API permissions** >
**Grant admin consent**, again for the permissions listed there.

## Requests from users

If your organization turned on the
[admin consent workflow](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow),
people who see **Need admin approval** can send a request, and postkeep
tells them that a reviewer will decide. A reviewer opens **Entra ID** >
**Enterprise apps** > **Admin consent requests** (under **Activity**),
selects postkeep on the **My Pending** tab, and approves it with **Review
permissions and consent**. Microsoft tells every requester the outcome;
after an approval they sign in with Microsoft again.

## Choose who can use postkeep

Once approved, postkeep is open to everyone in the organization. To limit
it, open the app under **Enterprise apps**, set **Assignment required** to
**Yes** in its **Properties**, and add people or groups under **Users and
groups** (assigning groups needs Microsoft Entra ID P1 or P2). Microsoft
refuses anyone else with `AADSTS50105`.

To stop postkeep for the whole organization, set **Enabled for users to
sign in?** to **No**; Microsoft then issues the app no tokens.

Microsoft's own guides:
[grant tenant-wide admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent),
[the admin consent endpoint](https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent),
[review admin consent requests](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/review-admin-consent-requests)
and [assign users and groups](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal).
