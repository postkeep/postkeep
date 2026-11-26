# Agent apps

Add your server's address to an agent app that supports remote MCP servers
(Streamable HTTP) with OAuth sign-in:

```
https://mail.example.com/mcp
```

The app opens postkeep's sign-in page. Sign in with Microsoft or Google, or
with your mailbox's address and an app password; the page shows how to
create one.

> [!NOTE]
> Each connection is one mailbox, so add the server to your agent app once
> for each mailbox you want, with a different name for each where the app
> asks for one.

Your agent reads your mail, and text in a message can try to steer it: keep
your app's approval prompts on for sending, moving and deleting.

## Claude

Add a custom connector and paste the address: on the web, desktop or
mobile, in *Customize → Connectors*. The Free plan allows one custom
connector. On a Team or Enterprise plan, an owner adds it first under
*Organization settings → Connectors*, and each member then connects it.

## ChatGPT

Create an app in developer mode, with the address and OAuth: turn on
developer mode in *Settings → Apps → Advanced settings* (in a Business,
Enterprise or Edu workspace, an admin may need to allow it), then choose
*Create* under *Settings → Apps*. Sending and other write actions need
full MCP support, which depends on your plan
([developer mode help](https://help.openai.com/en/articles/12584461)).

## Grok

Add a custom connector with the address (remote MCP); see
[xAI's connectors documentation](https://docs.x.ai/grok/connectors).

## Cursor

Add the address to `~/.cursor/mcp.json`:

```json
{ "mcpServers": { "postkeep": { "url": "https://mail.example.com/mcp" } } }
```

## VS Code

Run *MCP: Add Server*, choose *HTTP*, and paste the address, in GitHub
Copilot agent mode.

## Other apps

- **MCP Inspector**, for testing: `npx @modelcontextprotocol/inspector`,
  choose *Streamable HTTP*, enter the address and use the OAuth flow.
- An app that only runs local (stdio) servers can use a bridge such as
  `mcp-remote`: `npx mcp-remote https://mail.example.com/mcp`.

Replace `mail.example.com` with your server's host. If you already have a
`mcpServers` object, add the `postkeep` entry to it.

### Claude Code

Run this in your project, then use `/mcp` in Claude Code to sign in:

```sh
claude mcp add --transport http postkeep https://mail.example.com/mcp
```

### Cline

Open *MCP Servers → Configure → Configure MCP Servers* and add:

```json
{ "mcpServers": { "postkeep": { "type": "streamableHttp", "url": "https://mail.example.com/mcp" } } }
```

Select *Authenticate* for postkeep, then finish in your browser.

### Devin Desktop (formerly Windsurf)

Open *Agents → Customize → MCPs* and select *This computer*. Add the entry
in `~/.config/devin/mcp_config.json` (`%APPDATA%\devin\mcp_config.json` on Windows):

```json
{ "mcpServers": { "postkeep": { "url": "https://mail.example.com/mcp", "transport": "http" } } }
```

### Attaching large files

A file too large to write into a call goes by
[`upload_attachment`](reference/tools.md#uploads), which works where the agent
can see the file and run a command that reaches your server:

| Where the agent runs | A file too large for the call |
| -------------------- | ----------------------------- |
| A coding agent on your computer (Claude Code, Codex, Cursor, VS Code agent mode, Gemini CLI) | uploaded by a command; a sandbox may need your server's host allowed, or your yes |
| ChatGPT desktop or Codex with a local folder open, where its network is on | uploaded, untried |
| Claude desktop with a connected folder | uploaded from its own environment, where its network settings allow your server, untried |
| Claude chat | a file in the chat, from its code sandbox, where your server's host is allowed, untried |
| ChatGPT chat, the Gemini app | not attachable: small files go in the call |
| Agent frameworks, scripts, your own code | uploaded |

## Disconnect

Remove the server in the agent app. To also stop its tokens at once, revoke
every app on `/account` on your server. Deleting your data there removes
the server's copy of your password or sign-in; to end its access to the
mailbox, revoke that at the provider:

| Mailbox | Where |
| ------- | ----- |
| iCloud Mail | Delete the app-specific password at [account.apple.com](https://account.apple.com) |
| Gmail with an app password | Delete it at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords) |
| Gmail with Sign in with Google | Remove postkeep at [myaccount.google.com/permissions](https://myaccount.google.com/permissions); deleting your data on `/account` also tries this |
| Outlook | Personal accounts: [account.live.com/consent/Manage](https://account.live.com/consent/Manage); work or school: [myapps.microsoft.com](https://myapps.microsoft.com) or your administrator |
| Fastmail | Delete the app password in [Fastmail's settings](https://www.fastmail.help/hc/en-us/articles/360058752854-App-passwords) |
| Yahoo Mail | Delete the app password in [Yahoo's account security settings](https://login.yahoo.com/account/security) |

Access then ends once a cached provider token expires or an open IMAP
session ends.
