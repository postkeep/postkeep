# Installing postkeep

Choose Managed Cloud or self-hosting before adding the server. Use your
client's JSON or CLI format in [Other apps](docs/clients.md#other-apps),
which includes Cline's JSON format.

## Option 1: Managed Cloud

If you have access to postkeep Cloud, add `https://mcp.postkeep.ai/mcp` as
a new Streamable HTTP server without replacing existing entries. Have the
user complete OAuth 2.1 sign-in and approve workspace access in their browser.
Call `get_account` to verify the connection. To add a mailbox, call
`connect_mailbox` and have the user open the returned link.

## Option 2: Self-host with Docker (MIT)

Follow [Install](README.md#install) with [Docker Compose](deploy/compose/compose.yaml).
See the [deployment guide](https://postkeep.dev/docs/deployment/) for HTTPS
and configuration.

Add your server's HTTPS address, such as `https://mail.example.com/mcp`, as a
new, uniquely named server entry. Never edit the URL of an already signed-in
Cloud entry. Have the user sign in to the new server in their browser, then
call `list_folders` to verify the connection.

postkeep marks each tool as read-only or not, but does not ask for
confirmation itself. If your client offers approval prompts for sending,
moving, or deleting mail, keep them on.
