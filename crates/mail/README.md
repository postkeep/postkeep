# postkeep-mail

Async IMAP and SMTP mail client with presets for iCloud Mail, Fastmail,
Yahoo Mail and Gmail, the mail layer of [postkeep](https://github.com/postkeep/postkeep).

- IMAP via `async-imap` over TLS with `tokio-rustls`; SMTP via `lettre`, over
  TLS or with mandatory STARTTLS. No OpenSSL.
- Credentials in `secrecy::SecretString`; app-specific passwords accepted with
  or without dashes; secrets and message bodies are never logged.
- iCloud defaults; every host, port and TLS mode can be changed.

```rust,no_run
use postkeep_mail::{Credentials, MailClient, MailConfig, SecretString};

# async fn run() -> postkeep_mail::Result<()> {
let password = SecretString::from("abcd-efgh-ijkl-mnop".to_owned());
let client = MailClient::new(
    MailConfig::default(),
    Credentials::new("alice@example.com", &password)?,
)?;
client.verify_credentials().await?;

let mut imap = client.connect_imap().await?;
for folder in imap.list_folders().await? {
    let _ = folder.name;
}
imap.logout().await?;
# Ok(())
# }
```

See [`examples/smoke.rs`](examples/smoke.rs) for a runnable example that reads
`ICLOUD_EMAIL` and `ICLOUD_APP_PASSWORD` from the environment.

Licensed under the MIT license.
