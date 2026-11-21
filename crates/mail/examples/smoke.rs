//! Lists the folders of an iCloud account.
//!
//! ```sh
//! ICLOUD_EMAIL=alice@example.com ICLOUD_APP_PASSWORD=abcd-efgh-ijkl-mnop \
//!     cargo run -p postkeep-mail --example smoke
//! ```
#![expect(clippy::print_stdout, reason = "examples report to the terminal")]

use std::env;
use std::error::Error;

use postkeep_mail::{Credentials, MailClient, MailConfig, SecretString};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let email = env::var("ICLOUD_EMAIL").map_err(|_| "set ICLOUD_EMAIL")?;
    let password =
        SecretString::from(env::var("ICLOUD_APP_PASSWORD").map_err(|_| "set ICLOUD_APP_PASSWORD")?);
    let credentials = Credentials::new(&email, &password)?;
    let client = MailClient::new(MailConfig::default(), credentials)?;

    let mut imap = client.connect_imap().await?;
    for folder in imap.list_folders().await? {
        match folder.special_use {
            Some(role) => println!("{} ({role:?})", folder.name),
            None => println!("{}", folder.name),
        }
    }
    imap.logout().await?;
    Ok(())
}
