//! What the account page shows: the mail provider, the connected apps and
//! their activity. Pure view models, so they're easy to test.

use postkeep_mail::{ImapPreset, ImapServerId, ImapServers};
use postkeep_store::{Account, AccountClient, Provider};

use crate::pages;

/// The account's mail provider as the page describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderView {
    /// For example `iCloud Mail`.
    pub name: String,
    /// The logo file; each provider has its own so it can be swapped alone.
    pub logo: Option<&'static str>,
    /// How postkeep reaches the mailbox, after "Connected over".
    pub transport: &'static str,
    /// Whether the account signs in with a password that can be replaced
    /// on the page (IMAP accounts).
    pub uses_app_password: bool,
    /// The kind of password: "app-specific password", "app password" or
    /// "password".
    pub password_kind: &'static str,
    /// When to replace the password, under the setting's title.
    pub password_when: String,
    /// Who checks a new password: "iCloud Mail", "Fastmail", "your mail server".
    pub checked_by: String,
    /// Where the provider's app passwords are managed: link text and URL.
    pub password_link: Option<(String, &'static str)>,
    /// Placeholder of the new password field.
    pub password_placeholder: &'static str,
    /// What else to do to cut access completely after deleting the account.
    pub delete_hint: String,
}

impl ProviderView {
    /// The view for `account`, given the servers this postkeep offers.
    #[must_use]
    pub fn new(account: &Account, servers: &ImapServers) -> Self {
        match account.provider {
            Provider::Imap => Self::imap(account, servers),
            Provider::Graph => Self::oauth(
                "Microsoft Outlook",
                "Microsoft Graph",
                "Also remove postkeep under Privacy, Apps and services in your Microsoft account to fully cut access.",
            ),
            Provider::Gmail => Self::oauth(
                "Gmail",
                "the Gmail API",
                "Also remove postkeep under Third-party apps and services in your Google Account to fully cut access.",
            ),
        }
    }

    fn oauth(name: &str, transport: &'static str, delete_hint: &str) -> Self {
        Self {
            name: name.to_owned(),
            // The Microsoft and Google marks are only used inside their
            // sign-in buttons, per their brand guidelines.
            logo: None,
            transport,
            uses_app_password: false,
            password_kind: "",
            password_when: String::new(),
            checked_by: String::new(),
            password_link: None,
            password_placeholder: "",
            delete_hint: delete_hint.to_owned(),
        }
    }

    fn imap(account: &Account, servers: &ImapServers) -> Self {
        let server = servers.resolve(account.imap_server.as_deref());
        let id = server.as_ref().map(|server| server.id);
        let name = server
            .as_ref()
            .map_or_else(|| "IMAP mail".to_owned(), |server| server.name.clone());
        let link = server.as_ref().and_then(|server| {
            server
                .app_password_url
                .map(|url| (format!("{} app passwords", server.name), url))
        });
        match id {
            Some(ImapServerId::Preset(ImapPreset::ICloud)) => Self {
                logo: Some(pages::server_logo(ImapServerId::Preset(ImapPreset::ICloud))),
                transport: "IMAP + SMTP with an app-specific password",
                uses_app_password: true,
                password_kind: "app-specific password",
                password_when: "Replace it after changing your Apple Account password. Apps keep working.".to_owned(),
                checked_by: name.clone(),
                password_link: Some(("account.apple.com".to_owned(), pages::APPLE_ACCOUNT_URL)),
                password_placeholder: "abcd-efgh-ijkl-mnop",
                delete_hint: "Also delete the app-specific password at account.apple.com to fully cut access.".to_owned(),
                name,
            },
            Some(ImapServerId::Preset(preset)) => Self {
                logo: Some(pages::server_logo(ImapServerId::Preset(preset))),
                transport: "IMAP + SMTP with an app password",
                uses_app_password: true,
                password_kind: "app password",
                password_when: format!(
                    "Replace it if you revoke it at {name} or it stops working. Apps keep working."
                ),
                checked_by: name.clone(),
                password_link: link,
                password_placeholder: "",
                delete_hint: format!(
                    "Also delete the app password at {name} to fully cut access."
                ),
                name,
            },
            Some(ImapServerId::Custom) | None => Self {
                logo: Some(pages::server_logo(ImapServerId::Custom)),
                transport: "IMAP + SMTP with a password",
                uses_app_password: true,
                password_kind: "password",
                password_when: "Replace it after changing your mail password. Apps keep working."
                    .to_owned(),
                checked_by: "your mail server".to_owned(),
                password_link: None,
                password_placeholder: "",
                delete_hint: "Also change or revoke this password at your mail provider to fully cut access."
                    .to_owned(),
                name,
            },
        }
    }
}

/// One connected app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientView {
    pub id: String,
    pub name: String,
    /// The first letter of the name, for the avatar.
    pub initial: String,
    /// The host the app returns to after sign-in (`claude.ai`). When the
    /// redirect URI has no host, this is the full URI (`com.example.app:/cb`)
    /// so a scheme alone cannot hide the target.
    pub redirect_host: String,
    pub authorized_at: String,
    pub authorized_at_iso: String,
    /// For example `2 minutes ago`.
    pub last_active: String,
    pub last_active_iso: String,
}

impl ClientView {
    /// The view of `client` at time `now` (Unix seconds).
    #[must_use]
    pub fn new(client: &AccountClient, now: i64) -> Self {
        // Names registered before bidi controls were rejected can still be
        // stored. Strip them again so the account page cannot be reordered.
        let name = crate::register::client_name_for_display(client.name.as_deref(), "Unnamed app");
        Self {
            id: client.id.clone(),
            initial: initial(&name),
            redirect_host: client
                .redirect_uris
                .first()
                .map(|uri| display_host(uri))
                .unwrap_or_default(),
            authorized_at: pages::format_date(client.authorized_at),
            authorized_at_iso: pages::format_rfc3339(client.authorized_at),
            last_active: relative_time(now, client.last_active_at),
            last_active_iso: pages::format_rfc3339(client.last_active_at),
            name,
        }
    }
}

/// The first letter or digit of `name`, upper-cased, or `?`.
#[must_use]
pub fn initial(name: &str) -> String {
    name.chars()
        .find(|c| c.is_alphanumeric())
        .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect())
}

/// The host of a redirect URI, or the full URI when it has no host.
///
/// Private-use schemes such as `com.example.app:/cb` have no host. Showing
/// only `com.example.app:` would hide where the user is sent.
#[must_use]
pub fn display_host(uri: &str) -> String {
    url::Url::parse(uri)
        .ok()
        .map(|url| url.host_str().map_or_else(|| uri.to_owned(), str::to_owned))
        .unwrap_or_default()
}

/// `then` relative to `now` (Unix seconds): `just now`, `5 minutes ago`,
/// `3 hours ago`, `yesterday`, `6 days ago`, then a date.
#[must_use]
pub fn relative_time(now: i64, then: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    let ago = now.saturating_sub(then);
    let plural = |n: i64, unit: &str| {
        if n == 1 {
            format!("1 {unit} ago")
        } else {
            format!("{n} {unit}s ago")
        }
    };
    if ago < MINUTE {
        "just now".to_owned()
    } else if ago < HOUR {
        plural(ago / MINUTE, "minute")
    } else if ago < DAY {
        plural(ago / HOUR, "hour")
    } else if ago < 2 * DAY {
        "yesterday".to_owned()
    } else if ago < 30 * DAY {
        plural(ago / DAY, "day")
    } else {
        pages::format_date(then)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_times() {
        let now = 1_800_000_000;
        assert_eq!(relative_time(now, now + 30), "just now");
        assert_eq!(relative_time(now, now - 59), "just now");
        assert_eq!(relative_time(now, now - 60), "1 minute ago");
        assert_eq!(relative_time(now, now - 150), "2 minutes ago");
        assert_eq!(relative_time(now, now - 3_600), "1 hour ago");
        assert_eq!(relative_time(now, now - 86_399), "23 hours ago");
        assert_eq!(relative_time(now, now - 86_400), "yesterday");
        assert_eq!(relative_time(now, now - 2 * 86_400), "2 days ago");
        assert_eq!(relative_time(now, now - 29 * 86_400), "29 days ago");
        assert_eq!(
            relative_time(now, now - 30 * 86_400),
            pages::format_date(now - 30 * 86_400)
        );
        assert_eq!(relative_time(0, i64::MAX), "just now");
        // Out-of-range times must not panic.
        let _ = relative_time(i64::MAX, i64::MIN);
    }

    #[test]
    fn hosts_and_initials() {
        assert_eq!(display_host("https://claude.ai/api/callback"), "claude.ai");
        assert_eq!(display_host("http://127.0.0.1:33418/cb"), "127.0.0.1");
        assert_eq!(
            display_host("cursor://anysphere.cursor-mcp/cb"),
            "anysphere.cursor-mcp"
        );
        assert_eq!(display_host("com.example.app:/cb"), "com.example.app:/cb");
        assert_eq!(
            display_host("microsoft-edge:https://evil.example/phish"),
            "microsoft-edge:https://evil.example/phish"
        );
        assert_eq!(display_host("not a url"), "");
        assert_eq!(initial("vs Code"), "V");
        assert_eq!(initial("  ✨ 2fa"), "2");
        assert_eq!(initial("—"), "?");
    }

    #[test]
    fn unnamed_clients() {
        let client = AccountClient {
            id: "c1".to_owned(),
            name: Some("   ".to_owned()),
            redirect_uris: vec!["https://app.example/cb".to_owned()],
            authorized_at: 1_800_000_000,
            last_active_at: 1_800_000_000,
        };
        let view = ClientView::new(&client, 1_800_000_100);
        assert_eq!(view.name, "Unnamed app");
        assert_eq!(view.initial, "U");
        assert_eq!(view.redirect_host, "app.example");
        assert_eq!(view.last_active, "1 minute ago");
    }

    #[test]
    fn displayed_names_drop_bidi_controls_stored_earlier() {
        let client = AccountClient {
            id: "c1".to_owned(),
            name: Some("Acme\u{202E}\u{2028}Mail".to_owned()),
            redirect_uris: vec!["https://app.example/cb".to_owned()],
            authorized_at: 1_800_000_000,
            last_active_at: 1_800_000_000,
        };
        let view = ClientView::new(&client, 1_800_000_000);
        assert_eq!(view.name, "AcmeMail");
        assert_eq!(view.initial, "A");

        let only_marks = AccountClient {
            name: Some("\u{202E}\u{FEFF}".to_owned()),
            ..client
        };
        let view = ClientView::new(&only_marks, 1_800_000_000);
        assert_eq!(view.name, "Unnamed app");
        assert_eq!(view.initial, "U");
    }
}
