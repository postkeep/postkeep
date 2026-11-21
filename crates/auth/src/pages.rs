//! HTML pages: the sign-in page with the app-password guide, the account
//! page, a message page, and the brand assets they use. Stylesheets, script,
//! fonts and provider logos are in [`crate::assets`].
//!
//! Every page works without JavaScript; `app.js` only adds conveniences
//! (show/hide password, a busy state on submit, remembering the guide,
//! and selecting the preset that owns the address being typed).

use askama::Template;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Where the square mark (favicon) is served.
pub const ICON_PATH: &str = "/oauth/icon.svg";

/// Where the mark with wordmark is served.
pub const LOGO_PATH: &str = "/oauth/logo.svg";

/// Favicons, the touch icon and the web app manifest, served at the paths
/// browsers look for: (path, content type, contents).
pub const BRAND_ASSETS: &[(&str, &str, &[u8])] = &[
    (
        "/favicon.ico",
        "image/x-icon",
        include_bytes!("../assets/brand/favicon.ico"),
    ),
    (
        "/favicon.svg",
        "image/svg+xml",
        include_bytes!("../assets/brand/favicon.svg"),
    ),
    (
        "/apple-touch-icon.png",
        "image/png",
        include_bytes!("../assets/brand/apple-touch-icon.png"),
    ),
    (
        "/icon-192.png",
        "image/png",
        include_bytes!("../assets/brand/icon-192.png"),
    ),
    (
        "/icon-512.png",
        "image/png",
        include_bytes!("../assets/brand/icon-512.png"),
    ),
    (
        "/site.webmanifest",
        "application/manifest+json",
        include_bytes!("../assets/brand/site.webmanifest"),
    ),
];

const ICON: &str = include_str!("../assets/icon.svg");
const LOGO: &str = include_str!("../assets/logo.svg");

/// Apple's sign-in page for managing the Apple Account.
pub const APPLE_ACCOUNT_URL: &str = "https://account.apple.com";

/// Apple's support article on app-specific passwords.
pub const APPLE_GUIDE_URL: &str = "https://support.apple.com/en-us/102654";

/// The project's source repository.
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The project's documentation site.
pub const DOCS: &str = env!("CARGO_PKG_HOMEPAGE");

/// The sign-in page.
///
/// `email_error` and `password_error` mark a field as invalid and are listed
/// in a summary at the top of the form; `error` is a form-level alert (wrong
/// password, throttled, unreachable, not allowed).
#[derive(Template)]
#[template(path = "sign_in.html")]
pub struct SignInPage<'a> {
    pub client_name: &'a str,
    /// Host that published the client's metadata document, if it has one.
    pub client_host: Option<&'a str>,
    pub redirect_host: &'a str,
    pub request_id: &'a str,
    pub email: &'a str,
    pub error: Option<&'a str>,
    pub email_error: Option<&'a str>,
    pub password_error: Option<&'a str>,
    pub mail: &'a MailChoices,
    pub oauth: &'a OAuthButtons,
}

impl SignInPage<'_> {
    /// The first letter of the client's name, for its avatar.
    #[must_use]
    pub fn client_initial(&self) -> String {
        crate::account_view::initial(self.client_name)
    }
}

/// "Sign in with Microsoft/Google" buttons; a button shows only when its
/// provider is configured. Each is a form posting to the provider's start
/// path, carrying the pending authorization request if there is one.
#[derive(Debug, Clone, Default)]
pub struct OAuthButtons {
    pub microsoft: Option<String>,
    pub google: Option<String>,
    /// The MCP client's authorization request this sign-in completes, or
    /// `None` for an account page sign-in.
    pub request_id: Option<String>,
}

impl OAuthButtons {
    /// Whether any button shows.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.microsoft.is_some() || self.google.is_some()
    }
}

/// The IMAP servers a sign-in form offers, for the templates.
#[derive(Debug, Clone)]
pub struct MailChoices {
    /// Offered servers; the form shows a picker when there is more than one.
    pub servers: Vec<ServerOption>,
    /// Whether iCloud Mail is offered (its step-by-step guide is shown).
    pub icloud: bool,
    /// App password help for the other presets: name and URL.
    pub other_guides: Vec<(String, &'static str)>,
    /// The hint under the picker.
    pub hint: String,
    /// Placeholder of the email field.
    pub placeholder: &'static str,
    /// Hint under the email field.
    pub email_hint: &'static str,
    /// Shown under the email field when `selected` loses to the address's
    /// domain. `None` when the pick is honoured or the domain is unknown.
    pub override_hint: Option<&'static str>,
}

/// One server in the picker.
#[derive(Debug, Clone)]
pub struct ServerOption {
    pub id: &'static str,
    pub name: String,
    pub selected: bool,
    /// Logo URL; each provider has its own file so it can be swapped alone.
    pub logo: &'static str,
    /// Space-separated domains this preset owns. Empty for a custom server.
    pub domains: String,
    /// Sentence for an address at `domains`, empty when there are none.
    pub override_hint: &'static str,
}

/// "This is an iCloud address, so iCloud Mail will be used."
#[must_use]
pub const fn domain_override_hint(preset: postkeep_mail::ImapPreset) -> &'static str {
    match preset {
        postkeep_mail::ImapPreset::ICloud => {
            "This is an iCloud address, so iCloud Mail will be used."
        }
        postkeep_mail::ImapPreset::Fastmail => {
            "This is a Fastmail address, so Fastmail will be used."
        }
        postkeep_mail::ImapPreset::Yahoo => "This is a Yahoo address, so Yahoo Mail will be used.",
        postkeep_mail::ImapPreset::Gmail => "This is a Gmail address, so Gmail will be used.",
    }
}

/// The logo of a server in the picker.
pub const fn server_logo(id: postkeep_mail::ImapServerId) -> &'static str {
    use postkeep_mail::{ImapPreset, ImapServerId};
    match id {
        ImapServerId::Preset(ImapPreset::ICloud) => "/assets/providers/icloud.svg",
        ImapServerId::Preset(ImapPreset::Fastmail) => "/assets/providers/fastmail.svg",
        ImapServerId::Preset(ImapPreset::Yahoo) => "/assets/providers/yahoo.svg",
        ImapServerId::Preset(ImapPreset::Gmail) => "/assets/providers/gmail.svg",
        ImapServerId::Custom => "/assets/providers/imap.svg",
    }
}

impl MailChoices {
    /// The choices of `servers`. `selected` (a server identifier, or empty
    /// for automatic detection) is preselected; failing that, the server
    /// detected from `email`, then the default server.
    #[must_use]
    pub fn new(servers: &postkeep_mail::ImapServers, selected: &str, email: &str) -> Self {
        use postkeep_mail::{ImapPreset, ImapServerId};
        let choices = servers.choices();
        let icloud = choices
            .iter()
            .any(|server| server.id == ImapServerId::Preset(ImapPreset::ICloud));
        let other_guides = choices
            .iter()
            .filter(|server| server.id != ImapServerId::Preset(ImapPreset::ICloud))
            .filter_map(|server| {
                server
                    .app_password_url
                    .map(|url| (server.name.clone(), url))
            })
            .collect();
        let recognized: Vec<&str> = choices
            .iter()
            .filter(|server| matches!(server.id, ImapServerId::Preset(_)))
            .map(|server| server.name.as_str())
            .collect();
        let hint = if recognized.is_empty() {
            "Choose your mail provider.".to_owned()
        } else {
            format!(
                "{} addresses are recognized automatically. For a custom domain, choose your provider.",
                join_names(&recognized)
            )
        };
        let checked = choices
            .iter()
            .find(|server| server.id.id() == selected)
            .map(|server| server.id)
            .or_else(|| servers.choose("auto", email).map(|server| server.id));
        let override_hint = servers
            .domain_override(selected, email)
            .map(domain_override_hint);
        Self {
            servers: choices
                .iter()
                .map(|server| {
                    let (domains, preset_hint) = match server.id {
                        ImapServerId::Preset(preset) => {
                            (preset.domains().join(" "), domain_override_hint(preset))
                        }
                        ImapServerId::Custom => (String::new(), ""),
                    };
                    ServerOption {
                        id: server.id.id(),
                        name: server.name.clone(),
                        selected: Some(server.id) == checked,
                        logo: server_logo(server.id),
                        domains,
                        override_hint: preset_hint,
                    }
                })
                .collect(),
            icloud,
            other_guides,
            hint,
            placeholder: "alice@example.com",
            email_hint: if icloud {
                "iCloud addresses usually end in @icloud.com, @me.com or @mac.com."
            } else {
                "The address you sign in to your mail with."
            },
            override_hint,
        }
    }
}

/// `a`, `a and b`, `a, b and c`.
fn join_names(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Picks the icon and colour of a [`MessagePage`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    dead_code,
    reason = "success and info pages have no caller until the account page"
)]
pub enum MessageKind {
    Success,
    Info,
    #[default]
    Error,
}

impl MessageKind {
    /// The CSS modifier for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Info => "info",
            Self::Error => "error",
        }
    }
}

/// A page with a title and a short explanation.
#[derive(Template)]
#[template(path = "message.html")]
pub struct MessagePage<'a> {
    pub kind: MessageKind,
    pub title: &'a str,
    pub message: &'a str,
}

/// A one-line message at the top of the account page, chosen by a fixed
/// key in the redirect URL (never by user-supplied text).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notice {
    /// Success (green, `role=status`) or error (red, `role=alert`).
    pub success: bool,
    /// The message.
    pub text: &'static str,
}

impl Notice {
    /// The notice for a `?notice=` key.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        let (success, text) = match key {
            "signed-in" => (
                true,
                "You're signed in. If you used a new app-specific password, it now replaces the stored one and signs out other browsers on this page.",
            ),
            "revoked" => (
                true,
                "Every app was disconnected. Each one has to connect again to use your mail.",
            ),
            "confirm-revoke" => (
                false,
                "Tick the box to confirm, then choose Revoke all apps again. Nothing was changed.",
            ),
            "confirm-delete" => (
                false,
                "The address you typed didn't match. Nothing was deleted.",
            ),
            "client-revoked" => (
                true,
                "The app was disconnected. It has to sign in again to use your mail.",
            ),
            "password-updated" => (
                true,
                "Password updated. Connected apps keep working with the new one.",
            ),
            "webhook-saved" => (true, "Webhook settings saved."),
            "webhook-wait" => (
                false,
                "Wait a few seconds before sending another test event.",
            ),
            "webhook-no-url" => (false, "Enter an endpoint URL before sending a test event."),
            "webhook-save-first" => (
                false,
                "Save the webhook settings first; they get a signing secret then.",
            ),
            "webhook-unreadable" => (
                false,
                "These webhook settings can't be read because the encryption key changed. Enter them again and save to replace the stored settings.",
            ),
            "reauth-microsoft" => (
                false,
                "Microsoft no longer accepts this connection (the sign-in expired or access was removed). Sign out, then sign in with Microsoft again to reconnect.",
            ),
            "reauth-google" => (
                false,
                "Google no longer accepts this connection (the sign-in expired or access was removed). Sign out, then sign in with Google again to reconnect.",
            ),
            "secret-rotated" => (
                true,
                "New signing secret created. The old one no longer verifies. Update your receiver.",
            ),
            "filter-added" => (true, "Filter rule added."),
            "filter-saved" => (true, "Filter rule saved."),
            "filter-removed" => (true, "Filter rule removed."),
            "filters-removed" => (
                true,
                "Every filter rule was removed, so every new message calls the webhook.",
            ),
            "filter-gone" => (false, "That rule is no longer there, so nothing changed."),
            "filter-on" => (true, "Filter rule turned on."),
            "filter-off" => (
                true,
                "Filter rule turned off. It judges nothing until you turn it on again.",
            ),
            "filter-unknown" => (
                false,
                "Not turned on: this rule, or another rule that's on, has an action, field or kind this server doesn't know.",
            ),
            "filter-wont-compile" => (
                false,
                "Not turned on: the rules that are on wouldn't compile together with this one. Remove it, or turn off or remove other rules first.",
            ),
            _ => return None,
        };
        Some(Self { success, text })
    }
}

/// The account page.
#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountPage<'a> {
    pub email: &'a str,
    pub connected_at: &'a str,
    pub connected_at_iso: &'a str,
    pub csrf_token: &'a str,
    pub notice: Option<Notice>,
    pub provider: &'a crate::account_view::ProviderView,
    pub clients: &'a [crate::account_view::ClientView],
    /// The MCP endpoint, for the empty state.
    pub mcp_url: &'a str,
    /// The webhook section, or `None` when webhooks are off on this server.
    pub webhook: Option<crate::webhook::WebhookView>,
    /// A failed password update, shown in the reopened password form.
    pub password_error: Option<&'a str>,
    /// Whether the mail server rejected the stored password: shows a notice.
    pub password_rejected: bool,
    /// Added to the signed-in notice when the address's domain replaced the
    /// provider the user picked.
    pub override_hint: Option<&'static str>,
}

impl AccountPage<'_> {
    /// Number of connected apps.
    #[must_use]
    pub const fn app_count(&self) -> usize {
        self.clients.len()
    }
}

/// The account page's sign-in form.
#[derive(Template)]
#[template(path = "account_sign_in.html")]
pub struct AccountSignInPage<'a> {
    pub oauth: &'a OAuthButtons,
    pub email: &'a str,
    pub error: Option<&'a str>,
    pub email_error: Option<&'a str>,
    pub password_error: Option<&'a str>,
    pub mail: &'a MailChoices,
}

/// A Unix time as a date and time such as `Oct 2, 2026, 14:05 UTC`.
pub fn format_date_time(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|time| time.format("%b %-d, %Y, %H:%M UTC").to_string())
        .unwrap_or_default()
}

/// A Unix time as a date such as `Oct 2, 2026` (UTC).
pub fn format_date(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|time| time.format("%b %-d, %Y").to_string())
        .unwrap_or_default()
}

/// A Unix time in RFC 3339 for `<time datetime>`.
pub fn format_rfc3339(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Renders a template with security headers.
pub fn render(status: StatusCode, page: &impl Template) -> Response {
    match page.render() {
        Ok(body) => (status, security_headers(), axum::response::Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to render page");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                security_headers(),
                "internal error",
            )
                .into_response()
        }
    }
}

/// Marks a page of [`message`] with what it says, so that a route layer
/// can hand it to an embedding's page.
#[derive(Clone)]
pub struct Shown {
    pub title: String,
    pub message: String,
}

/// Renders an error [`MessagePage`].
pub fn message(status: StatusCode, title: &str, message: &str) -> Response {
    let mut page = render(
        status,
        &MessagePage {
            kind: MessageKind::Error,
            title,
            message,
        },
    );
    page.extensions_mut().insert(Shown {
        title: title.to_owned(),
        message: message.to_owned(),
    });
    page
}

/// The generic page for unexpected failures.
pub fn server_error() -> Response {
    message(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "The server hit an unexpected error. Go back to your app and try connecting again.",
    )
}

/// The page for a sign-in whose account was deleted before the sign-in
/// finished: nothing of the account is left.
pub fn account_deleted() -> Response {
    message(
        StatusCode::CONFLICT,
        "This account was just deleted",
        "It was deleted while you signed in, so nothing was saved. Sign in again to add the mailbox.",
    )
}

const fn security_headers() -> [(header::HeaderName, HeaderValue); 6] {
    [
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            ),
        ),
        (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        // `same-origin` keeps page URLs (which can carry OAuth parameters)
        // from leaking to other sites. `no-referrer` would also make
        // browsers send `Origin: null` on our own form posts, which the
        // account page's same-origin check rightly refuses.
        (
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        ),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        (header::PRAGMA, HeaderValue::from_static("no-cache")),
    ]
}

/// `GET /oauth/icon.svg`
pub async fn icon() -> impl IntoResponse {
    asset("image/svg+xml", ICON)
}

/// `GET /oauth/logo.svg`
pub async fn logo() -> impl IntoResponse {
    asset("image/svg+xml", LOGO)
}

/// A brand asset from [`BRAND_ASSETS`].
pub fn brand_asset(content_type: &'static str, body: &'static [u8]) -> Response {
    asset(content_type, body).into_response()
}

fn asset(content_type: &'static str, body: impl Into<axum::body::Body>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; sandbox"),
            ),
        ],
        body.into(),
    )
}

#[cfg(test)]
mod tests {
    use askama::Template;
    use postkeep_mail::ImapServers;
    use postkeep_store::{Account, AccountId, Provider};

    use super::*;
    use crate::account_view::{ClientView, ProviderView};

    #[test]
    fn sign_in_page_isolates_client_name_and_redirect_host() {
        let mail = MailChoices::new(&ImapServers::default(), "", "");
        let oauth = OAuthButtons::default();
        let page = SignInPage {
            client_name: "Acme\u{202E}",
            client_host: None,
            redirect_host: "app.example",
            request_id: "req",
            email: "",
            error: None,
            email_error: None,
            password_error: None,
            mail: &mail,
            oauth: &oauth,
        };
        let html = page.render().unwrap();
        assert!(
            html.contains("Connect your mailbox to <bdi>Acme\u{202E}</bdi>"),
            "{html}"
        );
        assert!(
            html.contains("<strong><bdi>Acme\u{202E}</bdi></strong>"),
            "{html}"
        );
        assert!(
            html.contains("<code><bdi>app.example</bdi></code>"),
            "{html}"
        );
    }

    #[test]
    fn account_page_isolates_client_name_and_redirect_host() {
        let account = Account {
            id: AccountId("a".to_owned()),
            email: "me@example.com".to_owned(),
            provider: Provider::Graph,
            imap_server: None,
        };
        let provider = ProviderView::new(&account, &ImapServers::default());
        let clients = [ClientView {
            id: "c".to_owned(),
            name: "Acme\u{202E}".to_owned(),
            initial: "A".to_owned(),
            redirect_host: "app.example".to_owned(),
            authorized_at: "Oct 2, 2026".to_owned(),
            authorized_at_iso: "2026-10-02T00:00:00Z".to_owned(),
            last_active: "just now".to_owned(),
            last_active_iso: "2026-10-02T00:00:00Z".to_owned(),
        }];
        let page = AccountPage {
            email: "me@example.com",
            connected_at: "Oct 2, 2026",
            connected_at_iso: "2026-10-02T00:00:00Z",
            csrf_token: "csrf",
            notice: None,
            provider: &provider,
            clients: &clients,
            mcp_url: "https://mail.example.com/mcp",
            webhook: None,
            password_error: None,
            password_rejected: false,
            override_hint: None,
        };
        let html = page.render().unwrap();
        assert!(
            html.contains("<bdi>Acme\u{202E}</bdi> <bdi class=\"row__host\">app.example</bdi>"),
            "{html}"
        );
        assert!(html.contains("Revoke <bdi>Acme\u{202E}</bdi>?"), "{html}");
    }

    #[test]
    fn domain_override_hint_names_the_preset() {
        use postkeep_mail::ImapPreset;
        assert_eq!(
            domain_override_hint(ImapPreset::ICloud),
            "This is an iCloud address, so iCloud Mail will be used."
        );
        assert_eq!(
            domain_override_hint(ImapPreset::Fastmail),
            "This is a Fastmail address, so Fastmail will be used."
        );
        assert_eq!(
            domain_override_hint(ImapPreset::Yahoo),
            "This is a Yahoo address, so Yahoo Mail will be used."
        );
        assert_eq!(
            domain_override_hint(ImapPreset::Gmail),
            "This is a Gmail address, so Gmail will be used."
        );
    }
}
