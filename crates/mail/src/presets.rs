//! IMAP and SMTP servers users can choose from: presets for well-known
//! providers, plus one custom server set by the operator.
//!
//! Users never enter a host name. Letting them would let anyone make the
//! server open connections to arbitrary hosts and ports (server-side
//! request forgery); the operator decides which servers are offered.

use std::time::Duration;

use secrecy::SecretString;

use crate::config::{
    DEFAULT_TIMEOUT, ICLOUD_IMAP_HOST, ICLOUD_IMAP_PORT, ICLOUD_SMTP_HOST, ICLOUD_SMTP_PORT,
};
use crate::{Credentials, ImapConfig, ImapSecurity, MailConfig, Result, SmtpConfig, SmtpSecurity};

/// A well-known provider that offers IMAP and SMTP with app passwords.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImapPreset {
    /// iCloud Mail. Server settings:
    /// <https://support.apple.com/en-us/102525>.
    ICloud,
    /// Fastmail. Server settings:
    /// <https://www.fastmail.help/hc/en-us/articles/1500000278342-Server-names-and-ports>.
    Fastmail,
    /// Yahoo Mail. Server settings:
    /// <https://help.yahoo.com/kb/imap-server-settings-sln4075.html>.
    Yahoo,
    /// Gmail with a Google app password, which needs 2-Step Verification.
    /// Server settings:
    /// <https://developers.google.com/workspace/gmail/imap/imap-smtp>.
    /// Gmail files sent mail itself and keeps a message that is deleted
    /// from a folder in All Mail, so [`Self::config`] sets
    /// [`MailConfig::server_files_sent`] and clears
    /// [`MailConfig::permanent_delete`].
    Gmail,
}

impl ImapPreset {
    /// Every preset, in the order they are offered.
    pub const ALL: [Self; 4] = [Self::ICloud, Self::Fastmail, Self::Yahoo, Self::Gmail];

    /// The identifier used in configuration and storage.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ICloud => "icloud",
            Self::Fastmail => "fastmail",
            Self::Yahoo => "yahoo",
            Self::Gmail => "gmail",
        }
    }

    /// Parses an identifier.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|preset| preset.id().eq_ignore_ascii_case(id.trim()))
    }

    /// The provider's name, for people.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ICloud => "iCloud Mail",
            Self::Fastmail => "Fastmail",
            Self::Yahoo => "Yahoo Mail",
            Self::Gmail => "Gmail",
        }
    }

    /// Where users create an app password.
    #[must_use]
    pub const fn app_password_url(self) -> &'static str {
        match self {
            Self::ICloud => "https://account.apple.com",
            Self::Fastmail => {
                "https://www.fastmail.help/hc/en-us/articles/360058752854-App-passwords"
            }
            Self::Yahoo => "https://login.yahoo.com/account/security",
            Self::Gmail => "https://myaccount.google.com/apppasswords",
        }
    }

    /// Address domains that belong to the provider, used to pick a preset
    /// from an email address. Custom domains can't be recognized, so a Google
    /// Workspace address has to be picked by hand.
    #[must_use]
    pub const fn domains(self) -> &'static [&'static str] {
        match self {
            Self::ICloud => &["icloud.com", "me.com", "mac.com"],
            Self::Fastmail => &["fastmail.com", "fastmail.fm"],
            Self::Yahoo => &["yahoo.com", "ymail.com", "rocketmail.com", "yahoo.co.uk"],
            Self::Gmail => &["gmail.com", "googlemail.com"],
        }
    }

    /// Whether `email` is at one of this preset's [`Self::domains`].
    #[must_use]
    pub fn owns_address(self, email: &str) -> bool {
        self.matches(email)
    }

    /// The server settings.
    #[must_use]
    pub fn config(self) -> MailConfig {
        let (imap_host, smtp_host, smtp_port, smtp_security) = match self {
            Self::ICloud => (
                ICLOUD_IMAP_HOST,
                ICLOUD_SMTP_HOST,
                ICLOUD_SMTP_PORT,
                SmtpSecurity::StartTls,
            ),
            Self::Fastmail => (
                "imap.fastmail.com",
                "smtp.fastmail.com",
                465,
                SmtpSecurity::Tls,
            ),
            Self::Yahoo => (
                "imap.mail.yahoo.com",
                "smtp.mail.yahoo.com",
                465,
                SmtpSecurity::Tls,
            ),
            Self::Gmail => ("imap.gmail.com", "smtp.gmail.com", 465, SmtpSecurity::Tls),
        };
        // Gmail files mail sent over SMTP itself, and a permanent delete there
        // only removes a label. The other presets keep both defaults.
        let gmail = self == Self::Gmail;
        MailConfig {
            imap: ImapConfig {
                host: imap_host.to_owned(),
                port: ICLOUD_IMAP_PORT,
                security: ImapSecurity::Tls,
            },
            smtp: SmtpConfig {
                host: smtp_host.to_owned(),
                port: smtp_port,
                security: smtp_security,
            },
            timeout: DEFAULT_TIMEOUT,
            sent_folder: None,
            trash_folder: None,
            drafts_folder: None,
            server_files_sent: gmail,
            permanent_delete: !gmail,
        }
    }

    fn matches(self, email: &str) -> bool {
        email.rsplit_once('@').is_some_and(|(_, domain)| {
            self.domains()
                .iter()
                .any(|d| d.eq_ignore_ascii_case(domain))
        })
    }
}

/// Which server an IMAP account uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImapServerId {
    /// A preset.
    Preset(ImapPreset),
    /// The operator's custom server.
    Custom,
}

impl ImapServerId {
    /// The identifier used in forms and storage.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Preset(preset) => preset.id(),
            Self::Custom => "custom",
        }
    }

    /// Parses an identifier.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        if id.trim().eq_ignore_ascii_case("custom") {
            Some(Self::Custom)
        } else {
            ImapPreset::parse(id).map(Self::Preset)
        }
    }
}

/// A server a user can connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapServer {
    /// Which server this is.
    pub id: ImapServerId,
    /// Its name, for people.
    pub name: String,
    /// Where users create an app password, if known.
    pub app_password_url: Option<&'static str>,
    /// Connection settings.
    pub config: MailConfig,
}

impl ImapServer {
    /// Credentials for this server. Presets use app passwords, so dashes
    /// and spaces are removed; a custom server gets the password as typed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidInput`] for an invalid address or an
    /// empty password.
    pub fn credentials(&self, email: &str, password: &SecretString) -> Result<Credentials> {
        match self.id {
            ImapServerId::Preset(_) => Credentials::new(email, password),
            ImapServerId::Custom => Credentials::exact(email, password),
        }
    }

    /// A client for an account on this server.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials (see [`Self::credentials`])
    /// or if TLS can't be set up.
    pub fn client(&self, email: &str, password: &SecretString) -> Result<crate::MailClient> {
        crate::MailClient::new(self.config.clone(), self.credentials(email, password)?)
    }

    /// The password as it should be stored for this server: normalized for
    /// presets, unchanged for a custom server.
    #[must_use]
    pub fn normalize_password(&self, password: &str) -> SecretString {
        match self.id {
            ImapServerId::Preset(_) => crate::normalize_app_password(password),
            ImapServerId::Custom => SecretString::from(password.to_owned()),
        }
    }
}

/// The servers offered by this deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapServers {
    presets: Vec<ImapPreset>,
    custom: Option<ImapServer>,
    timeout: Duration,
}

impl Default for ImapServers {
    /// Every preset, no custom server.
    fn default() -> Self {
        Self::new(ImapPreset::ALL.to_vec(), None)
    }
}

impl ImapServers {
    /// Offers `presets` and, if given, a custom server named `name`.
    #[must_use]
    pub fn new(presets: Vec<ImapPreset>, custom: Option<(String, MailConfig)>) -> Self {
        let mut unique = Vec::new();
        for preset in presets {
            if !unique.contains(&preset) {
                unique.push(preset);
            }
        }
        Self {
            presets: unique,
            custom: custom.map(|(name, config)| ImapServer {
                id: ImapServerId::Custom,
                name,
                app_password_url: None,
                config,
            }),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Only a custom server, for tests against a local mail server.
    #[must_use]
    pub fn custom_only(name: &str, config: MailConfig) -> Self {
        let timeout = config.timeout;
        Self::new(Vec::new(), Some((name.to_owned(), config))).with_timeout(timeout)
    }

    /// Applies `timeout` to every server.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether no server is offered at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.presets.is_empty() && self.custom.is_none()
    }

    /// Every offered server: presets first, then the custom server.
    #[must_use]
    pub fn choices(&self) -> Vec<ImapServer> {
        self.presets
            .iter()
            .filter_map(|preset| self.get(ImapServerId::Preset(*preset)))
            .chain(
                self.custom
                    .iter()
                    .map(|custom| self.with_timeout_applied(custom.clone())),
            )
            .collect()
    }

    /// An offered server.
    #[must_use]
    pub fn get(&self, id: ImapServerId) -> Option<ImapServer> {
        match id {
            ImapServerId::Preset(preset) if self.presets.contains(&preset) => {
                Some(self.with_timeout_applied(ImapServer {
                    id,
                    name: preset.name().to_owned(),
                    app_password_url: Some(preset.app_password_url()),
                    config: preset.config(),
                }))
            }
            ImapServerId::Preset(_) => None,
            ImapServerId::Custom => self
                .custom
                .clone()
                .map(|custom| self.with_timeout_applied(custom)),
        }
    }

    /// The server for accounts that don't name one: the custom server if
    /// there is one (that is what such accounts used before presets
    /// existed), otherwise iCloud Mail, otherwise the first preset.
    #[must_use]
    pub fn default_server(&self) -> Option<ImapServer> {
        if self.custom.is_some() {
            return self.get(ImapServerId::Custom);
        }
        self.get(ImapServerId::Preset(ImapPreset::ICloud))
            .or_else(|| self.choices().into_iter().next())
    }

    /// The server of a stored account: the named one, or the default for
    /// accounts that name none. `None` if that server is no longer offered.
    #[must_use]
    pub fn resolve(&self, stored: Option<&str>) -> Option<ImapServer> {
        stored.map_or_else(
            || self.default_server(),
            |id| ImapServerId::parse(id).and_then(|id| self.get(id)),
        )
    }

    /// The server for a sign-in. An address at a domain an offered preset
    /// owns (`@icloud.com`, `@fastmail.com`, `@yahoo.com`, ...) always goes
    /// to that preset, whatever was picked: those addresses can't live
    /// anywhere else. Otherwise `selection` names the server; empty or
    /// `auto` means the default server. `None` for an unknown selection.
    #[must_use]
    pub fn choose(&self, selection: &str, email: &str) -> Option<ImapServer> {
        let selection = selection.trim();
        let picked = if selection.is_empty() || selection.eq_ignore_ascii_case("auto") {
            None
        } else {
            Some(ImapServerId::parse(selection).and_then(|id| self.get(id))?)
        };
        self.presets
            .iter()
            .find(|preset| preset.matches(email))
            .and_then(|preset| self.get(ImapServerId::Preset(*preset)))
            .or(picked)
            .or_else(|| self.default_server())
    }

    /// The preset that replaces an explicit pick because it owns `email`'s
    /// domain. `None` when the pick is honoured, when `selection` is empty
    /// or `auto`, or when no offered preset owns the domain.
    #[must_use]
    pub fn domain_override(&self, selection: &str, email: &str) -> Option<ImapPreset> {
        let selection = selection.trim();
        if selection.is_empty() || selection.eq_ignore_ascii_case("auto") {
            return None;
        }
        let picked = ImapServerId::parse(selection)?;
        let chosen = self.choose(selection, email)?;
        let ImapServerId::Preset(preset) = chosen.id else {
            return None;
        };
        if picked == chosen.id || !preset.owns_address(email) {
            return None;
        }
        Some(preset)
    }

    const fn with_timeout_applied(&self, mut server: ImapServer) -> ImapServer {
        server.config.timeout = self.timeout;
        server
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> MailConfig {
        let mut config = MailConfig::default();
        config.imap.host = "127.0.0.1".to_owned();
        config
    }

    #[test]
    fn presets_round_trip() {
        for preset in ImapPreset::ALL {
            assert_eq!(ImapPreset::parse(preset.id()), Some(preset));
            assert_eq!(
                ImapServerId::parse(preset.id()),
                Some(ImapServerId::Preset(preset))
            );
            let config = preset.config();
            assert_eq!(config.imap.port, 993);
            assert_eq!(config.imap.security, ImapSecurity::Tls);
            assert_ne!(config.smtp.security, SmtpSecurity::Plaintext);
        }
        assert_eq!(ImapServerId::parse("CUSTOM"), Some(ImapServerId::Custom));
        // Any id that is no preset will do. This used to be "gmail": Gmail was
        // meant to be reached only through Sign in with Google. It is a preset
        // now, because Google still accepts app passwords over IMAP and SMTP.
        assert_eq!(ImapServerId::parse("hotmail"), None);
        assert_eq!(ImapPreset::ICloud.config(), MailConfig::default());
    }

    #[test]
    fn gmail_is_a_preset_for_app_passwords() {
        let gmail = ImapServerId::Preset(ImapPreset::Gmail);
        assert_eq!(ImapPreset::parse(" Gmail "), Some(ImapPreset::Gmail));
        assert_eq!(ImapServerId::parse("gmail"), Some(gmail));
        // Offered by default, after the others.
        assert_eq!(ImapPreset::ALL.last(), Some(&ImapPreset::Gmail));
        let server = ImapServers::default().get(gmail).unwrap();
        assert_eq!(server.name, "Gmail");
        assert_eq!(
            server.app_password_url,
            Some("https://myaccount.google.com/apppasswords")
        );
        assert_eq!(ImapPreset::Gmail.domains(), ["gmail.com", "googlemail.com"]);
        // Implicit TLS on both ports; Gmail files the Sent copy itself, and a
        // permanent delete would only remove a label.
        assert_eq!(
            server.config,
            MailConfig {
                imap: ImapConfig {
                    host: "imap.gmail.com".to_owned(),
                    port: 993,
                    security: ImapSecurity::Tls,
                },
                smtp: SmtpConfig {
                    host: "smtp.gmail.com".to_owned(),
                    port: 465,
                    security: SmtpSecurity::Tls,
                },
                server_files_sent: true,
                permanent_delete: false,
                ..MailConfig::default()
            }
        );
    }

    #[test]
    fn existing_servers_keep_appending_the_sent_copy() {
        assert!(!MailConfig::default().server_files_sent);
        for preset in [ImapPreset::ICloud, ImapPreset::Fastmail, ImapPreset::Yahoo] {
            assert!(!preset.config().server_files_sent, "{preset:?}");
        }
    }

    #[test]
    fn existing_servers_keep_permanent_deletes() {
        assert!(MailConfig::default().permanent_delete);
        for preset in [ImapPreset::ICloud, ImapPreset::Fastmail, ImapPreset::Yahoo] {
            assert!(preset.config().permanent_delete, "{preset:?}");
        }
    }

    #[test]
    fn chooses_by_domain_then_default() {
        let servers = ImapServers::default();
        let pick = |selection: &str, email: &str| servers.choose(selection, email).map(|s| s.id);
        assert_eq!(
            pick("auto", "a@me.com"),
            Some(ImapServerId::Preset(ImapPreset::ICloud))
        );
        assert_eq!(
            pick("", "a@FastMail.com"),
            Some(ImapServerId::Preset(ImapPreset::Fastmail))
        );
        assert_eq!(
            pick("auto", "a@yahoo.com"),
            Some(ImapServerId::Preset(ImapPreset::Yahoo))
        );
        // Unknown domains (iCloud custom domains, for example) use the
        // default.
        assert_eq!(
            pick("auto", "a@example.com"),
            Some(ImapServerId::Preset(ImapPreset::ICloud))
        );
        assert_eq!(
            pick("yahoo", "a@example.com"),
            Some(ImapServerId::Preset(ImapPreset::Yahoo))
        );
        assert_eq!(pick("custom", "a@example.com"), None);
        assert_eq!(pick("nonsense", "a@example.com"), None);
        // A provider's own domain wins over the picker.
        assert_eq!(
            pick("icloud", "a@yahoo.com"),
            Some(ImapServerId::Preset(ImapPreset::Yahoo))
        );
        assert_eq!(pick("nonsense", "a@yahoo.com"), None);
        // Gmail's two domains, in any case. A Google Workspace address is at
        // its own domain, so the person picks Gmail for it.
        let gmail = Some(ImapServerId::Preset(ImapPreset::Gmail));
        assert_eq!(pick("auto", "A@GMAIL.COM"), gmail);
        assert_eq!(pick("", "a@googlemail.com"), gmail);
        assert_eq!(pick("yahoo", "a@gmail.com"), gmail);
        assert_eq!(pick("gmail", "a@example.com"), gmail);
        assert_ne!(pick("auto", "a@example.com"), gmail);
        // The override is reported only when an explicit pick loses.
        assert_eq!(
            servers.domain_override("yahoo", "a@icloud.com"),
            Some(ImapPreset::ICloud)
        );
        assert_eq!(
            servers.domain_override("YAHOO", "A@Me.com"),
            Some(ImapPreset::ICloud)
        );
        assert_eq!(servers.domain_override("icloud", "a@icloud.com"), None);
        assert_eq!(servers.domain_override("yahoo", "a@example.com"), None);
        assert_eq!(servers.domain_override("auto", "a@me.com"), None);
        assert_eq!(servers.domain_override("", "a@yahoo.co.uk"), None);
        assert_eq!(servers.domain_override("nope", "a@fastmail.com"), None);
        assert_eq!(
            servers.domain_override("yahoo", "a@googlemail.com"),
            Some(ImapPreset::Gmail)
        );
        assert_eq!(servers.domain_override("gmail", "a@gmail.com"), None);
        assert_eq!(servers.domain_override("gmail", "a@example.com"), None);
    }

    #[test]
    fn only_offered_servers_resolve() {
        let servers = ImapServers::new(vec![ImapPreset::Fastmail], None);
        assert_eq!(servers.resolve(Some("icloud")), None);
        assert_eq!(
            servers.resolve(None).map(|s| s.id),
            Some(ImapServerId::Preset(ImapPreset::Fastmail))
        );
        assert_eq!(
            servers.choose("auto", "a@icloud.com").map(|s| s.id),
            Some(ImapServerId::Preset(ImapPreset::Fastmail))
        );
        // Where Gmail is not offered, its addresses go to the default too.
        assert_eq!(servers.resolve(Some("gmail")), None);
        assert_eq!(
            servers.choose("auto", "a@gmail.com").map(|s| s.id),
            Some(ImapServerId::Preset(ImapPreset::Fastmail))
        );
        assert!(ImapServers::new(Vec::new(), None).is_empty());
        assert_eq!(ImapServers::new(Vec::new(), None).default_server(), None);
    }

    #[test]
    fn custom_server_is_the_default() {
        let servers = ImapServers::new(
            ImapPreset::ALL.to_vec(),
            Some(("Company mail".to_owned(), local())),
        )
        .with_timeout(Duration::from_secs(5));
        let default = servers.resolve(None).unwrap();
        assert_eq!(default.id, ImapServerId::Custom);
        assert_eq!(default.name, "Company mail");
        assert_eq!(default.config.imap.host, "127.0.0.1");
        assert_eq!(default.config.timeout, Duration::from_secs(5));
        assert_eq!(
            servers.choose("auto", "a@example.com").map(|s| s.id),
            Some(ImapServerId::Custom)
        );
        assert_eq!(
            servers.domain_override("custom", "a@fastmail.fm"),
            Some(ImapPreset::Fastmail)
        );
        assert_eq!(servers.domain_override("custom", "a@example.com"), None);
        assert_eq!(servers.choices().len(), 5);
        assert!(
            servers
                .choices()
                .iter()
                .all(|server| server.config.timeout == Duration::from_secs(5))
        );
    }

    #[test]
    fn passwords_are_normalized_only_for_presets() {
        use secrecy::ExposeSecret;
        let servers = ImapServers::new(
            vec![ImapPreset::ICloud],
            Some(("Other".to_owned(), local())),
        );
        let icloud = servers
            .get(ImapServerId::Preset(ImapPreset::ICloud))
            .unwrap();
        let custom = servers.get(ImapServerId::Custom).unwrap();
        assert_eq!(
            icloud
                .normalize_password("abcd-efgh ijkl-mnop")
                .expose_secret(),
            "abcdefghijklmnop"
        );
        assert_eq!(
            custom.normalize_password("p4ss-word ").expose_secret(),
            "p4ss-word "
        );
        let password = SecretString::from("a-b".to_owned());
        assert!(icloud.credentials("a@icloud.com", &password).is_ok());
        assert!(custom.credentials("a@example.com", &password).is_ok());
        // Google shows an app password as four groups of four letters.
        let gmail = ImapServers::default()
            .get(ImapServerId::Preset(ImapPreset::Gmail))
            .unwrap();
        let shown = SecretString::from("abcd efgh ijkl mnop".to_owned());
        let stored = gmail.normalize_password("abcd efgh ijkl mnop");
        assert_eq!(stored.expose_secret(), "abcdefghijklmnop");
        let login = gmail.credentials("a@gmail.com", &shown).unwrap();
        assert_eq!(login.password().expose_secret(), "abcdefghijklmnop");
    }
}
