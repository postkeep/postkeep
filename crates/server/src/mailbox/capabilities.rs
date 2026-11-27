//! Static capabilities of providers and server deployments.

use postkeep_mail::{ImapPreset, ImapServer, ImapServerId, ImapServers, MailConfig};
use postkeep_store::Provider;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::tools::{MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS};

/// Mail provider class for a mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailboxProvider {
    /// iCloud Mail.
    Icloud,
    /// Gmail (over IMAP or Gmail API).
    Gmail,
    /// Outlook.com or Microsoft 365.
    Outlook,
    /// Fastmail.
    Fastmail,
    /// Yahoo Mail.
    Yahoo,
    /// Custom or generic IMAP server.
    Imap,
}

/// Mail transport protocol used for this mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailboxProtocol {
    /// Standard IMAP and SMTP.
    Imap,
    /// Microsoft Graph REST API.
    MicrosoftGraph,
    /// Google Gmail REST API.
    GmailApi,
}

/// Authentication mechanism used by this mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    /// Password-based authentication (an app password for consumer presets, or the account password for custom IMAP).
    AppPassword,
    /// OAuth sign-in.
    Oauth,
}

/// Whether message ids stay the same after a move between folders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdStabilityOnMove {
    /// Message ids currently returned by this server stay the same across moves (older Outlook ids can still change; use the move result's mapping).
    Stable,
    /// Moving a message assigns a new id in the destination folder.
    ChangesOnMove,
}

/// How search text filters match on this provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TextMatching {
    /// Substring matching in headers after local filtering; custom IMAP body search depends on the server.
    Substring,
    /// Whole-word matching, ignoring case and punctuation.
    WholeWords,
}

/// Static provider support for mailbox operations, independent of caller permissions, hidden tools, or retired-server availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags on the wire"
)]
pub struct OperationCapabilities {
    /// Whether this provider supports creating drafts.
    pub create_draft: bool,
    /// Whether this server supports editing existing drafts on this provider.
    pub edit_draft: bool,
    /// Whether permanent deletion is supported in any folder.
    pub permanent_delete: bool,
    /// Whether permanent deletion is supported only for messages already in Trash.
    pub permanent_delete_trash_only: bool,
    /// Whether this provider supports creating folders or labels.
    pub create_folder: bool,
    /// Whether this server supports renaming folders or labels on this provider.
    pub rename_folder: bool,
    /// Whether this server supports deleting folders or labels on this provider.
    pub delete_folder: bool,
}

/// Search and bulk-selection filter support for this provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SearchCapabilities {
    /// How text filters match messages.
    pub text_matching: TextMatching,
    /// Whether bulk selections accept the `text` filter (Outlook and Gmail API accept one alphanumeric word only).
    pub selection_supports_text: bool,
    /// Whether bulk selections accept the `to` filter.
    pub selection_supports_to: bool,
}

/// Attachment size, count, and upload limits on this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttachmentCapabilities {
    /// Maximum decoded attachment size returned by download, in bytes.
    pub download_max_bytes: usize,
    /// Maximum number of attachments supplied in one tool call, excluding files carried from a forwarded message.
    pub max_per_message: usize,
    /// Whether attachment uploads are enabled on this server.
    pub upload_enabled: bool,
}

/// Server deployment features that affect reported mailbox capabilities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent deployment settings"
)]
pub struct ServerFeatures {
    /// Whether new-mail webhooks are enabled on this server.
    pub webhooks_enabled: bool,
    /// Whether Microsoft Graph webhook push is configured on this server.
    pub graph_push_enabled: bool,
    /// Whether Google Gmail API webhook push is configured on this server.
    pub google_push_enabled: bool,
    /// Whether attachment uploads are enabled on this server.
    pub upload_enabled: bool,
}

/// Static provider and server deployment capabilities for a mailbox, independent of caller permissions, hidden tools, or transient sign-in state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MailboxCapabilities {
    /// Mail provider class for this mailbox.
    pub provider: MailboxProvider,
    /// Mail transport protocol used for this mailbox.
    pub protocol: MailboxProtocol,
    /// Authentication mechanism used by this mailbox.
    pub auth_type: AuthType,
    /// Static provider support for mailbox operations.
    pub operations: OperationCapabilities,
    /// Whether message ids stay the same when moved.
    pub id_stability_on_move: IdStabilityOnMove,
    /// Search and bulk-selection filter capabilities.
    pub search: SearchCapabilities,
    /// Attachment limits and upload availability.
    pub attachments: AttachmentCapabilities,
    /// Whether this deployment can watch this mailbox for new-mail webhooks (false when webhooks or provider push prerequisites are off, or the IMAP server is not offered), independent of sign-in state or current webhook settings.
    pub webhooks_available: bool,
}

pub(crate) struct SelectionFilterRules {
    pub(crate) one_word: &'static [&'static str],
    pub(crate) never: &'static [&'static str],
}

impl SelectionFilterRules {
    pub(crate) const fn for_provider(provider: Provider) -> Self {
        match provider {
            Provider::Imap => Self {
                one_word: &[],
                never: &["text"],
            },
            Provider::Graph => Self {
                one_word: &["text"],
                never: &[],
            },
            Provider::Gmail => Self {
                one_word: &["from", "subject", "text"],
                never: &["to"],
            },
        }
    }

    pub(crate) fn allows(&self, filter: &str) -> bool {
        !self.never.contains(&filter)
    }
}

impl MailboxCapabilities {
    /// Reports capabilities for a stored account and the current deployment without connecting to the provider.
    #[must_use]
    pub fn for_account(
        provider: Provider,
        imap_server: Option<&str>,
        servers: &ImapServers,
        features: ServerFeatures,
    ) -> Self {
        let (mail_provider, protocol, permanent_delete, text_matching, can_watch) = match provider {
            Provider::Imap => {
                let (mail_provider, permanent_delete, text_matching, offered) =
                    resolve_imap(imap_server, servers);
                (
                    mail_provider,
                    MailboxProtocol::Imap,
                    permanent_delete,
                    text_matching,
                    offered,
                )
            }
            Provider::Graph => (
                MailboxProvider::Outlook,
                MailboxProtocol::MicrosoftGraph,
                true,
                TextMatching::WholeWords,
                features.graph_push_enabled,
            ),
            Provider::Gmail => (
                MailboxProvider::Gmail,
                MailboxProtocol::GmailApi,
                false,
                TextMatching::WholeWords,
                features.google_push_enabled,
            ),
        };
        let imap = provider == Provider::Imap;
        let rules = SelectionFilterRules::for_provider(provider);
        Self {
            provider: mail_provider,
            protocol,
            auth_type: if provider.is_oauth() {
                AuthType::Oauth
            } else {
                AuthType::AppPassword
            },
            operations: OperationCapabilities {
                create_draft: imap,
                edit_draft: false,
                permanent_delete,
                permanent_delete_trash_only: false,
                create_folder: true,
                rename_folder: false,
                delete_folder: false,
            },
            id_stability_on_move: if imap {
                IdStabilityOnMove::ChangesOnMove
            } else {
                IdStabilityOnMove::Stable
            },
            search: SearchCapabilities {
                text_matching,
                selection_supports_text: rules.allows("text"),
                selection_supports_to: rules.allows("to"),
            },
            attachments: AttachmentCapabilities {
                download_max_bytes: MAX_ATTACHMENT_BYTES,
                max_per_message: MAX_ATTACHMENTS,
                upload_enabled: features.upload_enabled,
            },
            webhooks_available: features.webhooks_enabled && can_watch,
        }
    }
}

fn resolve_imap(
    imap_server: Option<&str>,
    servers: &ImapServers,
) -> (MailboxProvider, bool, TextMatching, bool) {
    let (preset, permanent_delete, offered) = match servers.resolve(imap_server) {
        Some(ImapServer {
            id: ImapServerId::Preset(preset),
            config,
            ..
        }) => (Some(preset), config.permanent_delete, true),
        Some(ImapServer {
            id: ImapServerId::Custom,
            config,
            ..
        }) => (None, config.permanent_delete, true),
        None => imap_server.and_then(ImapPreset::parse).map_or_else(
            || (None, MailConfig::default().permanent_delete, false),
            |preset| (Some(preset), preset.config().permanent_delete, false),
        ),
    };
    let provider = match preset {
        Some(ImapPreset::ICloud) => MailboxProvider::Icloud,
        Some(ImapPreset::Gmail) => MailboxProvider::Gmail,
        Some(ImapPreset::Fastmail) => MailboxProvider::Fastmail,
        Some(ImapPreset::Yahoo) => MailboxProvider::Yahoo,
        None => MailboxProvider::Imap,
    };
    let text_matching = if preset == Some(ImapPreset::Gmail) {
        TextMatching::WholeWords
    } else {
        TextMatching::Substring
    };
    (provider, permanent_delete, text_matching, offered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table exercises all account and deployment cases"
    )]
    fn capabilities_matrix_covers_all_providers_presets_and_features() {
        let defaults = ImapServers::default();
        let gmail_only = ImapServers::new(vec![ImapPreset::Gmail], None);
        let empty = ImapServers::new(Vec::new(), None);
        let custom = |permanent_delete| {
            ImapServers::custom_only(
                "Test mail",
                MailConfig {
                    permanent_delete,
                    ..MailConfig::default()
                },
            )
        };
        let enabled = custom(true);
        let disabled = custom(false);
        let features = ServerFeatures {
            webhooks_enabled: true,
            ..ServerFeatures::default()
        };
        let expected_operations = OperationCapabilities {
            create_draft: true,
            edit_draft: false,
            permanent_delete: true,
            permanent_delete_trash_only: false,
            create_folder: true,
            rename_folder: false,
            delete_folder: false,
        };
        let unknown = "unoffered-id";
        for (servers, id, provider, permanent_delete, offered) in [
            (
                &defaults,
                Some("icloud"),
                MailboxProvider::Icloud,
                true,
                true,
            ),
            (
                &defaults,
                Some("fastmail"),
                MailboxProvider::Fastmail,
                true,
                true,
            ),
            (&defaults, Some("yahoo"), MailboxProvider::Yahoo, true, true),
            (
                &defaults,
                Some("gmail"),
                MailboxProvider::Gmail,
                false,
                true,
            ),
            (&enabled, Some("custom"), MailboxProvider::Imap, true, true),
            (
                &disabled,
                Some("custom"),
                MailboxProvider::Imap,
                false,
                true,
            ),
            (&defaults, None, MailboxProvider::Icloud, true, true),
            (&disabled, None, MailboxProvider::Imap, false, true),
            (&gmail_only, None, MailboxProvider::Gmail, false, true),
            (&empty, None, MailboxProvider::Imap, true, false),
            (&empty, Some("gmail"), MailboxProvider::Gmail, false, false),
            (&defaults, Some(unknown), MailboxProvider::Imap, true, false),
        ] {
            let caps = MailboxCapabilities::for_account(Provider::Imap, id, servers, features);
            assert_eq!(caps.provider, provider, "{id:?}");
            assert_eq!(caps.protocol, MailboxProtocol::Imap);
            assert_eq!(caps.auth_type, AuthType::AppPassword);
            assert_eq!(
                caps.operations,
                OperationCapabilities {
                    permanent_delete,
                    ..expected_operations
                }
            );
            assert_eq!(caps.id_stability_on_move, IdStabilityOnMove::ChangesOnMove);
            assert_eq!(
                caps.search.text_matching,
                if provider == MailboxProvider::Gmail {
                    TextMatching::WholeWords
                } else {
                    TextMatching::Substring
                }
            );
            assert!(!caps.search.selection_supports_text);
            assert!(caps.search.selection_supports_to);
            assert_eq!(caps.webhooks_available, offered, "{id:?}");
            assert!(!serde_json::to_string(&caps).unwrap().contains(unknown));
        }
        for mask in 0..16 {
            let features = ServerFeatures {
                webhooks_enabled: mask & 1 != 0,
                graph_push_enabled: mask & 2 != 0,
                google_push_enabled: mask & 4 != 0,
                upload_enabled: mask & 8 != 0,
            };
            for (provider, family, protocol, permanent_delete, push) in [
                (
                    Provider::Graph,
                    MailboxProvider::Outlook,
                    MailboxProtocol::MicrosoftGraph,
                    true,
                    features.graph_push_enabled,
                ),
                (
                    Provider::Gmail,
                    MailboxProvider::Gmail,
                    MailboxProtocol::GmailApi,
                    false,
                    features.google_push_enabled,
                ),
            ] {
                let caps =
                    MailboxCapabilities::for_account(provider, Some(unknown), &defaults, features);
                assert_eq!(
                    (caps.provider, caps.protocol, caps.auth_type),
                    (family, protocol, AuthType::Oauth)
                );
                assert_eq!(
                    caps.operations,
                    OperationCapabilities {
                        create_draft: false,
                        permanent_delete,
                        ..expected_operations
                    }
                );
                assert_eq!(caps.id_stability_on_move, IdStabilityOnMove::Stable);
                assert_eq!(
                    caps.search,
                    SearchCapabilities {
                        text_matching: TextMatching::WholeWords,
                        selection_supports_text: true,
                        selection_supports_to: provider == Provider::Graph
                    }
                );
                assert_eq!(
                    caps.attachments,
                    AttachmentCapabilities {
                        download_max_bytes: MAX_ATTACHMENT_BYTES,
                        max_per_message: MAX_ATTACHMENTS,
                        upload_enabled: features.upload_enabled
                    }
                );
                assert_eq!(caps.webhooks_available, features.webhooks_enabled && push);
            }
        }
        let caps =
            MailboxCapabilities::for_account(Provider::Imap, Some("gmail"), &defaults, features);
        let wire = serde_json::to_string(&caps).unwrap();
        assert_eq!(
            wire,
            concat!(
                r#"{"provider":"gmail","protocol":"imap","auth_type":"app_password","operations":{"create_draft":true,"edit_draft":false,"permanent_delete":false,"#,
                r#""permanent_delete_trash_only":false,"create_folder":true,"rename_folder":false,"delete_folder":false},"id_stability_on_move":"changes_on_move","#,
                r#""search":{"text_matching":"whole_words","selection_supports_text":false,"selection_supports_to":true},"#,
                r#""attachments":{"download_max_bytes":3145728,"max_per_message":1000,"upload_enabled":false},"webhooks_available":true}"#,
            )
        );
        assert_eq!(
            serde_json::from_str::<MailboxCapabilities>(&wire).unwrap(),
            caps
        );
    }
}
