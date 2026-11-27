//! Folder listing and special-use folder detection.

use async_imap::types::{Name, NameAttribute};
use futures::TryStreamExt;

use super::{Conn, WritePhase};
use crate::{Error, Result, utf7};

/// A mail folder (IMAP mailbox).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Full folder name in UTF-8, as accepted by every operation.
    pub name: String,
    /// Hierarchy delimiter, for example `/`.
    pub delimiter: Option<String>,
    /// The folder's role: advertised by the server (RFC 6154), or inferred
    /// from a conventional name such as "Junk" when the server advertises
    /// no folder with that role.
    pub special_use: Option<SpecialUse>,
    /// Whether the folder can hold messages.
    pub selectable: bool,
}

impl Folder {
    fn from_name(name: &Name) -> Self {
        let raw = name.name();
        let attributes = name.attributes();
        Self {
            name: utf7::decode(raw).unwrap_or_else(|| raw.to_owned()),
            delimiter: name.delimiter().map(str::to_owned),
            special_use: attributes.iter().find_map(SpecialUse::from_attribute),
            selectable: !attributes
                .iter()
                .any(|attr| matches!(attr, NameAttribute::NoSelect)),
        }
    }
}

/// Special folder roles from RFC 6154.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecialUse {
    /// Virtual folder containing all messages.
    All,
    /// Archive folder.
    Archive,
    /// Drafts folder.
    Drafts,
    /// Virtual folder containing flagged messages.
    Flagged,
    /// Junk / spam folder.
    Junk,
    /// Sent messages folder.
    Sent,
    /// Trash folder (iCloud: "Deleted Messages").
    Trash,
}

impl SpecialUse {
    const fn from_attribute(attribute: &NameAttribute<'_>) -> Option<Self> {
        match attribute {
            NameAttribute::All => Some(Self::All),
            NameAttribute::Archive => Some(Self::Archive),
            NameAttribute::Drafts => Some(Self::Drafts),
            NameAttribute::Flagged => Some(Self::Flagged),
            NameAttribute::Junk => Some(Self::Junk),
            NameAttribute::Sent => Some(Self::Sent),
            NameAttribute::Trash => Some(Self::Trash),
            _ => None,
        }
    }

    /// Roles that can be inferred from a folder name.
    const INFERABLE: [Self; 5] = [
        Self::Sent,
        Self::Trash,
        Self::Drafts,
        Self::Junk,
        Self::Archive,
    ];

    /// The role in lowercase, for example `"sent"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Archive => "archive",
            Self::Drafts => "drafts",
            Self::Flagged => "flagged",
            Self::Junk => "junk",
            Self::Sent => "sent",
            Self::Trash => "trash",
        }
    }

    /// Conventional folder names, used when the server does not advertise
    /// special-use attributes. iCloud's names come first.
    const fn fallback_names(self) -> &'static [&'static str] {
        match self {
            Self::All | Self::Flagged => &[],
            Self::Archive => &["Archive", "Archives"],
            Self::Drafts => &["Drafts", "Draft"],
            Self::Junk => &["Junk", "Spam", "Junk E-mail", "Junk Email", "Bulk Mail"],
            Self::Sent => &["Sent Messages", "Sent", "Sent Items", "Sent Mail"],
            Self::Trash => &["Deleted Messages", "Trash", "Deleted Items", "Deleted"],
        }
    }
}

impl std::fmt::Display for SpecialUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lists every folder of the account, with roles inferred by name where the
/// server does not advertise them.
pub(super) async fn list(conn: &mut Conn) -> Result<Vec<Folder>> {
    let names: Vec<Name> = conn.list(Some(""), Some("*")).await?.try_collect().await?;
    let mut folders: Vec<Folder> = names.iter().map(Folder::from_name).collect();
    infer_roles(&mut folders);
    Ok(folders)
}

/// Assigns each role the server did not advertise to the first selectable
/// folder with a conventional name for it. iCloud, for example, advertises
/// `\Sent` and `\Trash` but not Archive, Junk or Drafts.
fn infer_roles(folders: &mut [Folder]) {
    for role in SpecialUse::INFERABLE {
        if folders
            .iter()
            .any(|folder| folder.special_use == Some(role))
        {
            continue;
        }
        let found = role.fallback_names().iter().find_map(|candidate| {
            folders.iter().position(|folder| {
                folder.selectable
                    && folder.special_use.is_none()
                    && folder.name.eq_ignore_ascii_case(candidate)
            })
        });
        if let Some(index) = found {
            folders[index].special_use = Some(role);
        }
    }
}

/// Creates a folder named `name`.
pub(super) async fn create(conn: &mut Conn, name: &str, phase: &mut WritePhase) -> Result<()> {
    if name.trim().is_empty() {
        return Err(Error::invalid("folder names must not be empty"));
    }
    *phase = WritePhase::Started;
    conn.create(utf7::encode(name)).await?;
    Ok(())
}

/// Resolves the folder for `role`, preferring an explicitly configured name.
pub(super) async fn resolve(
    conn: &mut Conn,
    role: SpecialUse,
    configured: Option<&str>,
) -> Result<String> {
    if let Some(name) = configured {
        return Ok(name.to_owned());
    }
    let folders = list(conn).await?;
    pick(&folders, role)
        .map(|folder| folder.name.clone())
        .ok_or_else(|| Error::FolderNotFound(format!("no {role:?} folder found")))
}

/// Compares exact folder names, except that INBOX is case-insensitive.
#[must_use]
pub fn same_folder(a: &str, b: &str) -> bool {
    a == b || (a.eq_ignore_ascii_case("INBOX") && b.eq_ignore_ascii_case("INBOX"))
}

/// Whether a selectable folder called `name` exists.
pub(super) async fn exists(conn: &mut Conn, name: &str) -> Result<bool> {
    Ok(list(conn)
        .await?
        .iter()
        .any(|folder| folder.selectable && same_folder(&folder.name, name)))
}

/// Picks the folder for `role` by special-use attribute, then by name.
fn pick(folders: &[Folder], role: SpecialUse) -> Option<&Folder> {
    folders
        .iter()
        .find(|folder| folder.selectable && folder.special_use == Some(role))
        .or_else(|| {
            role.fallback_names().iter().find_map(|candidate| {
                folders
                    .iter()
                    .find(|folder| folder.selectable && folder.name.eq_ignore_ascii_case(candidate))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str, special_use: Option<SpecialUse>) -> Folder {
        Folder {
            name: name.to_owned(),
            delimiter: Some("/".to_owned()),
            special_use,
            selectable: true,
        }
    }

    #[test]
    fn prefers_special_use_attribute() {
        let folders = [
            folder("Trash", None),
            folder("Papierkorb", Some(SpecialUse::Trash)),
        ];
        assert_eq!(
            pick(&folders, SpecialUse::Trash).unwrap().name,
            "Papierkorb"
        );
    }

    #[test]
    fn falls_back_to_icloud_names_first() {
        let folders = [
            folder("INBOX", None),
            folder("Sent", None),
            folder("Sent Messages", None),
            folder("deleted messages", None),
        ];
        assert_eq!(
            pick(&folders, SpecialUse::Sent).unwrap().name,
            "Sent Messages"
        );
        assert_eq!(
            pick(&folders, SpecialUse::Trash).unwrap().name,
            "deleted messages"
        );
        assert_eq!(pick(&folders, SpecialUse::Archive), None);
    }

    #[test]
    fn infers_missing_roles_like_icloud() {
        // What iCloud returns: only Sent and Trash carry special-use flags.
        let mut folders = vec![
            folder("INBOX", None),
            folder("Sent Messages", Some(SpecialUse::Sent)),
            folder("Deleted Messages", Some(SpecialUse::Trash)),
            folder("Archive", None),
            folder("Junk", None),
            folder("Drafts", None),
            folder("Projects", None),
        ];
        infer_roles(&mut folders);
        let roles: Vec<(&str, Option<&str>)> = folders
            .iter()
            .map(|f| (f.name.as_str(), f.special_use.map(SpecialUse::as_str)))
            .collect();
        assert_eq!(
            roles,
            [
                ("INBOX", None),
                ("Sent Messages", Some("sent")),
                ("Deleted Messages", Some("trash")),
                ("Archive", Some("archive")),
                ("Junk", Some("junk")),
                ("Drafts", Some("drafts")),
                ("Projects", None),
            ]
        );
    }

    #[test]
    fn advertised_roles_win_over_names() {
        let mut folders = vec![
            folder("Sent", None),
            folder("Gesendet", Some(SpecialUse::Sent)),
            folder("trash", None),
        ];
        infer_roles(&mut folders);
        assert_eq!(folders[0].special_use, None);
        assert_eq!(folders[1].special_use, Some(SpecialUse::Sent));
        assert_eq!(folders[2].special_use, Some(SpecialUse::Trash));
    }

    #[test]
    fn infers_each_role_once() {
        let mut folders = vec![folder("Junk", None), folder("Spam", None)];
        infer_roles(&mut folders);
        assert_eq!(folders[0].special_use, Some(SpecialUse::Junk));
        assert_eq!(folders[1].special_use, None);
    }

    #[test]
    fn ignores_unselectable_folders() {
        let mut trash = folder("Trash", Some(SpecialUse::Trash));
        trash.selectable = false;
        assert_eq!(pick(&[trash], SpecialUse::Trash), None);
    }
}
