//! Single-file MCP skills backed by validated Markdown documents.

use std::sync::{Arc, LazyLock};

use rmcp::model::{Resource, Skill, SkillFrontmatter, SkillResource, SkillResources};

const MAX_SKILL_BYTES: usize = 16 * 1024 * 1024;
/// Media type of the skill resource in both discovery and reads.
pub(super) const MARKDOWN_MIME_TYPE: &str = "text/markdown";
const BUILTIN_MARKDOWN: [&str; 3] = [
    include_str!("../../skills/cross-inbox-search/SKILL.md"),
    include_str!("../../skills/multi-inbox-triage/SKILL.md"),
    include_str!("../../skills/safe-bulk-cleanup/SKILL.md"),
];

/// Why a Markdown document cannot be served as a skill.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SkillError {
    /// The document does not start with a complete frontmatter block.
    #[error("missing skill frontmatter")]
    MissingFrontmatter,
    /// The frontmatter does not follow the supported two-field format.
    #[error("invalid skill frontmatter: {0}")]
    InvalidFrontmatter(&'static str),
    /// A required frontmatter field is absent.
    #[error("missing skill frontmatter field: {0}")]
    MissingField(&'static str),
    /// The name is not a valid skill name.
    #[error("invalid skill name: {0:?}")]
    InvalidName(String),
    /// The description is blank or longer than 1024 characters.
    #[error("skill description must contain non-whitespace and at most 1024 characters")]
    InvalidDescription,
    /// The document exceeds 16 MiB.
    #[error("skill document is {size} bytes, exceeding the 16 MiB limit")]
    TooLarge {
        /// The document's size in bytes.
        size: usize,
    },
    /// The derived entry does not satisfy the MCP skill contract.
    #[error(transparent)]
    Validation(#[from] rmcp::model::SkillValidationError),
}

/// A validated `SKILL.md` and the skill and resource metadata derived from it.
///
/// Clones share the document and its metadata. The resource serves the exact
/// bytes supplied to [`Self::from_markdown`].
#[derive(Debug, Clone, PartialEq)]
pub struct SkillDocument(Arc<SkillDocumentInner>);

#[derive(Debug, PartialEq)]
struct SkillDocumentInner {
    markdown: String,
    entry: Skill,
    resource: Resource,
}

impl SkillDocument {
    /// Builds a skill from Markdown that begins with `---`-fenced frontmatter.
    ///
    /// Only `name: "..."` and `description: "..."` are allowed. Use one line
    /// per field, without indentation, trailing whitespace, or escapes.
    ///
    /// # Errors
    ///
    /// Returns [`SkillError`] if the document exceeds 16 MiB, the frontmatter
    /// is missing or invalid, or the derived skill entry fails validation.
    pub fn from_markdown(markdown: impl Into<String>) -> Result<Self, SkillError> {
        let markdown = markdown.into();
        if markdown.len() > MAX_SKILL_BYTES {
            return Err(SkillError::TooLarge {
                size: markdown.len(),
            });
        }
        let (name, description) = parse_two_field_frontmatter(&markdown)?;
        if !is_valid_skill_name(name) {
            return Err(SkillError::InvalidName(name.to_owned()));
        }
        if description.trim().is_empty() || description.chars().count() > 1024 {
            return Err(SkillError::InvalidDescription);
        }
        let uri = format!("skill://{name}/SKILL.md");
        let file = SkillResource::from_bytes(&uri, markdown.as_bytes());
        let resource = Resource::new(&uri, name)
            .with_description(description)
            .with_mime_type(MARKDOWN_MIME_TYPE)
            .with_size(file.size);
        let entry = Skill::new(
            uri,
            SkillFrontmatter::new(name, description),
            SkillResources::Files(vec![file]),
        );
        entry.validate()?;
        Ok(Self(Arc::new(SkillDocumentInner {
            markdown,
            entry,
            resource,
        })))
    }

    /// The `skill://<name>/SKILL.md` resource URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.0.entry.uri
    }

    /// The name from the document's frontmatter.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0.entry.name()
    }

    /// The description from the document's frontmatter.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.0.entry.frontmatter.description
    }

    /// The verbatim document, including the frontmatter.
    #[must_use]
    pub fn markdown(&self) -> &str {
        &self.0.markdown
    }

    /// The entry used for discovery and manifest verification.
    pub(super) fn skill(&self) -> &Skill {
        &self.0.entry
    }

    /// The same file advertised as an MCP resource.
    pub(super) fn resource(&self) -> &Resource {
        &self.0.resource
    }
}

fn parse_two_field_frontmatter(markdown: &str) -> Result<(&str, &str), SkillError> {
    if markdown.starts_with('\u{feff}') {
        return Err(SkillError::InvalidFrontmatter("unexpected byte-order mark"));
    }
    let lines = markdown
        .strip_prefix("---\n")
        .or_else(|| markdown.strip_prefix("---\r\n"))
        .ok_or(SkillError::MissingFrontmatter)?
        .lines();
    let end = lines
        .clone()
        .position(|line| line == "---")
        .ok_or(SkillError::MissingFrontmatter)?;
    let (mut name, mut description) = (None, None);
    for line in lines.take(end).filter(|line| !line.is_empty()) {
        let (key, value) = line
            .split_once(": ")
            .ok_or(SkillError::InvalidFrontmatter("expected `key: value`"))?;
        let field = match key {
            "name" => &mut name,
            "description" => &mut description,
            _ => return Err(SkillError::InvalidFrontmatter("unknown field")),
        };
        if field.is_some() {
            return Err(SkillError::InvalidFrontmatter("duplicate field"));
        }
        *field = Some(parse_quoted_scalar(value)?);
    }
    Ok((
        name.ok_or(SkillError::MissingField("name"))?,
        description.ok_or(SkillError::MissingField("description"))?,
    ))
}

fn parse_quoted_scalar(value: &str) -> Result<&str, SkillError> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| {
            !value.chars().any(|c| {
                // YAML 1.1 also treats the Unicode line and paragraph separators as breaks.
                c.is_control()
                    || matches!(
                        c,
                        '"' | '\\' | '\u{2028}' | '\u{2029}' | '\u{fffe}' | '\u{ffff}'
                    )
            })
        })
        .ok_or(SkillError::InvalidFrontmatter(
            "expected a single-line double-quoted string without escapes or invalid characters",
        ))
}

fn is_valid_skill_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

/// The server's embedded skills, parsed once and ordered by name.
pub(super) fn builtin_skills() -> &'static [SkillDocument] {
    static BUILTIN_SKILLS: LazyLock<Vec<SkillDocument>> = LazyLock::new(|| {
        BUILTIN_MARKDOWN
            .into_iter()
            .filter_map(|markdown| match SkillDocument::from_markdown(markdown) {
                Ok(skill) => Some(skill),
                Err(error) => {
                    tracing::error!(%error, "invalid built-in skill");
                    None
                }
            })
            .collect()
    });
    &BUILTIN_SKILLS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_skills_parse_validate_and_match_bytes() {
        let loaded = builtin_skills();
        assert_eq!(loaded.len(), 3);
        assert!(
            loaded
                .windows(2)
                .all(|pair| pair[0].name() < pair[1].name())
        );
        for (markdown, loaded) in BUILTIN_MARKDOWN.into_iter().zip(loaded) {
            let doc = SkillDocument::from_markdown(markdown).expect("valid built-in skill");
            assert_eq!(&doc, loaded);
            assert_eq!(doc.markdown(), markdown);
            assert!(doc.skill().validate().is_ok());
            let SkillResources::Files(files) = &doc.skill().resources else {
                panic!("built-in skill must have a manifest");
            };
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].uri, doc.uri());
            assert!(files[0].verify(doc.markdown().as_bytes()).is_ok());
        }
    }

    #[test]
    fn from_markdown_rejects_invalid_frontmatter_names_and_limits() {
        for field in [
            "extra: \"other\"",
            "# comment",
            " name: \"indented\"",
            "name: \"duplicate\"",
            "description: \"duplicate\"",
        ] {
            let markdown = format!("---\nname: \"demo\"\ndescription: \"Example\"\n{field}\n---\n");
            assert!(
                matches!(
                    SkillDocument::from_markdown(markdown),
                    Err(SkillError::InvalidFrontmatter(_))
                ),
                "{field:?}"
            );
        }
        for value in [
            "safe-bulk-cleanup",
            "0b101",
            "12:34",
            "\"",
            " \"extra space\"",
            "\"extra space\" ",
            "\"inner \"quote\"\"",
            "\"back\\slash\"",
            "\"control\tchar\"",
            "\"line \u{2028} separator\"",
            "\"paragraph \u{2029} separator\"",
            "\"noncharacter \u{fffe}\"",
            "\"noncharacter \u{ffff}\"",
        ] {
            for fields in [
                format!("name: {value}\ndescription: \"Example\""),
                format!("name: \"demo\"\ndescription: {value}"),
            ] {
                assert!(
                    matches!(
                        SkillDocument::from_markdown(format!("---\n{fields}\n---\n")),
                        Err(SkillError::InvalidFrontmatter(_))
                    ),
                    "{fields:?}"
                );
            }
        }
        assert!(matches!(
            SkillDocument::from_markdown(
                "\u{feff}---\nname: \"demo\"\ndescription: \"Example\"\n---\n"
            ),
            Err(SkillError::InvalidFrontmatter(_))
        ));
        for markdown in [
            "# No frontmatter",
            "---\nname: \"demo\"\ndescription: \"Example\"\n",
        ] {
            assert_eq!(
                SkillDocument::from_markdown(markdown),
                Err(SkillError::MissingFrontmatter)
            );
        }
        for (fields, missing) in [
            ("name: \"demo\"", "description"),
            ("description: \"Example\"", "name"),
        ] {
            assert_eq!(
                SkillDocument::from_markdown(format!("---\n{fields}\n---\n")),
                Err(SkillError::MissingField(missing))
            );
        }
        for name in [
            "",
            "UPPERCASE",
            "-start",
            "end-",
            "double--hyphen",
            "café",
            &"x".repeat(65),
        ] {
            assert_eq!(
                SkillDocument::from_markdown(format!(
                    "---\nname: \"{name}\"\ndescription: \"Example\"\n---\n"
                )),
                Err(SkillError::InvalidName(name.to_owned()))
            );
        }
        for description in ["", "  ", &"é".repeat(1025)] {
            assert_eq!(
                SkillDocument::from_markdown(format!(
                    "---\nname: \"demo\"\ndescription: \"{description}\"\n---\n"
                )),
                Err(SkillError::InvalidDescription)
            );
        }
        let size = MAX_SKILL_BYTES + 1;
        assert_eq!(
            SkillDocument::from_markdown("x".repeat(size)),
            Err(SkillError::TooLarge { size })
        );
    }

    #[test]
    fn from_markdown_accepts_quoted_values_that_look_like_yaml_literals() {
        let markdown = "---\r\nname: \"0b101\"\r\n\r\ndescription: \"12:34: check status\"\r\n---\r\n\r\n# Body\r\n";
        let doc = SkillDocument::from_markdown(markdown).expect("quoted values are strings");
        assert_eq!(doc.name(), "0b101");
        assert_eq!(doc.description(), "12:34: check status");
        assert_eq!(doc.uri(), "skill://0b101/SKILL.md");
        assert_eq!(doc.markdown(), markdown);
    }
}
