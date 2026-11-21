//! The pages' static files (designer stylesheets, script, self-hosted fonts
//! and provider artwork), embedded in the binary and served under
//! [`ASSETS_PREFIX`].
//!
//! Each provider logo is its own file under `static/providers/`, so one
//! can be swapped or removed without touching the templates' layout.

/// URL prefix of the static files.
pub const ASSETS_PREFIX: &str = "/assets/";

/// Every static file: (path under [`ASSETS_PREFIX`], content type, contents).
pub const FILES: &[(&str, &str, &[u8])] = &[
    (
        "css/app.css",
        "text/css; charset=utf-8",
        include_bytes!("../static/css/app.css"),
    ),
    (
        "css/postkeep.css",
        "text/css; charset=utf-8",
        include_bytes!("../static/css/postkeep.css"),
    ),
    (
        "css/tokens.css",
        "text/css; charset=utf-8",
        include_bytes!("../static/css/tokens.css"),
    ),
    (
        "fonts/Geist-Variable.woff2",
        "font/woff2",
        include_bytes!("../static/fonts/Geist-Variable.woff2"),
    ),
    (
        "fonts/GeistMono-Variable.woff2",
        "font/woff2",
        include_bytes!("../static/fonts/GeistMono-Variable.woff2"),
    ),
    (
        "js/app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../static/js/app.js"),
    ),
    (
        "providers/fastmail.svg",
        "image/svg+xml",
        include_bytes!("../static/providers/fastmail.svg"),
    ),
    (
        "providers/gmail.svg",
        "image/svg+xml",
        include_bytes!("../static/providers/gmail.svg"),
    ),
    (
        "providers/google/signin-dark.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-dark.png"),
    ),
    (
        "providers/google/signin-dark@2x.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-dark@2x.png"),
    ),
    (
        "providers/google/signin-dark@3x.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-dark@3x.png"),
    ),
    (
        "providers/google/signin-dark@4x.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-dark@4x.png"),
    ),
    (
        "providers/google/signin-light.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-light.png"),
    ),
    (
        "providers/google/signin-light@2x.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-light@2x.png"),
    ),
    (
        "providers/google/signin-light@3x.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-light@3x.png"),
    ),
    (
        "providers/google/signin-light@4x.png",
        "image/png",
        include_bytes!("../static/providers/google/signin-light@4x.png"),
    ),
    (
        "providers/icloud.svg",
        "image/svg+xml",
        include_bytes!("../static/providers/icloud.svg"),
    ),
    (
        "providers/imap.svg",
        "image/svg+xml",
        include_bytes!("../static/providers/imap.svg"),
    ),
    (
        "providers/microsoft/ms-symbollockup_signin_dark.svg",
        "image/svg+xml",
        include_bytes!("../static/providers/microsoft/ms-symbollockup_signin_dark.svg"),
    ),
    (
        "providers/microsoft/ms-symbollockup_signin_light.svg",
        "image/svg+xml",
        include_bytes!("../static/providers/microsoft/ms-symbollockup_signin_light.svg"),
    ),
    (
        "providers/yahoo.svg",
        "image/svg+xml",
        include_bytes!("../static/providers/yahoo.svg"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_file_is_listed_once_with_contents() {
        let mut paths: Vec<&str> = FILES.iter().map(|(path, _, _)| *path).collect();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), FILES.len());
        assert!(FILES.iter().all(|(_, _, body)| !body.is_empty()));
    }

    /// Adding a file to `static/` without listing it here fails this test.
    #[test]
    fn lists_every_file_in_the_static_directory() {
        fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, root, out);
                } else if path.extension().is_some_and(|ext| ext != "txt") {
                    out.push(
                        path.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
        let mut found = Vec::new();
        walk(&root, &root, &mut found);
        found.sort();
        let mut listed: Vec<String> = FILES
            .iter()
            .map(|(path, _, _)| (*path).to_owned())
            .collect();
        listed.sort();
        assert_eq!(found, listed);
    }
}
