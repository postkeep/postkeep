//! postkeep: an open-source, self-hostable MCP server that gives agents
//! access to mail: IMAP accounts (iCloud Mail, Fastmail, Yahoo,
//! Gmail with an app password, or a custom server), Outlook.com and
//! Microsoft 365 through Microsoft
//! Graph, and Gmail through the Gmail API.
//!
//! The binary serves MCP over Streamable HTTP at `/mcp`, protected by a
//! built-in OAuth 2.1 authorization server. Its sign-in page takes an IMAP
//! address and app-specific password, or sends the user to Microsoft or
//! Google. See the repository README for deployment instructions.
//!
//! To embed the server, build it with [`ServerBuilder`]: it takes the same
//! settings as `postkeep serve`, can add routes and can leave out the
//! landing and account pages. With nothing added it is the binary. An
//! embedding that keeps its own tables in the same database opens it with
//! [`open_store`] and shares the connection pool. A
//! [`ToolExtension`](tools::ToolExtension) adds tools for the callers it
//! picks and can turn down any tool call before it runs. A
//! [`WatchOwnership`](watch::WatchOwnership) shares the mailboxes that
//! new-mail webhooks watch, and jobs such as the purge, between several
//! server processes on one database. The repository's `docs/embedding.md`
//! walks through an example, every extension point and the rules for
//! using them.

pub mod app;
pub mod cli;
mod forward;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod http;
pub mod limits;
pub mod mailbox;
mod metrics;
pub mod pool;
pub mod push;
pub mod readiness;
mod request_log;
mod retention;
mod run;
mod selector;
mod text;
pub mod tools;
pub mod watch;

pub use run::{
    Error, ServerBuilder, generate_key, healthcheck, migrate, open_store, serve, storage_level,
};
