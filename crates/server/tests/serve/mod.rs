//! `postkeep serve` on a port it picks itself. The test reads the address
//! from the log, so no other process can take the port in between.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

/// Has `command`, a `postkeep serve`, bind a free local port and log in
/// JSON, for [`bound`].
pub fn on_any_port(command: &mut Command) -> &mut Command {
    command
        .env("POSTKEEP_BIND", "127.0.0.1:0")
        .env("POSTKEEP_LOG_FORMAT", "json")
}

/// The `bind` address of the line `message` in `child`'s JSON `log`, once
/// it is written. Panics with the log if `child` exits first.
pub fn bound(child: &mut Child, log: &Path, message: &str) -> SocketAddr {
    loop {
        let exited = child.try_wait().unwrap();
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let line = text
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|line| line["message"] == message);
        if let Some(line) = line {
            return line["bind"]
                .as_str()
                .and_then(|bind| bind.parse().ok())
                .unwrap_or_else(|| panic!("no address in {line}"));
        }
        if let Some(status) = exited {
            panic!("postkeep serve exited with {status} before {message:?}\n{text}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
