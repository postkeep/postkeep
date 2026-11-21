//! The `postkeep` binary.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use postkeep::cli::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve(args) => postkeep::serve(*args).await,
        Command::GenerateKey => postkeep::generate_key(),
        Command::Healthcheck(args) => postkeep::healthcheck(&args).await,
        Command::Migrate(args) => postkeep::migrate(&args).await,
        Command::StorageLevel(args) => postkeep::storage_level(&args).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Logging may not be initialized yet, so write to stderr directly.
            let _ = writeln!(std::io::stderr().lock(), "error: {err}");
            ExitCode::FAILURE
        }
    }
}
