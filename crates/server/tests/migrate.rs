//! `postkeep migrate`, `POSTKEEP_DATABASE_MIGRATE_ON_START` and
//! `postkeep storage-level`, through the binary.

#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::process::{Command, Output};
use std::time::Duration;

fn postkeep(args: &[&str], env: &[(&str, String)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_postkeep"));
    command.env_clear().args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn sqlite_url(dir: &tempfile::TempDir, name: &str) -> String {
    format!("sqlite://{}", dir.path().join(name).display())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn migrate_applies_pending_migrations_once() {
    let dir = tempfile::tempdir().unwrap();
    let env = [("POSTKEEP_DATABASE_URL", sqlite_url(&dir, "server.db"))];
    let first = postkeep(&["migrate"], &env);
    assert!(first.status.success(), "{}", text(&first.stderr));
    assert_eq!(
        text(&first.stdout),
        "applied migrations 0001, 0002, 0003, 0004, 0005, 0006, 0007, 0008, 0009, 0010, 0011, 0012, 0013, 0014, 0015, 0016, 0017, 0018, 0019\n"
    );
    let again = postkeep(&["migrate"], &env);
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert_eq!(text(&again.stdout), "the database is up to date\n");
}

#[test]
fn migrate_prefers_the_migration_url() {
    let dir = tempfile::tempdir().unwrap();
    let env = [
        ("POSTKEEP_DATABASE_URL", sqlite_url(&dir, "pooled.db")),
        (
            "POSTKEEP_DATABASE_MIGRATE_URL",
            sqlite_url(&dir, "direct.db"),
        ),
    ];
    let output = postkeep(&["migrate"], &env);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(dir.path().join("direct.db").exists());
    assert!(!dir.path().join("pooled.db").exists());
}

#[test]
fn serve_refuses_pending_migrations_when_told_not_to_apply_them() {
    let dir = tempfile::tempdir().unwrap();
    let env = [
        ("POSTKEEP_DATABASE_URL", sqlite_url(&dir, "server.db")),
        ("POSTKEEP_DATABASE_MIGRATE_ON_START", "false".to_owned()),
        ("POSTKEEP_PUBLIC_URL", "https://mail.example.com".to_owned()),
        ("POSTKEEP_MASTER_KEY", "00".repeat(32)),
        ("POSTKEEP_BIND", "127.0.0.1:0".to_owned()),
    ];
    let started = std::time::Instant::now();
    let output = postkeep(&["serve"], &env);
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(30), "it fails fast");
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("the database is missing migrations 0001, 0002")
            && stderr.contains("run `postkeep migrate` first"),
        "{stderr}"
    );
}

async fn set_level(path: &std::path::Path, level: i64) {
    use sqlx::Connection as _;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(path);
    let mut conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let set = sqlx::query("UPDATE storage_level SET level = ?").bind(level);
    set.execute(&mut conn).await.unwrap();
    conn.close().await.unwrap();
}

async fn level(path: &std::path::Path) -> i64 {
    use sqlx::Connection as _;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(path);
    let mut conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let level = sqlx::query_scalar("SELECT level FROM storage_level")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    level
}

#[tokio::test]
async fn storage_level_shows_and_raises_the_level_and_never_lowers_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.db");
    let env = [("POSTKEEP_DATABASE_URL", sqlite_url(&dir, "server.db"))];

    let missing = postkeep(&["storage-level"], &env);
    assert_eq!(missing.status.code(), Some(1));
    let stderr = text(&missing.stderr);
    assert!(
        stderr.starts_with("error: could not read the storage level: "),
        "{stderr}"
    );
    assert!(!path.exists(), "it creates no database");

    let output = postkeep(&["migrate"], &env);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let shown = "storage level 1 in the database; this version reads up to level 1\n";
    let show = postkeep(&["storage-level"], &env);
    assert!(show.status.success(), "{}", text(&show.stderr));
    assert_eq!(text(&show.stdout), shown);
    let raise = postkeep(&["storage-level", "raise"], &env);
    assert!(raise.status.success(), "{}", text(&raise.stderr));
    assert_eq!(
        text(&raise.stdout),
        format!("{shown}the storage level is already 1\n")
    );

    set_level(&path, 0).await;
    let raise = postkeep(&["storage-level", "raise"], &env);
    assert!(raise.status.success(), "{}", text(&raise.stderr));
    assert_eq!(
        text(&raise.stdout),
        "storage level 0 in the database; this version reads up to level 1\n\
         raised the storage level from 0 to 1\n"
    );
    assert_eq!(level(&path).await, 1);

    set_level(&path, 2).await;
    let show = postkeep(&["storage-level"], &env);
    assert!(show.status.success(), "{}", text(&show.stderr));
    assert_eq!(
        text(&show.stdout),
        "storage level 2 in the database; this version reads up to level 1\n"
    );
    let raise = postkeep(&["storage-level", "raise"], &env);
    assert_eq!(raise.status.code(), Some(1));
    assert_eq!(text(&raise.stdout), "");
    assert_eq!(
        text(&raise.stderr),
        "error: could not raise the storage level: the database is at storage level 2 and this version reads up to level 1; run the newer release that raised it\n"
    );
    assert_eq!(level(&path).await, 2, "it never lowers the level");

    let lower = postkeep(&["storage-level", "lower"], &env);
    assert_eq!(lower.status.code(), Some(2));
}

#[test]
fn storage_level_prefers_the_migration_url() {
    let dir = tempfile::tempdir().unwrap();
    let direct = [("POSTKEEP_DATABASE_URL", sqlite_url(&dir, "direct.db"))];
    let output = postkeep(&["migrate"], &direct);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let env = [
        ("POSTKEEP_DATABASE_URL", sqlite_url(&dir, "pooled.db")),
        (
            "POSTKEEP_DATABASE_MIGRATE_URL",
            sqlite_url(&dir, "direct.db"),
        ),
    ];
    let output = postkeep(&["storage-level"], &env);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(!dir.path().join("pooled.db").exists());
}

#[tokio::test]
async fn serve_and_migrate_refuse_a_database_above_the_storage_level() {
    use sqlx::Connection as _;
    let dir = tempfile::tempdir().unwrap();
    let env = [
        ("POSTKEEP_DATABASE_URL", sqlite_url(&dir, "server.db")),
        ("POSTKEEP_PUBLIC_URL", "https://mail.example.com".to_owned()),
        ("POSTKEEP_MASTER_KEY", "00".repeat(32)),
        ("POSTKEEP_BIND", "127.0.0.1:0".to_owned()),
    ];
    let output = postkeep(&["migrate"], &env);
    assert!(output.status.success(), "{}", text(&output.stderr));
    // A newer version raised the level.
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("server.db"));
    let mut conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let raise = sqlx::query("UPDATE storage_level SET level = 2");
    raise.execute(&mut conn).await.unwrap();
    conn.close().await.unwrap();
    for command in ["serve", "migrate"] {
        let output = postkeep(&[command], &env);
        assert!(!output.status.success(), "{command}");
        let stderr = text(&output.stderr);
        assert!(
            stderr.contains("the database is at storage level 2 and this version reads up to level 1; run the newer release"),
            "{command}: {stderr}"
        );
    }
}
