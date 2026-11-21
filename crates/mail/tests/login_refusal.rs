//! Which login refusals mean "wrong password" and which only mean "not now",
//! against scripted IMAP and SMTP servers. The codes are those of RFC 5530
//! (IMAP response codes) and RFC 4954 (SMTP authentication); the plain `NO`
//! and the 535 reply are what GreenMail sends.

// Helpers outside `#[test]` functions are not covered by clippy.toml's
// `allow-*-in-tests` settings, but they are still test code.
#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::time::Duration;

use postkeep_mail::{
    Credentials, EmailAddress, Error, ImapConfig, ImapSecurity, MailClient, MailConfig,
    OutgoingMessage, SecretString, SendOptions, SmtpConfig, SmtpSecurity,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// A server for one connection on 127.0.0.1: it sends `greeting`, answers
/// each line with `reply(line)`, and ends when the client hangs up. Returns
/// its port and a task that yields how many lines it read.
async fn serve(
    greeting: &'static str,
    mut reply: impl FnMut(&str) -> Option<String> + Send + 'static,
) -> (u16, JoinHandle<usize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let _ = write.write_all(greeting.as_bytes()).await;
        let mut lines = BufReader::new(read).lines();
        let mut count = 0;
        while let Ok(Some(line)) = lines.next_line().await {
            count += 1;
            let Some(answer) = reply(&line) else { break };
            let _ = write.write_all(answer.as_bytes()).await;
        }
        count
    });
    (port, task)
}

fn client(email: &str, imap_port: u16, smtp_port: u16) -> MailClient {
    let config = MailConfig {
        imap: ImapConfig {
            host: "127.0.0.1".to_owned(),
            port: imap_port,
            security: ImapSecurity::Plaintext,
        },
        smtp: SmtpConfig {
            host: "127.0.0.1".to_owned(),
            port: smtp_port,
            security: SmtpSecurity::Plaintext,
        },
        timeout: Duration::from_secs(5),
        ..MailConfig::default()
    };
    let credentials = Credentials::new(email, &SecretString::from("secret".to_owned())).unwrap();
    MailClient::new(config, credentials).unwrap()
}

/// What an error says about the login: `authentication`, `unavailable` with
/// its code, or `smtp` for any other SMTP error.
fn kind(err: &Error) -> String {
    match err {
        Error::Authentication => "authentication".to_owned(),
        Error::Unavailable { code } => format!("unavailable {code}"),
        Error::Smtp(_) => "smtp".to_owned(),
        other => format!("{other:?}"),
    }
}

/// Logs `email` in to an IMAP server that answers its `LOGIN` commands with
/// `answers` in turn (the last one repeats). Returns the kind of the error
/// and the number of commands the server read.
async fn imap_login(email: &str, answers: Vec<&'static str>) -> (String, usize) {
    let mut logins = 0;
    let (port, server) = serve("* OK ready\r\n", move |line| {
        let tag = line.split(' ').next().unwrap_or("*");
        let answer = answers[logins.min(answers.len() - 1)];
        logins += 1;
        Some(format!("{tag} {answer}\r\n"))
    })
    .await;
    let err = client(email, port, 1)
        .verify_credentials()
        .await
        .unwrap_err();
    (kind(&err), server.await.unwrap())
}

/// Sends a message through an SMTP server that answers `AUTH` with `reply`
/// (lines of a multi-line reply separated by `\r\n`). Returns the error's kind.
async fn smtp_send(reply: &'static str) -> String {
    let (port, _server) = serve("220 test ready\r\n", move |line| {
        Some(if line.starts_with("EHLO") {
            "250-test\r\n250 AUTH PLAIN LOGIN\r\n".to_owned()
        } else if line.starts_with("AUTH") {
            format!("{reply}\r\n")
        } else {
            "221 bye\r\n".to_owned()
        })
    })
    .await;
    kind(&send_message(port).await)
}

async fn send_message(port: u16) -> Error {
    let message = OutgoingMessage {
        to: vec![EmailAddress::new("bob@example.com")],
        subject: "hello".to_owned(),
        text_body: "hello".to_owned(),
        ..OutgoingMessage::default()
    };
    let options = SendOptions {
        save_to_sent: false,
    };
    let client = client("alice@example.com", 1, port);
    client.send(&message, options).await.unwrap_err()
}

#[tokio::test]
async fn imap_login_answers_are_told_apart() {
    for (answer, code) in [
        ("NO [UNAVAILABLE] Backend down", "UNAVAILABLE"),
        ("NO [LIMIT] At most 15 connections", "LIMIT"),
        ("NO [INUSE] Mailbox in use", "INUSE"),
        ("NO [SERVERBUG] Should not happen", "SERVERBUG"),
        ("NO [limit] Codes ignore case", "LIMIT"),
        ("NO [LIMIT 15] A code may have an argument", "LIMIT"),
    ] {
        let (found, _) = imap_login("alice@example.com", vec![answer]).await;
        assert_eq!(found, format!("unavailable {code}"), "{answer}");
    }
    for answer in [
        "NO [AUTHENTICATIONFAILED] Failed",
        "NO [EXPIRED] That password isn't valid",
        "NO LOGIN failed. Invalid login/password for user id alice@example.com",
        "NO [ALERT] App password required",
        // Only a code at the start of the text counts.
        "NO [ALERT] [LIMIT] The code is ALERT",
        "NO Login failed [LIMIT] is no code",
        "NO [AUTHENTICATIONFAILED] Too many tries [LIMIT]",
    ] {
        let (found, _) = imap_login("alice@example.com", vec![answer]).await;
        assert_eq!(found, "authentication", "{answer}");
    }
}

#[tokio::test]
async fn the_next_login_name_is_tried_only_after_a_rejection() {
    // iCloud addresses log in as `john`, then as `john@icloud.com`.
    let rejected = "NO [AUTHENTICATIONFAILED] Failed";
    let busy = "NO [UNAVAILABLE] Busy";
    let login = |answers| imap_login("john@icloud.com", answers);
    assert_eq!(
        login(vec![busy]).await,
        ("unavailable UNAVAILABLE".to_owned(), 1)
    );
    assert_eq!(
        login(vec![rejected]).await,
        ("authentication".to_owned(), 2)
    );
    assert_eq!(
        login(vec![rejected, busy]).await,
        ("unavailable UNAVAILABLE".to_owned(), 2)
    );
}

#[tokio::test]
async fn smtp_auth_replies_are_told_apart() {
    for reply in [
        "535 5.7.8  Authentication credentials invalid",
        "535-5.7.8 Not accepted.\r\n535 5.7.8 See the help page.",
    ] {
        assert_eq!(smtp_send(reply).await, "authentication", "{reply}");
    }
    let temporary = "454 4.7.0 Temporary authentication failure";
    assert_eq!(smtp_send(temporary).await, "unavailable 454");
    for reply in [
        "421 4.3.2 Service not available, closing transmission channel",
        "530 5.7.0 Authentication required",
        "534 5.7.9 Authentication mechanism is too weak",
    ] {
        assert_eq!(smtp_send(reply).await, "smtp", "{reply}");
    }
}

#[test]
fn a_temporary_refusal_reads_the_same_for_every_command() {
    // An IMAP code or an SMTP reply code; the server's text is never in it.
    for code in ["UNAVAILABLE", "454"] {
        let expected = format!("the mail server refused for now ({code}); try again later");
        assert_eq!(Error::Unavailable { code }.to_string(), expected);
    }
}

#[tokio::test]
async fn smtp_distinguishes_a_lost_acceptance_reply_from_a_definite_failure() {
    for (drop_at, final_reply) in [("DATA", ""), (".", ""), (".", "550 message rejected\r\n")] {
        let reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = reached.clone();
        let (port, server) = serve("220 test ready\r\n", move |line| {
            if line == drop_at {
                observed.store(true, std::sync::atomic::Ordering::Relaxed);
                return (!final_reply.is_empty()).then(|| final_reply.to_owned());
            }
            Some(if line.starts_with("EHLO") {
                "250-test\r\n250 AUTH PLAIN LOGIN\r\n".to_owned()
            } else if line == "DATA" {
                "354 send message\r\n".to_owned()
            } else if line.starts_with("AUTH")
                || line.starts_with("MAIL")
                || line.starts_with("RCPT")
            {
                "250 OK\r\n".to_owned()
            } else if line == "QUIT" {
                "221 bye\r\n".to_owned()
            } else {
                // DATA lines must be read without replying until the terminator.
                String::new()
            })
        })
        .await;
        let error = send_message(port).await;
        server.await.unwrap();
        assert!(reached.load(std::sync::atomic::Ordering::Relaxed));
        match (drop_at, final_reply, error) {
            (".", "", Error::SubmissionUnconfirmed) => (),
            ("DATA", "", Error::Smtp(err)) if err.status().is_none() => (),
            (".", _, Error::Smtp(err)) if err.is_permanent() => (),
            (_, _, other) => panic!("unexpected error: {other:?}"),
        }
    }
}
