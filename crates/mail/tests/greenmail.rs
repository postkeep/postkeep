//! Integration tests against a local [GreenMail](https://greenmail-mail-test.github.io/greenmail/)
//! server.
//!
//! They are ignored by default. Start GreenMail and run them with:
//!
//! ```sh
//! docker run --rm -p 3025:3025 -p 3143:3143 \
//!   -e GREENMAIL_OPTS="-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imap \
//!     -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users.login=email \
//!     -Dgreenmail.users=alice:alicepass@example.com,bob:abcdabcdabcdabcd@example.com" \
//!   greenmail/standalone:2.1.14
//! cargo nextest run --run-ignored all   # or: cargo test -- --include-ignored
//! ```
//!
//! `GREENMAIL_HOST`, `GREENMAIL_IMAP_PORT` and `GREENMAIL_SMTP_PORT` override
//! the default `127.0.0.1:3143` / `127.0.0.1:3025`.
//!
//! A test that opens a mailbox uses a [`User`] of its own. Alice only sends, and
//! `verifies_credentials` logs alice and bob in.

// Helpers outside `#[test]` functions are not covered by clippy.toml's
// `allow-*-in-tests` settings, but they are still test code.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]

use std::time::{Duration, Instant};

use postkeep_mail::{
    Check, Credentials, DeleteMode, EmailAddress, Error, Flag, IdleEvent, ImapConfig, ImapSecurity,
    ImapSession, MailClient, MailConfig, MessageSummary, NaiveDate, OutgoingAttachment,
    OutgoingMessage, Paging, Reply, SearchQuery, SecretString, SendOptions, SentCopy, SmtpConfig,
    SmtpSecurity,
};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const SENT: &str = "Sent Messages";
const TRASH: &str = "Deleted Messages";

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn config() -> MailConfig {
    let host = env_or("GREENMAIL_HOST", "127.0.0.1");
    MailConfig {
        imap: ImapConfig {
            host: host.clone(),
            port: env_or("GREENMAIL_IMAP_PORT", "3143").parse().unwrap(),
            security: ImapSecurity::Plaintext,
        },
        smtp: SmtpConfig {
            host,
            port: env_or("GREENMAIL_SMTP_PORT", "3025").parse().unwrap(),
            security: SmtpSecurity::Plaintext,
        },
        timeout: Duration::from_secs(10),
        ..MailConfig::default()
    }
}

fn client(email: &str, password: &str) -> MailClient {
    client_on(config(), email, password)
}

fn client_on(config: MailConfig, email: &str, password: &str) -> MailClient {
    let credentials = Credentials::new(email, &SecretString::from(password.to_owned())).unwrap();
    MailClient::new(config, credentials).unwrap()
}

/// A client for a server that files sent mail itself, as Gmail does.
fn files_sent(email: &str, password: &str) -> MailClient {
    let config = MailConfig {
        server_files_sent: true,
        ..config()
    };
    client_on(config, email, password)
}

/// Whether the server files sent mail itself, `save_to_sent`, and how many
/// copies `send` and `reply` append to Sent.
const SENT_COPY_CASES: [(bool, bool, usize); 3] =
    [(false, true, 1), (true, true, 0), (true, false, 0)];

fn copy_report(by_server: bool) -> SentCopy {
    if by_server {
        SentCopy::ByServer
    } else {
        SentCopy::Saved {
            folder: SENT.to_owned(),
        }
    }
}

fn alice() -> MailClient {
    client(ALICE, "alicepass")
}

fn bob() -> MailClient {
    // Formatted like an Apple app-specific password; GreenMail stores it
    // without dashes, so this also checks password normalization.
    client(BOB, "abcd-abcd-abcd-abcd")
}

/// A tag unique to one test run.
fn unique(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4().simple())
}

/// Creates the folder `name` for `client`'s account.
async fn create_folder(client: &MailClient, name: &str) {
    let mut imap = client.connect_imap().await.unwrap();
    imap.create_folder(name).await.unwrap();
    imap.logout().await.unwrap();
}

/// A user that no other test uses. GreenMail 2.1.14 cannot serve two
/// sessions that work in one mailbox at once: while one session changes
/// flags or expunges, the others get `NO ... No such message with uid` or
/// lose their connection, so tests cannot share a mailbox. GreenMail
/// creates the user, with its address as password, when the first mail for
/// it arrives.
struct User {
    address: String,
    client: MailClient,
}

impl User {
    async fn new() -> Self {
        let address = format!("u{}@example.com", uuid::Uuid::new_v4().simple());
        let user = Self {
            client: client(&address, &address),
            address,
        };
        let subject = unique("welcome");
        send_to(user.email(), &subject, "The first mail creates the user.").await;
        wait_for(&user.client, "INBOX", &subject, 1).await;
        user
    }

    fn email(&self) -> EmailAddress {
        EmailAddress::new(self.address.as_str())
    }
}

/// Sends a mail from alice, whose mailboxes no test opens.
async fn send_to(to: EmailAddress, subject: &str, text: &str) {
    send_from(&alice(), to, subject, text).await;
}

async fn send_from(from: &MailClient, to: EmailAddress, subject: &str, text: &str) {
    let message = OutgoingMessage {
        to: vec![to],
        subject: subject.to_owned(),
        text_body: text.to_owned(),
        ..OutgoingMessage::default()
    };
    let options = SendOptions {
        save_to_sent: false,
    };
    from.send(&message, options).await.unwrap();
}

/// Waits until `folder` of `client` holds `count` messages with `subject`.
async fn wait_for(
    client: &MailClient,
    folder: &str,
    subject: &str,
    count: usize,
) -> Vec<MessageSummary> {
    let query = SearchQuery::new().subject(subject);
    for _ in 0..50 {
        let mut imap = client.connect_imap().await.unwrap();
        let results = imap
            .search(folder, &query, Paging::default())
            .await
            .unwrap();
        imap.logout().await.unwrap();
        if results.total == count {
            return results.messages;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("expected {count} message(s) with subject {subject:?} in {folder}");
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn verifies_credentials() {
    alice().verify_credentials().await.unwrap();
    bob().verify_credentials().await.unwrap();
    let err = client(ALICE, "wrong-password")
        .verify_credentials()
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Authentication), "{err:?}");
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn lists_folders_including_non_ascii_names() {
    let user = User::new().await;
    let name = unique("Entwürfe");
    create_folder(&user.client, &name).await;
    let mut imap = user.client.connect_imap().await.unwrap();
    let folders = imap.list_folders().await.unwrap();
    imap.logout().await.unwrap();
    assert!(folders.iter().any(|folder| folder.name == "INBOX"));
    let created = folders.iter().find(|folder| folder.name == name).unwrap();
    assert!(created.selectable);
}

fn csv_file() -> OutgoingAttachment {
    OutgoingAttachment {
        filename: "data.csv".to_owned(),
        content_type: "text/csv".to_owned(),
        content: b"a,b\n1,2\n".to_vec(),
        content_id: None,
        inline: false,
    }
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn sends_searches_and_fetches() {
    let (alice, bob) = tokio::join!(User::new(), User::new());
    create_folder(&alice.client, SENT).await;
    let subject = unique("roundtrip");
    let message = OutgoingMessage {
        to: vec![EmailAddress::with_name("Bob", bob.address.as_str())],
        cc: vec![alice.email()],
        subject: subject.clone(),
        text_body: "Hello Bob, plain text.".to_owned(),
        html_body: Some("<p>Hello Bob, <b>HTML</b>.</p>".to_owned()),
        attachments: vec![csv_file()],
        ..OutgoingMessage::default()
    };
    let sent = alice
        .client
        .clone()
        .with_display_name("Alice")
        .send(&message, SendOptions::default())
        .await
        .unwrap();
    assert_eq!(
        sent.sent_copy,
        SentCopy::Saved {
            folder: SENT.to_owned()
        }
    );
    assert!(sent.message_id.ends_with("@example.com"));
    wait_for(&alice.client, SENT, &subject, 1).await;

    let summaries = wait_for(&bob.client, "INBOX", &subject, 1).await;
    let summary = &summaries[0];
    assert_eq!(summary.subject.as_deref(), Some(subject.as_str()));
    assert_eq!(
        summary.from,
        Some(EmailAddress::with_name("Alice", alice.address.as_str()))
    );
    assert!(!summary.flags.seen);
    assert!(summary.date.is_some());

    let mut imap = bob.client.connect_imap().await.unwrap();
    let size = imap.message_size("INBOX", summary.uid, None).await.unwrap() as usize;
    assert!(matches!(
        imap.fetch_raw("INBOX", summary.uid, None, size - 1).await,
        Err(postkeep_mail::Error::MessageTooLarge)
    ));
    assert_eq!(
        imap.fetch_raw("INBOX", summary.uid, None, size + 1024)
            .await
            .unwrap()
            .len(),
        size
    );
    let full = imap
        .fetch_message("INBOX", summary.uid, None)
        .await
        .unwrap()
        .0;
    assert_eq!(
        full.headers.message_id.as_deref(),
        Some(sent.message_id.as_str())
    );
    assert_eq!(
        full.headers.to,
        [EmailAddress::with_name("Bob", bob.address.as_str())]
    );
    assert_eq!(full.headers.cc, [alice.email()]);
    assert_eq!(
        full.text_body.as_deref().map(str::trim),
        Some("Hello Bob, plain text.")
    );
    assert!(full.html_body.unwrap().contains("<b>HTML</b>"));
    assert_eq!(full.attachments.len(), 1);
    let file = imap
        .fetch_attachment("INBOX", summary.uid, None, full.attachments[0].id, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file.attachment.filename.as_deref(), Some("data.csv"));
    assert_eq!(file.content, Some(csv_file().content));
    assert!(
        !full.flags.seen,
        "fetching must not mark the message as read"
    );

    let by_id = SearchQuery::new().message_id(format!("<{}>", sent.message_id));
    let found = imap
        .search("INBOX", &by_id, Paging::default())
        .await
        .unwrap();
    assert_eq!(found.total, 1);
    // A new message lists its recipients: the `To` addresses, then the `Cc` ones.
    imap.examine("INBOX").await.unwrap();
    let listed = imap.messages_after(summary.uid - 1, 1).await.unwrap();
    let to: Vec<_> = listed[0].recipients.iter().map(|a| &*a.address).collect();
    assert_eq!(to, [bob.address.as_str(), alice.address.as_str()]);
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn pages_newest_first() {
    let bob = User::new().await;
    let subject = unique("paging");
    for index in 1..=3 {
        send_to(bob.email(), &format!("{subject} #{index}"), "body").await;
    }
    wait_for(&bob.client, "INBOX", &subject, 3).await;
    let query = SearchQuery::new().subject(subject.as_str());
    let mut imap = bob.client.connect_imap().await.unwrap();
    let first = imap
        .search("INBOX", &query, Paging::new(0, 2))
        .await
        .unwrap();
    let second = imap
        .search("INBOX", &query, Paging::new(2, 2))
        .await
        .unwrap();
    imap.logout().await.unwrap();

    assert_eq!((first.total, first.messages.len()), (3, 2));
    assert_eq!(
        (second.total, second.messages.len(), second.offset),
        (3, 1, 2)
    );
    let subjects: Vec<_> = first
        .messages
        .iter()
        .chain(&second.messages)
        .map(|summary| summary.subject.clone().unwrap())
        .collect();
    assert_eq!(
        subjects,
        [3, 2, 1].map(|index| format!("{subject} #{index}"))
    );
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn searches_non_ascii_text() {
    let bob = User::new().await;
    let tag = unique("utf8");
    send_to(
        bob.email(),
        &format!("Grüße aus Zürich {tag}"),
        "Viele Grüße",
    )
    .await;
    wait_for(&bob.client, "INBOX", &tag, 1).await;
    let query = SearchQuery::new().subject(tag.as_str()).subject("Grüße");
    let mut imap = bob.client.connect_imap().await.unwrap();
    let results = imap
        .search("INBOX", &query, Paging::default())
        .await
        .unwrap();
    imap.logout().await.unwrap();
    assert_eq!(results.total, 1);
    assert_eq!(
        results.messages[0].subject.as_deref(),
        Some(format!("Grüße aus Zürich {tag}").as_str())
    );
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn sets_and_clears_flags() {
    let bob = User::new().await;
    let subject = unique("flags");
    send_to(bob.email(), &subject, "flag me").await;
    let uid = wait_for(&bob.client, "INBOX", &subject, 1).await[0].uid;
    let unread = SearchQuery::new().subject(subject.as_str()).unread(true);
    let flagged = SearchQuery::new().subject(subject.as_str()).flagged(true);

    let mut imap = bob.client.connect_imap().await.unwrap();
    assert_eq!(
        imap.search("INBOX", &unread, Paging::default())
            .await
            .unwrap()
            .total,
        1
    );

    imap.set_flag("INBOX", uid, None, Flag::Seen, true)
        .await
        .unwrap();
    imap.set_flag("INBOX", uid, None, Flag::Flagged, true)
        .await
        .unwrap();
    assert_eq!(
        imap.search("INBOX", &unread, Paging::default())
            .await
            .unwrap()
            .total,
        0
    );
    let hits = imap
        .search("INBOX", &flagged, Paging::default())
        .await
        .unwrap();
    assert!(hits.messages[0].flags.seen && hits.messages[0].flags.flagged);

    imap.set_flag("INBOX", uid, None, Flag::Seen, false)
        .await
        .unwrap();
    imap.set_flag("INBOX", uid, None, Flag::Flagged, false)
        .await
        .unwrap();
    assert_eq!(
        imap.search("INBOX", &unread, Paging::default())
            .await
            .unwrap()
            .total,
        1
    );
    assert_eq!(
        imap.search("INBOX", &flagged, Paging::default())
            .await
            .unwrap()
            .total,
        0
    );
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn moves_and_deletes() {
    let bob = User::new().await;
    create_folder(&bob.client, TRASH).await;
    let archive = unique("Archiv-ü");
    create_folder(&bob.client, &archive).await;
    let subject = unique("move");
    send_to(bob.email(), &subject, "move me").await;
    let uid = wait_for(&bob.client, "INBOX", &subject, 1).await[0].uid;

    let mut imap = bob.client.connect_imap().await.unwrap();
    imap.move_message("INBOX", uid, None, &archive)
        .await
        .unwrap();
    let missing = imap
        .move_message("INBOX", uid, None, "No Such Folder")
        .await
        .unwrap_err();
    assert!(matches!(missing, Error::FolderNotFound(_)), "{missing:?}");
    imap.logout().await.unwrap();
    wait_for(&bob.client, "INBOX", &subject, 0).await;
    let uid = wait_for(&bob.client, &archive, &subject, 1).await[0].uid;

    let mut imap = bob.client.connect_imap().await.unwrap();
    imap.delete_message(&archive, uid, None, DeleteMode::Trash)
        .await
        .unwrap();
    imap.logout().await.unwrap();
    wait_for(&bob.client, &archive, &subject, 0).await;
    let uid = wait_for(&bob.client, TRASH, &subject, 1).await[0].uid;

    let mut imap = bob.client.connect_imap().await.unwrap();
    let again = imap
        .delete_message(TRASH, uid, None, DeleteMode::Trash)
        .await
        .unwrap_err();
    assert!(
        matches!(&again, Error::InvalidInput(text) if text.contains("use permanent deletion")),
        "{again:?}"
    );
    imap.delete_message(TRASH, uid, None, DeleteMode::Permanent)
        .await
        .unwrap();
    imap.logout().await.unwrap();
    wait_for(&bob.client, TRASH, &subject, 0).await;
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn moves_flags_and_trashes_sets() {
    let user = User::new().await;
    for folder in [TRASH, "Archive"] {
        create_folder(&user.client, folder).await;
    }
    let subject = unique("sets");
    for _ in 0..3 {
        send_to(user.email(), &subject, "move and flag this set").await;
    }
    let summaries = wait_for(&user.client, "INBOX", &subject, 3).await;
    let mut uids: Vec<_> = summaries.iter().map(|message| message.uid).collect();
    let done = uids.clone();
    uids.push(u32::MAX);
    let query = SearchQuery::new().subject(subject);
    let mut imap = user.client.connect_imap().await.unwrap();
    let validity = Some(imap.examine("INBOX").await.unwrap().uid_validity);
    let found = imap
        .find_messages("INBOX", &uids, validity, Check::Exists)
        .await
        .unwrap();
    assert_eq!(found.uid_validity, validity);
    assert_eq!(found.done, done);
    assert_eq!(found.missing, [u32::MAX]);
    let flags = [(Flag::Seen, true), (Flag::Flagged, true)];
    assert_eq!(
        imap.set_flags("INBOX", &uids, validity, &flags, Check::Exists, &mut None)
            .await
            .unwrap(),
        found
    );
    let flagged = imap
        .search("INBOX", &query, Paging::default())
        .await
        .unwrap();
    assert!(
        flagged
            .messages
            .iter()
            .all(|message| message.flags.seen && message.flags.flagged)
    );
    let moved = imap
        .move_messages(
            "INBOX",
            &uids,
            validity,
            "Archive",
            Check::Exists,
            &mut None,
        )
        .await
        .unwrap();
    assert_eq!(moved.uid_validity, validity);
    assert_eq!(moved.done, done);
    assert_eq!(moved.missing, [u32::MAX]);
    let archive = imap
        .search("Archive", &query, Paging::default())
        .await
        .unwrap();
    assert_eq!(archive.total, 3);
    assert_eq!(moved.destination_uid_validity, archive.uid_validity);
    assert_eq!(
        moved.new_uids,
        std::collections::HashMap::from([(2, 1), (3, 2), (4, 3)])
    );
    let mut uids: Vec<_> = archive.messages.iter().map(|message| message.uid).collect();
    let done = uids.clone();
    uids.push(u32::MAX);
    let trash = imap.trash_folder().await.unwrap();
    assert_eq!(trash, TRASH);
    let trashed = imap
        .move_messages(
            "Archive",
            &uids,
            archive.uid_validity,
            &trash,
            Check::Exists,
            &mut None,
        )
        .await
        .unwrap();
    assert_eq!(trashed.uid_validity, archive.uid_validity);
    assert_eq!(trashed.done, done);
    assert_eq!(trashed.missing, [u32::MAX]);
    let trash = imap.search(TRASH, &query, Paging::default()).await.unwrap();
    assert_eq!(trash.total, 3);
    assert_eq!(trashed.destination_uid_validity, trash.uid_validity);
    assert_eq!(
        trashed.new_uids,
        std::collections::HashMap::from([(1, 1), (2, 2), (3, 3)])
    );
    for folder in ["INBOX", "Archive"] {
        assert_eq!(
            imap.search(folder, &query, Paging::default())
                .await
                .unwrap()
                .total,
            0
        );
    }
    imap.logout().await.unwrap();
}

/// The refusal of a permanent delete where that would only remove a label.
const LABEL_ONLY: &str = "On Gmail, a permanent delete would only remove this folder's label \
    and keep the message in All Mail. Delete without `permanent` to move it to the trash, \
    which Gmail empties after 30 days.";

/// What deleting a message that is in Trash says where that refusal applies.
const IN_TRASH: &str = "the message is already in Trash; Gmail empties Trash after 30 days";

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn refuses_a_permanent_delete_where_it_only_removes_a_label() {
    // A mailbox of its own, which the first mail makes: no other test
    // delivers to it or deletes from it.
    let email = format!("l{}@example.com", uuid::Uuid::new_v4().simple());
    let user = client(&email, &email);
    let subject = unique("label");
    send_to(EmailAddress::new(email.as_str()), &subject, "keep me").await;
    let uid = wait_for(&user, "INBOX", &subject, 1).await[0].uid;
    create_folder(&user, TRASH).await;

    let config = MailConfig {
        permanent_delete: false,
        ..config()
    };
    let mut imap = client_on(config.clone(), &email, &email)
        .connect_imap()
        .await
        .unwrap();
    let refused = imap
        .delete_message("INBOX", uid, None, DeleteMode::Permanent)
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, Error::InvalidInput(text) if text == LABEL_ONLY),
        "{refused:?}"
    );
    wait_for(&user, "INBOX", &subject, 1).await;
    // The session keeps the setting through IDLE, and a delete to Trash works.
    imap.examine("INBOX").await.unwrap();
    let wait = Duration::from_millis(200);
    let (mut imap, _) = imap.idle(wait, std::future::pending()).await.unwrap();
    let again = imap
        .delete_message("INBOX", uid, None, DeleteMode::Permanent)
        .await
        .unwrap_err();
    assert!(matches!(again, Error::InvalidInput(_)), "{again:?}");
    imap.delete_message("INBOX", uid, None, DeleteMode::Trash)
        .await
        .unwrap();
    imap.logout().await.unwrap();
    wait_for(&user, "INBOX", &subject, 0).await;
    let uid = wait_for(&user, TRASH, &subject, 1).await[0].uid;

    // Deleting it again does not advise the permanent delete that is refused.
    let mut imap = client_on(config, &email, &email)
        .connect_imap()
        .await
        .unwrap();
    let again = imap
        .delete_message(TRASH, uid, None, DeleteMode::Trash)
        .await
        .unwrap_err();
    assert!(
        matches!(&again, Error::InvalidInput(text) if text == IN_TRASH),
        "{again:?}"
    );
    imap.logout().await.unwrap();

    // Without the setting a permanent delete removes the message, as before.
    let mut imap = user.connect_imap().await.unwrap();
    imap.delete_message(TRASH, uid, None, DeleteMode::Permanent)
        .await
        .unwrap();
    imap.logout().await.unwrap();
    wait_for(&user, TRASH, &subject, 0).await;
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn replies_with_threading_headers() {
    let (alice, bob) = tokio::join!(User::new(), User::new());
    create_folder(&bob.client, SENT).await;
    let subject = unique("thread");
    send_from(&alice.client, bob.email(), &subject, "Shall we meet?").await;
    let parent_uid = wait_for(&bob.client, "INBOX", &subject, 1).await[0].uid;
    let mut imap = bob.client.connect_imap().await.unwrap();
    let original = imap
        .fetch_message("INBOX", parent_uid, None)
        .await
        .unwrap()
        .0;
    imap.logout().await.unwrap();
    let original_id = original.headers.message_id.unwrap();

    let reply = Reply {
        text_body: "Yes, Tuesday works.".to_owned(),
        ..Reply::default()
    };
    let sent = bob
        .client
        .reply("INBOX", parent_uid, None, &reply, SendOptions::default())
        .await
        .unwrap();
    assert!(
        matches!(sent.sent_copy, SentCopy::Saved { .. }),
        "{:?}",
        sent.sent_copy
    );

    let reply_subject = format!("Re: {subject}");
    let uid = wait_for(&alice.client, "INBOX", &reply_subject, 1).await[0].uid;
    let mut imap = alice.client.connect_imap().await.unwrap();
    let received = imap.fetch_message("INBOX", uid, None).await.unwrap().0;
    imap.logout().await.unwrap();
    assert_eq!(
        received.headers.in_reply_to,
        std::slice::from_ref(&original_id)
    );
    assert_eq!(received.headers.references, [original_id]);
    assert_eq!(received.headers.to, [alice.email()]);
    assert_eq!(
        received.text_body.as_deref().map(str::trim),
        Some("Yes, Tuesday works.")
    );

    let original = wait_for(&bob.client, "INBOX", &subject, 1).await;
    assert!(original[0].flags.answered);
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn saves_a_new_draft_without_sending_it() {
    let (alice, bob) = tokio::join!(User::new(), User::new());
    create_folder(&alice.client, "Drafts").await;
    let subject = unique("draft");
    let message = OutgoingMessage {
        to: vec![bob.email()],
        bcc: vec![EmailAddress::new("hidden@example.com")],
        subject: subject.clone(),
        text_body: "Not sent yet.".to_owned(),
        attachments: vec![csv_file()],
        ..OutgoingMessage::default()
    };
    let mut imap = alice.client.connect_imap().await.unwrap();
    let saved = alice.client.save_draft(&mut imap, &message).await.unwrap();
    assert_eq!(saved.folder, "Drafts");
    assert!(saved.message_id.ends_with("@example.com"));

    let by_id = SearchQuery::new().message_id(format!("<{}>", saved.message_id));
    let found = imap
        .search("Drafts", &by_id, Paging::default())
        .await
        .unwrap();
    assert_eq!(found.total, 1);
    let uid = found.messages[0].uid;
    let (validity, appended) = saved.append_uid.unwrap();
    assert_ne!(validity, 0);
    assert_eq!(appended, uid);
    let (full, _) = imap.fetch_message("Drafts", uid, None).await.unwrap();
    assert_eq!(full.attachments.len(), 1);
    let file = imap
        .fetch_attachment("Drafts", uid, None, full.attachments[0].id, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file.content, Some(csv_file().content));
    // The draft keeps its Bcc recipient: TEXT searches the recipients too.
    let hidden = SearchQuery::new().text("hidden@example.com");
    let found = imap
        .search("Drafts", &hidden, Paging::default())
        .await
        .unwrap();
    assert_eq!(found.total, 1);
    imap.logout().await.unwrap();
    assert_eq!(full.headers.subject.as_deref(), Some(subject.as_str()));
    assert_eq!(full.headers.to, [bob.email()]);
    assert_eq!(
        full.text_body.as_deref().map(str::trim),
        Some("Not sent yet.")
    );
    assert!(full.flags.draft, "{:?}", full.flags);
    assert!(full.flags.seen, "{:?}", full.flags);

    // The draft was never sent.
    let mut bob_imap = bob.client.connect_imap().await.unwrap();
    let inbox = bob_imap
        .search(
            "INBOX",
            &SearchQuery::new().subject(subject.clone()),
            Paging::default(),
        )
        .await
        .unwrap();
    bob_imap.logout().await.unwrap();
    assert_eq!(inbox.total, 0);
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn saves_a_reply_draft_in_the_thread() {
    let (alice, bob) = tokio::join!(User::new(), User::new());
    create_folder(&bob.client, "Drafts").await;
    let subject = unique("draft-thread");
    send_from(&alice.client, bob.email(), &subject, "Shall we meet?").await;
    let parent_uid = wait_for(&bob.client, "INBOX", &subject, 1).await[0].uid;
    let reply = Reply {
        text_body: "Yes, Tuesday works.".to_owned(),
        ..Reply::default()
    };
    let mut imap = bob.client.connect_imap().await.unwrap();
    let saved = bob
        .client
        .save_draft_reply(&mut imap, "INBOX", parent_uid, None, &reply)
        .await
        .unwrap();
    assert_eq!(saved.folder, "Drafts");

    let original = imap
        .fetch_message("INBOX", parent_uid, None)
        .await
        .unwrap()
        .0;
    let by_id = SearchQuery::new().message_id(format!("<{}>", saved.message_id));
    let found = imap
        .search("Drafts", &by_id, Paging::default())
        .await
        .unwrap();
    let uid = found.messages[0].uid;
    let (validity, appended) = saved.append_uid.unwrap();
    assert_ne!(validity, 0);
    assert_eq!(appended, uid);
    let draft = imap.fetch_message("Drafts", uid, None).await.unwrap().0;
    imap.logout().await.unwrap();
    let original_id = original.headers.message_id.unwrap();
    assert_eq!(draft.headers.subject, Some(format!("Re: {subject}")));
    assert_eq!(draft.headers.to, [alice.email()]);
    assert_eq!(
        draft.headers.in_reply_to,
        std::slice::from_ref(&original_id)
    );
    assert_eq!(draft.headers.references, [original_id]);
    assert!(draft.flags.draft, "{:?}", draft.flags);
    assert!(!original.flags.answered);
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn send_appends_no_copy_where_the_server_files_it() {
    let (alice, bob) = tokio::join!(User::new(), User::new());
    // The Sent folder exists, so a copy appended by mistake would be found.
    create_folder(&alice.client, SENT).await;
    for (by_server, save_to_sent, copies) in SENT_COPY_CASES {
        let subject = unique("sent-copy");
        let message = OutgoingMessage {
            to: vec![EmailAddress::with_name("Bob", bob.address.as_str())],
            subject: subject.clone(),
            text_body: "Hello Bob.".to_owned(),
            ..OutgoingMessage::default()
        };
        let client = if by_server {
            files_sent(&alice.address, &alice.address)
        } else {
            alice.client.clone()
        };
        let sent = client
            .send(&message, SendOptions { save_to_sent })
            .await
            .unwrap();
        let case = format!("by_server: {by_server}, save_to_sent: {save_to_sent}");
        assert_eq!(sent.sent_copy, copy_report(by_server), "{case}");
        wait_for(&bob.client, "INBOX", &subject, 1).await;
        wait_for(&alice.client, SENT, &subject, copies).await;
    }
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn reply_appends_no_copy_where_the_server_files_it() {
    let (alice, bob) = tokio::join!(User::new(), User::new());
    create_folder(&bob.client, SENT).await;
    let reply = Reply {
        text_body: "Yes, Tuesday works.".to_owned(),
        ..Reply::default()
    };
    for (by_server, save_to_sent, copies) in SENT_COPY_CASES {
        let subject = unique("reply-copy");
        send_from(&alice.client, bob.email(), &subject, "Shall we meet?").await;
        let parent_uid = wait_for(&bob.client, "INBOX", &subject, 1).await[0].uid;
        let client = if by_server {
            files_sent(&bob.address, &bob.address)
        } else {
            bob.client.clone()
        };
        let sent = client
            .reply(
                "INBOX",
                parent_uid,
                None,
                &reply,
                SendOptions { save_to_sent },
            )
            .await
            .unwrap();
        let case = format!("by_server: {by_server}, save_to_sent: {save_to_sent}");
        assert_eq!(sent.sent_copy, copy_report(by_server), "{case}");
        wait_for(&alice.client, "INBOX", &format!("Re: {subject}"), 1).await;
        wait_for(&bob.client, SENT, &format!("Re: {subject}"), copies).await;
    }
}

/// Sends `raw` from alice to `to` as it is, over SMTP.
async fn send_raw(to: &str, raw: &str) {
    use lettre::AsyncTransport;
    let smtp = config().smtp;
    let transport =
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(smtp.host)
            .port(smtp.port)
            .credentials(lettre::transport::smtp::authentication::Credentials::new(
                ALICE.to_owned(),
                "alicepass".to_owned(),
            ))
            .build();
    let envelope =
        lettre::address::Envelope::new(Some(ALICE.parse().unwrap()), vec![to.parse().unwrap()])
            .unwrap();
    transport.send_raw(&envelope, raw.as_bytes()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn fetches_attachments_without_marking_read() {
    let bob = User::new().await;
    let subject = unique("attachment");
    let raw = format!(
        "From: {ALICE}\r\nTo: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
         --b\r\nContent-Type: text/plain\r\n\r\nSee the file.\r\n\
         --b\r\nContent-Type: application/octet-stream\r\n\
         Content-Disposition: attachment; filename=\"bytes.bin\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\nAP9B\r\n--b--\r\n",
        to = bob.address,
    );
    send_raw(&bob.address, &raw).await;
    let uid = wait_for(&bob.client, "INBOX", &subject, 1).await[0].uid;

    let mut imap = bob.client.connect_imap().await.unwrap();
    let data = imap
        .fetch_attachment("INBOX", uid, None, 1, 1 << 20)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.attachment.id, 1);
    assert_eq!(data.attachment.filename.as_deref(), Some("bytes.bin"));
    assert_eq!(data.content.as_deref(), Some(&[0x00, 0xFF, 0x41][..]));
    let missing = imap.fetch_attachment("INBOX", uid, None, 2, 1 << 20).await;
    assert_eq!(missing.unwrap(), None);
    let too_large = imap
        .fetch_attachment("INBOX", uid, None, 1, 2)
        .await
        .unwrap();
    assert_eq!(too_large.unwrap().content, None);
    let err = imap
        .fetch_attachment("INBOX", 4_000_000, None, 1, 1 << 20)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::MessageNotFound { uid: 4_000_000, .. }),
        "{err:?}"
    );
    imap.logout().await.unwrap();

    let after = wait_for(&bob.client, "INBOX", &subject, 1).await;
    assert!(
        !after[0].flags.seen,
        "fetching an attachment must not mark the message as read"
    );
}

/// A new message, a search result and a fetched message say whether a mail client shows the
/// `From` address as the sender, and hold each `From` value as sent. A reply to a sender that
/// is not clear, such as one of two `From` headers, needs its recipients.
#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn new_messages_say_whether_their_sender_address_is_clear() {
    let bob = User::new().await;
    let subject = unique("sender");
    let named = format!("Alice <{ALICE}>");
    let froms = [
        vec![named.clone()],
        vec![format!("<{BOB}> {ALICE}")],
        vec![BOB.to_owned(), named],
    ];
    for from in &froms {
        let to = &bob.address;
        let from = from.join("\r\nFrom: ");
        let raw = format!("From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\nHello\r\n");
        send_raw(to, &raw).await;
    }
    let sent = wait_for(&bob.client, "INBOX", &subject, 3).await;
    let first = sent.iter().map(|message| message.uid).min().unwrap();
    let mut imap = bob.client.connect_imap().await.unwrap();
    imap.examine("INBOX").await.unwrap();
    let new = imap.messages_after(first - 1, 3).await.unwrap();
    let clear: Vec<_> = new.iter().map(|message| message.from_clear).collect();
    assert_eq!(clear, [true, false, false]);
    let values: Vec<_> = new.iter().map(|message| &message.from_values).collect();
    assert_eq!(values, froms.iter().collect::<Vec<_>>());
    for message in &new {
        let found = sent.iter().find(|found| found.uid == message.uid).unwrap();
        assert_eq!(found.from_clear, message.from_clear);
        assert_eq!(found.from_values, message.from_values);
        let (fetched, _) = imap
            .fetch_message("INBOX", message.uid, None)
            .await
            .unwrap();
        assert_eq!(fetched.headers.from_clear, message.from_clear);
        assert_eq!(fetched.headers.from_values, message.from_values);
    }
    imap.logout().await.unwrap();
    let (reply, options) = (Reply::default(), SendOptions::default());
    let refused = bob.client.reply("INBOX", new[2].uid, None, &reply, options);
    assert!(matches!(refused.await, Err(Error::InvalidInput(_))));
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn reports_missing_messages_and_folders() {
    let bob = User::new().await;
    let mut imap = bob.client.connect_imap().await.unwrap();
    let err = imap
        .fetch_message("INBOX", 4_000_000, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::MessageNotFound { uid: 4_000_000, .. }),
        "{err:?}"
    );
    let err = imap
        .set_flag("INBOX", 4_000_000, None, Flag::Seen, true)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::MessageNotFound { .. }), "{err:?}");
    let err = imap
        .search("No Such Folder", &SearchQuery::new(), Paging::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::FolderNotFound(_)), "{err:?}");
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn idle_reports_new_mail() {
    let bob = User::new().await;
    let mut imap = bob.client.connect_imap().await.unwrap();
    assert!(imap.supports_idle());
    let before = imap.examine("INBOX").await.unwrap();
    assert!(before.uid_validity > 0);
    // The welcome mail is the only message so far.
    let known = before.uid_next.saturating_sub(1);

    let subject = unique("idle");
    let sender = {
        let (to, subject) = (bob.email(), subject.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            send_to(to, &subject, "new mail").await;
        })
    };
    let mut changed = false;
    let mut found = Vec::new();
    // Wait until this message shows up.
    for _ in 0..10 {
        let (session, event) = imap
            .idle(Duration::from_secs(10), std::future::pending())
            .await
            .unwrap();
        imap = session;
        changed |= event == IdleEvent::Changed;
        found = imap.messages_after(known, 10).await.unwrap();
        if found
            .iter()
            .any(|message| message.subject.as_deref() == Some(subject.as_str()))
        {
            break;
        }
    }
    sender.await.unwrap();
    assert!(changed);
    let message = found
        .iter()
        .find(|message| message.subject.as_deref() == Some(subject.as_str()))
        .unwrap();
    assert!(message.uid > known);
    assert_eq!(message.from.as_ref().unwrap().address, ALICE);
    assert!(message.message_id.is_some());
    assert!(message.date.is_some());
    assert!(found.windows(2).all(|pair| pair[0].uid < pair[1].uid));

    // A limit of one is the oldest UID still above `known`.
    let oldest = imap.messages_after(known, 1).await.unwrap();
    assert_eq!(oldest.len(), 1);
    assert_eq!(oldest[0].uid, found[0].uid);

    // Same UIDVALIDITY, higher UIDNEXT.
    let after = imap.examine("INBOX").await.unwrap();
    assert_eq!(after.uid_validity, before.uid_validity);
    assert!(after.uid_next > before.uid_next);
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn idle_reports_mail_that_arrived_before_it_started() {
    // A fresh user (GreenMail creates it on first delivery, with the
    // address as password), so no other test touches this mailbox.
    let email = format!("i{}@example.com", uuid::Uuid::new_v4().simple());
    let send = async |subject: &str| {
        let message = OutgoingMessage {
            to: vec![EmailAddress::new(email.as_str())],
            subject: subject.to_owned(),
            text_body: "hello".to_owned(),
            ..OutgoingMessage::default()
        };
        let options = SendOptions {
            save_to_sent: false,
        };
        alice().send(&message, options).await.unwrap();
    };
    send("first").await;
    let user = client(&email, &email);
    wait_for(&user, "INBOX", "first", 1).await;
    let mut imap = user.connect_imap().await.unwrap();
    imap.examine("INBOX").await.unwrap();

    // Delivered while this session is not running a command: the server
    // announces it in reply to the IDLE command itself, before the
    // continuation, which must still count as a change.
    send("second").await;
    wait_for(&user, "INBOX", "second", 1).await;
    let (imap, event) = imap
        .idle(Duration::from_secs(3), std::future::pending())
        .await
        .unwrap();
    assert_eq!(event, IdleEvent::Changed);
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn idle_stops_on_request_and_keeps_the_session() {
    // A mailbox nobody else delivers to. The shared alice inbox receives
    // mail from concurrent tests, and IDLE then returns Changed before the
    // stop signal, which is not what this test is checking.
    let email = format!("s{}@example.com", uuid::Uuid::new_v4().simple());
    let user = client(&email, &email);
    let subject = unique("seed");
    let message = OutgoingMessage {
        to: vec![EmailAddress::new(email.as_str())],
        subject: subject.clone(),
        text_body: "hello".to_owned(),
        ..OutgoingMessage::default()
    };
    let options = SendOptions {
        save_to_sent: false,
    };
    alice().send(&message, options).await.unwrap();
    wait_for(&user, "INBOX", &subject, 1).await;

    let mut imap = user.connect_imap().await.unwrap();
    imap.examine("INBOX").await.unwrap();
    let started = std::time::Instant::now();
    let (mut imap, event) = imap
        .idle(
            Duration::from_secs(60),
            tokio::time::sleep(Duration::from_millis(300)),
        )
        .await
        .unwrap();
    assert_eq!(event, IdleEvent::Stopped);
    assert!(started.elapsed() < Duration::from_secs(10));
    // The session still works after DONE.
    imap.examine("INBOX").await.unwrap();

    // This mailbox stays quiet, so the short wait ends because time passed.
    let started = std::time::Instant::now();
    let (imap, event) = imap
        .idle(Duration::from_secs(1), std::future::pending())
        .await
        .unwrap();
    assert_eq!(event, IdleEvent::Timeout);
    assert!(started.elapsed() < Duration::from_secs(10));
    imap.logout().await.unwrap();
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn examine_reports_missing_folders() {
    let user = User::new().await;
    let mut imap = user.client.connect_imap().await.unwrap();
    let err = imap.examine("No Such Folder").await.unwrap_err();
    assert!(matches!(err, Error::FolderNotFound(_)), "{err:?}");
    imap.logout().await.unwrap();
}

/// Opens a raw `async-imap` session for `user`, for commands the crate does
/// not offer, such as `DELETE` and `STATUS`.
async fn raw_session(user: &User) -> async_imap::Session<tokio::net::TcpStream> {
    let host = env_or("GREENMAIL_HOST", "127.0.0.1");
    let port: u16 = env_or("GREENMAIL_IMAP_PORT", "3143").parse().unwrap();
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .unwrap();
    let mut client = async_imap::Client::new(tcp);
    client.read_response().await.unwrap().unwrap();
    client
        .login(&user.address, &user.address)
        .await
        .map_err(|(err, _)| err)
        .unwrap()
}

/// Appends a minimal message with `subject` to `folder`.
async fn append(
    session: &mut async_imap::Session<tokio::net::TcpStream>,
    folder: &str,
    subject: &str,
) {
    let raw = format!(
        "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: {subject}\r\n\
         Message-ID: <{subject}@example.com>\r\n\r\n{subject}\r\n"
    );
    session.append(folder, None, None, raw).await.unwrap();
}

/// Appends a message with `subject`, the `Date` header `date` and the
/// arrival time (INTERNALDATE) `arrived`.
async fn append_dated(
    session: &mut async_imap::Session<tokio::net::TcpStream>,
    folder: &str,
    subject: &str,
    date: &str,
    arrived: &str,
) {
    let raw = format!(
        "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: {subject}\r\n\
         Date: {date}\r\n\r\n{subject}\r\n"
    );
    let arrived = format!("\"{arrived}\"");
    session
        .append(folder, None, Some(&arrived), raw)
        .await
        .unwrap();
}

/// The subjects that `query` finds in `folder`, in the order listed.
async fn subjects(imap: &mut ImapSession, folder: &str, query: &SearchQuery) -> Vec<String> {
    let page = imap.search(folder, query, Paging::default()).await.unwrap();
    page.messages
        .into_iter()
        .map(|summary| summary.subject.unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn dates_and_order_follow_the_date_header() {
    let user = User::new().await;
    let folder = unique("dated");
    let mut raw = raw_session(&user).await;
    raw.create(&folder).await.unwrap();
    // Mail that did not arrive when it is dated: imported, delayed or
    // appended by another client. The reply arrived before the question.
    for (subject, date, arrived) in [
        (
            "dated-3rd",
            "Sat, 03 Feb 2001 12:00:00 +0000",
            "10-Feb-2001 12:00:00 +0000",
        ),
        (
            "dated-10th",
            "Sat, 10 Feb 2001 12:00:00 +0000",
            "03-Feb-2001 12:00:00 +0000",
        ),
        (
            "reply",
            "Sun, 04 Feb 2001 09:12:00 +0000",
            "04-Feb-2001 09:12:00 +0000",
        ),
        (
            "question",
            "Sun, 04 Feb 2001 09:11:00 +0000",
            "04-Feb-2001 09:13:00 +0000",
        ),
    ] {
        append_dated(&mut raw, &folder, subject, date, arrived).await;
    }
    let census = unique("census");
    raw.create(&census).await.unwrap();
    for (subject, date) in [
        ("otter census notes", "Sun, 04 Feb 2001 12:00:00 +0000"),
        ("census of otters", "Sun, 04 Feb 2001 12:00:00 +0000"),
        ("otter census", "Fri, 02 Feb 2001 12:00:00 +0000"),
    ] {
        append_dated(
            &mut raw,
            &census,
            subject,
            date,
            "04-Feb-2001 12:00:00 +0000",
        )
        .await;
    }
    raw.logout().await.unwrap();

    let day = |day| NaiveDate::from_ymd_opt(2001, 2, day).unwrap();
    let mut imap = user.client.connect_imap().await.unwrap();
    let all = subjects(&mut imap, &folder, &SearchQuery::new()).await;
    assert_eq!(all, ["dated-10th", "reply", "question", "dated-3rd"]);
    let third = SearchQuery::new().since(day(3)).before(day(4));
    assert_eq!(subjects(&mut imap, &folder, &third).await, ["dated-3rd"]);
    let fourth = SearchQuery::new().since(day(4)).before(day(5));
    assert_eq!(
        subjects(&mut imap, &folder, &fourth).await,
        ["reply", "question"]
    );
    let query = SearchQuery::new()
        .subject("otter census")
        .since(day(3))
        .before(day(5));
    let page = imap
        .search(&census, &query, Paging::default())
        .await
        .unwrap();
    let [matched] = page.messages.as_slice() else {
        panic!("expected one census match");
    };
    assert_eq!(matched.subject.as_deref(), Some("otter census notes"));
    assert_eq!(
        imap.matching(
            &census,
            &query,
            page.uid_validity.unwrap(),
            4,
            Instant::now() + Duration::from_secs(5)
        )
        .await
        .unwrap(),
        [matched.uid]
    );
    imap.logout().await.unwrap();
}

async fn uid_validity(
    session: &mut async_imap::Session<tokio::net::TcpStream>,
    folder: &str,
) -> u32 {
    session
        .status(folder, "(UIDVALIDITY)")
        .await
        .unwrap()
        .uid_validity
        .unwrap()
}

#[tokio::test]
#[ignore = "requires a GreenMail server"]
async fn stale_uidvalidity_is_refused_and_changes_nothing() {
    let user = User::new().await;
    create_folder(&user.client, TRASH).await;
    let folder = unique("stale");

    // GreenMail sets a folder's UIDVALIDITY to the epoch second it was
    // created, so recreating it a second later renumbers it.
    let mut raw = raw_session(&user).await;
    raw.create(&folder).await.unwrap();
    append(&mut raw, &folder, "old-1").await;
    append(&mut raw, &folder, "old-2").await;
    let v1 = uid_validity(&mut raw, &folder).await;
    raw.delete(&folder).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    raw.create(&folder).await.unwrap();
    append(&mut raw, &folder, "new-1").await;
    append(&mut raw, &folder, "new-2").await;
    let v2 = uid_validity(&mut raw, &folder).await;
    raw.logout().await.unwrap();
    assert_ne!(
        v1, v2,
        "GreenMail kept the UIDVALIDITY of a recreated folder"
    );

    let stale = |err: Error| {
        assert!(
            matches!(&err, Error::StaleId { folder: f } if *f == folder),
            "{err:?}"
        );
        assert!(err.leaves_session_usable());
    };
    let mut imap = user.client.connect_imap().await.unwrap();
    stale(imap.fetch_message(&folder, 2, Some(v1)).await.unwrap_err());
    stale(
        imap.fetch_attachment(&folder, 2, Some(v1), 1, 1 << 20)
            .await
            .unwrap_err(),
    );
    stale(
        imap.set_flag(&folder, 2, Some(v1), Flag::Flagged, true)
            .await
            .unwrap_err(),
    );
    stale(
        imap.move_message(&folder, 2, Some(v1), "INBOX")
            .await
            .unwrap_err(),
    );
    stale(
        imap.delete_message(&folder, 2, Some(v1), DeleteMode::Trash)
            .await
            .unwrap_err(),
    );
    stale(
        imap.delete_message(&folder, 2, Some(v1), DeleteMode::Permanent)
            .await
            .unwrap_err(),
    );
    imap.logout().await.unwrap();
    let reply = Reply {
        text_body: "This must not be sent.".to_owned(),
        ..Reply::default()
    };
    stale(
        user.client
            .reply(&folder, 2, Some(v1), &reply, SendOptions::default())
            .await
            .unwrap_err(),
    );

    let mut imap = user.client.connect_imap().await.unwrap();
    let (message, seen) = imap.fetch_message(&folder, 2, Some(v2)).await.unwrap();
    assert_eq!(message.headers.subject.as_deref(), Some("new-2"));
    assert!(!message.flags.flagged && !message.flags.answered);
    assert_eq!(seen, Some(v2));
    // Without an expected value nothing is checked: the old UID 2 now names
    // another message.
    let (message, seen) = imap.fetch_message(&folder, 2, None).await.unwrap();
    assert_eq!(message.headers.subject.as_deref(), Some("new-2"));
    assert_eq!(seen, Some(v2));
    let results = imap
        .search(&folder, &SearchQuery::new(), Paging::default())
        .await
        .unwrap();
    assert_eq!(results.total, 2);
    assert_eq!(results.uid_validity, Some(v2));
    imap.logout().await.unwrap();
}
