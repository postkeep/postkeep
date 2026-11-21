//! The Graph watcher against recorded responses in Microsoft's documented
//! shapes: Inbox paging, throttling, an outage, the three lifecycle
//! notifications, and a create that conflicts with a leftover subscription.
//! The files, and where each shape comes from, are in `tests/data/graph/`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use postkeep_store::{Provider, PushSubscription};
use serde_json::Value;
use tower::ServiceExt as _;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::graph::GraphPosition;
use super::harness::{self, ProviderSetup, provider_setup};

const INBOX_PAGE_1: &str = include_str!("../../tests/data/graph/inbox-page-1.json");
const INBOX_PAGE_2: &str = include_str!("../../tests/data/graph/inbox-page-2.json");
const THROTTLED: &str = include_str!("../../tests/data/graph/throttled.json");
const UNAVAILABLE: &str = include_str!("../../tests/data/graph/unavailable.json");
const REAUTHORIZATION_REQUIRED: &str =
    include_str!("../../tests/data/graph/lifecycle-reauthorization-required.json");
const SUBSCRIPTION_REMOVED: &str =
    include_str!("../../tests/data/graph/lifecycle-subscription-removed.json");
const MISSED: &str = include_str!("../../tests/data/graph/lifecycle-missed.json");
const CONFLICT: &str = include_str!("../../tests/data/graph/subscription-conflict.json");
const SUBSCRIPTIONS_PAGE_1: &str = include_str!("../../tests/data/graph/subscriptions-page-1.json");
const SUBSCRIPTIONS_PAGE_2: &str = include_str!("../../tests/data/graph/subscriptions-page-2.json");
const CREATED: &str = include_str!("../../tests/data/graph/subscription-created.json");

/// Graph's address in the recorded bodies.
const RECORDED_GRAPH: &str = "https://graph.microsoft.com/v1.0/";
const INBOX: &str = "/graph/v1.0/me/mailFolders/inbox/messages";
const SUBSCRIPTIONS: &str = "/graph/v1.0/subscriptions";
/// The subscription the recorded lifecycle notifications name, and their
/// `clientState`.
const NOTIFIED: &str = "0e8f1b3a-4c5d-4e6f-9a0b-1c2d3e4f5a6b";
const CLIENT_STATE: &str = "recorded-client-state";
/// The id in the recorded create response.
const CREATED_ID: &str = "7f105c7d-2dc5-4530-97cd-4e7ae6534c07";
/// The leftover Inbox subscription on the second recorded list page.
const ORPHAN: &str = "5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a";

/// `recorded` as the mock server at `server` answers it, with Graph's
/// address replaced by the server's.
fn answer(server: &MockServer, status: u16, recorded: &str) -> ResponseTemplate {
    let graph = format!("{}/graph/v1.0/", server.uri());
    let body: Value = serde_json::from_str(&recorded.replace(RECORDED_GRAPH, &graph)).unwrap();
    ResponseTemplate::new(status).set_body_json(body)
}

/// Starts listening just before the first recorded Inbox message.
async fn listen_from_the_recorded_morning(setup: &ProviderSetup) {
    let position = GraphPosition {
        since: "2026-10-08T09:00:00Z".to_owned(),
        ids: Vec::new(),
        resume: None,
    };
    setup
        .store
        .set_watch_position(&setup.account, &position.encode())
        .await
        .unwrap();
}

/// Stores the subscription the recorded notifications name, as a create
/// with the recorded `clientState` would have.
async fn store_the_notified_subscription(setup: &ProviderSetup) {
    let subscription = PushSubscription {
        provider: Provider::Graph,
        subscription_id: Some(NOTIFIED.to_owned()),
        client_state_hash: Some(PushSubscription::hash_client_state(CLIENT_STATE)),
        expires_at: postkeep_store::now() + 6 * 24 * 3600,
    };
    setup
        .store
        .save_push_subscription(&setup.account, &subscription)
        .await
        .unwrap();
}

/// Posts a recorded lifecycle notification to the lifecycle URL.
async fn notify_lifecycle(setup: &ProviderSetup, recorded: &str) {
    let request = Request::post(crate::push::GRAPH_LIFECYCLE_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(recorded.to_owned()))
        .unwrap();
    let response = crate::push::router(setup.watchers.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn recorded_inbox_pages_give_one_event_per_page() {
    let mut setup = provider_setup(Provider::Graph).await;
    listen_from_the_recorded_morning(&setup).await;
    let server = &setup.server;
    Mock::given(method("GET"))
        .and(path(INBOX))
        .and(query_param_is_missing("$skip"))
        .respond_with(answer(server, 200, INBOX_PAGE_1))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(INBOX))
        .and(query_param("$skip", "3"))
        .respond_with(answer(server, 200, INBOX_PAGE_2))
        .expect(1)
        .mount(server)
        .await;

    setup.watchers.schedule_graph_catch_up(&setup.account);
    let first = harness::next_event(&mut setup.receiver).await.json();
    assert_eq!(first["count"], 3);
    assert_eq!(
        first["id"],
        "graph.AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0AN030KvBDnEepQdGId5xqFAAACW-GZwAA"
    );
    assert_eq!(first["subject"], "Weekly report");
    assert_eq!(first["from"], "Reports <reports@example.org>");
    assert_eq!(first["message_id"], "weekly-41@reports.example.org");
    let second = harness::next_event(&mut setup.receiver).await.json();
    assert_eq!(second["count"], 1);
    assert_eq!(second["from"], "no-reply@accounts.example.com", "no name");
    assert_eq!(second["date"], "2026-10-08T09:03:59+00:00");

    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    let position = GraphPosition::parse(hook.position.as_deref()).unwrap();
    assert_eq!(position.since, "2026-10-08T09:03:59Z");
    assert_eq!(position.resume, None);
    harness::finish(&setup).await;
}

#[tokio::test]
async fn recorded_throttling_and_outage_are_retried_until_the_page_arrives() {
    let mut setup = provider_setup(Provider::Graph).await;
    listen_from_the_recorded_morning(&setup).await;
    let server = &setup.server;
    let refusals = [
        (answer(server, 429, THROTTLED), "10"),
        (answer(server, 503, UNAVAILABLE), "5"),
    ];
    for (priority, (refusal, retry_after)) in (1..).zip(refusals) {
        Mock::given(method("GET"))
            .and(path(INBOX))
            .respond_with(refusal.insert_header("retry-after", retry_after))
            .up_to_n_times(1)
            .with_priority(priority)
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(INBOX))
        .respond_with(answer(server, 200, INBOX_PAGE_2))
        .with_priority(3)
        .mount(server)
        .await;

    setup.watchers.schedule_graph_catch_up(&setup.account);
    let event = harness::next_event(&mut setup.receiver).await.json();
    assert_eq!(event["subject"], "Password reset requested");
    assert_eq!(
        harness::requests(server, "GET", INBOX).await,
        3,
        "a 429, a 503, then the page, with no push in between"
    );
    harness::finish(&setup).await;
}

#[tokio::test]
async fn a_recorded_reauthorization_request_reauthorizes_that_subscription() {
    let setup = provider_setup(Provider::Graph).await;
    store_the_notified_subscription(&setup).await;
    let reauthorize = format!("{SUBSCRIPTIONS}/{NOTIFIED}/reauthorize");
    Mock::given(method("POST"))
        .and(path(reauthorize.as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&setup.server)
        .await;

    notify_lifecycle(&setup, REAUTHORIZATION_REQUIRED).await;
    harness::finish(&setup).await;
    assert_eq!(
        harness::requests(&setup.server, "POST", &reauthorize).await,
        1
    );
    harness::wait_for_subscription(&setup, Some(NOTIFIED)).await;
}

#[tokio::test]
async fn a_recorded_removal_recreates_the_subscription_and_catches_up() {
    let mut setup = provider_setup(Provider::Graph).await;
    listen_from_the_recorded_morning(&setup).await;
    store_the_notified_subscription(&setup).await;
    let server = &setup.server;
    Mock::given(method("POST"))
        .and(path(SUBSCRIPTIONS))
        .respond_with(answer(server, 201, CREATED))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(INBOX))
        .respond_with(answer(server, 200, INBOX_PAGE_2))
        .mount(server)
        .await;

    notify_lifecycle(&setup, SUBSCRIPTION_REMOVED).await;
    harness::wait_for_subscription(&setup, Some(CREATED_ID)).await;
    let event = harness::next_event(&mut setup.receiver).await.json();
    assert_eq!(event["subject"], "Password reset requested");
    harness::finish(&setup).await;
}

#[tokio::test]
async fn a_recorded_missed_notification_catches_up() {
    let mut setup = provider_setup(Provider::Graph).await;
    listen_from_the_recorded_morning(&setup).await;
    store_the_notified_subscription(&setup).await;
    let server = &setup.server;
    Mock::given(method("GET"))
        .and(path(INBOX))
        .respond_with(answer(server, 200, INBOX_PAGE_2))
        .expect(1)
        .mount(server)
        .await;

    notify_lifecycle(&setup, MISSED).await;
    let event = harness::next_event(&mut setup.receiver).await.json();
    assert_eq!(event["subject"], "Password reset requested");
    harness::wait_for_subscription(&setup, Some(NOTIFIED)).await;
    harness::finish(&setup).await;
}

#[tokio::test]
async fn a_recorded_conflict_deletes_the_leftover_and_creates_again() {
    let setup = provider_setup(Provider::Graph).await;
    listen_from_the_recorded_morning(&setup).await;
    let server = &setup.server;
    Mock::given(method("POST"))
        .and(path(SUBSCRIPTIONS))
        .respond_with(answer(server, 409, CONFLICT))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(SUBSCRIPTIONS))
        .respond_with(answer(server, 201, CREATED))
        .with_priority(2)
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(SUBSCRIPTIONS))
        .and(query_param_is_missing("$skiptoken"))
        .respond_with(answer(server, 200, SUBSCRIPTIONS_PAGE_1))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(SUBSCRIPTIONS))
        .and(query_param("$skiptoken", "e1d0c9b8a7f6"))
        .respond_with(answer(server, 200, SUBSCRIPTIONS_PAGE_2))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("{SUBSCRIPTIONS}/{ORPHAN}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(INBOX))
        .respond_with(answer(server, 200, INBOX_PAGE_2))
        .mount(server)
        .await;

    setup.watchers.refresh(&setup.account);
    harness::wait_for_subscription(&setup, Some(CREATED_ID)).await;
    harness::finish(&setup).await;
    for other in [
        "a8b5f2a4-6c8e-4d4c-bf8e-3f0b0f6e2c11",
        "e1d0c9b8-a7f6-4e5d-8c4b-3a2f1e0d9c8b",
    ] {
        let kept = format!("{SUBSCRIPTIONS}/{other}");
        assert_eq!(
            harness::requests(server, "DELETE", &kept).await,
            0,
            "{other}"
        );
    }
}
