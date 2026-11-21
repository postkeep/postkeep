//! A stand-in S3 bucket at [`PATH`] on a test's `wiremock` server: it keeps
//! each object put, gives it back and deletes it, and records every request.

#![allow(
    dead_code,
    reason = "each test file uses its own share of the stand-in"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use postkeep::bucket::S3Bucket;
use postkeep_upstream::Http;
use secrecy::SecretString;
use wiremock::matchers::path_regex;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// How long a held answer waits before it comes, as a `503`.
pub const HELD: Duration = Duration::from_secs(5);

/// The bucket's own path, with a made-up marker no log may hold.
pub const PATH: &str = "/made-up-bucket-marker";

/// The made-up access key the stand-in's bucket signs with.
pub const KEY_ID: &str = "made-up-bucket-key-id";

/// The stand-in's objects, requests and switches, shared with the test.
#[derive(Clone, Default)]
pub struct StandIn {
    /// The objects, by their path under the bucket.
    pub objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    /// Every request received, in order, with when it came.
    pub requests: Arc<Mutex<Vec<(Instant, Request)>>>,
    /// Methods answered `500`, changing nothing.
    failing: Arc<Mutex<Vec<&'static str>>>,
    /// Methods whose answer is held back for [`HELD`], changing nothing.
    holding: Arc<Mutex<Vec<&'static str>>>,
}

impl StandIn {
    /// Answers `500` to every `method` request.
    pub fn fail(&self, method: &'static str) {
        self.failing.lock().unwrap().push(method);
    }

    /// Holds back the answer to every `method` request.
    pub fn hold(&self, method: &'static str) {
        self.holding.lock().unwrap().push(method);
    }

    /// Answers every request again.
    pub fn answer(&self) {
        self.failing.lock().unwrap().clear();
        self.holding.lock().unwrap().clear();
    }

    /// When the first `method` request came.
    pub fn first(&self, method: &str) -> Option<Instant> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .find(|(_, request)| request.method.as_str() == method)
            .map(|(at, _)| *at)
    }

    /// The names of the objects held.
    pub fn names(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }
}

impl Respond for StandIn {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.requests
            .lock()
            .unwrap()
            .push((Instant::now(), request.clone()));
        let method = request.method.as_str();
        if self.failing.lock().unwrap().contains(&method) {
            return ResponseTemplate::new(500);
        }
        if self.holding.lock().unwrap().contains(&method) {
            return ResponseTemplate::new(503).set_delay(HELD);
        }
        let path = request.url.path();
        let name = path
            .trim_start_matches(PATH)
            .trim_start_matches('/')
            .to_owned();
        let objects = &self.objects;
        match method {
            "PUT" => {
                objects.lock().unwrap().insert(name, request.body.clone());
                ResponseTemplate::new(200)
            }
            "GET" => objects.lock().unwrap().get(&name).map_or_else(
                || ResponseTemplate::new(404),
                |body| ResponseTemplate::new(200).set_body_bytes(body.clone()),
            ),
            "DELETE" => {
                objects.lock().unwrap().remove(&name);
                ResponseTemplate::new(204)
            }
            _ => ResponseTemplate::new(405),
        }
    }
}

/// The stand-in mounted at [`PATH`] on `server`, and a bucket that reaches it.
pub async fn stand_in(server: &MockServer) -> (StandIn, S3Bucket) {
    let stand_in = StandIn::default();
    Mock::given(path_regex(format!("^{PATH}/")))
        .respond_with(stand_in.clone())
        .mount(server)
        .await;
    let url = url::Url::parse(&format!("{}{PATH}", server.uri())).unwrap();
    let bucket = S3Bucket::new(
        url,
        "auto".to_owned(),
        SecretString::from(KEY_ID.to_owned()),
        SecretString::from("made-up-bucket-secret".to_owned()),
        Http::for_tests(),
    );
    (stand_in, bucket)
}
