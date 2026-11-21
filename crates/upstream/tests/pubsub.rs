//! Pub/Sub push token verification against a mocked Google key set.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep_upstream::{Endpoints, Http, PushExpectations, PushTokenError, PushVerifier};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};
use serde_json::{Value, json};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A throwaway RSA key generated for these tests only.
const TEST_KEY: &[u8] = include_bytes!("data/pubsub-test-key.pk8");
const AUDIENCE: &str = "https://mail.example.com/push/google";
const SERVICE_ACCOUNT: &str = "push@project.iam.gserviceaccount.com";

fn key() -> RsaKeyPair {
    RsaKeyPair::from_pkcs8(TEST_KEY).unwrap()
}

fn jwks(kid: &str) -> Value {
    let key = key();
    let public = RsaPublicKeyComponents::<Vec<u8>>::from(key.public());
    let encode = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    json!({"keys": [{
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": encode(&public.n),
        "e": encode(&public.e),
    }]})
}

fn sign(kid: &str, claims: &Value) -> String {
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg": "RS256", "kid": kid, "typ": "JWT"}).to_string());
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signed = format!("{header}.{claims}");
    let key = key();
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        signed.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn claims() -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": "https://accounts.google.com",
        "aud": AUDIENCE,
        "azp": "1234567890",
        "email": SERVICE_ACCOUNT,
        "email_verified": true,
        "iat": now,
        "exp": now + 3600,
        "sub": "1234567890",
    })
}

fn expected() -> PushExpectations {
    PushExpectations {
        audience: AUDIENCE.to_owned(),
        service_account: SERVICE_ACCOUNT.to_owned(),
    }
}

fn verifier(server: &MockServer) -> PushVerifier {
    let base = Url::parse(&server.uri()).unwrap();
    PushVerifier::new(Http::for_tests(), Endpoints::all_at(&base))
}

#[tokio::test]
async fn accepts_google_signed_tokens_for_the_configured_audience_and_account() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/google-certs"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cache-control", "public, max-age=20000")
                .set_body_json(jwks("key-1")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let verifier = verifier(&server);
    let claims_seen = verifier
        .verify(&sign("key-1", &claims()), &expected())
        .await
        .unwrap();
    assert_eq!(claims_seen.email, SERVICE_ACCOUNT);
    // The key set is cached.
    verifier
        .verify(&sign("key-1", &claims()), &expected())
        .await
        .unwrap();
}

#[tokio::test]
async fn refuses_tokens_with_wrong_claims_or_signatures() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/google-certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks("key-1")))
        .mount(&server)
        .await;
    let verifier = verifier(&server);
    let with = |field: &str, value: Value| {
        let mut claims = claims();
        claims[field] = value;
        sign("key-1", &claims)
    };
    let now = chrono::Utc::now().timestamp();
    let cases = [
        (
            with("aud", json!("https://evil.example.com/push/google")),
            PushTokenError::Claim("aud"),
        ),
        (
            with("iss", json!("https://evil.example.com")),
            PushTokenError::Claim("iss"),
        ),
        (
            with("email", json!("other@project.iam.gserviceaccount.com")),
            PushTokenError::Claim("email"),
        ),
        (
            with("email_verified", json!(false)),
            PushTokenError::Claim("email"),
        ),
        (with("exp", json!(now - 3600)), PushTokenError::Claim("exp")),
        (with("iat", json!(now + 3600)), PushTokenError::Claim("iat")),
    ];
    for (token, error) in cases {
        assert_eq!(
            verifier.verify(&token, &expected()).await.unwrap_err(),
            error
        );
    }

    // A tampered payload breaks the signature.
    let token = sign("key-1", &claims());
    let mut parts: Vec<&str> = token.split('.').collect();
    let mut forged = claims();
    forged["email"] = json!("attacker@example.com");
    let forged = URL_SAFE_NO_PAD.encode(forged.to_string());
    parts[1] = &forged;
    assert_eq!(
        verifier
            .verify(&parts.join("."), &expected())
            .await
            .unwrap_err(),
        PushTokenError::BadSignature
    );

    // Unsigned tokens are refused outright.
    let unsigned = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"key-1"}"#),
        URL_SAFE_NO_PAD.encode(claims().to_string())
    );
    assert!(matches!(
        verifier.verify(&unsigned, &expected()).await.unwrap_err(),
        PushTokenError::Malformed(_)
    ));
}

#[tokio::test]
async fn unknown_key_ids_refetch_the_key_set_at_most_once_a_minute() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/google-certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks("key-1")))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/google-certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks("key-2")))
        .expect(0)
        .mount(&server)
        .await;
    let verifier = verifier(&server);
    verifier
        .verify(&sign("key-1", &claims()), &expected())
        .await
        .unwrap();
    // Google rotated keys moments ago: the refetch waits out the interval,
    // so a flood of bogus key ids cannot hammer Google.
    assert_eq!(
        verifier
            .verify(&sign("key-2", &claims()), &expected())
            .await
            .unwrap_err(),
        PushTokenError::UnknownKey
    );
}

#[tokio::test]
async fn unavailable_keys_are_reported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/google-certs"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let verifier = verifier(&server);
    assert!(matches!(
        verifier
            .verify(&sign("key-1", &claims()), &expected())
            .await
            .unwrap_err(),
        PushTokenError::Keys(_)
    ));
}

#[tokio::test]
async fn a_failed_key_fetch_is_not_retried_during_the_backoff() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/google-certs"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let verifier = verifier(&server);
    let token = sign("key-1", &claims());
    assert_eq!(
        verifier.verify(&token, &expected()).await.unwrap_err(),
        PushTokenError::Keys("HTTP 503 Service Unavailable".to_owned())
    );
    // The cache is still empty. A second push during the backoff must fail
    // fast and must not call Google again, including for a different key id.
    assert_eq!(
        verifier
            .verify(&sign("other", &claims()), &expected())
            .await
            .unwrap_err(),
        PushTokenError::Keys("Google's signing keys are temporarily unavailable".to_owned())
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
