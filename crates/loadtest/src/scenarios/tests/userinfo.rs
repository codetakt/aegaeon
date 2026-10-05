//! Exercise UserInfo through the complete TLS authorization and OIDC consumer.
use super::protocol_fixture::{
    assert_http, assert_report_redaction, record_userinfo_proof, resource_challenge, OidcIssuer,
    RS_NONCE, SENSITIVE_MARKER,
};
use super::{fixture_profile, fixture_reply, sha256, tls_fixture, ScenarioExecutor};
use crate::accounting::HttpAccounting;

fn assert_userinfo_http(accounting: &HttpAccounting, resource_statuses: &[(&str, u64)]) {
    let resource_attempts = resource_statuses.iter().map(|(_, count)| count).sum();
    let mut statuses = vec![
        ("GET /authorize 302", 1),
        ("POST /token 200", 1),
        ("GET /.well-known/jwks.json 200", 1),
    ];
    statuses.extend_from_slice(resource_statuses);
    assert_http(
        accounting,
        &[
            ("GET /authorize", 1),
            ("POST /token", 1),
            ("GET /.well-known/jwks.json", 1),
            ("GET /userinfo", resource_attempts),
        ],
        &statuses,
    );
}

#[tokio::test]
async fn userinfo_consumes_only_after_real_rs256_id_token_verification() {
    let mut issuer = OidcIssuer::new();
    let digest = sha256(&issuer.jwks);
    let proofs = issuer.proofs.clone();
    let (base, thread, client) = tls_fixture(4, move |step, request, base| {
        if let Some(reply) = issuer.setup_reply(step, request, base) {
            return reply;
        }
        assert_eq!(step, 3);
        record_userinfo_proof(&issuer.proofs, request, base, None);
        fixture_reply(200, br#"{"sub":"subject"}"#.to_vec())
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true))).unwrap();
    executor.client = client;
    assert!(executor.userinfo_flow().await.unwrap().0);
    thread.join().unwrap();
    assert_eq!(executor.jwks_sha256.as_deref(), Some(digest.as_str()));
    assert_eq!(
        executor
            .cached_userinfo_access_token
            .as_ref()
            .unwrap()
            .subject
            .as_deref(),
        Some("subject")
    );
    assert_eq!(proofs.lock().unwrap().len(), 2);
    let accounting = executor.take_accounting();
    assert_userinfo_http(&accounting, &[("GET /userinfo 200", 1)]);
    assert!(accounting.nonce_challenges.is_empty());
    assert!(accounting.nonce_retries.is_empty());
}

#[tokio::test]
async fn userinfo_rejects_subject_different_from_verified_id_token_without_echoing_it() {
    let mut issuer = OidcIssuer::new();
    let (base, thread, client) = tls_fixture(4, move |step, request, base| {
        if let Some(reply) = issuer.setup_reply(step, request, base) {
            return reply;
        }
        record_userinfo_proof(&issuer.proofs, request, base, None);
        fixture_reply(
            200,
            serde_json::to_vec(&serde_json::json!({"sub":SENSITIVE_MARKER})).unwrap(),
        )
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true))).unwrap();
    executor.client = client;
    let error = executor.userinfo_flow().await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "UserInfo subject differs from verified ID Token"
    );
    thread.join().unwrap();
    let accounting = executor.take_accounting();
    assert_userinfo_http(&accounting, &[("GET /userinfo 200", 1)]);
    assert!(accounting.nonce_challenges.is_empty());
    assert!(accounting.nonce_retries.is_empty());
    assert_report_redaction(&error, "userinfo", accounting).await;
}

#[tokio::test]
async fn userinfo_rs_nonce_retry_preserves_key_token_and_changes_jti() {
    let mut issuer = OidcIssuer::new();
    let proofs = issuer.proofs.clone();
    let (base, thread, client) = tls_fixture(5, move |step, request, base| {
        if let Some(reply) = issuer.setup_reply(step, request, base) {
            return reply;
        }
        match step {
            3 => {
                record_userinfo_proof(&issuer.proofs, request, base, None);
                resource_challenge()
            }
            4 => {
                record_userinfo_proof(&issuer.proofs, request, base, Some(RS_NONCE));
                fixture_reply(200, br#"{"sub":"subject"}"#.to_vec())
            }
            _ => panic!("unexpected fixture request"),
        }
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true))).unwrap();
    executor.client = client;
    assert!(executor.userinfo_flow().await.unwrap().0);
    thread.join().unwrap();
    let proofs = proofs.lock().unwrap();
    assert_eq!(proofs.len(), 3);
    assert_eq!(proofs[1].jwk, proofs[2].jwk);
    assert_eq!(proofs[1].claims["ath"], proofs[2].claims["ath"]);
    assert_ne!(proofs[1].claims["jti"], proofs[2].claims["jti"]);
    let accounting = executor.take_accounting();
    assert_userinfo_http(
        &accounting,
        &[("GET /userinfo 401", 1), ("GET /userinfo 200", 1)],
    );
    assert_eq!(accounting.nonce_challenges.len(), 1);
    assert_eq!(accounting.nonce_challenges["resource_server"], 1);
    assert_eq!(accounting.nonce_retries.len(), 1);
    assert_eq!(accounting.nonce_retries["resource_server"], 1);
}

#[tokio::test]
async fn userinfo_repeated_rs_nonce_challenge_is_fatal_and_accounted_once_per_response() {
    let mut issuer = OidcIssuer::new();
    let proofs = issuer.proofs.clone();
    let (base, thread, client) = tls_fixture(5, move |step, request, base| {
        if let Some(reply) = issuer.setup_reply(step, request, base) {
            return reply;
        }
        assert!(matches!(step, 3 | 4));
        record_userinfo_proof(
            &issuer.proofs,
            request,
            base,
            (step == 4).then_some(RS_NONCE),
        );
        resource_challenge()
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true))).unwrap();
    executor.client = client;
    let error = executor.userinfo_flow().await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "unexpected or repeated RS nonce challenge"
    );
    thread.join().unwrap();
    assert_eq!(proofs.lock().unwrap().len(), 3);
    let accounting = executor.take_accounting();
    assert_userinfo_http(&accounting, &[("GET /userinfo 401", 2)]);
    assert_eq!(accounting.nonce_challenges.len(), 1);
    assert_eq!(accounting.nonce_challenges["resource_server"], 2);
    assert_eq!(accounting.nonce_retries.len(), 1);
    assert_eq!(accounting.nonce_retries["resource_server"], 1);
    assert_report_redaction(&error, "userinfo", accounting).await;
}

#[tokio::test]
async fn userinfo_invalid_signed_id_token_prevents_resource_request_and_cache_publication() {
    let mut issuer = OidcIssuer::new();
    issuer.subject = SENSITIVE_MARKER;
    let proofs = issuer.proofs.clone();
    let (base, thread, client) = tls_fixture(3, move |step, request, base| {
        issuer.setup_reply(step, request, base).unwrap()
    });
    let mut executor =
        ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, true))).unwrap();
    executor.client = client;
    let error = executor.userinfo_flow().await.unwrap_err();
    assert_eq!(error.to_string(), "invalid ID Token or issuer JWKS");
    assert!(executor.cached_userinfo_access_token.is_none());
    thread.join().unwrap();
    assert_eq!(proofs.lock().unwrap().len(), 1);
    let accounting = executor.take_accounting();
    assert_http(
        &accounting,
        &[
            ("GET /authorize", 1),
            ("POST /token", 1),
            ("GET /.well-known/jwks.json", 1),
        ],
        &[
            ("GET /authorize 302", 1),
            ("POST /token 200", 1),
            ("GET /.well-known/jwks.json 200", 1),
        ],
    );
    assert!(accounting.nonce_challenges.is_empty());
    assert!(accounting.nonce_retries.is_empty());
    assert_report_redaction(&error, "userinfo", accounting).await;
}
