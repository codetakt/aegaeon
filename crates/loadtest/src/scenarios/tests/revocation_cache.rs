//! A remotely effective revocation cannot leave a locally reusable token.
use super::protocol_fixture::{assert_report_redaction, header, SENSITIVE_MARKER};
use super::{
    authorization_fixture_reply, fixture_profile, fixture_reply, fixture_token, tls_fixture,
    FixtureDelivery, ScenarioExecutor,
};
use crate::accounting::HttpAccounting;
use std::collections::BTreeMap;

const ORIGINAL_TOKEN: &str = "original-response-private-value-195";
const REPLACEMENT_TOKEN: &str = "replacement-token";

fn assert_revocation_http(
    accounting: &HttpAccounting,
    delivery: FixtureDelivery,
    replacement_issued: bool,
) {
    let exchanges: u64 = if replacement_issued { 2 } else { 1 };
    let lost_reply = u64::from(matches!(delivery, FixtureDelivery::Disconnect));
    let unreadable_body = u64::from(matches!(delivery, FixtureDelivery::Truncated));
    accounting.validate().unwrap();
    assert_eq!(accounting.attempts, 2 * exchanges + 1);
    assert_eq!(accounting.responses, accounting.attempts - lost_reply);
    assert_eq!(accounting.transport_failures, lost_reply);
    assert_eq!(accounting.body_failures, unreadable_body);
    assert_eq!(
        accounting.methods_endpoints,
        BTreeMap::from([
            ("GET /authorize".into(), exchanges),
            ("POST /token".into(), exchanges),
            ("POST /revoke".into(), 1),
        ])
    );
    let mut statuses = BTreeMap::from([
        ("GET /authorize 302".into(), exchanges),
        ("POST /token 200".into(), exchanges),
    ]);
    if lost_reply == 0 {
        statuses.insert("POST /revoke 200".into(), 1);
    }
    assert_eq!(accounting.statuses, statuses);
    assert!(accounting.nonce_challenges.is_empty());
    assert!(accounting.nonce_retries.is_empty());
}

#[tokio::test]
async fn revocation_ambiguous_reply_discards_cached_token_and_issues_replacement() {
    for delivery in [
        FixtureDelivery::Disconnect,
        FixtureDelivery::Truncated,
        FixtureDelivery::Complete,
    ] {
        let (base, thread, client) = tls_fixture(5, move |step, request, base| match step {
            0 | 3 => authorization_fixture_reply(request, base).0,
            1 | 4 => {
                assert!(request.starts_with("POST /token "));
                let mut token = fixture_token(false, 300);
                token["access_token"] = if step == 1 {
                    ORIGINAL_TOKEN.into()
                } else {
                    REPLACEMENT_TOKEN.into()
                };
                fixture_reply(200, serde_json::to_vec(&token).unwrap())
            }
            2 => {
                assert!(request.starts_with("POST /revoke "));
                assert!(header(request, "Authorization")
                    .unwrap()
                    .starts_with("Basic "));
                assert!(header(request, "Cookie").is_none());
                let (_, body) = request.split_once("\r\n\r\n").unwrap();
                let form: BTreeMap<_, _> = form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect();
                assert_eq!(form.len(), 2);
                assert_eq!(form["token"], ORIGINAL_TOKEN);
                assert_eq!(form["token_type_hint"], "access_token");
                let mut reply = fixture_reply(200, SENSITIVE_MARKER.as_bytes().to_vec());
                reply.delivery = delivery;
                reply
            }
            _ => panic!("unexpected fixture request"),
        });
        let mut executor =
            ScenarioExecutor::with_profile(base.clone(), Some(fixture_profile(&base, false)))
                .unwrap();
        executor.client = client;
        let original = executor.ensure_token(false).await.unwrap();
        assert_eq!(original.access_token, ORIGINAL_TOKEN);
        assert_eq!(
            executor.cached_access_token.as_ref().unwrap().access_token,
            ORIGINAL_TOKEN
        );
        let error = executor.revocation_flow().await.unwrap_err();
        let expected_error = match delivery {
            FixtureDelivery::Disconnect => "HTTP transport failed for POST /revoke",
            FixtureDelivery::Truncated => "HTTP response body failed for POST /revoke",
            FixtureDelivery::Complete => "revocation must return empty HTTP 200",
        };
        assert_eq!(error.to_string(), expected_error);
        assert!(executor.cached_access_token.is_none(), "{delivery:?}");
        let failed_accounting = executor.accounting.clone();
        assert_revocation_http(&failed_accounting, delivery, false);
        assert_report_redaction(&error, "revocation", failed_accounting).await;
        let replacement = executor.ensure_token(false).await.unwrap();
        assert_eq!(replacement.access_token, REPLACEMENT_TOKEN);
        assert_ne!(replacement.access_token, original.access_token);
        assert_eq!(
            executor.cached_access_token.as_ref().unwrap().access_token,
            REPLACEMENT_TOKEN
        );
        thread.join().unwrap();
        assert_revocation_http(&executor.take_accounting(), delivery, true);
    }
}
