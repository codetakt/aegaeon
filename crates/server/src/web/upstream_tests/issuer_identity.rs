use super::*;
use crate::web::upstream_callback_state::{
    validate_upstream_callback_issuer, UpstreamCallbackQuery,
};
use crate::web::upstream_metadata::fetch_upstream_discovery_cached;

#[test]
fn upstream_issuer_validation_preserves_identity_and_rejects_forgiving_inputs() {
    for issuer in [
        "https://issuer.example",
        "https://issuer.example/",
        "https://ISSUER.example:443",
        "https://issuer.example/path/",
        "https://issuer.example/%61",
        "https://issuer.example/%6A",
    ] {
        assert_eq!(validate_upstream_issuer(issuer).as_deref(), Some(issuer));
    }
    for issuer in [
        " https://issuer.example",
        "https://issuer.example\n",
        "https://issuer.\texample",
        "https://issuer.example/ a",
        "https://issuer.example\\path",
        "https:issuer.example",
        "https:///issuer.example",
        "http://issuer.example",
        "https://@issuer.example",
        "https://user@issuer.example",
        "https://issuer.example?",
        "https://issuer.example#",
    ] {
        assert!(validate_upstream_issuer(issuer).is_none(), "{issuer:?}");
    }
}

#[test]
fn upstream_issuer_discovery_and_federation_compare_exact_bytes() -> TestResult {
    for (issuer, variants) in [
        (
            "https://issuer.example",
            vec![
                "https://issuer.example/",
                "https://ISSUER.example",
                "https://issuer.example:443",
                " https://issuer.example",
            ],
        ),
        (
            "https://issuer.example/path",
            vec![
                "https://issuer.example/path/",
                "https://issuer.example/%70ath",
            ],
        ),
        (
            "https://issuer.example/%6a",
            vec!["https://issuer.example/%6A"],
        ),
    ] {
        let discovery = base_discovery(issuer)?;
        for variant in variants {
            let mut changed = discovery.clone();
            changed.issuer = variant.to_string();
            assert!(
                validate_upstream_discovery(&changed, issuer, &base_profile(), "none", &[])
                    .is_err()
            );
            let metadata = json!({"issuer": variant, "authorization_endpoint": discovery.authorization_endpoint,
                "token_endpoint": discovery.token_endpoint, "jwks_uri": discovery.jwks_uri});
            assert!(validate_upstream_discovery_matches_federation_metadata(
                &discovery, issuer, &metadata
            )
            .is_err());
        }
    }
    Ok(())
}

#[test]
fn upstream_issuer_callback_checks_optional_and_required_success_and_error() -> TestResult {
    let mut request = make_auth_request("state", std::time::Duration::from_secs(60));
    for required in [false, true] {
        request.require_iss_parameter = required;
        for error in [false, true] {
            for issuer in [
                None,
                Some(TEST_ISSUER),
                Some("https://issuer.example/"),
                Some("https://ISSUER.example"),
                Some("https://issuer.example:443"),
                Some(" https://issuer.example"),
            ] {
                let params: UpstreamCallbackQuery = serde_json::from_value(json!({
                    "iss": issuer, "code": if error { None } else { Some("code") },
                    "error": if error { Some("access_denied") } else { None },
                }))
                .map_err(|e| e.to_string())?;
                assert_eq!(
                    validate_upstream_callback_issuer(&params, &request, TEST_ISSUER).is_ok(),
                    issuer == Some(TEST_ISSUER) || (issuer.is_none() && !required)
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn upstream_issuer_cache_keys_are_exact_and_mismatched_entries_reject() -> TestResult {
    let cache = crate::upstream::NonAuthoritativeMetadataCache::with_ttl_secs(60);
    let client = reqwest::Client::new();
    let slash = "https://issuer.example/";
    cache.try_insert(TEST_ISSUER, base_discovery(TEST_ISSUER)?)?;
    cache.try_insert(slash, base_discovery(slash)?)?;
    for issuer in [TEST_ISSUER, slash] {
        assert_eq!(
            fetch_upstream_discovery_cached(&client, issuer, &cache, &[])
                .await?
                .issuer,
            issuer
        );
    }
    cache.try_insert(TEST_ISSUER, base_discovery(slash)?)?;
    assert!(
        fetch_upstream_discovery_cached(&client, TEST_ISSUER, &cache, &[])
            .await
            .is_err()
    );
    Ok(())
}

pub(in crate::web) fn check_upstream_issuer_signed_token(
    request: &crate::upstream::UpstreamAuthRequest,
    discovery: &OidcDiscovery,
) -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let key = upstream_signing_key()?;
    let jwks = upstream_jwks(&key)?;
    for issuer in [
        request.issuer.clone(),
        if request.issuer.ends_with('/') {
            request.issuer.trim_end_matches('/').to_string()
        } else {
            format!("{}/", request.issuer)
        },
        request.issuer.replace("%6a", "%6A"),
        request.issuer.replace("%6a", "j"),
        request.issuer.replace("issuer.example", "ISSUER.example"),
        request
            .issuer
            .replace("issuer.example", "issuer.example:443"),
    ] {
        let mut claims_request = request.clone();
        claims_request.issuer = issuer.clone();
        let token = sign_upstream_id_token(&key, &claims_request, "access", "code")?;
        // No parser-unavailable skip: this fixture requires real RS256 verification.
        let result =
            decode_upstream_id_token(crate::web::upstream_id_token::UpstreamIdTokenDecodeInput {
                token: &token,
                jwks: &jwks,
                discovery,
                request,
                access_token: Some("access"),
                code: "code",
                jwt_leeway_secs: 60,
                jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
            });
        assert_eq!(
            result.is_ok(),
            issuer == request.issuer,
            "issuer={issuer}; result={:?}",
            result.err().map(|e| e.message)
        );
    }
    Ok(())
}

#[test]
fn upstream_issuer_signed_token_checks_path_percent_spelling() -> TestResult {
    let mut request = make_auth_request("percent-state", std::time::Duration::from_secs(60));
    request.issuer = "https://issuer.example/%6a".to_string();
    check_upstream_issuer_signed_token(&request, &base_discovery(&request.issuer)?)
}
