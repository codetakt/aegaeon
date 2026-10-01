use super::*;
use crate::test_utils::jwk_usage::{cases, keyset, material, sign};
use jsonwebtoken::Algorithm;
use serde_json::{json, Value};
use std::time::Instant;

const CLIENT: &str = "usage-client";
const AUDIENCE: &str = "https://issuer.example/token";

fn registry() -> ClientRegistry {
    let policy = ClientAssertionRuntimePolicy::try_new(
        ["RS256".to_string(), "PS256".to_string()],
        false,
        60,
        aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        300,
        300,
    )
    .expect("assertion policy");
    ClientRegistry::new_process_local_with_runtime_policy_for_tests(
        policy,
        JwksRuntimePolicy {
            allow_http_loopback_for_tests: true,
            http_retries: 0,
            http_timeout_secs: 3,
            ..JwksRuntimePolicy::default()
        },
    )
}

fn client(algorithm: Algorithm, inline: Option<Value>, uri: Option<String>) -> RegisteredClient {
    RegisteredClient {
        client_id: CLIENT.into(),
        client_secret: None,
        redirect_uris: vec!["https://client.example/cb".into()],
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: if matches!(algorithm, Algorithm::RS256 | Algorithm::PS256) {
            "private_key_jwt"
        } else {
            "none"
        }
        .into(),
        jwks_pem: None,
        inline_jwks: inline.map(|value| {
            RegisteredClientJwks::from_value(value, true)
                .expect("set retains an eligible second key")
        }),
        jwks_uri: uri,
        token_endpoint_auth_signing_alg: (matches!(algorithm, Algorithm::RS256 | Algorithm::PS256))
            .then(|| format!("{algorithm:?}")),
        allowed_scopes: vec!["openid".into()],
        allowed_grant_types: vec!["authorization_code".into(), "client_credentials".into()],
        registration_access_token: None,
        client_id_issued_at: None,
    }
}

fn assertion(algorithm: Algorithm, key: &jsonwebtoken::EncodingKey) -> String {
    let now = unix_epoch_now_i64("usage test clock").expect("clock");
    let claims = if matches!(algorithm, Algorithm::RS256 | Algorithm::PS256) {
        json!({"iss":CLIENT,"sub":CLIENT,"aud":AUDIENCE,
            "iat":now,"exp":now+120,"jti":"usage-assertion"})
    } else {
        json!({"iss":CLIENT,"aud":[AUDIENCE],"iat":now,"nbf":now-1,"exp":now+120,
            "client_id":CLIENT,"response_type":"code","scope":"openid",
            "redirect_uri":"https://client.example/cb","state":"usage-state",
            "nonce":"usage-nonce","code_challenge":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            "code_challenge_method":"S256","jti":"usage-request-object"})
    };
    sign(algorithm, key, &claims)
}

// Client assertions support RS256/PS256. ES256 is exercised through the
// supported public Request Object API with a valid ordinary assertion policy.
fn accepted(registry: &ClientRegistry, token: &str, algorithm: Algorithm) -> bool {
    if algorithm == Algorithm::ES256 {
        return match registry.verify_request_object(
            CLIENT,
            token,
            AUDIENCE,
            aegaeon_jose::algorithms::CryptoProfile::Compat,
        ) {
            Ok(verified) => {
                assert_eq!(verified.claims.client_id.as_deref(), Some(CLIENT));
                true
            }
            Err(RequestObjectValidationError::VerificationKeyMissing(_)) => false,
            Err(error) => panic!("Request Object failed outside key selection: {error:?}"),
        };
    }
    registry
        .try_validate_private_key_jwt(
            CLIENT,
            token,
            AUDIENCE,
            aegaeon_jose::algorithms::CryptoProfile::Compat,
        )
        .expect("verification must not fail internally")
        .is_some()
}

#[test]
fn jwk_usage_inline_rsa_assertions_and_ec_request_objects_require_verification_metadata() {
    for algorithm in [Algorithm::RS256, Algorithm::ES256] {
        let (key, signer) = material(algorithm);
        let token = assertion(algorithm, &signer);
        for (metadata, expected) in cases() {
            let registry = registry();
            assert!(registry.register(client(algorithm, Some(keyset(&key, &metadata)), None)));
            assert_eq!(
                accepted(&registry, &token, algorithm),
                expected,
                "{algorithm:?}: {metadata}"
            );
        }
    }
}

#[test]
fn jwk_usage_remote_rsa_assertions_and_ec_request_objects_recheck_serialized_cache() {
    let _env = env_lock().expect("environment lock");
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    for algorithm in [Algorithm::RS256, Algorithm::ES256] {
        let (key, signer) = material(algorithm);
        let token = assertion(algorithm, &signer);
        for (metadata, expected) in cases() {
            let (uri, server) = super::owned_result_tests::response_fixture(
                200,
                serde_json::to_vec(&keyset(&key, &metadata)).expect("JWKS bytes"),
                "max-age=300",
            );
            let fetched = registry();
            assert!(fetched.register(client(algorithm, None, Some(uri.clone()))));
            assert_eq!(
                accepted(&fetched, &token, algorithm),
                expected,
                "fetched {algorithm:?}: {metadata}"
            );
            server.join().expect("bounded local request");
            let bytes = {
                let cache = fetched.jwks_state.inner.cache.lock().expect("cache lock");
                cache
                    .get(&uri)
                    .expect("admitted cache entry")
                    .jwks
                    .to_fixture_bytes()
                    .expect("serialized cached set")
            };
            let reloaded = registry();
            let jwks: FetchedJwks =
                FetchedJwks::from_fixture_bytes(&bytes).expect("cache fixture reload");
            reloaded
                .jwks_state
                .inner
                .cache
                .lock()
                .expect("reload cache lock")
                .insert(uri.clone(), cache_test_entry(jwks, Instant::now()));
            assert!(reloaded.register(client(algorithm, None, Some(uri))));
            // The server is closed and the replay store is fresh: this verifies
            // the same signed bytes with the serialized/reloaded cache entry.
            assert_eq!(
                accepted(&reloaded, &token, algorithm),
                expected,
                "reloaded {algorithm:?}: {metadata}"
            );
        }
    }
}

#[test]
fn jwk_usage_fetched_metadata_preserves_absence_and_rejects_null_before_projection() {
    let (key, _) = material(Algorithm::RS256);
    let absent = keyset(&key, &json!({}));
    let parsed: FetchedJwks = serde_json::from_value(absent).expect("absent usage");
    let serialized = serde_json::to_value(&parsed).expect("cached representation");
    for key in serialized["keys"].as_array().expect("key array") {
        assert!(key.get("use").is_none());
        assert!(key.get("key_ops").is_none());
    }
    let reloaded: FetchedJwks = serde_json::from_value(serialized).expect("old valid cache");
    assert!(select_jwk(&reloaded, Some(crate::test_utils::jwk_usage::KID)).is_some());
    for metadata in [
        json!({"use":null}),
        json!({"use":1}),
        json!({"use":[]}),
        json!({"key_ops":null}),
        json!({"key_ops":"verify"}),
        json!({"key_ops":[1]}),
    ] {
        let bytes = serde_json::to_vec(&keyset(&key, &metadata)).expect("invalid set bytes");
        let admitted =
            crate::util::deserialize_json_without_duplicate_object_keys::<FetchedJwks>(&bytes)
                .expect("valid sibling survives");
        assert!(select_jwk(&admitted, Some(crate::test_utils::jwk_usage::KID)).is_none());
        assert!(select_jwk(&admitted, Some("other-key")).is_some());
    }
    for raw in [
        r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","use":"sig","\u0075se":"sig"}]}"#,
        r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","key_ops":["verify"],"key_ops":["verify"]}]}"#,
    ] {
        assert!(
            crate::util::deserialize_json_without_duplicate_object_keys::<FetchedJwks>(
                raw.as_bytes()
            )
            .is_err()
        );
    }
    let mut escaped_key = key.clone();
    escaped_key["use"] = json!("sig");
    escaped_key["key_ops"] = json!(["verify"]);
    let escaped = json!({"keys":[escaped_key]})
        .to_string()
        .replace("\"use\"", "\"\\u0075se\"")
        .replace("verify", "ver\\u0069fy");
    let parsed: FetchedJwks =
        crate::util::deserialize_json_without_duplicate_object_keys(escaped.as_bytes())
            .expect("escaped exact metadata");
    assert!(select_jwk(&parsed, None).is_some());
}

#[test]
fn jwk_usage_direct_fetched_mutations_cannot_grant_verification() {
    let (key, _) = material(Algorithm::RS256);
    let mut set: FetchedJwks = serde_json::from_value(json!({"keys":[key]})).expect("fixture");
    for operations in [
        vec!["verify", "verify"],
        vec!["verify", "encrypt"],
        vec!["sign"],
        vec![],
    ] {
        set.keys[0].key_ops = Some(operations.into_iter().map(String::from).collect());
        assert!(select_jwk(&set, None).is_none());
    }
    set.keys[0].key_ops = None;
    set.keys[0].key_use = Some("SIG".into());
    assert!(select_jwk(&set, None).is_none());
}

#[test]
fn jwk_usage_remote_fetch_ignores_malformed_usage_beside_an_eligible_key() {
    let _env = env_lock().expect("environment lock");
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    let (key, _) = material(Algorithm::RS256);
    for metadata in [
        json!({"use":null}),
        json!({"use":1}),
        json!({"key_ops":null}),
        json!({"key_ops":"verify"}),
        json!({"key_ops":["verify",null]}),
        json!({"key_ops":["verify","verify"]}),
        json!({"use":"sig","key_ops":["encrypt"]}),
        json!({"use":"enc","key_ops":["verify"]}),
    ] {
        let (uri, server) = super::owned_result_tests::response_fixture(
            200,
            serde_json::to_vec(&keyset(&key, &metadata)).expect("JWKS bytes"),
            "max-age=300",
        );
        let registry = registry();
        let admitted = fetch_jwks_with_state(&registry.jwks_state, &registry.jwks_policy, &uri)
            .expect("valid sibling survives");
        assert!(select_jwk(&admitted, Some(crate::test_utils::jwk_usage::KID)).is_none());
        assert!(select_jwk(&admitted, Some("other-key")).is_some());
        server.join().expect("bounded local request");
        assert!(registry
            .jwks_state
            .inner
            .cache
            .lock()
            .expect("cache lock")
            .contains_key(&uri));
    }
}

mod algorithm_binding;

mod mixed_sets;
