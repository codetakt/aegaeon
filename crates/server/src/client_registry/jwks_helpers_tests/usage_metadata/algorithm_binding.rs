use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(super) fn verify(registry: &ClientRegistry, token: &str, algorithm: Algorithm) -> bool {
    if matches!(algorithm, Algorithm::RS256 | Algorithm::PS256) {
        registry
            .try_validate_private_key_jwt(
                CLIENT,
                token,
                AUDIENCE,
                aegaeon_jose::algorithms::CryptoProfile::Compat,
            )
            .expect("registry state")
            .is_some()
    } else {
        registry
            .verify_request_object(
                CLIENT,
                token,
                AUDIENCE,
                aegaeon_jose::algorithms::CryptoProfile::Compat,
            )
            .is_ok()
    }
}

fn variants(key: &Value, algorithm: Algorithm) -> Vec<(Value, bool)> {
    let mut variants = vec![(key.clone(), true)];
    let mut absent_alg = key.clone();
    absent_alg.as_object_mut().unwrap().remove("alg");
    variants.push((absent_alg, true));
    for alg in [
        format!("{algorithm:?}").to_ascii_lowercase(),
        format!(" {algorithm:?}"),
        format!("{algorithm:?} "),
        "HS256".into(),
    ] {
        let mut value = key.clone();
        value["alg"] = json!(alg);
        variants.push((value, false));
    }
    if algorithm != Algorithm::RS256 {
        let curve = if algorithm == Algorithm::ES256 {
            "P-256"
        } else {
            "P-384"
        };
        let other = if algorithm == Algorithm::ES256 {
            "P-384"
        } else {
            "P-256"
        };
        for crv in [
            other.to_string(),
            curve.to_ascii_lowercase(),
            format!(" {curve}"),
            format!("{curve} "),
            String::new(),
            "P-521".into(),
        ] {
            let mut value = key.clone();
            value["crv"] = json!(crv);
            variants.push((value, false));
        }
        let mut absent = key.clone();
        absent.as_object_mut().unwrap().remove("crv");
        variants.push((absent, false));
    }
    variants
}

#[test]
fn jwk_binding_registry_signed_rsa_p256_p384_inline_fetch_and_cache() {
    let _env = env_lock().expect("environment lock");
    let _proxy = EnvVarGuard::new("NO_PROXY", Some("127.0.0.1,localhost,::1"));
    for algorithm in [Algorithm::RS256, Algorithm::ES256, Algorithm::ES384] {
        let (key, signer) = material(algorithm);
        let token = assertion(algorithm, &signer);
        for (variant, expected) in variants(&key, algorithm) {
            let set = json!({"keys":[variant]});
            let inline = registry();
            let mut registration = client(algorithm, None, None);
            match RegisteredClientJwks::from_value(set.clone(), true) {
                Ok(keys) => {
                    registration.inline_jwks = Some(keys);
                    assert!(inline.register(registration));
                    assert_eq!(verify(&inline, &token, algorithm), expected, "inline {set}");
                }
                Err(_) => assert!(!expected, "inline admission {set}"),
            }
            let (uri, server) = super::super::owned_result_tests::response_fixture(
                200,
                serde_json::to_vec(&set).unwrap(),
                "max-age=300",
            );
            let fetched = registry();
            assert!(fetched.register(client(algorithm, None, Some(uri.clone()))));
            assert_eq!(verify(&fetched, &token, algorithm), expected, "fetch {set}");
            server.join().expect("one bounded HTTP fetch");
            let cached = fetched
                .jwks_state
                .inner
                .cache
                .lock()
                .unwrap()
                .get(&uri)
                .map(|entry| entry.jwks.to_fixture_bytes().unwrap());
            if let Some(bytes) = cached {
                if algorithm != Algorithm::RS256 {
                    assert_eq!(
                        verify(&fetched, &token, algorithm),
                        expected,
                        "live cache {set}"
                    );
                }
                let reloaded = registry();
                reloaded.jwks_state.inner.cache.lock().unwrap().insert(
                    uri.clone(),
                    cache_test_entry(
                        FetchedJwks::from_fixture_bytes(&bytes).unwrap(),
                        Instant::now(),
                    ),
                );
                assert!(reloaded.register(client(algorithm, None, Some(uri))));
                assert_eq!(
                    verify(&reloaded, &token, algorithm),
                    expected,
                    "cache {set}"
                );
            } else {
                assert!(!expected, "valid names must produce a cached body");
                assert!(!expected, "ineligible material cannot enter the cache");
            }
        }
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut sig = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
        sig[0] ^= 1;
        parts[2] = URL_SAFE_NO_PAD.encode(sig);
        let exact = registry();
        assert!(exact.register(client(algorithm, Some(json!({"keys":[key]})), None)));
        assert!(!verify(&exact, &parts.join("."), algorithm));
    }
}
