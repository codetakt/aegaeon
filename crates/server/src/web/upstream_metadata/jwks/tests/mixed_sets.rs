use super::*;
use crate::test_utils::jwk_usage::{material, sign, unusable_siblings};
use crate::web::upstream_id_token::verify_upstream_id_token_claims;
use jsonwebtoken::Algorithm;

#[tokio::test]
async fn jwk_mixed_upstream_signed_members_cache_and_known_rejected_kid() -> TestResult {
    for algorithm in [
        Algorithm::RS256,
        Algorithm::PS256,
        Algorithm::ES256,
        Algorithm::ES384,
    ] {
        let (key, signer) = material(algorithm);
        let token = sign(
            algorithm,
            &signer,
            &json!({"iss":"https://issuer.example","sub":"subject","aud":"client","iat":1,"exp":2}),
        );
        let mut discovery = crate::web::upstream_tests::base_discovery("https://issuer.example")?;
        discovery.id_token_signing_alg_values_supported = vec![format!("{algorithm:?}")];
        let admitted = admit_upstream_id_token_header(&token, &discovery, 4096).unwrap();
        for bad in unusable_siblings(&key) {
            for keys in [
                vec![key.clone(), bad.clone()],
                vec![bad.clone(), key.clone()],
            ] {
                let server = HttpFixture::new(json!({"keys":keys}).to_string()).await?;
                let clock = ManualClock::new();
                let h = Harness::new(&clock, 1, 60);
                for _ in 0..2 {
                    let set = fetch_upstream_jwks_cached(
                        &h.client,
                        &server.url,
                        &h.cache,
                        &h.coordinator,
                        &admitted,
                        &[],
                    )
                    .await?;
                    assert_eq!(set.keys().len(), 1);
                    assert!(
                        verify_upstream_id_token_claims(&token, &set, &discovery, 4096).is_ok()
                    );
                    assert!(select_upstream_signing_key(&set, Some("ignored")).is_err());
                }
                assert_eq!(server.hits(), 1);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn jwk_mixed_upstream_observed_rejected_kids_suppress_refresh_without_selection() -> TestResult
{
    let mut value: serde_json::Value = serde_json::from_str(&keyset("good"))?;
    value["keys"]
        .as_array_mut()
        .unwrap()
        .extend([json!({"kty":"OKP","kid":"known"}), json!({"kid":""})]);
    let server = HttpFixture::new(value.to_string()).await?;
    let clock = ManualClock::new();
    let h = Harness::new(&clock, 1, 60);
    h.get(&server.url, Some("good")).await?;
    for kid in ["known", ""] {
        let set = h.get(&server.url, Some(kid)).await?;
        assert!(select_upstream_signing_key(&set, Some(kid)).is_err());
    }
    assert_eq!(server.hits(), 1);
    let old = h.cache.try_get(&server.url)?.unwrap();
    server.respond(
        StatusCode::OK,
        json!({"keys":[{"kty":"OKP","kid":"unknown"}]}).to_string(),
    );
    clock.advance(30_000);
    assert!(h.get(&server.url, Some("unknown")).await.is_err());
    assert_eq!(h.cache.try_get(&server.url)?, Some(old));
    assert_eq!(server.hits(), 2);
    Ok(())
}

#[test]
fn jwk_mixed_upstream_raw_duplicate_names_in_rejected_extensions_and_trailing_refuse() {
    let good = keyset("good");
    let valid: serde_json::Value = serde_json::from_str(&good).unwrap();
    let key = &valid["keys"][0];
    for rejected in [
        r#"{"kty":"OKP","extension":{"nested":1,"nested":2}}"#,
        r#"{"kty":"oct","kid":"x","kid":"y"}"#,
    ] {
        let raw = format!("{{\"keys\":[{key},{rejected}]}}");
        assert!(parse_upstream_jwks_body(raw.as_bytes()).is_err());
    }
    assert!(parse_upstream_jwks_body(format!("{good} trailing").as_bytes()).is_err());
}
