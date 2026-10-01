use super::*;
use crate::test_utils::jwk_usage::{material, sign};
use crate::web::upstream_id_token::{
    verify_upstream_id_token_claims, UpstreamIdTokenSignatureError,
};
use jsonwebtoken::Algorithm;

#[tokio::test]
async fn jwk_binding_upstream_signed_rsa_p256_p384_fetch_cache_and_discovery() -> TestResult {
    for algorithm in [Algorithm::RS256, Algorithm::ES256, Algorithm::ES384] {
        let (key, signer) = material(algorithm);
        let token = sign(
            algorithm,
            &signer,
            &json!({"iss":"https://issuer.example",
            "sub":"subject","aud":"client","iat":1,"exp":2}),
        );
        let name = format!("{algorithm:?}");
        let mut discovery = crate::web::upstream_tests::base_discovery("https://issuer.example")?;
        discovery.id_token_signing_alg_values_supported = vec![name.clone()];
        let admitted = admit_upstream_id_token_header(&token, &discovery, 4096)
            .map_err(|e| format!("exact header {e:?}"))?;
        let mut variants = vec![(key.clone(), true)];
        let mut absent = key.clone();
        absent.as_object_mut().ok_or("key")?.remove("alg");
        variants.push((absent, true));
        for declared in [
            name.to_ascii_lowercase(),
            format!(" {name}"),
            format!("{name} "),
            "HS256".into(),
            String::new(),
        ] {
            let mut value = key.clone();
            value["alg"] = json!(declared);
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
            for declared in [
                curve.to_ascii_lowercase(),
                format!(" {curve}"),
                format!("{curve} "),
                other.into(),
                "P-521".into(),
                String::new(),
            ] {
                let mut value = key.clone();
                value["crv"] = json!(declared);
                variants.push((value, false));
            }
            let mut absent = key.clone();
            absent.as_object_mut().ok_or("key")?.remove("crv");
            let bytes = serde_json::to_vec(&json!({"keys":[absent]}))?;
            assert!(parse_upstream_jwks_body(&bytes).is_err());
        }
        for (variant, expected) in variants {
            let server = HttpFixture::new(json!({"keys":[variant]}).to_string()).await?;
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
                .await;
                if !expected {
                    assert!(set.is_err(), "all-ineligible set must fail retrieval");
                    assert!(h.cache.try_get(&server.url)?.is_none());
                    break;
                }
                let set = set?;
                let result = verify_upstream_id_token_claims(&token, &set, &discovery, 4096);
                if expected {
                    let (claims, _) = result.map_err(|e| format!("exact {algorithm:?}: {e:?}"))?;
                    assert_eq!(claims.sub, "subject");
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(UpstreamIdTokenSignatureError::JwkAlgMismatch
                                | UpstreamIdTokenSignatureError::CurveMismatch)
                        ),
                        "{variant}: {result:?}"
                    );
                }
            }
            assert_eq!(server.hits(), 1, "second verification uses cache");
        }
        let exact = JwkSet::from_value(json!({"keys":[key]}))?;
        for advertised in [
            name.to_ascii_lowercase(),
            format!(" {name}"),
            format!("{name} "),
            "HS256".into(),
            String::new(),
        ] {
            discovery.id_token_signing_alg_values_supported = vec![advertised];
            assert!(matches!(
                verify_upstream_id_token_claims(&token, &exact, &discovery, 4096),
                Err(UpstreamIdTokenSignatureError::AlgNotSupported)
            ));
        }
        discovery.id_token_signing_alg_values_supported = vec![name.to_ascii_lowercase(), name];
        assert!(verify_upstream_id_token_claims(&token, &exact, &discovery, 4096).is_ok());
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut sig = URL_SAFE_NO_PAD.decode(&parts[2])?;
        sig[0] ^= 1;
        parts[2] = URL_SAFE_NO_PAD.encode(sig);
        assert!(matches!(
            verify_upstream_id_token_claims(&parts.join("."), &exact, &discovery, 4096),
            Err(UpstreamIdTokenSignatureError::SignatureInvalid)
        ));
    }
    Ok(())
}
