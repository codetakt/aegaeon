use super::*;
use crate::test_utils::jwk_usage::{cases, keyset, material, sign, KID};
use crate::web::upstream_id_token::{
    verify_upstream_id_token_claims, UpstreamIdTokenSignatureError,
};
use jsonwebtoken::Algorithm;

#[tokio::test]
async fn jwk_usage_upstream_rsa_and_ec_signed_tokens_recheck_fetched_and_cached_metadata(
) -> TestResult {
    for algorithm in [Algorithm::RS256, Algorithm::ES256] {
        let (key, signer) = material(algorithm);
        let token = sign(
            algorithm,
            &signer,
            &json!({"iss":"https://issuer.example",
            "sub":"subject","aud":"client","iat":1,"exp":2}),
        );
        let mut discovery = crate::web::upstream_tests::base_discovery("https://issuer.example")?;
        discovery.id_token_signing_alg_values_supported = vec![format!("{algorithm:?}")];
        let admitted = admit_upstream_id_token_header(&token, &discovery, 4096)
            .map_err(|error| format!("header admission: {error:?}"))?;
        for (metadata, expected) in cases() {
            let server = HttpFixture::new(keyset(&key, &metadata).to_string()).await?;
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
                let result = verify_upstream_id_token_claims(&token, &set, &discovery, 4096);
                if expected {
                    let (claims, _) =
                        result.map_err(|error| format!("{algorithm:?}: {metadata}: {error:?}"))?;
                    assert_eq!(claims.sub, "subject");
                } else {
                    assert!(
                        matches!(result, Err(UpstreamIdTokenSignatureError::KeySelection(_))),
                        "{algorithm:?}: {metadata}: {result:?}"
                    );
                }
            }
            assert_eq!(
                server.hits(),
                1,
                "second acquisition must use the cached set"
            );
            assert!(!admitted.unfamiliar_kid(&h.cache.try_get(&server.url)?.ok_or("cached set")?));
        }
        let allowed = JwkSet::from_value(keyset(&key, &json!({"key_ops":["verify"]})))?;
        // Real signature verification remains active when metadata permits it.
        let mut pieces: Vec<String> = token.split('.').map(String::from).collect();
        let mut signature = URL_SAFE_NO_PAD.decode(&pieces[2])?;
        signature[0] ^= 1;
        pieces[2] = URL_SAFE_NO_PAD.encode(signature);
        assert!(matches!(
            verify_upstream_id_token_claims(&pieces.join("."), &allowed, &discovery, 4096),
            Err(UpstreamIdTokenSignatureError::SignatureInvalid)
        ));
        assert!(select_upstream_signing_key(&allowed, Some(KID)).is_ok());
    }
    Ok(())
}
