use super::*;
use crate::middleware::replay_store::PostgresReplayStore;
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; native signed assertions and durable replay admission"]
async fn pg_replay_native_client_assertions() -> TestResult {
    let database = crate::dcr_persistence::test_database::Database::create(false)
        .await
        .map_err(|e| e.to_string())?;
    let result = async {
        let namespace = format!("assertions-{}", Uuid::new_v4());
        let registry = ClientRegistry::with_replay_store_and_policy(
            Arc::new(PostgresReplayStore::new(database.pool.clone(), namespace)),
            ClientAssertionRuntimePolicy::default(), JwksRuntimePolicy::default()
        );
        let client_id = "durable-assertion-client";
        let audience = "https://issuer.example/token";
        let client = promoted_rsa_test_client(client_id, "RS256", "private_key_jwt")?;
        assert!(registry.register(client));
        let now = current_test_epoch()?;
        for (subject, private_key) in [(client_id, true), ("resource-owner", false)] {
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("promoted-rsa-test-key".into());
            let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
                .map_err(|error| error.to_string())?;
            let assertion = jsonwebtoken::encode(&header, &serde_json::json!({
                "iss":client_id,"sub":subject,"aud":audience,"exp":now+300,"iat":now,"jti":"same-jti-different-kind"
            }), &encoding_key).map_err(|error| error.to_string())?;
            let prepare = || {
                if private_key {
                    registry.prepare_private_key_jwt(client_id, &assertion, audience, aegaeon_jose::algorithms::CryptoProfile::Verified)
                } else {
                    registry.prepare_jwt_bearer_grant_assertion(client_id, &assertion, audience, "https://issuer.example", false, aegaeon_jose::algorithms::CryptoProfile::Verified)
                }
            };
            let first = prepare().map_err(|e| format!("{e:?}"))?.ok_or("valid assertion refused")?;
            let second = prepare().map_err(|e| format!("{e:?}"))?.ok_or("valid assertion refused")?;
            let (first, second) = tokio::join!(first.finish_async(), second.finish_async());
            let first = first.map_err(|e| format!("{e:?}"))?;
            let second = second.map_err(|e| format!("{e:?}"))?;
            assert_eq!(usize::from(first.is_some()) + usize::from(second.is_some()), 1);
            assert_eq!(first.or(second).as_deref(), Some(subject));
        }
        Ok(())
    }.await;
    database.cleanup().await.map_err(|e| e.to_string())?;
    result
}
