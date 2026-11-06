use super::*;
use crate::client_registry::{ClientAssertionRuntimePolicy, ClientRegistry, RegisteredClient};
use crate::test_utils::jwk_usage::{material, sign};
use aegaeon_jose::algorithms::CryptoProfile;

#[tokio::test]
#[ignore = "requires PostgreSQL; remote keys in private assertion, JWT grant and Request Object consumers"]
async fn pg_jwks_native_signed_consumers() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result=async {
        sqlx::raw_sql(crate::organization_schema::component!("runtime_replay")).execute(&f.pool).await?;
        let (key,encoding)=material(jsonwebtoken::Algorithm::RS256);
        let server=Server::new(vec![ok(serde_json::json!({"keys":[key]}).to_string(),"max-age=60")],false).await?;
        let policy=JwksRuntimePolicy {allow_http_loopback_for_tests:true,http_retries:0,..Default::default()};
        let registry=ClientRegistry::from_postgres_with_runtime_policy(f.pool.clone(),ClientAssertionRuntimePolicy::default(),policy,&crate::config::RuntimeStateNamespace::from_environment_id(uuid::Uuid::new_v4()))?;
        anyhow::ensure!(registry.register(RegisteredClient {
            client_id:"remote-client".into(),client_secret:None,redirect_uris:vec!["https://client.example/cb".into()],post_logout_redirect_uris:vec![],backchannel_logout_uri:None,backchannel_logout_session_required:false,token_endpoint_auth_method:"private_key_jwt".into(),jwks_pem:None,inline_jwks:None,jwks_uri:Some(server.uri.clone()),token_endpoint_auth_signing_alg:Some("RS256".into()),allowed_scopes:vec!["read".into()],allowed_grant_types:vec!["authorization_code".into()],registration_access_token:None,client_id_issued_at:None,dpop_bound_access_tokens:false,
        }));
        let now=crate::util::now_unix_epoch_secs_i64()?;
        let audience="https://issuer.example/token";
        for (private,subject) in [(true,"remote-client"),(false,"resource-owner")] {
            let assertion=sign(jsonwebtoken::Algorithm::RS256,&encoding,&serde_json::json!({"iss":"remote-client","sub":subject,"aud":audience,"iat":now,"exp":now+300,"jti":"same-jti-two-uses"}));
            let prepared=if private {registry.prepare_private_key_jwt_async("remote-client",&assertion,audience,CryptoProfile::Verified).await}
                else {registry.prepare_jwt_bearer_grant_assertion_async("remote-client",&assertion,audience,"https://issuer.example",false,CryptoProfile::Verified).await};
            let prepared=prepared.map_err(|e|anyhow::anyhow!("{e:?}"))?.ok_or_else(||anyhow::anyhow!("assertion refused"))?;
            anyhow::ensure!(prepared.finish_async().await.map_err(|e|anyhow::anyhow!("{e:?}"))?.as_deref()==Some(subject));
        }
        let object=sign(jsonwebtoken::Algorithm::RS256,&encoding,&serde_json::json!({"iss":"remote-client","aud":"https://issuer.example","client_id":"remote-client","response_type":"code","redirect_uri":"https://client.example/cb","scope":"read","code_challenge":"challenge","code_challenge_method":"S256","iat":now,"exp":now+300,"jti":"object"}));
        registry.verify_request_object_async("remote-client",&object,"https://issuer.example",CryptoProfile::Verified).await?;
        anyhow::ensure!(registry.verify_request_object("remote-client",&object,"https://issuer.example",CryptoProfile::Verified).is_err(),"native synchronous API must not silently use memory");
        anyhow::ensure!(registry.try_resolve_client_jwk_async("remote-client",Some(crate::test_utils::jwk_usage::KID)).await?.is_some());
        anyhow::ensure!(registry.verify_request_object_async("remote-client","malformed","https://issuer.example",CryptoProfile::Verified).await.is_err());
        anyhow::ensure!(server.count()==1,"shared admitted body serves all three consumers");
        f.pool.close().await;
        anyhow::ensure!(registry.verify_request_object_async("remote-client",&object,"https://issuer.example",CryptoProfile::Verified).await.is_err());
        anyhow::ensure!(server.count()==1);
        Ok::<_,anyhow::Error>(())
    }.await;
    f.cleanup().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; near-expiry background ownership and non-queuing capacity"]
async fn pg_jwks_native_background_and_capacity() -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        let server = Server::new(
            vec![
                ok(body("A", jsonwebtoken::Algorithm::RS256), "max-age=5"),
                ok(body("B", jsonwebtoken::Algorithm::ES256), "max-age=60"),
            ],
            true,
        )
        .await?;
        let runtime = f.runtime.clone();
        let uri = server.uri.clone();
        let initial = tokio::spawn(async move { runtime.fetch(&uri).await });
        tokio::time::timeout(
            Duration::from_secs(5),
            server.state.entered.as_ref().unwrap().notified(),
        )
        .await?;
        server.state.hold.as_ref().unwrap().notify_one();
        anyhow::ensure!(initial.await?.map_err(anyhow::Error::msg)?.is_some());
        let first = fetch(&f.runtime, &server.uri).await?;
        tokio::time::timeout(
            Duration::from_secs(5),
            server.state.entered.as_ref().unwrap().notified(),
        )
        .await?;
        for _ in 0..32 {
            let cached = fetch(&f.runtime, &server.uri).await?;
            anyhow::ensure!(Arc::ptr_eq(&first, &cached));
        }
        anyhow::ensure!(
            server.count() == 2,
            "one URI must have one owned background task"
        );
        server.state.hold.as_ref().unwrap().notify_one();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if f.runtime.background_uris.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        anyhow::ensure!(
            fetch(&f.runtime, &server.uri).await?.jwks.keys()[0]
                .kid
                .as_deref()
                == Some("B")
        );
        let slots = f.runtime.fetch_slots.acquire_many(32).await?;
        anyhow::ensure!(f
            .runtime
            .fetch(&format!("{}?new", server.uri))
            .await
            .is_err());
        anyhow::ensure!(
            fetch(&f.runtime, &server.uri).await?.jwks.keys()[0]
                .kid
                .as_deref()
                == Some("B")
        );
        let owners: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.runtime_jwks_fetches WHERE owner IS NOT NULL",
        )
        .fetch_one(&f.pool)
        .await?;
        anyhow::ensure!(owners == 0 && server.count() == 2);
        drop(slots);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    f.cleanup().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; bounded wire body at and above limit"]
async fn pg_jwks_native_body_limit() -> anyhow::Result<()> {
    let mut f = Fixture::new().await?;
    Arc::get_mut(&mut f.runtime).unwrap().policy.max_body_bytes = 1024;
    let result = async {
        let mut exact = body("A", jsonwebtoken::Algorithm::RS256);
        anyhow::ensure!(exact.len() < 1024);
        exact.extend(std::iter::repeat_n(' ', 1024 - exact.len()));
        let oversized = format!("{exact} ");
        let server = Server::new(
            vec![ok(exact, "no-store"), ok(oversized, "no-store")],
            false,
        )
        .await?;
        let admitted = fetch(&f.runtime, &server.uri).await?;
        anyhow::ensure!(f.runtime.fetch(&server.uri).await.is_err());
        anyhow::ensure!(f
            .runtime
            .state
            .current_body(&server.uri, &admitted.admission.body_digest())
            .await
            .map_err(anyhow::Error::msg)?);
        let state: (i64, bool) =
            sqlx::query_as("SELECT failures,owner IS NULL FROM aegaeon.runtime_jwks_fetches")
                .fetch_one(&f.pool)
                .await?;
        anyhow::ensure!(state == (1, true) && server.count() == 2);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    f.cleanup().await?;
    result
}

#[test]
fn native_jwks_url_and_cache_bounds() -> anyhow::Result<()> {
    let policy = JwksRuntimePolicy::default();
    for url in [
        "http://1.1.1.1/keys",
        "https://127.0.0.1/keys",
        "https://[::1]/keys",
        "https://user@1.1.1.1/keys",
        "https://1.1.1.1/keys#fragment",
    ] {
        anyhow::ensure!(transport::validate_target(&policy, url, false).is_err());
    }
    anyhow::ensure!(transport::validate_target(&policy, "https://1.1.1.1/keys", false).is_ok());
    let now = Instant::now();
    let factory = |charge| -> anyhow::Result<Arc<Entry>> {
        let jwks: FetchedJwks = serde_json::from_str(&body("A", jsonwebtoken::Algorithm::RS256))?;
        let admission = AdmittedKeys::from_validated(&jwks).map_err(anyhow::Error::msg)?;
        let metadata = CacheMetadata::from_headers(
            &HeaderMap::new(),
            super::super::super::jwks_validators::DateContext::capture(),
        );
        let timing = super::super::super::jwks_cache_control::ResponseTiming::received(now);
        Ok(Arc::new(Entry {
            body: Arc::new(Body {
                jwks,
                admission,
                charge,
            }),
            freshness: metadata.freshness(timing, 60),
            metadata,
            validators: JwksValidators::default(),
            target: "https://1.1.1.1/keys".into(),
            admitted_at: now,
            retain_until: now + Duration::from_secs(60),
            charge,
            header_charge: 0,
        }))
    };
    let mut cache = cache::BodyCache::default();
    cache.publish("A", Some(factory(40 * 1024 * 1024)?), now, 4096);
    cache.publish("B", Some(factory(40 * 1024 * 1024)?), now, 4096);
    anyhow::ensure!(cache.capture("A", now).is_none() && cache.capture("B", now).is_some());
    cache.publish("oversized", Some(factory(65 * 1024 * 1024)?), now, 4096);
    anyhow::ensure!(cache.capture("oversized", now).is_none() && cache.capture("B", now).is_some());
    cache.publish("C", Some(factory(1024)?), now, 1);
    anyhow::ensure!(cache.capture("B", now).is_none() && cache.capture("C", now).is_some());
    cache.prune(now + Duration::from_secs(60));
    anyhow::ensure!(cache.capture("C", now + Duration::from_secs(60)).is_none());
    Ok(())
}
