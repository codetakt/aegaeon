use super::*;
use crate::web::test_support::native_dpop;

async fn send_proof(
    state: &AppState,
    fields: &[(String, String)],
    proof: Option<&str>,
) -> TestResult<(StatusCode, Value)> {
    let app = crate::web::build_router(state.clone()).layer(Extension(ConnectInfo(
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )));
    let mut builder = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, basic());
    if let Some(proof) = proof {
        builder = builder.header("DPoP", proof);
    }
    let response = app
        .oneshot(builder.body(Body::from(serde_urlencoded::to_string(fields)?))?)
        .await?;
    let status = response.status();
    let value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    Ok((status, value))
}

async fn minimum_grant(grant: &str) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture_with_minimum(&pool, &env, true).await?;
        native_dpop::install(&mut state)?;
        let fields = routed::request_fields(&state, grant).await?;
        let before = state.tokens.store.try_snapshot()?.access_tokens.len();
        for proof in [None, Some("malformed")] {
            let (status, body) = send_proof(&state, &fields, proof).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{grant}: {body}");
            assert_eq!(body["error"], "invalid_dpop_proof");
            if grant == "refresh_token" {
                let old = fields.iter().find(|(name, _)| name == "refresh_token").ok_or("old refresh")?;
                assert!(!state.tokens.store.try_get_refresh_token(&old.1)?.ok_or("old refresh retained")?.rotated);
            }

            assert_eq!(
                before,
                state.tokens.store.try_snapshot()?.access_tokens.len()
            );
        }
        let material = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let proof = native_dpop::proof(&state, &material, json!({}))?;
        let (status, body) = send_proof(&state, &fields, Some(&proof)).await?;
        assert_eq!(status, StatusCode::OK, "{grant}: {body}");
        assert_eq!(body["token_type"], "DPoP");
        let token = body["access_token"].as_str().ok_or("access token")?;
        let saved = state
            .tokens
            .store
            .try_verify_access_token_async(token.into())
            .await?
            .ok_or("published token")?;
        assert_eq!(saved.token_type, "DPoP");
        let jkt=crate::util::compute_dpop_jkt_from_proof(&proof).ok_or("proof jkt")?;
        assert_eq!(saved.cnf,Some(crate::authcode::types::CnfClaim::Jkt(jkt.clone())));
        let metadata=state.tokens.store.try_get_bearer_meta_async(token.into()).await?.ok_or("stored token metadata")?;
        assert!(matches!(metadata.sender_binding,Some(crate::authcode::types::SenderBinding::DPoP {jkt:ref actual}) if crate::util::jwk_thumbprint_matches(actual,&jkt)));
        if let Some(refresh)=body["refresh_token"].as_str() {
            let successor=state.tokens.store.try_get_refresh_token(refresh)?.ok_or("successor refresh")?;
            assert!(matches!(successor.sender_binding,Some(crate::authcode::types::SenderBinding::DPoP {jkt:ref actual}) if crate::util::jwk_thumbprint_matches(actual,&jkt)));
        }
        let count = state.tokens.store.try_snapshot()?.access_tokens.len();
        let (status, body) = send_proof(&state, &fields, Some(&proof)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_dpop_proof");
        assert_eq!(
            count,
            state.tokens.store.try_snapshot()?.access_tokens.len()
        );
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; real native DPoP on five mounted token grants"]
async fn shared_redis_client_dpop_minimum_native_code_refresh_device_jwt_and_client_credentials(
) -> TestResult {
    for grant in [
        "authorization_code",
        "refresh_token",
        crate::policy::DEVICE_CODE_GRANT_TYPE,
        crate::policy::JWT_BEARER_GRANT_TYPE,
        "client_credentials",
    ] {
        minimum_grant(grant).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; native signature/method/URI/nonce failures and backend fault injection"]
async fn shared_redis_client_dpop_minimum_native_errors_preserve_grant_and_distinguish_backend(
) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture_with_minimum(&pool, &env, true).await?;
        native_dpop::install(&mut state)?;
        let fields = routed::request_fields(&state, "authorization_code").await?;
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        for claims in [
            json!({"htm":"GET"}),
            json!({"htu":"https://wrong.example/token"}),
            json!({"jti":""}),
        ] {
            let proof = native_dpop::proof(&state, &key, claims)?;
            let (status, body) = send_proof(&state, &fields, Some(&proof)).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], "invalid_dpop_proof");
        }
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let proof = native_dpop::proof(&state, &key, json!({}))?;
        let (input, signature) = proof.rsplit_once('.').ok_or("proof")?;
        let mut signature = URL_SAFE_NO_PAD.decode(signature)?;
        signature[0] ^= 1;
        let bad = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert_eq!(
            send_proof(&state, &fields, Some(&bad)).await?.1["error"],
            "invalid_dpop_proof"
        );
        let nonces = crate::middleware::dpop::DpopNonceStore::redis(
            &std::env::var("AEGAEON_TEST_REDIS_URL")?,
            format!("client-minimum-nonce-{}", env.environment_id),
            std::time::Duration::from_secs(300),
        )?;
        state.dpop = Arc::new(
            state
                .dpop
                .as_ref()
                .clone()
                .with_nonce_store(Arc::new(nonces)),
        );
        for claims in [json!({}), json!({"nonce":"wrong"})] {
            let proof = native_dpop::proof(&state, &key, claims)?;
            let (status, body) = send_proof(&state, &fields, Some(&proof)).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], "use_dpop_nonce");
        }
        let nonce = state
            .dpop
            .current_nonce()
            .map_err(|e| format!("nonce: {e:?}"))?
            .ok_or("nonce")?;
        let proof = native_dpop::proof(&state, &key, json!({"nonce":nonce}))?;
        let count = state.tokens.store.try_snapshot()?.access_tokens.len();
        let mut unavailable = state.clone();
        unavailable.dpop = Arc::new(
            crate::middleware::DpopMiddleware::new(
                "fault-injection",
                state.issuer.as_str(),
                Arc::new(UnavailableReplay),
                std::time::Duration::from_secs(360),
            )
            .with_native_verifier_for_tests(),
        );
        let (status, body) = send_proof(&unavailable, &fields, Some(&proof)).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error"], "temporarily_unavailable");
        assert_eq!(
            count,
            state.tokens.store.try_snapshot()?.access_tokens.len()
        );
        assert_eq!(
            send_proof(&state, &fields, Some(&proof)).await?.0,
            StatusCode::OK,
            "all refusals preserve the actual code"
        );
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

struct UnavailableReplay;
impl crate::middleware::replay_store::ReplayStore for UnavailableReplay {
    fn check_and_store(
        &self,
        _: crate::middleware::replay_store::ReplayEntry<'_>,
    ) -> Result<(), crate::middleware::replay_store::ReplayStoreError> {
        Err(
            crate::middleware::replay_store::ReplayStoreError::BackendUnavailable(
                "test backend outage".into(),
            ),
        )
    }
}

async fn held_minimum(grant: &str, initial: bool) -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture_with_minimum(&pool, &env, initial).await?;
        native_dpop::install(&mut state)?;
        let fields = routed::request_fields(&state, grant).await?;
        let observed = Arc::new(tokio::sync::Barrier::new(2));
        let resume = Arc::new(tokio::sync::Barrier::new(2));
        let held = snapshot_test_hook::OBSERVATION.scope(
            (
                snapshot_test_hook::Phase::AfterAuthentication,
                observed.clone(),
                resume.clone(),
            ),
            send_proof(&state, &fields, None),
        );
        let update = async {
            observed.wait().await;
            let result = native_dpop::set_minimum(
                &state,
                BASIC,
                &format!("assertion-test-rat-{BASIC}"),
                !initial,
            )
            .await;
            resume.wait().await;
            result
        };
        let (held, update) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(held, update)
        })
        .await?;
        update?;
        let (status, body) = held?;
        if grant == "client_credentials" {
            assert_ne!(status, StatusCode::OK, "stronger revision check: {body}");
            return Ok(());
        }
        assert_eq!(
            status,
            if initial {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            },
            "captured {initial}: {body}"
        );
        let next_fields = if initial {
            fields
        } else {
            routed::request_fields(&state, grant).await?
        };
        let (status, body) = send_proof(&state, &next_fields, None).await?;
        assert_eq!(
            status,
            if initial {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "new minimum: {body}"
        );
        if !initial {
            assert_eq!(body["error"], "invalid_dpop_proof");
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual paused requests and database reload"]
async fn shared_redis_client_dpop_minimum_captured_code_refresh_and_stronger_client_credentials_currentness(
) -> TestResult {
    for grant in ["authorization_code", "refresh_token"] {
        for initial in [false, true] {
            held_minimum(grant, initial).await?;
        }
    }
    held_minimum("client_credentials", false).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; independent minimum versus profile mechanisms"]
async fn shared_redis_client_dpop_minimum_profile_none_dpop_and_mtls_conflict() -> TestResult {
    let pool = test_pg_pool().await?.ok_or("PostgreSQL required")?;
    let env = setup_test_environment(&pool).await?;
    let result=async {
        let mut state=fixture_with_minimum(&pool,&env,false).await?;
        native_dpop::install(&mut state)?;
        let key=aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        for profile in ["NONE","DPOP"] {
            sqlx::query("UPDATE aegaeon.oauth_profiles SET sender_constrained=$1::aegaeon.oauth_sender_constraint WHERE environment_id=$2").bind(profile).bind(env.environment_id).execute(&pool).await?;
            for minimum in [false,true] {
                native_dpop::set_minimum(&state,BASIC,&format!("assertion-test-rat-{BASIC}"),minimum).await?;
                let fields=routed::request_fields(&state,"client_credentials").await?;
                let (status,body)=send_proof(&state,&fields,None).await?;
                assert_eq!(status,if profile=="NONE" && !minimum {StatusCode::OK}else{StatusCode::BAD_REQUEST},"{profile}/{minimum}: {body}");
                let proof=native_dpop::proof(&state,&key,json!({}))?;
                assert_eq!(send_proof(&state,&fields,Some(&proof)).await?.0,StatusCode::OK);
            }
        }
        update_test_policy(&mut state,|policy| policy.mtls_enabled=true).await?;
        sqlx::query("UPDATE aegaeon.oauth_profiles SET sender_constrained='MTLS' WHERE environment_id=$1").bind(env.environment_id).execute(&pool).await?;
        let fields=routed::request_fields(&state,"client_credentials").await?;
        let before=state.tokens.store.try_snapshot()?.access_tokens.len();
        let (status,body)=send_proof(&state,&fields,None).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST,"{body}");assert_eq!(body["error"],"unauthorized_client");
        assert_eq!(body["error_description"],"Client DPoP requirement conflicts with mTLS policy");
        assert_eq!(before,state.tokens.store.try_snapshot()?.access_tokens.len());
        Ok(())
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
