use super::{fixture::*, policy::accepted};
use crate::middleware::{
    dpop::{DpopEndpointRole, DpopNonceStore},
    replay_store::{ReplayEntry, ReplayStore, ReplayStoreError},
    DpopMiddleware,
};
use crate::web::test_support::TestResult;
use axum::{body::Body, http::StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{sync::Arc, time::Duration};

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual routers and native proof replay controls"]
async fn resource_authentication_early_refusals_do_not_consume_signed_proof() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = async {
        for (method, path) in SURFACES {
            let token = fixture.token(path, "openid read", true, false).await?;
            for early in [
                "absent",
                "unsupported",
                "malformed",
                "query",
                "mixed",
                "form",
            ] {
                if matches!(early, "mixed" | "form") && !(method == "POST" && path == "/userinfo") {
                    continue;
                }
                let proof = signed_proof(method, path, Some(&token), None)?;
                let valid_auth = format!("DPoP {token}");
                let early_auth = match early {
                    "absent" => None,
                    "unsupported" => Some("Unknown credentials"),
                    "malformed" => Some("DPoP"),
                    _ => Some(valid_auth.as_str()),
                };
                let uri = if early == "query" {
                    format!("{path}?access_token=synthetic")
                } else {
                    path.to_string()
                };
                let before = fixture.replay.attempts();
                let response = request(
                    &fixture.state,
                    method,
                    &uri,
                    headers(
                        early_auth,
                        Some(&proof),
                        method == "POST" && early != "form",
                    )?,
                    if early == "mixed" {
                        "access_token=other"
                    } else if early == "form" {
                        "unused=value"
                    } else {
                        ""
                    },
                )
                .await?;
                let absent = matches!(early, "absent" | "unsupported");
                expect(
                    response,
                    if absent {
                        StatusCode::UNAUTHORIZED
                    } else {
                        StatusCode::BAD_REQUEST
                    },
                    Some(if absent { "Bearer" } else { "DPoP" }),
                    if absent {
                        None
                    } else {
                        Some("invalid_request")
                    },
                    false,
                )
                .await?;
                assert_eq!(fixture.replay.attempts(), before);
                // The same htm/htu/ath/JTI/signature is then accepted, and its replay refused.
                accepted(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&valid_auth), Some(&proof), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    path,
                )
                .await?;
                assert_eq!(fixture.replay.attempts(), before + 1);
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&valid_auth), Some(&proof), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::UNAUTHORIZED,
                    Some("DPoP"),
                    Some("invalid_dpop_proof"),
                    false,
                )
                .await?;
            }
            for (token, scheme, status, error) in [
                (
                    "invalid-fixture-token".to_string(),
                    "Bearer",
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                ),
                (
                    fixture.token(path, "profile", true, false).await?,
                    "DPoP",
                    StatusCode::FORBIDDEN,
                    "insufficient_scope",
                ),
            ] {
                let proof = signed_proof(method, path, Some(&token), None)?;
                let auth = format!("{scheme} {token}");
                let before = fixture.replay.attempts();
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&auth), Some(&proof), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    status,
                    Some(scheme),
                    Some(error),
                    false,
                )
                .await?;
                assert_eq!(
                    fixture.replay.attempts(),
                    before + 1,
                    "admitted later refusal preserves prior proof consumption order"
                );
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&auth), Some(&proof), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::UNAUTHORIZED,
                    Some("DPoP"),
                    Some("invalid_dpop_proof"),
                    false,
                )
                .await?;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}

struct UnavailableReplay;
impl ReplayStore for UnavailableReplay {
    fn check_and_store(&self, _entry: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        Err(ReplayStoreError::BackendUnavailable(
            "fixture unavailable".into(),
        ))
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB and Redis; native proof, real nonce storage, injected replay backend fault"]
async fn resource_authentication_nonce_state_and_backend_errors_keep_their_boundaries() -> TestResult
{
    let mut fixture = Fixture::new().await?;
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let namespace = format!("resource-auth-{}", uuid::Uuid::new_v4());
    let material = crate::middleware::replay_store::replay_key_material(&[namespace.as_bytes()]);
    let key = format!(
        "dpop:nonce:v2:{}:rs",
        URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(&material))
    );
    let mut redis = redis::Client::open(url.as_str())?.get_connection()?;
    let nonce = Arc::new(DpopNonceStore::redis(
        &url,
        namespace,
        Duration::from_secs(300),
    )?);
    fixture.state.dpop = Arc::new(
        fixture
            .state
            .dpop
            .as_ref()
            .clone()
            .with_nonce_store(nonce.clone()),
    );
    let result = async {
        assert_eq!(
            redis::cmd("EXISTS").arg(&key).query::<usize>(&mut redis)?,
            0
        );
        // Compare both absent state and an existing record whose rotation is due.
        // Only this fixture's Redis key is seeded; no shared clock/service is changed.
        for existing in [false, true] {
            if existing {
                let original = nonce
                    .try_get_current_nonce_for(DpopEndpointRole::ResourceServer)
                    .map_err(|error| format!("{error:?}"))?;
                let raw: String = redis::cmd("GET").arg(&key).query(&mut redis)?;
                let mut record: serde_json::Value = serde_json::from_str(&raw)?;
                record["rotate_at"] = serde_json::json!(0);
                redis::cmd("SET")
                    .arg(&key)
                    .arg(serde_json::to_string(&record)?)
                    .arg("KEEPTTL")
                    .query::<()>(&mut redis)?;
                assert_eq!(record["current"], original);
            }
            for (method, path) in SURFACES {
                let token = fixture.token(path, "openid read", true, false).await?;
                let proof = signed_proof(method, path, Some(&token), None)?;
                let mut refused = vec![
                    (path.to_string(), None, "", method == "POST"),
                    (
                        path.to_string(),
                        Some("Unknown token".to_string()),
                        "",
                        method == "POST",
                    ),
                    (
                        path.to_string(),
                        Some("DPoP".to_string()),
                        "",
                        method == "POST",
                    ),
                    (
                        format!("{path}?access_token=x"),
                        Some(format!("DPoP {token}")),
                        "",
                        method == "POST",
                    ),
                ];
                if method == "POST" && path == "/userinfo" {
                    refused.push((
                        path.to_string(),
                        Some(format!("DPoP {token}")),
                        "access_token=other",
                        true,
                    ));
                    refused.push((
                        path.to_string(),
                        Some(format!("DPoP {token}")),
                        "unused=value",
                        false,
                    ));
                }
                for (uri, auth, body, form) in refused {
                    let before: Option<Vec<u8>> = redis::cmd("DUMP").arg(&key).query(&mut redis)?;
                    let ttl_before: i64 = redis::cmd("PTTL").arg(&key).query(&mut redis)?;
                    let response = request(
                        &fixture.state,
                        method,
                        &uri,
                        headers(auth.as_deref(), Some(&proof), form)?,
                        body,
                    )
                    .await?;
                    assert!(response.status().is_client_error());
                    assert!(!response.headers().contains_key("dpop-nonce"));
                    let after: Option<Vec<u8>> = redis::cmd("DUMP").arg(&key).query(&mut redis)?;
                    assert_eq!(before, after);
                    let ttl_after: i64 = redis::cmd("PTTL").arg(&key).query(&mut redis)?;
                    if existing {
                        assert!(
                            ttl_after > 0 && ttl_after <= ttl_before,
                            "early refusal must not renew nonce retention"
                        );
                    } else {
                        assert_eq!((ttl_before, ttl_after), (-2, -2));
                    }
                }
            }
            assert_eq!(fixture.replay.attempts(), 0);
            assert_eq!(
                redis::cmd("EXISTS").arg(&key).query::<usize>(&mut redis)?,
                usize::from(existing),
                "early refusals must neither issue nor delete a nonce"
            );
        }
        for (method, path) in SURFACES {
            let token = fixture.token(path, "openid read", true, false).await?;
            let auth = format!("DPoP {token}");
            let proof = signed_proof(method, path, Some(&token), None)?;
            let response = request(
                &fixture.state,
                method,
                path,
                headers(Some(&auth), Some(&proof), method == "POST")?,
                Body::empty(),
            )
            .await?;
            let value = response.headers()["dpop-nonce"].to_str()?.to_string();
            expect(
                response,
                StatusCode::UNAUTHORIZED,
                Some("DPoP"),
                Some("use_dpop_nonce"),
                true,
            )
            .await?;
            assert!(nonce
                .try_validate_nonce_for(DpopEndpointRole::ResourceServer, &value)
                .map_err(|error| format!("{error:?}"))?);
            let proof = signed_proof(method, path, Some(&token), Some(&value))?;
            accepted(
                request(
                    &fixture.state,
                    method,
                    path,
                    headers(Some(&auth), Some(&proof), method == "POST")?,
                    Body::empty(),
                )
                .await?,
                path,
            )
            .await?;
            let mut unavailable = fixture.state.clone();
            unavailable.dpop = Arc::new(
                DpopMiddleware::new(
                    "fault",
                    "https://proof.example",
                    Arc::new(UnavailableReplay),
                    Duration::from_secs(360),
                )
                .with_native_verifier_for_tests(),
            );
            let proof = signed_proof(method, path, Some(&token), None)?;
            expect(
                request(
                    &unavailable,
                    method,
                    path,
                    headers(Some(&auth), Some(&proof), method == "POST")?,
                    Body::empty(),
                )
                .await?,
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                Some("temporarily_unavailable"),
                false,
            )
            .await?;
        }
        // Corrupt only the owned Redis record: a real nonce-backend failure must not challenge.
        redis::cmd("SET")
            .arg(&key)
            .arg("invalid nonce record")
            .arg("KEEPTTL")
            .query::<()>(&mut redis)?;
        for (method, path) in SURFACES {
            let token = fixture.token(path, "openid read", true, false).await?;
            let proof = signed_proof(method, path, Some(&token), None)?;
            let before = fixture.replay.attempts();
            expect(
                request(
                    &fixture.state,
                    method,
                    path,
                    headers(
                        Some(&format!("DPoP {token}")),
                        Some(&proof),
                        method == "POST",
                    )?,
                    Body::empty(),
                )
                .await?,
                StatusCode::SERVICE_UNAVAILABLE,
                None,
                Some("temporarily_unavailable"),
                false,
            )
            .await?;
            assert_eq!(fixture.replay.attempts(), before);
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    redis::cmd("DEL").arg(&key).query::<usize>(&mut redis)?;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}
