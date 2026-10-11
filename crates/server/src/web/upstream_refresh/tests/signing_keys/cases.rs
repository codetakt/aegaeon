use super::*;

fn combined(f: &Fixture, flow: &Flow) -> ResultTest<Value> {
    let mut keys = serde_json::to_value(f.signing_key.jwks())?;
    keys["keys"]
        .as_array_mut()
        .ok_or("keys array")?
        .push(serde_json::to_value(flow.new_key.jwks())?["keys"][0].clone());
    Ok(keys)
}
fn sign_as(flow: &Flow, claims: &Value, kid: Option<&str>) -> ResultTest<String> {
    Ok(jsonwebtoken::encode(
        &jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: kid.map(str::to_string),
            ..Default::default()
        },
        claims,
        flow.new_key.local_encoding_key().ok_or("fixture key")?,
    )?)
}
async fn original(f: &Fixture) -> ResultTest {
    f.store_callback(&f.callback(&f.claims()?, Some("private-refresh"))?)
        .await
        .map_err(error)?;
    Ok(())
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_jwks_refresh_pg_callback_rotates_and_does_not_resurrect_removed_keys() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            original(f).await?;
            let flow = Flow::new(f).await?;
            let claims = f.claims()?;
            flow.keys
                .respond(StatusCode::OK, combined(f, &flow)?.to_string());
            flow.token(flow.signed(&claims)?);
            assert_eq!(flow.callback().await?.status(), StatusCode::FOUND);
            assert_eq!(flow.keys.hits(), 1);
            assert_eq!(flow.tokens.hits(), 1);
            flow.token(f.signed(&claims)?);
            assert_eq!(flow.callback().await?.status(), StatusCode::FOUND);
            assert_eq!(flow.keys.hits(), 1);
            assert_eq!(flow.tokens.hits(), 2);
            let stored = f.stored().await?;
            flow.keys
                .respond(StatusCode::OK, serde_json::to_string(&flow.new_key.jwks())?);
            flow.clock.advance(30_000);
            flow.token(sign_as(&flow, &claims, Some("missing-third"))?);
            assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(flow.keys.hits(), 2);
            assert_eq!(flow.tokens.hits(), 3);
            flow.token(f.signed(&claims)?);
            assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(flow.keys.hits(), 2);
            assert_eq!(flow.tokens.hits(), 4);
            flow.assert_no_effects(f, &stored, 2).await
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_jwks_refresh_pg_rotation_preserves_original_context() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            original(f).await?;
            let flow = Flow::new(f).await?;
            let claims = f.claims()?;
            let original = f.load().await.map_err(error)?.original_authentication;
            flow.keys
                .respond(StatusCode::OK, combined(f, &flow)?.to_string());
            flow.token(flow.signed(&claims)?);
            assert_eq!(
                flow.refresh(f).await.map_err(error)?.status(),
                StatusCode::OK
            );
            assert_eq!(flow.keys.hits(), 1);
            assert_eq!(flow.tokens.hits(), 1);
            assert!(f.load().await.map_err(error)?.original_authentication == original);
            flow.token(f.signed(&claims)?);
            assert_eq!(
                flow.refresh(f).await.map_err(error)?.status(),
                StatusCode::OK
            );
            assert_eq!(flow.keys.hits(), 1);
            let stored = f.stored().await?;
            flow.keys
                .respond(StatusCode::OK, serde_json::to_string(&flow.new_key.jwks())?);
            flow.clock.advance(30_000);
            flow.token(sign_as(&flow, &claims, Some("missing-third"))?);
            assert_eq!(
                flow.refresh(f).await.expect_err("missing key").status(),
                StatusCode::BAD_GATEWAY
            );
            assert_eq!(flow.keys.hits(), 2);
            flow.token(f.signed(&claims)?);
            assert_eq!(
                flow.refresh(f).await.expect_err("withdrawn key").status(),
                StatusCode::BAD_GATEWAY
            );
            assert_eq!(flow.keys.hits(), 2);
            assert_eq!(flow.tokens.hits(), 4);
            flow.assert_no_effects(f, &stored, 0).await
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_jwks_refresh_pg_known_bad_tokens_never_force_retrieval() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            original(f).await?;
            let flow = Flow::new(f).await?;
            let claims = f.claims()?;
            let stored = f.stored().await?;
            let raw = |header: Value| {
                format!("{}.e30.invalid", URL_SAFE_NO_PAD.encode(header.to_string()))
            };
            let duplicate = format!(
                "{}.e30.invalid",
                URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","alg":"RS256","kid":"new-key"}"#)
            );
            let mut wrong_claims = claims.clone();
            wrong_claims["aud"] = json!("different-client");
            let mut tokens = vec![
                sign_as(&flow, &claims, Some(f.signing_key.kid()))?,
                sign_as(&flow, &claims, None)?,
                sign_as(&flow, &claims, Some(""))?,
                raw(json!({"alg":"HS256","kid":"new-key"})),
                raw(json!({"alg":"RS512","kid":"new-key"})),
                raw(json!({
                    "alg": "RS256",
                    "kid": "new-key",
                    "padding": "x".repeat(flow.state.cfg.jose_header_max_len + 1),
                })),
                duplicate,
                "not-a-jwt".into(),
                f.signed(&wrong_claims)?,
            ];
            let unfamiliar =
                URL_SAFE_NO_PAD.encode(json!({"alg":"RS256","kid":"new-key"}).to_string());
            for (payload, signature) in [
                ("e30", ""),
                ("", "c2ln"),
                ("e30", "YR"),
                ("e31", "c2ln"),
                ("e30", "YQ=="),
                ("e30", "Y+"),
                ("e30", "a"),
                ("e30", "Y/"),
            ] {
                tokens.push(format!("{unfamiliar}.{payload}.{signature}"));
            }
            let expected_exchanges = (tokens.len() + 4) * 2;
            for token in tokens {
                flow.token(token);
                assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
                assert_eq!(
                    flow.refresh(f).await.expect_err("invalid token").status(),
                    StatusCode::BAD_GATEWAY
                );
                assert_eq!(flow.keys.hits(), 0);
                flow.assert_no_effects(f, &stored, 0).await?;
            }
            for mutation in ["usage", "algorithm", "type", "ambiguous"] {
                let mut keys = combined(f, &flow)?;
                match mutation {
                    "usage" => keys["keys"][0]["use"] = json!("enc"),
                    "algorithm" => keys["keys"][0]["alg"] = json!("PS256"),
                    "type" => {
                        keys["keys"][0] = json!({
                            "kty": "EC", "kid": f.signing_key.kid(),
                            "crv": "P-256", "x": "AA", "y": "AA",
                        });
                    }
                    _ => (),
                }
                flow.cache_keys(keys)?;
                flow.token(if mutation == "ambiguous" {
                    sign_as(&flow, &claims, None)?
                } else {
                    f.signed(&claims)?
                });
                assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
                assert_eq!(
                    flow.refresh(f)
                        .await
                        .expect_err("unusable known key")
                        .status(),
                    StatusCode::BAD_GATEWAY
                );
                assert_eq!(flow.keys.hits(), 0);
                flow.assert_no_effects(f, &stored, 0).await?;
            }
            assert_eq!(flow.tokens.hits(), expected_exchanges);
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_jwks_refresh_pg_new_set_still_missing_key_rejects_without_loop() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            original(f).await?;
            let flow = Flow::new(f).await?;
            let stored = f.stored().await?;
            flow.keys.respond(
                StatusCode::OK,
                serde_json::to_string(&f.signing_key.jwks())?,
            );
            flow.token(flow.signed(&f.claims()?)?);
            assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(flow.keys.hits(), 1);
            assert_eq!(
                flow.refresh(f)
                    .await
                    .expect_err("still missing key")
                    .status(),
                StatusCode::BAD_GATEWAY
            );
            assert_eq!(flow.keys.hits(), 1);
            assert_eq!(flow.tokens.hits(), 2);
            flow.assert_no_effects(f, &stored, 0).await
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_jwks_refresh_pg_claims_and_original_context_still_reject_after_fetch() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            original(f).await?;
            let flow = Flow::new(f).await?;
            let stored = f.stored().await?;
            let mut claims = f.claims()?;
            claims["aud"] = json!("different-client");
            flow.token(flow.signed(&claims)?);
            assert_eq!(flow.callback().await?.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(flow.keys.hits(), 1);
            flow.assert_no_effects(f, &stored, 0).await?;
            flow.cache_keys(serde_json::to_value(f.signing_key.jwks())?)?;
            flow.clock.advance(30_000);
            claims = f.claims()?;
            claims["nonce"] = json!("changed-private-nonce");
            flow.token(flow.signed(&claims)?);
            assert_eq!(
                flow.refresh(f)
                    .await
                    .expect_err("original nonce changed")
                    .status(),
                StatusCode::BAD_GATEWAY
            );
            assert_eq!(flow.keys.hits(), 2);
            assert_eq!(flow.tokens.hits(), 2);
            flow.assert_no_effects(f, &stored, 0).await
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_jwks_refresh_pg_final_set_requires_federation_endorsement() -> ResultTest {
    run(false, |rt, f| {
        rt.block_on(async {
            original(f).await?;
            let flow = Flow::new(f).await?;
            let stored = f.stored().await?;
            federation::bind(&flow, f, serde_json::to_value(f.signing_key.jwks())?).await?;
            flow.token(flow.signed(&f.claims()?)?);
            let callback = flow.callback().await?;
            assert_eq!(callback.status(), StatusCode::BAD_GATEWAY);
            let body = axum::body::to_bytes(callback.into_body(), 16384).await?;
            let body = std::str::from_utf8(&body)?;
            assert!(
                body.contains("upstream JWKS does not match federation metadata"),
                "{body}"
            );
            assert_eq!(flow.keys.hits(), 1);
            flow.assert_no_effects(f, &stored, 0).await?;
            let retained = flow
                .state
                .upstream
                .jwks_cache
                .try_get(&flow.discovery.jwks_uri)?
                .ok_or("previous keys displaced")?;
            assert!(retained
                .keys()
                .iter()
                .any(|key| key.kid.as_deref() == Some(f.signing_key.kid())));
            assert!(!retained
                .keys()
                .iter()
                .any(|key| key.kid.as_deref() == Some(flow.new_key.kid())));
            flow.clock.advance(30_000);
            let refresh = flow.refresh(f).await.expect_err("unendorsed refreshed key");
            assert_eq!(refresh.status(), StatusCode::BAD_GATEWAY);
            let body = axum::body::to_bytes(refresh.into_body(), 16384).await?;
            let body = std::str::from_utf8(&body)?;
            assert!(
                body.contains("upstream JWKS does not match federation metadata"),
                "{body}"
            );
            assert_eq!(flow.keys.hits(), 2);
            flow.assert_no_effects(f, &stored, 0).await?;
            // Rejected replacements must not break a valid token using the endorsed old key.
            flow.token(f.signed(&f.claims()?)?);
            assert_eq!(
                flow.refresh(f).await.map_err(error)?.status(),
                StatusCode::OK
            );
            assert_eq!(flow.keys.hits(), 2);
            flow.token(flow.signed(&f.claims()?)?);
            federation::bind(&flow, f, serde_json::to_value(flow.new_key.jwks())?).await?;
            assert_eq!(
                flow.refresh(f)
                    .await
                    .expect_err("candidate not cached")
                    .status(),
                StatusCode::BAD_GATEWAY
            );
            assert_eq!(flow.keys.hits(), 2);
            flow.clock.advance(30_000);
            assert_eq!(
                flow.refresh(f).await.map_err(error)?.status(),
                StatusCode::OK
            );
            assert_eq!(flow.keys.hits(), 3);
            assert_eq!(flow.tokens.hits(), 5);
            Ok(())
        })
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL with repository migrations"]
fn upstream_jwks_refresh_pg_connection_change_during_key_fetch_rejects_publication() -> ResultTest {
    for rotate in [false, true] {
        run(false, |rt, f| {
            rt.block_on(async {
                original(f).await?;
                let flow = Flow::new(f).await?;
                let stored = f.stored().await?;
                flow.keys
                    .state
                    .hold
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                flow.tokens.respond(
                    StatusCode::OK,
                    json!({
                        "id_token": flow.signed(&f.claims()?)?,
                        "access_token": "private-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": rotate.then_some("private-refresh-rotated"),
                    })
                    .to_string(),
                );
                let change_connection = async {
                    flow.keys.wait_hits(1).await?;
                    let changed = sqlx::query(
                        "UPDATE aegaeon.connections SET client_id='changed-client' \
                         WHERE environment_id=$1 AND connection_identifier='refresh-test'",
                    )
                    .bind(f.env.environment_id)
                    .execute(&f.pool)
                    .await;
                    flow.keys.state.release.add_permits(1);
                    assert_eq!(changed?.rows_affected(), 1);
                    Ok::<(), Box<dyn Error>>(())
                };
                let (response, changed) = tokio::join!(flow.refresh(f), change_connection);
                changed?;
                let response = response.expect_err("connection changed during key retrieval");
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 16384).await?;
                let body = std::str::from_utf8(&body)?;
                assert_eq!(status, StatusCode::CONFLICT, "{body}");
                assert!(!body.contains("private-"));
                assert_eq!((flow.keys.hits(), flow.tokens.hits()), (1, 1));
                flow.assert_no_effects(f, &stored, 0).await
            })
        })?;
    }
    Ok(())
}
