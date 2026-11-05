use super::*;
use axum::{body::Body, extract::ConnectInfo, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;

fn proof(
    issuer: &str,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    path: &str,
    token: Option<&str>,
) -> Result<String> {
    let signing = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&key.pkcs8)?;
    let now = crate::util::now_unix_epoch_secs()?;
    let header = json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(&key.public_key)}});
    let mut claims = json!({"htm":"POST","htu":format!("{issuer}{path}"),"iat":now,"jti":uuid::Uuid::new_v4().to_string()});
    if let Some(token) = token {
        claims["ath"] =
            json!(URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(token.as_bytes())));
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    let proof = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signing.sign(input.as_bytes())?)
    );
    // Validate the fixture signature before exercising the native HTTP verifier.
    assert!(ffi::verify_dpop_with_iat_window(
        &proof,
        "POST",
        &format!("{issuer}{path}"),
        now,
        claims.get("ath").and_then(Value::as_str),
        300
    )
    .is_some());
    Ok(proof)
}
async fn request(
    fixture: &Fixture,
    path: &str,
    authorization: String,
    proof: Option<&str>,
    data: String,
) -> Result<axum::response::Response> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12454))))
        .header("authorization", authorization)
        .header(
            "content-type",
            if path == "/token" {
                "application/x-www-form-urlencoded"
            } else {
                "application/json"
            },
        );
    if let Some(proof) = proof {
        request = request.header("dpop", proof);
    }
    Ok(crate::web::build_router(fixture.state.clone())
        .oneshot(request.body(Body::from(data))?)
        .await?)
}
#[tokio::test]
#[ignore = "requires restricted PostgreSQL; HTTP native DPoP and durable replay decisions"]
async fn pg_lti_default_dpop_launch_checks_ath_scheme_and_replay() -> Result {
    let mut fixture = Fixture::new(true, true).await?;
    let namespace =
        crate::config::RuntimeStateNamespace::from_environment_id(fixture.state.environment_id);
    fixture.state.dpop = std::sync::Arc::new(
        crate::middleware::DpopMiddleware::from_postgres(
            fixture.state.db_pool.clone(),
            namespace.replay_namespace("dpop"),
            fixture.state.issuer.to_string(),
            std::time::Duration::from_secs(601),
        )
        .with_native_verifier_for_tests(),
    );
    let mut tx = fixture.state.db_pool.begin().await?;
    store::activate(&mut tx, fixture.state.environment_id, "tool", 1).await?;
    tx.commit().await?;
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let authorization = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode("context-producer:test-lti-producer-secret")
    );
    let token = body(
        request(
            &fixture,
            "/token",
            authorization,
            Some(&proof(&fixture.state.issuer, &key, "/token", None)?),
            "grant_type=client_credentials&scope=lti%3Alaunch".into(),
        )
        .await?,
    )
    .await?;
    assert_eq!(token.0, StatusCode::OK, "{}", token.1);
    let token: Value = serde_json::from_str(&token.1)?;
    assert_eq!(token["token_type"], "DPoP");
    fixture.access_token = token["access_token"].as_str().ok_or("bound token")?.into();
    let data=json!({"clientId":"tool","deploymentId":"deployment-1","resourceLinkId":"resource-1","userId":fixture.user,"roles":[]}).to_string();
    let authorization = format!("DPoP {}", fixture.access_token);
    for (auth, proof) in [
        (authorization.clone(), None),
        (
            authorization.clone(),
            Some(proof(
                &fixture.state.issuer,
                &key,
                "/lti/launches",
                Some("wrong-token"),
            )?),
        ),
        (
            format!("Bearer {}", fixture.access_token),
            Some(proof(
                &fixture.state.issuer,
                &key,
                "/lti/launches",
                Some(&fixture.access_token),
            )?),
        ),
    ] {
        assert_eq!(
            request(
                &fixture,
                "/lti/launches",
                auth,
                proof.as_deref(),
                data.clone()
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let original = fixture
        .state
        .tokens
        .store
        .try_get_bearer_meta(&fixture.access_token)?
        .ok_or("metadata")?;
    let mut stale = original.clone();
    stale
        .client_credentials_grant
        .as_mut()
        .ok_or("client grant")?
        .context_digest = "0".repeat(64);
    fixture
        .state
        .tokens
        .store
        .try_replace_bearer_meta_record(stale)?;
    let refused = request(
        &fixture,
        "/lti/launches",
        authorization.clone(),
        Some(&proof(
            &fixture.state.issuer,
            &key,
            "/lti/launches",
            Some(&fixture.access_token),
        )?),
        data.clone(),
    )
    .await?;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(refused.headers()["www-authenticate"]
        .to_str()?
        .starts_with("DPoP "));
    fixture
        .state
        .tokens
        .store
        .try_replace_bearer_meta_record(original)?;
    // Preserve the issued token and its matching metadata, but remove the
    // current registration scope. This reaches the producer's own rejection rather
    // than the earlier token/metadata consistency check exercised above.
    let original_scopes: Vec<String> = sqlx::query_scalar("SELECT allowed_scopes FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier='context-producer'")
        .bind(fixture.state.environment_id).fetch_one(&fixture.state.db_pool).await?;
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=ARRAY[]::text[] WHERE environment_id=$1 AND client_identifier='context-producer'")
        .bind(fixture.state.environment_id).execute(&fixture.state.db_pool).await?;
    let refused = request(
        &fixture,
        "/lti/launches",
        authorization.clone(),
        Some(&proof(
            &fixture.state.issuer,
            &key,
            "/lti/launches",
            Some(&fixture.access_token),
        )?),
        data.clone(),
    )
    .await?;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(refused.headers()["www-authenticate"]
        .to_str()?
        .starts_with("DPoP "));
    sqlx::query("UPDATE aegaeon.clients SET allowed_scopes=$2 WHERE environment_id=$1 AND client_identifier='context-producer'")
        .bind(fixture.state.environment_id).bind(original_scopes).execute(&fixture.state.db_pool).await?;
    let proof = proof(
        &fixture.state.issuer,
        &key,
        "/lti/launches",
        Some(&fixture.access_token),
    )?;
    let accepted = body(
        request(
            &fixture,
            "/lti/launches",
            authorization.clone(),
            Some(&proof),
            data.clone(),
        )
        .await?,
    )
    .await?;
    assert_eq!(accepted.0, StatusCode::CREATED, "{}", accepted.1);
    assert_eq!(
        request(&fixture, "/lti/launches", authorization, Some(&proof), data)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let launch: Value = serde_json::from_str(&accepted.1)?;
    let launch = url::Url::parse(launch["launchUrl"].as_str().ok_or("launch URL")?)?;
    let auth = fixture.initiate(launch.path(), true).await?;
    let issued = body(
        fixture
            .send("GET", &format!("/lti/authorize?{auth}"), true, None, None)
            .await?,
    )
    .await?;
    fixture.verify(&hidden(&issued.1, "id_token")?).await?;
    Ok(())
}
