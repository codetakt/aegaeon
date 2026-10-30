//! Actual client authentication, DPoP, RS256, Redis commit and current primary checks.
use super::*;
use crate::organizations::repository_tests::Fixture;
mod fixture;
mod happy;
mod invitation_recipient;
mod publication;
mod recipients;
mod resource;

const OWNER: &str = "consent-client";
const RS: &str = "explicit-resource-server";
const IDENTIFIER: &str = "学校/É-%2f";

async fn http(
    state: &AppState,
    path: &str,
    client: &str,
    fields: &[(&str, &str)],
    proof: Option<&str>,
    signed: bool,
) -> TestResult<(StatusCode, Value)> {
    let app = Router::new()
        .route("/token", post(crate::web::token_endpoint::token))
        .route("/introspect", post(crate::web::token_lifecycle::introspect))
        .layer(Extension(ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            12543,
        )))))
        .with_state(state.clone());
    let mut req = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{client}:{SECRET}"))),
        );
    if let Some(proof) = proof {
        req = req.header("DPoP", proof);
    }
    if signed {
        req = req.header(header::ACCEPT, "application/token-introspection+jwt");
    }
    let response = app
        .oneshot(req.body(Body::from(serde_urlencoded::to_string(fields)?))?)
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = if signed && status == StatusCode::OK {
        let jwt = std::str::from_utf8(&bytes)?;
        let parts: Vec<_> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert_eq!(payload["aud"], client);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
        assert!(state
            .keys
            .jwt_introspection
            .as_ref()
            .ok_or("signer")?
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)?);
        payload["token_introspection"].clone()
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}

fn selection(id: &str) -> String {
    json!([{"type":crate::organizations::ORGANIZATION_ACCESS_TYPE,"identifier":id,"privileges":["documents.read"]}]).to_string()
}
async fn select(
    state: &AppState,
    source: &str,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    id: &str,
) -> TestResult<(StatusCode, Value)> {
    let proof = crate::web::test_support::native_dpop::proof(state, key, json!({}))?;
    http(
        state,
        "/token",
        OWNER,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", source),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", "management-api"),
            ("authorization_details", &selection(id)),
        ],
        Some(&proof),
        false,
    )
    .await
}
async fn inspect(state: &AppState, token: &str, client: &str, active: bool) -> TestResult {
    for signed in [false, true] {
        let (status, body) = http(
            state,
            "/introspect",
            client,
            &[("token", token)],
            None,
            signed,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "introspection: {body}");
        assert_eq!(body["active"], active, "{body}");
        if !active {
            assert_eq!(body, json!({"active":false}));
        } else {
            assert_eq!(body["authorization_details"][0]["identifier"], IDENTIFIER);
            assert!(body.get("selected_organization").is_none());
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selected_sender_replay_storage_and_metadata_refusal(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = fixture::state(&f).await?;
    let result = async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let parent = fixture::parent(&f, &state, &key).await?;
        let source = parent["access_token"].as_str().ok_or("parent")?;
        let details = selection(IDENTIFIER);
        let fields = [
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", source),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", "management-api"),
            ("authorization_details", details.as_str()),
        ];
        let wrong = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let wrong = crate::web::test_support::native_dpop::proof(&state, &wrong, json!({}))?;
        for proof in [None, Some(wrong.as_str())] {
            assert_eq!(
                http(&state, "/token", OWNER, &fields, proof, false)
                    .await?
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        for extra in [
            ("resource", "https://api.example/resource"),
            ("audience", "management-api"),
            ("organization_id", IDENTIFIER),
        ] {
            let mut invalid = fields.to_vec();
            invalid.push(extra);
            let proof = crate::web::test_support::native_dpop::proof(&state, &key, json!({}))?;
            assert_eq!(
                http(&state, "/token", OWNER, &invalid, Some(&proof), false)
                    .await?
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        let proof = crate::web::test_support::native_dpop::proof(&state, &key, json!({}))?;
        let (status, body) = http(&state, "/token", OWNER, &fields, Some(&proof), false).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["access_token"].as_str().ok_or("selected")?;
        assert_eq!(
            http(&state, "/token", OWNER, &fields, Some(&proof), false)
                .await?
                .0,
            StatusCode::BAD_REQUEST
        );
        let original = state
            .tokens
            .store
            .try_get_bearer_meta(token)?
            .ok_or("metadata")?;
        for field in ["details", "snapshot", "root", "authentication"] {
            let mut corrupt = original.clone();
            match field {
                "details" => {
                    corrupt.authorization_details.as_mut().ok_or("details")?[0]["identifier"] =
                        json!("other")
                }
                "snapshot" => corrupt.selected_organization = None,
                "root" => corrupt.exchange_grant = None,
                _ => corrupt.auth_time_epoch_secs = Some(1),
            }
            state.tokens.store.try_replace_bearer_meta_record(corrupt)?;
            inspect(&state, token, RS, false).await?;
        }
        state
            .tokens
            .store
            .try_replace_bearer_meta_record(original)?;
        publication::refuses_changed_output(&state, source, token).await?;
        inspect(&state, token, RS, true).await?;
        let mut unavailable = state.clone();
        unavailable.db_pool = sqlx::postgres::PgPoolOptions::new()
            .connect_with(f.pool.connect_options().as_ref().clone())
            .await?;
        unavailable.db_pool.close().await;
        assert_eq!(
            http(
                &unavailable,
                "/introspect",
                RS,
                &[("token", token)],
                None,
                false
            )
            .await?
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        inspect(&state, token, RS, true).await?;
        state
            .tokens
            .store
            .try_revoke_token(parent["refresh_token"].as_str().ok_or("refresh")?)?;
        inspect(&state, token, RS, false).await?;
        assert_eq!(
            select(&state, source, &key, IDENTIFIER).await?.0,
            StatusCode::BAD_REQUEST
        );
        Ok(())
    }
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
