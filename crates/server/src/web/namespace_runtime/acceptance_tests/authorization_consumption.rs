use super::{
    authorization_fixture as f,
    support::{remote, unavailable, unavailable_states, TestResult},
};
use crate::web::{self, AppState};
use axum::{
    body::{to_bytes, Bytes},
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Form,
};
use serde_json::Value;

async fn body(response: Response, expected: StatusCode) -> TestResult<String> {
    let status = response.status();
    let text = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
    assert_eq!(status, expected, "{text}");
    Ok(text)
}

async fn consent_rows(state: &AppState) -> TestResult<Vec<Value>> {
    Ok(sqlx::query_scalar("SELECT to_jsonb(c) FROM aegaeon.authorization_consents c WHERE environment_id=$1 ORDER BY id")
        .bind(state.environment_id).fetch_all(&state.db_pool).await?)
}

async fn pushed_uri(
    state: &AppState,
    headers: &HeaderMap,
    jwt: &str,
) -> TestResult<(String, String)> {
    let mut headers = headers.clone();
    headers.insert("content-type", "application/x-www-form-urlencoded".parse()?);
    let form: Vec<(String, String)> = vec![
        ("client_id".into(), f::CLIENT.into()),
        ("request".into(), jwt.into()),
    ];
    for denied in unavailable_states(state) {
        unavailable(
            web::par_endpoint::par(
                State(denied),
                remote(),
                OriginalUri("/par".parse()?),
                headers.clone(),
                Ok(Bytes::from(serde_urlencoded::to_string(&form)?)),
            )
            .await,
        )
        .await?;
    }
    let response = web::par_endpoint::par(
        State(state.clone()),
        remote(),
        OriginalUri("/par".parse()?),
        headers.clone(),
        Ok(Bytes::from(serde_urlencoded::to_string(&form)?)),
    )
    .await;
    let result: Value = serde_json::from_str(&body(response, StatusCode::CREATED).await?)?;
    let request_uri = result["request_uri"]
        .as_str()
        .ok_or("PAR URI missing")?
        .to_owned();
    Ok((
        format!(
            "/authorize?{}",
            serde_urlencoded::to_string([
                ("client_id", f::CLIENT),
                ("request_uri", request_uri.as_str())
            ])?
        ),
        request_uri,
    ))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_par_jar_and_consent_remain_usable_then_commit_one_code() -> TestResult {
    exercise_publication(false, false).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime; native SQL PAR/JAR/code publication through consent"]
async fn pg_namespace_sql_par_jar_consent_publish_code_atomically() -> TestResult {
    exercise_publication(true, false).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime; real SQL consent/code/refresh HTTP flow"]
async fn pg_namespace_sql_consent_code_and_refresh_http() -> TestResult {
    exercise_publication(true, true).await
}

async fn use_postgres(state: &mut AppState, redeem: bool) -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let database =
        crate::authcode::store::PostgresGrantDatabase::new(state.db_pool.clone(), &namespace);
    // Replace the fixture stores before revalidating the real database-bound permit.
    state.subject_namespace = None;
    std::sync::Arc::get_mut(&mut state.tokens.issuer)
        .ok_or("test issuer must be uniquely owned")?
        .code_store = crate::authcode::AuthCodeStore::from_postgres(
        database.clone(),
        std::time::Duration::from_secs(300),
    )?;
    if redeem {
        let sessions = crate::oidc::OidcSessionStore::from_postgres(60, database.clone())?;
        let policy = state.cfg.token_runtime();
        let issuer = crate::authcode::TokenIssuer::from_postgres_with_ttls(
            state.keys.access_token.clone(),
            policy.access_token_ttl_secs(),
            policy.refresh_token_ttl_secs(),
            policy.authorization_code_ttl_secs(),
            database.clone(),
        )?
        .with_oidc(state.oidc.config.as_deref().cloned())
        .with_oidc_sessions(Some(sessions.clone()))
        .with_issuer(state.issuer.to_string())
        .with_token_exchange_policy(state.cfg.token_exchange.clone())
        .with_jwt_access_tokens_enabled(policy.jwt().access_tokens_enabled());
        let tokens = issuer.token_store.clone();
        state.tokens.issuer = std::sync::Arc::new(issuer);
        let mut validator = state.tokens.validator.as_ref().clone();
        validator.replace_store_for_tests(tokens.clone());
        state.tokens.validator = std::sync::Arc::new(validator);
        state.tokens.store = std::sync::Arc::new(tokens);
        state.oidc.sessions = Some(sessions);
    }
    let par = std::sync::Arc::new(crate::par::ParStore::from_postgres(90, database.clone())?);
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?;
    state.protocol.par_endpoint = std::sync::Arc::new(crate::par::ParEndpoint::new(
        std::sync::Arc::new(crate::metrics_integration::MetricsIntegration::new(
            std::sync::Arc::new(metrics),
        )),
        par.clone(),
    ));
    state.protocol.par_store = par;
    state.protocol.request_object_jti_store = std::sync::Arc::new(
        crate::request_object_store::RequestObjectJtiStore::from_postgres(300, database)?,
    );
    state.validate_subject_namespace().await?;
    Ok(())
}

async fn exercise_publication(postgres: bool, redeem: bool) -> TestResult {
    for pushed in [false, true] {
        let (mut state, sid) = f::fixture().await?;
        if postgres {
            use_postgres(&mut state, redeem).await?;
        }
        let headers = f::headers(&state, &sid)?;
        let jti = uuid::Uuid::new_v4().to_string();
        let jwt = f::signed_request(&state, &jti)?;
        let (uri, request_uri) = if pushed {
            pushed_uri(&state, &headers, &jwt).await?
        } else {
            (
                format!(
                    "/authorize?{}",
                    serde_urlencoded::to_string([
                        ("client_id", f::CLIENT),
                        ("request", jwt.as_str())
                    ])?
                ),
                String::new(),
            )
        };
        for denied in unavailable_states(&state) {
            unavailable(
                super::support::authorize(
                    State(denied),
                    remote(),
                    headers.clone(),
                    OriginalUri(uri.parse()?),
                )
                .await,
            )
            .await?;
            assert!(consent_rows(&state).await?.is_empty());
        }
        let response = super::support::authorize(
            State(state.clone()),
            remote(),
            headers.clone(),
            OriginalUri(uri.parse()?),
        )
        .await;
        let html = body(response, StatusCode::OK).await?;
        let transaction = html
            .split("name=\"transaction\" value=\"")
            .nth(1)
            .and_then(|tail| tail.split('"').next())
            .ok_or("consent transaction missing")?;
        let form: Vec<(String, String)> = vec![
            ("transaction".into(), transaction.into()),
            ("decision".into(), "approve".into()),
        ];
        let before = consent_rows(&state).await?;
        assert_eq!(before.len(), 1);
        for denied in unavailable_states(&state) {
            unavailable(
                web::authorize_endpoint::consent_submit(
                    State(denied),
                    headers.clone(),
                    Ok(Form(form.clone())),
                )
                .await,
            )
            .await?;
            assert_eq!(consent_rows(&state).await?, before);
        }
        let response =
            web::authorize_endpoint::consent_submit(State(state.clone()), headers, Ok(Form(form)))
                .await;
        let result: Value = serde_json::from_str(&body(response, StatusCode::OK).await?)?;
        let code = result["code"]
            .as_str()
            .ok_or("code missing after consent")?;
        assert!(state
            .tokens
            .issuer
            .code_store
            .try_get_code_async(code.to_owned())
            .await?
            .is_some());
        assert!(
            matches!(
                state
                    .protocol
                    .request_object_jti_store
                    .check_and_store_for_async(
                        f::CLIENT.to_owned(),
                        jti,
                        std::time::Duration::from_secs(60)
                    )
                    .await,
                Err(crate::request_object_store::RequestObjectReplayError::Replay)
            ),
            "the successful code commit records the JAR replay guard"
        );
        if pushed {
            assert!(
                state
                    .protocol
                    .par_store
                    .clone()
                    .try_consume_request_async(request_uri)
                    .await
                    .map_err(|e| e.error)?
                    .is_none(),
                "the successful code commit consumes PAR"
            );
        }
        if redeem {
            Box::pin(super::authorization_redemption::redeem(&state, code)).await?;
        }
    }
    Ok(())
}
