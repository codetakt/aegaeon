use super::{
    authorization_fixture as f,
    support::{remote, unavailable, unavailable_states, TestResult},
};
use crate::web::{self, AppState};
use axum::{
    body::to_bytes,
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
    let form = vec![
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
                Ok(Form(form.clone())),
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
        Ok(Form(form)),
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
    for pushed in [false, true] {
        let (state, sid) = f::fixture().await?;
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
                web::authorize_endpoint::authorize(
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
        let response = web::authorize_endpoint::authorize(
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
        let form = vec![
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
        assert!(state.tokens.issuer.code_store.try_get_code(code)?.is_some());
        assert!(
            matches!(
                state
                    .protocol
                    .request_object_jti_store
                    .check_and_store(f::CLIENT, &jti),
                Err(crate::request_object_store::RequestObjectReplayError::Replay)
            ),
            "the successful code commit records the JAR replay guard"
        );
        if pushed {
            assert!(
                state
                    .protocol
                    .par_store
                    .try_consume_request(&request_uri)
                    .map_err(|e| e.error)?
                    .is_none(),
                "the successful code commit consumes PAR"
            );
        }
    }
    Ok(())
}
