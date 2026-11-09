//! Initial request failures use OAuth responses; invalid continuations remain local.
use super::*;

const STATE: &str = "selection&state=\"<roundtrip>\"";

async fn response(
    state: &AppState,
    sid: &str,
    uri: &str,
    form: Option<&[(&str, &str)]>,
) -> TestResult<(StatusCode, Option<String>, String)> {
    let mut request = if form.is_some() {
        Request::post(uri)
    } else {
        Request::get(uri)
    }
    .header(header::COOKIE, format!("aegaeon_auth_session={sid}"));
    let body = if let Some(form) = form {
        request = request
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, state.issuer.as_str());
        serde_urlencoded::to_string(form)?
    } else {
        String::new()
    };
    let mut request = request.body(Body::from(body))?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(state.clone())
        .oneshot(request)
        .await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()?;
    let body = String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?;
    Ok((status, location, body))
}

fn assert_oauth_error(
    state: &AppState,
    mode: Option<&str>,
    observed: &(StatusCode, Option<String>, String),
) -> TestResult {
    let (status, location, body) = observed;
    if mode == Some("form_post") {
        assert_eq!(*status, StatusCode::OK, "{body}");
        assert!(location.is_none());
        assert!(body.contains(
            "<form id=\"aegaeon-form-post\" method=\"post\" action=\"https://example.test/cb\">"
        ));
        for field in [
            "name=\"error\" value=\"invalid_authorization_details\"".to_owned(),
            "name=\"state\" value=\"selection&amp;state=&quot;&lt;roundtrip&gt;&quot;\"".to_owned(),
            format!("name=\"iss\" value=\"{}\"", state.issuer),
        ] {
            assert!(body.contains(&field), "{body}");
        }
        for field in ["code", "access_token", "refresh_token", "transaction"] {
            assert!(!body.contains(&format!("name=\"{field}\"")));
        }
    } else {
        assert_eq!(*status, StatusCode::FOUND, "{body}");
        let target = url::Url::parse(location.as_deref().ok_or("OAuth redirect missing")?)?;
        let mut callback = target.clone();
        callback.set_query(None);
        assert_eq!(callback.as_str(), "https://example.test/cb");
        let fields: std::collections::HashMap<_, _> = target.query_pairs().collect();
        for (key, expected) in [
            ("error", "invalid_authorization_details"),
            ("state", STATE),
            ("iss", state.issuer.as_str()),
        ] {
            assert_eq!(fields.get(key).map(|value| value.as_ref()), Some(expected));
        }
        for field in ["code", "access_token", "refresh_token", "transaction"] {
            assert!(!fields.contains_key(field));
        }
    }
    Ok(())
}

async fn missing_offline_access(mode: Option<&str>) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(
        &state,
        Box::pin(async {
            let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
            for initial in [authorize(&state, &key)?, selector_uri(&state, &key)?] {
                let mut fields: Vec<(String, String)> =
                    serde_urlencoded::from_str(initial.split_once('?').ok_or("query")?.1)?;
                for (name, value) in &mut fields {
                    if name == "scope" {
                        *value = "read".into();
                    }
                    if name == "state" {
                        *value = STATE.into();
                    }
                }
                if let Some(mode) = mode {
                    fields.push(("response_mode".into(), mode.into()));
                }
                let uri = format!("/authorize?{}", serde_urlencoded::to_string(&fields)?);
                assert_oauth_error(&state, mode, &response(&state, &sid, &uri, None).await?)?;

                // Validation must never turn an unregistered callback into an error redirect.
                fields
                    .iter_mut()
                    .find(|(name, _)| name == "redirect_uri")
                    .ok_or("redirect URI")?
                    .1 = "https://unregistered.invalid/callback".into();
                let uri = format!("/authorize?{}", serde_urlencoded::to_string(fields)?);
                let (status, location, body) = response(&state, &sid, &uri, None).await?;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                assert!(location.is_none() && !body.contains("<form"));
            }

            // A valid request still separates selection from explicit grant approval.
            let (status, _, picker) =
                response(&state, &sid, &selector_uri(&state, &key)?, None).await?;
            assert_eq!(status, StatusCode::OK, "{picker}");
            assert!(picker.contains("Select organization"));
            let (status, location, body) = response(
                &state,
                &sid,
                "/auth/consent",
                Some(&[
                    ("transaction", transaction(&picker)?),
                    ("decision", "select:99"),
                ]),
            )
            .await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(location.is_none());
            let error: Value = serde_json::from_str(&body)?;
            assert_eq!(error["error"], "invalid_request");
            assert!(error.get("state").is_none() && error.get("code").is_none());
            let (status, _, consent) =
                response(&state, &sid, &authorize(&state, &key)?, None).await?;
            assert_eq!(status, StatusCode::OK, "{consent}");
            assert!(consent.contains("Organization access") && transaction(&consent).is_ok());
            Ok(())
        }),
    )
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selection_initial_error_default_query() -> TestResult {
    missing_offline_access(None).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selection_initial_error_query() -> TestResult {
    missing_offline_access(Some("query")).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selection_initial_error_form_post() -> TestResult {
    missing_offline_access(Some("form_post")).await
}
