//! Registered scope subsets still obey the discovery-only composition rule.
use super::*;

pub(super) async fn authorize_error(
    state: &AppState,
    sid: &str,
    uri: &str,
    expected: &str,
) -> TestResult {
    let mut request = Request::get(uri)
        .header(header::COOKIE, format!("aegaeon_auth_session={sid}"))
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(state.clone())
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let location = response
        .headers()
        .get(header::LOCATION)
        .ok_or("error redirect")?
        .to_str()?;
    let target = url::Url::parse(location)?;
    assert_eq!(
        target.origin().ascii_serialization(),
        "https://example.test"
    );
    assert_eq!(target.path(), "/cb");
    let fields: std::collections::HashMap<_, _> = target.query_pairs().collect();
    assert_eq!(fields.get("error").map(|s| s.as_ref()), Some(expected));
    assert_eq!(
        fields.get("state").map(|s| s.as_ref()),
        Some("organization-browser")
    );
    assert_eq!(
        fields.get("iss").map(|s| s.as_ref()),
        Some(state.issuer.as_str())
    );
    assert!(!fields.contains_key("code") && !fields.contains_key("access_token"));
    Ok(())
}

fn fields(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    scope: &str,
) -> TestResult<Vec<(String, String)>> {
    let ordinary = authorize(state, key)?;
    let mut fields: Vec<(String, String)> =
        serde_urlencoded::from_str(ordinary.split_once('?').ok_or("query")?.1)?;
    fields.retain(|(key, _)| key != "authorization_details");
    for (key, value) in &mut fields {
        if key == "resource" {
            *value = format!("{}/organization-discovery", state.issuer);
        }
        if key == "scope" {
            *value = scope.into();
        }
    }
    Ok(fields)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_scope_composition_is_invalid_scope_in_authorize_and_par(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let mut state = configured_discovery(&f).await?;
    request_objects::shared_request_stores(&mut state).await?;
    let result = fixture::in_epoch(
        &state,
        Box::pin(async {
            let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
            let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
            for scope in [
                "organizations:discover offline_access",
                "organizations:discover read",
            ] {
                let fields = fields(&state, &key, scope)?;
                let uri = format!("/authorize?{}", serde_urlencoded::to_string(&fields)?);
                authorize_error(&state, &sid, &uri, "invalid_scope").await?;
                let refs: Vec<_> = fields
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
                    .collect();
                let (status, body) = request_objects::par(&state, &key, &refs).await?;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                assert_eq!(body["error"], "invalid_scope");
            }
            let fields = fields(&state, &key, DISCOVERY_SCOPE)?;
            let uri = format!("/authorize?{}", serde_urlencoded::to_string(&fields)?);
            let (status, body) = page(&state, &sid, &uri, None).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert!(
                transaction(&body).is_ok(),
                "valid discovery requires a separate approval"
            );
            let refs: Vec<_> = fields
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            let (status, body) = request_objects::par(&state, &key, &refs).await?;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert!(body["request_uri"].is_string());
            Ok(())
        }),
    )
    .await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
