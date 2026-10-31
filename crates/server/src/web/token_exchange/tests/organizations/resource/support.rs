use super::*;
use crate::organizations::{repository_tests::support_policy, support as service};
use uuid::Uuid;
mod setup;

async fn send(
    witness: &Arc<crate::organizations::witness::tests::caller_fixture::CallerFixture>,
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    token: &str,
    path: &str,
    method: Method,
    body: Value,
    tag: Option<&str>,
    nonce: &str,
) -> TestResult<(StatusCode, Value, Option<String>)> {
    let proof = crate::web::test_support::native_dpop::proof(
        state,
        key,
        json!({"htm":method.as_str(),"htu":format!("{}{path}",state.issuer),"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),"jti":nonce}),
    )?;
    let mut request = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof);
    if method == Method::POST {
        request = request
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", nonce);
    }
    if let Some(tag) = tag {
        request = request.header(header::IF_MATCH, tag);
    }
    let mut request = request.body(if body.is_null() {
        Body::empty()
    } else {
        Body::from(body.to_string())
    })?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = witness
        .router(
            crate::web::build_router(state.clone()),
            fixture::fixture_class,
        )
        .oneshot(request)
        .await?;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let tag = response
        .headers()
        .get(header::ETAG)
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()?;
    let bytes = to_bytes(response.into_body(), 65536).await?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body, tag))
}

async fn exchange(
    state: &AppState,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
    source: &str,
    id: Option<Uuid>,
) -> TestResult<(StatusCode, Value)> {
    let mut detail = json!({"type":crate::organizations::ORGANIZATION_ACCESS_TYPE,"identifier":IDENTIFIER,"privileges":[PRIVILEGE]});
    if let Some(id) = id {
        detail["admin_access_grant_id"] = json!(id);
    }
    let details = json!([detail]).to_string();
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
            ("audience", &format!("{}/organizations", state.issuer)),
            ("authorization_details", &details),
        ],
        Some(&proof),
        false,
    )
    .await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_support_grants_http_jwt_introspection_and_revocation(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let (state, evidence) = Box::pin(setup::state(&f)).await?;
    let witness = Arc::new(
        crate::organizations::witness::tests::caller_fixture::CallerFixture::new(
            state.environment_id,
        )
        .await?,
    );
    let result =
        fixture::in_witness(&witness, Box::pin(flow(&f, &state, &evidence, &witness))).await;
    let result = result.and(fixture::finish_witness(witness).await);
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

async fn flow(
    f: &Fixture,
    state: &AppState,
    evidence: &crate::organizations::authentication::OriginalAuthentication,
    witness: &Arc<crate::organizations::witness::tests::caller_fixture::CallerFixture>,
) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let (parent, activation) = setup::parent(f, state, &key, evidence).await?;
    let source = parent["access_token"].as_str().ok_or("source")?;
    assert_eq!(
        exchange(state, &key, source, None).await?.0,
        StatusCode::BAD_REQUEST
    );
    let path = format!(
        "/organization-support/{}/grants",
        f.organization.scope.domain_id
    );
    let tag = format!("\"{}.{}\"", f.organization.id, f.organization.revision);
    let body = json!({"organizationId":f.organization.id,"audience":format!("{}/organizations",state.issuer),"roles":["reader"],"reason":"Requested support"});
    assert_eq!(
        send(
            witness,
            state,
            &key,
            source,
            &format!("/organization-support/{}/grants", Uuid::new_v4()),
            Method::POST,
            body.clone(),
            Some(&tag),
            "wrong-domain"
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            witness,
            state,
            &key,
            &activation,
            &path,
            Method::POST,
            body.clone(),
            None,
            "missing-tag"
        )
        .await?
        .0,
        StatusCode::PRECONDITION_REQUIRED
    );
    let (status, grant, validator) = send(
        witness,
        state,
        &key,
        &activation,
        &path,
        Method::POST,
        body.clone(),
        Some(&tag),
        "activate",
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let id: Uuid = serde_json::from_value(grant["id"].clone())?;
    assert!(grant["expiresAt"].as_i64().ok_or("expiry")? <= evidence.auth_time + 300);
    assert_eq!(
        send(
            witness,
            state,
            &key,
            &activation,
            &path,
            Method::POST,
            body,
            Some(&tag),
            "activate"
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED,
        "exact DPoP replay refused before idempotency"
    );
    let (status, selected) = exchange(state, &key, source, Some(id)).await?;
    assert_eq!(status, StatusCode::OK, "{selected}");
    let details = &selected["authorization_details"];
    assert_eq!(details[0]["access_basis"], "administrative_grant");
    assert_eq!(details[0]["admin_access_grant_id"], id.to_string());
    assert_eq!(details[0]["identifier"], IDENTIFIER);
    assert_eq!(
        crate::web::token_exchange::tests::jwt(&selected)?["authorization_details"],
        *details
    );
    let token = selected["access_token"].as_str().ok_or("selected")?;
    let proof = super::proof(state, &key, token, "GET", json!({}))?;
    assert_eq!(
        get(
            state,
            Method::GET,
            PATH,
            Some(&format!("DPoP {token}")),
            Some(&proof),
            ""
        )
        .await?
        .0,
        StatusCode::OK
    );
    // This resource's only introspection recipient is explicitly registered.
    for signed in [false, true] {
        let (status, value) =
            http(state, "/introspect", RS, &[("token", token)], None, signed).await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        // The shared helper verifies and unwraps signed introspection responses.
        assert_eq!(value["active"], true, "{value}");
        assert_eq!(value["authorization_details"], *details);
    }
    let read_path = format!("{path}/{id}");
    assert_eq!(
        send(
            witness,
            state,
            &key,
            &activation,
            &read_path,
            Method::GET,
            Value::Null,
            None,
            "read"
        )
        .await?
        .0,
        StatusCode::OK
    );
    // A disabled policy removes resource access, but the owner can still revoke.
    support_policy::configure(f, "off", 2, None).await?;
    let proof = super::proof(state, &key, token, "GET", json!({}))?;
    assert_eq!(
        get(
            state,
            Method::GET,
            PATH,
            Some(&format!("DPoP {token}")),
            Some(&proof),
            ""
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, revoked, _) = send(
        witness,
        state,
        &key,
        &activation,
        &format!("{read_path}/revoke"),
        Method::POST,
        json!({"reason":"Completed support"}),
        validator.as_deref(),
        "revoke",
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(revoked["state"], "revoked");
    let (_, value) = http(state, "/introspect", RS, &[("token", token)], None, false).await?;
    assert_eq!(value, json!({"active":false}));
    Ok(())
}
