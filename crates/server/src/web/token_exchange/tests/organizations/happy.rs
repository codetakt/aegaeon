use super::*;

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_selected_exchange_and_introspection_currentness() -> TestResult
{
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = Box::pin(fixture::state(&f)).await?;
    let result = Box::pin(flow(&f, &state)).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

async fn flow(f: &Fixture, state: &AppState) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let parent = Box::pin(fixture::parent(f, state, &key)).await?;
    let source = parent["access_token"].as_str().ok_or("parent")?;
    let token = Box::pin(exchange_and_observe(state, &parent, &key)).await?;
    Box::pin(suspend(f)).await?;
    inspect(state, &token, RS, false).await?;
    assert_eq!(
        select(state, source, &key, IDENTIFIER).await?.0,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn exchange_and_observe(
    state: &AppState,
    parent: &Value,
    key: &aegaeon_crypto::signing::Ed25519KeyData,
) -> TestResult<String> {
    let source = parent["access_token"].as_str().ok_or("parent")?;
    for wrong in ["学校/é-%2f", "学校/E\u{301}-%2f", "opaque-01"] {
        let (status, body) = select(state, source, key, wrong).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.get("access_token").is_none());
    }
    let (status, body) = select(state, source, key, IDENTIFIER).await?;
    assert_eq!(status, StatusCode::OK, "selected exchange: {body}");
    assert_eq!(body["token_type"], "DPoP");
    assert!(body.get("refresh_token").is_none());
    let token = body["access_token"].as_str().ok_or("selected")?;
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').next().ok_or("header")?)?)?;
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "at+jwt");
    assert!(body["expires_in"]
        .as_u64()
        .is_some_and(|v| v > 0 && v <= 300));
    let claims = super::super::jwt(&body)?;
    assert_eq!(
        claims["authorization_details"],
        body["authorization_details"]
    );
    assert_eq!(claims["authorization_details"][0]["identifier"], IDENTIFIER);
    assert_eq!(claims["auth_time"], super::super::jwt(parent)?["auth_time"]);
    assert!(claims.get("selected_organization").is_none());
    assert_eq!(
        state.tokens.validator.introspect_token(token),
        json!({"active":false})
    );
    inspect(state, token, RS, true).await?;
    inspect(state, token, OWNER, false).await?;
    let (status, body) = select(state, token, key, IDENTIFIER).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "chaining: {body}");
    Ok(token.into())
}

async fn suspend(f: &Fixture) -> TestResult {
    let mut tx = f.pool.begin().await?;
    let member = crate::organizations::repository::membership(&mut tx, &f.organization, f.users[1])
        .await?
        .ok_or("member")?;
    crate::organizations::repository::update_membership(
        &mut tx,
        f.organization.scope,
        f.organization.id,
        crate::organizations::repository::MembershipUpdate {
            user_id: f.users[1],
            expected_revision: member.revision,
            state: crate::organizations::MembershipState::Suspended,
            roles: member.roles,
        },
        &f.actor,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
