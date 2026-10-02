use super::*;

async fn valid_credentials(state: &AppState) -> TestResult {
    let invisible = token(state, PUBLIC)?;
    for caller in [OWNER, POST, ASSERTION] {
        let visible = token(state, caller)?;
        for jwt in [false, true] {
            let accept = jwt.then_some("application/token-introspection+jwt");
            let signed = jwt && state.cfg.jwt_runtime().introspection_enabled();
            for (value, active) in [
                (visible.token.as_str(), true),
                ("unknown-token", false),
                (invisible.token.as_str(), false),
            ] {
                let auth = (caller == OWNER).then(|| basic(OWNER, SECRET));
                let assertion = assertion(state)?;
                let fields = match caller {
                    POST => vec![("client_id", POST), ("client_secret", SECRET)],
                    ASSERTION => assertion_fields(&assertion),
                    _ => vec![],
                };
                success(
                    request(state, value, &fields, auth.as_deref(), accept).await?,
                    state,
                    caller,
                    signed,
                    active,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn invalid_credentials(state: &AppState) -> TestResult {
    let access = token(state, OWNER)?;
    for accept in [None, Some("application/token-introspection+jwt")] {
        for (fields, auth) in [
            (vec![], Some(basic(OWNER, "wrong"))),
            (vec![("client_id", POST), ("client_secret", "wrong")], None),
            (assertion_fields("not-a-jwt"), None),
            (vec![("client_id", POST)], Some(basic(OWNER, SECRET))),
            (
                vec![("client_id", POST), ("client_secret", SECRET)],
                Some(basic(OWNER, SECRET)),
            ),
            (vec![("client_id", PUBLIC), ("client_secret", SECRET)], None),
        ] {
            error(
                request(state, &access.token, &fields, auth.as_deref(), accept).await?,
                state,
                StatusCode::UNAUTHORIZED,
            )
            .await?;
        }
        let value = assertion(state)?;
        let fields = assertion_fields(&value);
        // A mixed-method early refusal must not consume the valid assertion.
        error(
            request(
                state,
                "unknown-token",
                &fields,
                Some(&basic(OWNER, SECRET)),
                accept,
            )
            .await?,
            state,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        let signed = accept.is_some() && state.cfg.jwt_runtime().introspection_enabled();
        success(
            request(state, "unknown-token", &fields, None, accept).await?,
            state,
            ASSERTION,
            signed,
            false,
        )
        .await?;
        error(
            request(state, "unknown-token", &fields, None, accept).await?,
            state,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_authentication_preserves_credentials_visibility_and_replay() -> TestResult {
    for jwt in [false, true] {
        let fixture = fixture(jwt, false).await?;
        let result = async {
            valid_credentials(&fixture.state).await?;
            invalid_credentials(&fixture.state).await
        }
        .await;
        fixture.finish(result).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn introspection_authentication_profile_refusal_preserves_assertion_consumption() -> TestResult
{
    let mut fixture = fixture(true, false).await?;
    let result = async {
        sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=$1 WHERE environment_id=$2")
            .bind(vec!["none"]).bind(fixture.env.environment_id).execute(&fixture.pool).await?;
        let value = assertion(&fixture.state)?;
        let fields = assertion_fields(&value);
        for (fields,auth) in [
            (vec![],Some(basic(OWNER,SECRET))),
            (vec![("client_id",POST),("client_secret",SECRET)],None),
            (fields.clone(),None),
        ] {
            error(request(&fixture.state,"unknown-token",&fields,auth.as_deref(),None).await?,&fixture.state,StatusCode::UNAUTHORIZED).await?;
        }
        sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=$1 WHERE environment_id=$2")
            .bind(vec!["private_key_jwt"]).bind(fixture.env.environment_id).execute(&fixture.pool).await?;
        // Authentication preceded profile refusal, so this assertion is already consumed.
        error(request(&fixture.state,"unknown-token",&fields,None,None).await?,&fixture.state,StatusCode::UNAUTHORIZED).await?;
        let fresh = assertion(&fixture.state)?;
        success(request(&fixture.state,"unknown-token",&assertion_fields(&fresh),None,None).await?,&fixture.state,ASSERTION,false,false).await?;
        // Reload remains permitted with the original persisted false flag.
        reload_authorization_runtime(&mut fixture.state).await?;
        assert!(fixture.state.cfg.require_client_auth_introspection);
        Ok(())
    }.await;
    fixture.finish(result).await
}
