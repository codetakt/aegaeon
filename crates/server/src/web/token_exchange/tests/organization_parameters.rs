use super::*;

// Return errors so owned schema cleanup also runs on a failed assertion.
macro_rules! check {
    ($condition:expr) => {
        if !$condition {
            return Err(format!("check failed: {}", stringify!($condition)).into());
        }
    };
}
mod fixture;
mod membership;
mod membership_semantics;
mod reader_contract;
use fixture::*;

const ORG_A: &str = "organization_00000000-0000-4000-8000-000000000001";
const ORG_B: &str = "organization_00000000-0000-4000-8000-000000000002";

fn refused(result: &(StatusCode, Value), code: &str) -> TestResult {
    check!(result.0 == StatusCode::BAD_REQUEST);
    check!(result.1["error"] == code);
    check!(result.1.get("access_token").is_none());
    Ok(())
}

async fn code_and_refresh(
    state: &AppState,
    projection: &crate::application_authorization::inorii::Grant,
) -> TestResult<String> {
    let code = projected_code(state, projection)?;
    let body = code_body(&code)?;
    for selector in [ORG_A, " "] {
        refused(
            &send(state, format!("{body}&organization_id={selector}"), true).await?,
            "invalid_request",
        )?;
        check!(state
            .tokens
            .issuer
            .code_store
            .try_get_code(&code)?
            .is_some());
    }
    let bad_auth = send(state, format!("{body}&organizationId={ORG_B}"), false).await?;
    check!(bad_auth.0 == StatusCode::UNAUTHORIZED);
    check!(bad_auth.1["error"] == "invalid_client");
    check!(bad_auth.1.get("access_token").is_none());
    check!(state
        .tokens
        .issuer
        .code_store
        .try_get_code(&code)?
        .is_some());
    let suffix = format!("&organization_id&organization_id=&organizationId={ORG_B}&organizationId=x&unknown=a&unknown=b");
    let (status, issued) = send(state, format!("{body}{suffix}"), true).await?;
    check!(status == StatusCode::OK);
    let audience = format!("{}/userinfo", state.issuer);
    output(state, &issued, Some(projection), &audience, SOURCE_SCOPE)?;
    let refresh = issued["refresh_token"].as_str().ok_or("refresh missing")?;
    let refresh_body =
        serde_urlencoded::to_string([("grant_type", "refresh_token"), ("refresh_token", refresh)])?;
    refused(
        &send(
            state,
            format!("{refresh_body}&organization_id={ORG_A}"),
            true,
        )
        .await?,
        "invalid_request",
    )?;
    check!(
        !state
            .tokens
            .store
            .try_get_refresh_token(refresh)?
            .ok_or("refresh retained")?
            .rotated
    );
    let (status, rotated) = send(state, format!("{refresh_body}{suffix}"), true).await?;
    check!(status == StatusCode::OK);
    output(state, &rotated, Some(projection), &audience, SOURCE_SCOPE)?;
    check!(
        state
            .tokens
            .store
            .try_get_refresh_token(refresh)?
            .ok_or("rotation record")?
            .rotated
    );
    refused(&send(state, refresh_body, true).await?, "invalid_grant")?;
    refused(&send(state, body, true).await?, "invalid_grant")?;
    // Replay may revoke its family. Start a fresh valid family for exchange checks.
    let code = projected_code(state, projection)?;
    let (status, issued) = send(state, code_body(&code)?, true).await?;
    check!(status == StatusCode::OK);
    output(state, &issued, Some(projection), &audience, SOURCE_SCOPE)
}

async fn organization_exchange(
    state: &AppState,
    source: &str,
    projection: &crate::application_authorization::inorii::Grant,
) -> TestResult {
    let original = serde_json::to_value(state.tokens.store.try_get_bearer_meta(source)?)?;
    for suffix in [
        String::new(),
        format!("&organizationId={ORG_A}"),
        "&organization_id=&organization_id".into(),
    ] {
        refused(
            &exchange_raw(state, source, &suffix).await?,
            "invalid_target",
        )?;
    }
    for suffix in [
        format!("&organization_id={ORG_A}&organization_id={ORG_A}"),
        format!("&organization_id={ORG_A}&organization_%69d={ORG_A}"),
    ] {
        refused(
            &exchange_raw(state, source, &suffix).await?,
            "invalid_request",
        )?;
    }
    refused(
        &exchange_raw(state, source, "&organization_id=+").await?,
        "invalid_target",
    )?;
    let expected = projection.restrict("internal-api", Some(ORG_A))?;
    for suffix in [format!("&organization_id={ORG_A}"),
        format!("&organization_id={ORG_A}&organizationId={ORG_B}&organizationId=ignored"),
        "&organization_%69d=organization_%300000000-0000-4000-8000-000000000001&organization_id=&organization_id".into()] {
        let (status, body) = exchange_raw(state,source,&suffix).await?;
        check!(status == StatusCode::OK);
        let selected = output(state,&body,Some(&expected),"internal-api","api.read")?;
        check!(!expected.claims.roles.contains(&crate::application_authorization::inorii::GlobalRole::SuperAdmin));
        for ignored in [String::new(),format!("&organizationId={ORG_B}"),format!("&organization_id={ORG_A}&organizationId={ORG_B}")] {
            let (status, next) = exchange_raw(state,&selected,&ignored).await?;
            check!(status == StatusCode::OK);
            output(state,&next,Some(&expected),"internal-api","api.read")?;
        }
        refused(&exchange_raw(state,&selected,&format!("&organization_id={ORG_B}")).await?,"invalid_target")?;
    }
    check!(serde_json::to_value(state.tokens.store.try_get_bearer_meta(source)?)? == original);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; owns a unique membership schema"]
async fn token_unknown_parameters_preserve_organization_restrictions_and_grants() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let membership = Membership::create(&pool).await?;
        let result = async {
            let (state, projection) = state_with_projection(&pool,&env,&membership,true).await?;
            let source = code_and_refresh(&state,&projection).await?;
            organization_exchange(&state,&source,&projection).await?;
            membership::refusals(&state,&membership,&projection).await?;
            sqlx::query("UPDATE aegaeon.application_authorizations SET enabled=false,revision=revision+1 WHERE environment_id=$1")
                .bind(env.environment_id).execute(&pool).await?;
            refused(&exchange_raw(&state,&source,&format!("&organization_id={ORG_A}&organizationId={ORG_B}")).await?,"invalid_request")?;
            Ok(())
        }.await;
        membership.finish(&pool,result).await
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; owns a unique membership schema"]
async fn token_unknown_parameters_do_not_create_application_authority() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let membership = Membership::create(&pool).await?;
        let result = async {
            let (state, projection) = state_with_projection(&pool,&env,&membership,false).await?;
            let code = projected_code(&state,&projection)?;
            let (status,issued) = send(&state,code_body(&code)?,true).await?;
            check!(status == StatusCode::OK);
            let source = issued["access_token"].as_str().ok_or("source")?;
            let expected = projection.restrict("internal-api",None)?;
            for suffix in [String::new(),format!("&organizationId={ORG_A}&organizationId={ORG_B}")] {
                let (status,body) = exchange_raw(&state,source,&suffix).await?;
                check!(status == StatusCode::OK);
                output(&state,&body,Some(&expected),"internal-api","api.read")?;
                check!(expected.claims.roles.contains(&crate::application_authorization::inorii::GlobalRole::SuperAdmin));
            }
            refused(&exchange_raw(&state,source,&format!("&organization_id={ORG_A}")).await?,"invalid_target")?;
            let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
                "redirect_uri":"https://client.example.com/callback","resource":format!("{}/userinfo",state.issuer),
                "scope":SOURCE_SCOPE,"state":"ordinary-selector-control",
                "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
            let (code,_) = issue_code(&state,req,"ordinary-subject")?;
            let (status,ordinary) = send(&state,code_body(&code)?,true).await?;
            check!(status == StatusCode::OK);
            let source = ordinary["access_token"].as_str().ok_or("ordinary source")?;
            for suffix in [String::new(),format!("&organizationId={ORG_A}")] {
                let (status,body) = exchange_raw(&state,source,&suffix).await?;
                check!(status == StatusCode::OK);
                output(&state,&body,None,"internal-api","api.read")?;
            }
            refused(&exchange_raw(&state,source,&format!("&organization_id={ORG_A}")).await?,"invalid_target")?;
            Ok(())
        }.await;
        membership.finish(&pool,result).await
    }.await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
