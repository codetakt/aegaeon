use super::*;
use crate::application_authorization::{store::capture, Authority};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_projection_exchange_audits_with_one_connection() -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = fixture(&pool, &env).await?;
        state.application_authority = Some(Authority {
            projections: pool.clone(),
            memberships: None,
        });
        let audience = format!("{}/userinfo", state.issuer);
        seed_test_projection(&pool, &env, CLIENT, "exchange-user", json!([audience, "internal-api"]),
            json!({"roles":["USER"],"organization_roles":[]})).await?;
        let projection = capture(&pool, env.environment_id, &env.issuer_url, CLIENT, "exchange-user")
            .await?.ok_or("projection")?;
        let req = serde_json::from_value(json!({"response_type":"code","client_id":CLIENT,
            "redirect_uri":"https://client.example.com/callback","resource":audience,
            "scope":SOURCE_SCOPE,"state":"projection-pool",
            "code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}))?;
        let client = state.clients.try_get(CLIENT)?.ok_or("client")?;
        let input = crate::authcode::AuthorizationCodeIssueInput {
            application_grant: Some(projection.clone()),
            exchange_scope_ceiling: client.allowed_scopes,
            ..crate::authcode::AuthorizationCodeIssueInput::new(req, "exchange-user".into(), true, 0)
        };
        let (code, _) = state.tokens.issuer.issue_authorization_code_with_local_profile(input)?;
        let (status, source) = request(&state, &[
            ("grant_type", "authorization_code"), ("code", &code), ("client_id", CLIENT),
            ("redirect_uri", "https://client.example.com/callback"), ("code_verifier", VERIFIER),
        ], true).await?;
        assert_eq!(status, StatusCode::OK, "{source}");
        let source = source["access_token"].as_str().ok_or("access token")?;
        let meta = state.tokens.store.try_get_bearer_meta(source)?.ok_or("metadata")?;
        assert_eq!(meta.application_grant, Some(projection.clone()));
        let (status, output) = exchange(&state, source, &[("audience", "internal-api")], true).await?;
        assert_eq!(status, StatusCode::OK, "{output}");
        let token = output["access_token"].as_str().ok_or("exchanged token")?;
        let output_meta = state.tokens.store.try_get_bearer_meta(token)?.ok_or("output metadata")?;
        assert_eq!(output_meta.application_grant, Some(projection.restrict("internal-api", None)?));
        let events: Vec<(String, String)> = sqlx::query_as("SELECT outcome,target_id FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='oauth.token.issue.requested.v1' AND target_id=$2")
            .bind(env.environment_id).bind(TOKEN_EXCHANGE_GRANT_TYPE).fetch_all(&pool).await?;
        assert_eq!(events, vec![("requested".into(), TOKEN_EXCHANGE_GRANT_TYPE.into())]);
        let function = format!("projection_audit_failure_{}", env.environment_id.simple());
        sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND NEW.event_type='oauth.token.issue.requested.v1' THEN RAISE EXCEPTION 'fixture audit refusal'; END IF; RETURN NEW; END $$; CREATE TRIGGER {function} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{function}()", env.environment_id))
            .execute(&pool).await?;
        let failure = exchange(&state, source, &[("audience", "internal-api")], true).await;
        sqlx::raw_sql(&format!("DROP TRIGGER {function} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{function}()"))
            .execute(&pool).await?;
        let (status, failure) = failure?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(failure["error"], "temporarily_unavailable");
        assert!(failure.get("access_token").is_none());
        sqlx::query("UPDATE aegaeon.application_authorizations SET enabled=false,revision=2,source_revision=2 WHERE environment_id=$1")
            .bind(env.environment_id).execute(&pool).await?;
        let (status, denied) = exchange(&state, source, &[("audience", "internal-api")], true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
        assert_eq!(denied["error"], "invalid_request");
        assert!(denied.get("access_token").is_none());
        // A token without an application projection still uses the ordinary path.
        let ordinary = grant(&state).await?;
        let ordinary = ordinary["access_token"].as_str().ok_or("ordinary token")?;
        let (status, output) = exchange(&state, ordinary, &[("audience", "internal-api")], true).await?;
        assert_eq!(status, StatusCode::OK, "{output}");
        Ok(())
    }.await;
    sqlx::query("DELETE FROM aegaeon.application_authorizations WHERE environment_id=$1")
        .bind(env.environment_id)
        .execute(&pool)
        .await?;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
