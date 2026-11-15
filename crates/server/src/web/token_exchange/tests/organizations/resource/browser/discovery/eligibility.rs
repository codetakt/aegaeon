//! Existing discovery tokens and new picker/issuance requests use current registration.
use super::*;

async fn rejects_changed_client(change: &str) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(&state, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let parent = discovery_parent(&state, &key, &sid).await?;
        let token = parent["access_token"].as_str().ok_or("discovery token")?;
        let query = serde_urlencoded::to_string([("audience", format!("{}/organizations", state.issuer))])?;
        let audience = format!("{}/organization-discovery", state.issuer);
        let binding: Value = sqlx::query_scalar("SELECT to_jsonb(b) FROM aegaeon.organization_client_bindings b WHERE environment_id=$1 AND client_identifier=$2")
            .bind(state.environment_id).bind(OWNER).fetch_one(&f.pool).await?;
        assert_eq!(memberships(&state, &key, token, &query).await?.0, StatusCode::OK);
        crate::web::organization_resource::discovery::permission(&state, OWNER, &audience)
            .await.map_err(|_| "eligible producer permission refused")?;

        // Each caller supplies a fixed test-only mutation. The binding stays intact.
        sqlx::query(&format!("UPDATE aegaeon.clients SET {change} WHERE environment_id=$1 AND client_identifier=$2"))
            .bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
        let unchanged: Value = sqlx::query_scalar("SELECT to_jsonb(b) FROM aegaeon.organization_client_bindings b WHERE environment_id=$1 AND client_identifier=$2")
            .bind(state.environment_id).bind(OWNER).fetch_one(&f.pool).await?;
        assert_eq!(unchanged, binding);
        let rejected = crate::web::organization_resource::discovery::permission(&state, OWNER, &audience)
            .await.expect_err("ineligible client must not obtain discovery permission");
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&to_bytes(rejected.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "invalid_scope");
        let (status, body) = memberships(&state, &key, token, &query).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "insufficient_scope");
        scope_errors::authorize_error(&state, &sid, &selector_uri(&state, &key)?, "invalid_authorization_details").await?;

        sqlx::query("UPDATE aegaeon.clients SET client_type='CONFIDENTIAL',token_endpoint_authentication_method='client_secret_basic',allowed_grant_types=ARRAY['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'] WHERE environment_id=$1 AND client_identifier=$2")
            .bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
        crate::web::organization_resource::discovery::permission(&state, OWNER, &audience)
            .await.map_err(|_| "restored producer permission refused")?;
        assert_eq!(memberships(&state, &key, token, &query).await?.0, StatusCode::OK);
        let (status, body) = page(&state, &sid, &selector_uri(&state, &key)?, None).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("Select organization") && body.contains(IDENTIFIER));
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_rechecks_token_exchange_eligibility() -> TestResult {
    rejects_changed_client("allowed_grant_types=array_remove(allowed_grant_types,'urn:ietf:params:oauth:grant-type:token-exchange')").await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_rechecks_confidential_client() -> TestResult {
    rejects_changed_client("client_type='PUBLIC',token_endpoint_authentication_method='none'").await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_revoked_permission_is_insufficient_scope(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(&state, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let parent = discovery_parent(&state, &key, &sid).await?;
        let token = parent["access_token"].as_str().ok_or("discovery token")?;
        let audience = format!("{}/organization-discovery", state.issuer);
        let query = serde_urlencoded::to_string([("audience", format!("{}/organizations", state.issuer))])?;
        let targets: Value = sqlx::query_scalar("SELECT targets FROM aegaeon.organization_client_bindings WHERE environment_id=$1 AND client_identifier=$2")
            .bind(state.environment_id).bind(OWNER).fetch_one(&f.pool).await?;
        assert_eq!(memberships(&state, &key, token, &query).await?.0, StatusCode::OK);

        // Keep the registration and business audience active while revoking only
        // the binding's dedicated discovery audience.
        sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=(SELECT jsonb_agg(t) FROM jsonb_array_elements(targets) AS t WHERE t->>'audience' <> $1),revision=revision+1 WHERE environment_id=$2 AND client_identifier=$3")
            .bind(&audience).bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
        let (status, body) = memberships(&state, &key, token, &query).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "insufficient_scope");
        let rejected = crate::web::organization_resource::discovery::permission(&state, OWNER, &audience)
            .await.expect_err("revoked discovery permission must prevent issuance");
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&to_bytes(rejected.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "invalid_scope");

        sqlx::query("UPDATE aegaeon.organization_client_bindings SET targets=$1,revision=revision+1 WHERE environment_id=$2 AND client_identifier=$3")
            .bind(targets).bind(state.environment_id).bind(OWNER).execute(&f.pool).await?;
        assert_eq!(memberships(&state, &key, token, &query).await?.0, StatusCode::OK);
        let (status, body) = memberships(&state, &key, token, &format!("{query}&cursor=invalid!")).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and Redis"]
async fn shared_redis_organizations_discovery_rejects_inconsistent_token_authentication(
) -> TestResult {
    let f = Fixture::with_identifier(IDENTIFIER).await?;
    let state = configured_discovery(&f).await?;
    let result = fixture::in_epoch(&state, Box::pin(async {
        let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
        let sid = session(&state, format!("organization-user-{}", f.users[1])).await?;
        let parent = discovery_parent(&state, &key, &sid).await?;
        let token = parent["access_token"].as_str().ok_or("discovery token")?;
        let original: Value = sqlx::query_scalar("SELECT to_jsonb(c) FROM aegaeon.clients c WHERE environment_id=$1 AND client_identifier=$2")
            .bind(state.environment_id).bind(OWNER).fetch_one(&f.pool).await?;
        // A confidential client cannot independently lose authentication: the
        // existing database invariant rejects the inconsistent registration.
        let rejected = sqlx::query("UPDATE aegaeon.clients SET token_endpoint_authentication_method='none' WHERE environment_id=$1 AND client_identifier=$2")
            .bind(state.environment_id).bind(OWNER).execute(&f.pool).await.expect_err("inconsistent registration must be rejected");
        let database = rejected.as_database_error().ok_or("database rejection")?;
        assert_eq!(database.code().as_deref(), Some("23514"));
        assert_eq!(database.constraint(), Some("clients_auth_method_matches_client_type"));
        let unchanged: Value = sqlx::query_scalar("SELECT to_jsonb(c) FROM aegaeon.clients c WHERE environment_id=$1 AND client_identifier=$2")
            .bind(state.environment_id).bind(OWNER).fetch_one(&f.pool).await?;
        assert_eq!(unchanged, original);
        let audience = format!("{}/organization-discovery", state.issuer);
        crate::web::organization_resource::discovery::permission(&state, OWNER, &audience)
            .await.map_err(|_| "unchanged eligible registration refused")?;
        let query = serde_urlencoded::to_string([("audience", format!("{}/organizations", state.issuer))])?;
        assert_eq!(memberships(&state, &key, token, &query).await?.0, StatusCode::OK);
        Ok(())
    })).await;
    fixture::finish(&state).await?;
    f.cleanup(result).await
}
