use super::super::initialization::{initialize_management, InitializationInput};
use super::*;
use axum::{
    body::{self, Body},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

mod fingerprints;

fn input() -> InitializationInput {
    InitializationInput {
        owner_email: "owner@example.com".into(),
        owner_password: "test-password-!2026".into(),
        allowed_origins: vec!["https://admin.aegaeon.test".into()],
        issuer_base_domain: "aegaeon.test".into(),
    }
}

// A separate disposable DB is essential: initialization operates on a global singleton.
// Never delete or reseed the caller's database. The CI Postgres role has CREATEDB.
async fn database() -> anyhow::Result<(PgPool, PgPool, String)> {
    let url = std::env::var("AEGAEON_DATABASE_URL")?;
    let control = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await?;
    let name = format!("initialization_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&control)
        .await?;
    let options = control.connect_options().as_ref().clone().database(&name);
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect_with(options)
        .await?;
    sqlx::raw_sql(include_str!("../../../../../../db/schema.sql"))
        .execute(&pool)
        .await?;
    sqlx::query("SET search_path = aegaeon, public")
        .execute(&pool)
        .await?;
    Ok((control, pool, name))
}

async fn cleanup(control: PgPool, pool: PgPool, name: &str) -> anyhow::Result<()> {
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&control)
        .await?;
    control.close().await;
    Ok(())
}

fn request(
    uri: &str,
    payload: serde_json::Value,
    cookie: &str,
    origin: &str,
    csrf: bool,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .header("origin", origin)
        .header("cookie", format!("csrf_token=csrf-test; {cookie}"));
    if csrf {
        request = request.header("x-csrf-token", "csrf-test");
    }
    request
        .extension(ConnectInfo(
            "127.0.0.1:43210".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .body(Body::from(payload.to_string()))
        .unwrap()
}

async fn snapshot(pool: &PgPool, environment: Uuid) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('environment', to_jsonb(e), 'version', to_jsonb(v), 'policy', to_jsonb(p), 'keyStore', to_jsonb(k))::text FROM aegaeon.environments e JOIN aegaeon.configuration_versions v ON v.id = e.active_configuration_version_id JOIN aegaeon.environment_policies p ON p.environment_id=e.id JOIN aegaeon.environment_key_stores k ON k.environment_id=e.id WHERE e.id=$1")
        .bind(environment).fetch_one(pool).await?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_supports_login_and_second_environment_without_repair_sql(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let mut mgmt = test_management_state();
        mgmt.cfg = std::sync::Arc::new(super::super::ManagementConfig::try_from_env_with_database(&pool).await?);
        let app = crate::web::build_router(test_app_state(pool.clone(), mgmt)?);
        let login = serde_json::json!({"email": input().owner_email, "password": input().owner_password});
        let response = app.clone().oneshot(request("/api/v1/authentication/sessions", login, "", "https://admin.aegaeon.test", true)).await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let session = response.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("aegaeon_admin_session=")).expect("login session cookie").split(';').next().unwrap().to_string();
        let uri = format!("/api/v1/teams/{}/tenants/{}/environments", initialized.team_id, initialized.tenant_id);
        let before = snapshot(&pool, initialized.environment_id).await?;
        let payload = serde_json::json!({"name":"Second", "slug":"second"});
        for (cookie, origin, csrf, expected) in [
            (session.as_str(), "https://untrusted.example.com", true, StatusCode::FORBIDDEN),
            (session.as_str(), "https://admin.aegaeon.test", false, StatusCode::FORBIDDEN),
            ("", "https://admin.aegaeon.test", true, StatusCode::UNAUTHORIZED),
        ] {
            let response = app.clone().oneshot(request(&uri, payload.clone(), cookie, origin, csrf)).await?;
            assert_eq!(response.status(), expected);
        }
        let response = app.oneshot(request(&uri, payload, &session, "https://admin.aegaeon.test", true)).await?;
        let status = response.status();
        let bytes = body::to_bytes(response.into_body(), 65536).await?;
        assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&bytes));
        let created: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(created["issuerHost"], "second.primary.local.aegaeon.test");
        assert_eq!(before, snapshot(&pool, initialized.environment_id).await?);
        let second = Uuid::parse_str(created["id"].as_str().unwrap())?;
        assert_ne!(second, initialized.environment_id);
        let document: String = sqlx::query_scalar("SELECT configuration_document::text FROM aegaeon.configuration_versions WHERE id=(SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1)")
            .bind(second).fetch_one(&pool).await?;
        super::super::configuration_documents::prepare_configuration_document(&serde_json::from_str(&document)?, "test").expect("persisted strict v1");
        assert!(initialize_management(&pool, &input()).await.is_err());
        assert_eq!(before, snapshot(&pool, initialized.environment_id).await?);
        let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.api_keys").fetch_one(&pool).await?;
        assert_eq!(keys, 0);
        let audit: String = sqlx::query_scalar("SELECT jsonb_agg(data)::text FROM aegaeon.audit_events").fetch_one(&pool).await?;
        assert!(!audit.contains(&input().owner_password));
        Ok(())
    }.await;
    cleanup(control, pool, &name).await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_rejects_invalid_input_and_rolls_back_all_writes() -> ManagementTestResult
{
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        for origins in [vec![], vec!["https://localhost"], vec!["http://admin.example.com"],
            vec!["https://admin.example.com", "https://ADMIN.example.com/"]] {
            let mut bad = input();
            bad.allowed_origins = origins.into_iter().map(str::to_owned).collect();
            assert!(initialize_management(&pool, &bad).await.is_err());
        }
        let mut bad = input(); bad.owner_password = "short".into();
        assert!(initialize_management(&pool, &bad).await.is_err());
        let mut bad = input(); bad.issuer_base_domain = "bad/path".into();
        assert!(initialize_management(&pool, &bad).await.is_err());
        let admins: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.administrators").fetch_one(&pool).await?;
        assert_eq!(admins, 0);
        // Abort the last required audit write, after owner, policy and topology inserts.
        sqlx::raw_sql("CREATE FUNCTION aegaeon.reject_initialization_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'MANAGEMENT_INITIALIZED' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_initialization_audit BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.reject_initialization_audit();").execute(&pool).await?;
        assert!(initialize_management(&pool, &input()).await.is_err());
        for table in ["administrators", "control_plane_policies", "teams", "tenants", "environments", "configuration_versions", "environment_policies", "environment_key_stores", "environment_scope_allowlist", "team_memberships", "audit_events"] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM aegaeon.{table}")).fetch_one(&pool).await?;
            assert_eq!(count, 0, "rollback must remove {table}");
        }
        sqlx::query("DROP TRIGGER reject_initialization_audit ON aegaeon.audit_events").execute(&pool).await?;
        initialize_management(&pool, &input()).await?;
        Ok(())
    }.await;
    cleanup(control, pool, &name).await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_concurrent_callers_preserve_the_winning_owner() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        // Each new connection defaults to repeatable read; initializer must explicitly
        // select READ COMMITTED before locking so a waiter sees the winner's commit.
        sqlx::query(&format!(
            "ALTER DATABASE {name} SET default_transaction_isolation = 'repeatable read'"
        ))
        .execute(&control)
        .await?;
        let racing = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let first = input();
        let mut other = input();
        other.owner_email = "other@example.com".into();
        let (a, b) = tokio::join!(
            initialize_management(&racing, &first),
            initialize_management(&racing, &other)
        );
        assert_ne!(a.is_ok(), b.is_ok(), "exactly one initializer must succeed");
        let rejected = if let Err(error) = a.as_ref() {
            error
        } else {
            b.as_ref().unwrap_err()
        };
        assert!(
            rejected.to_string().contains("already initialized"),
            "waiting caller must observe the committed owner: {rejected}"
        );
        let email: String = sqlx::query_scalar("SELECT email FROM aegaeon.administrators")
            .fetch_one(&racing)
            .await?;
        assert_eq!(
            email,
            if a.is_ok() {
                "owner@example.com"
            } else {
                "other@example.com"
            }
        );
        assert!(initialize_management(&racing, &first).await.is_err());
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM aegaeon.team_memberships WHERE role='OWNER'")
                .fetch_one(&racing)
                .await?;
        assert_eq!(count, 1);
        racing.close().await;
        Ok(())
    }
    .await;
    cleanup(control, pool, &name).await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_does_not_upgrade_observability_seed() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let seed = super::super::hosted_bootstrap::seed_observability_environment(
            &pool,
            "localhost:8080",
            "aeg_test_readonly_0123456789",
        )
        .await?;
        let before = snapshot(&pool, seed.environment_id).await?;
        assert!(initialize_management(&pool, &input()).await.is_err());
        assert_eq!(before, snapshot(&pool, seed.environment_id).await?);
        let capabilities: Vec<String> =
            sqlx::query_scalar("SELECT capability::text FROM aegaeon.api_key_capabilities")
                .fetch_all(&pool)
                .await?;
        assert_eq!(capabilities, vec!["AUDIT_READ"]);
        Ok(())
    }
    .await;
    cleanup(control, pool, &name).await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_preserves_preexisting_control_plane_policy() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        sqlx::query("INSERT INTO aegaeon.control_plane_policies (id, management_allowed_origins) VALUES ('default', ARRAY['https://existing.example.com'])").execute(&pool).await?;
        let before: String = sqlx::query_scalar("SELECT to_jsonb(p)::text FROM aegaeon.control_plane_policies p").fetch_one(&pool).await?;
        assert!(initialize_management(&pool, &input()).await.is_err());
        let after: String = sqlx::query_scalar("SELECT to_jsonb(p)::text FROM aegaeon.control_plane_policies p").fetch_one(&pool).await?;
        assert_eq!(before, after);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.administrators").fetch_one(&pool).await?;
        assert_eq!(count, 0);
        Ok(())
    }.await;
    cleanup(control, pool, &name).await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_runtime_fingerprints_ignore_search_path() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let default_path = PgPoolOptions::new().max_connections(2)
            .connect_with(pool.connect_options().as_ref().clone().options([("search_path", "public")])).await?;
        let baseline = crate::runtime_configuration::load_database_runtime_configuration(
            &default_path, &initialized.issuer_host).await?;
        let expected = baseline.authority_revision()?;
        // A caller-controlled search_path must not replace the migrated hash function.
        sqlx::raw_sql("CREATE FUNCTION public.digest(text, text) RETURNS bytea LANGUAGE sql AS $$ SELECT decode(repeat('00',32),'hex') $$; CREATE FUNCTION public.digest(bytea, text) RETURNS bytea LANGUAGE sql AS $$ SELECT decode(repeat('00',32),'hex') $$;")
            .execute(&default_path).await?;
        let actual = crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            &default_path, &initialized.issuer_host).await?;
        assert_eq!(expected, actual);
        default_path.close().await;
        Ok(())
    }.await;
    cleanup(control, pool, &name).await?;
    result
}
