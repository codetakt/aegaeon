use super::*;
use crate::dcr_persistence::{DcrClientSecretChange, DcrStoredClient};
use crate::web::test_support::TestResult;
use std::time::Duration;
use tokio::task::JoinSet;

async fn named_pool(pool: &PgPool, name: &str) -> TestResult<PgPool> {
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            pool.connect_options()
                .as_ref()
                .clone()
                .application_name(name),
        )
        .await?)
}

async fn wait_blocker(pool: &PgPool, name: &str, blocker: i32) -> TestResult<i32> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND $2=ANY(pg_blocking_pids(pid))",
            ).bind(name).bind(blocker).fetch_optional(pool).await?;
            if let Some(pid) = pid {
                return Ok::<_, sqlx::Error>(pid);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.map_err(|error| std::io::Error::other(format!("{name} did not wait on backend {blocker}: {error}")))??)
}

async fn seed(pool: &PgPool) -> TestResult<(TestEnvironment, DcrStoredClient)> {
    let init = initialize_management(pool, &input()).await?;
    let env = TestEnvironment {
        team_id: init.team_id,
        tenant_id: init.tenant_id,
        environment_id: init.environment_id,
        issuer_url: format!("https://{}", init.issuer_host),
        issuer_host: init.issuer_host,
    };
    sqlx::query("INSERT INTO aegaeon.oauth_profiles (environment_id,configuration_version_id,name,profile_type,is_default,allowed_grant_types,token_endpoint_auth_methods_allowed) VALUES ($1,$2,'lock-order','DOWNSTREAM',true,ARRAY['authorization_code','client_credentials'],ARRAY['client_secret_basic','none'])")
        .bind(env.environment_id).bind(init.configuration_version_id).execute(pool).await?;
    let mut client = sample_registered_client("concurrent-metadata");
    client.token_endpoint_auth_method = "client_secret_basic".into();
    client.client_secret = Some("fixture-secret".into());
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "old-owner-token",
        "seed",
    )
    .await?;
    let stored = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &client.client_id,
        "old-owner-token",
    )
    .await?
    .ok_or("stored registration")?;
    Ok((env, stored))
}

async fn owner_mutation(
    pool: &PgPool,
    stored: &DcrStoredClient,
    delete: bool,
) -> Result<(), String> {
    if delete {
        crate::dcr_persistence::delete_dynamic_registration(pool, stored, "concurrent-owner")
            .await
            .map_err(|error| error.to_string())
    } else {
        crate::dcr_persistence::update_dynamic_registration(
            pool,
            stored,
            &stored.client,
            &stored.response_types,
            "new-owner-token",
            DcrClientSecretChange::Preserve,
            "concurrent-owner",
        )
        .await
        .map_err(|error| error.to_string())
    }
}

async fn check_result(
    pool: &PgPool,
    env: &TestEnvironment,
    management_first: bool,
    delete: bool,
) -> TestResult {
    let loaded = crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        "concurrent-metadata",
        "new-owner-token",
    )
    .await?;
    if delete {
        assert!(loaded.is_none());
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM aegaeon.dynamic_client_registrations WHERE environment_id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(pool)
        .await?;
        assert_eq!(count, 0);
    } else {
        let loaded = loaded.ok_or("rotated owner token must remain usable")?;
        let grant = if management_first {
            "authorization_code"
        } else {
            "client_credentials"
        };
        assert_eq!(loaded.client.allowed_grant_types, vec![grant]);
        assert_eq!(
            loaded.response_types,
            if management_first {
                vec!["code"]
            } else {
                vec![]
            }
        );
    }
    assert!(crate::dcr_persistence::load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        "concurrent-metadata",
        "old-owner-token",
    )
    .await?
    .is_none());
    Ok(())
}

async fn scenario(pool: &PgPool, management_first: bool, delete: bool) -> TestResult {
    let (env, stored) = seed(pool).await?;
    let management_pool = named_pool(pool, "metadata-management").await?;
    let owner_pool = named_pool(pool, "metadata-owner").await?;
    let (app, cookie) = login(&management_pool, &env).await?;
    let uri = format!(
        "/api/v1/teams/{}/environments/{}/clients/{}",
        env.team_id, env.environment_id, stored.database_client_id
    );
    let (table, operation, condition) = if management_first {
        ("clients", "UPDATE", "TRUE")
    } else {
        (
            "audit_events",
            "INSERT",
            if delete {
                "NEW.event_type='dcr.client.deleted.v1'"
            } else {
                "NEW.event_type='dcr.client.updated.v1'"
            },
        )
    };
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION aegaeon.metadata_lock_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id='{}'::uuid AND {condition} THEN PERFORM pg_advisory_xact_lock(735122); END IF; RETURN NEW; END $$; CREATE TRIGGER metadata_lock_gate BEFORE {operation} ON aegaeon.{table} FOR EACH ROW EXECUTE FUNCTION aegaeon.metadata_lock_gate()",
        env.environment_id,
    )).execute(pool).await?;
    let mut tasks = JoinSet::new();
    let result = run_contended(
        pool,
        &mut tasks,
        app,
        cookie,
        uri,
        owner_pool.clone(),
        stored,
        management_first,
        delete,
    )
    .await;
    tasks.shutdown().await;
    sqlx::raw_sql(&format!("DROP TRIGGER metadata_lock_gate ON aegaeon.{table}; DROP FUNCTION aegaeon.metadata_lock_gate()"))
        .execute(pool).await?;
    management_pool.close().await;
    owner_pool.close().await;
    result?;
    check_result(pool, &env, management_first, delete).await
}

type MutationResult = Result<Option<(StatusCode, Value)>, String>;

#[expect(
    clippy::too_many_arguments,
    reason = "test coordinates both real transaction entry points"
)]
async fn run_contended(
    pool: &PgPool,
    tasks: &mut JoinSet<MutationResult>,
    app: Router,
    cookie: String,
    uri: String,
    owner_pool: PgPool,
    stored: DcrStoredClient,
    management_first: bool,
    delete: bool,
) -> TestResult {
    let mut controller = pool.begin().await?;
    let controller_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *controller)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(735122)")
        .execute(&mut *controller)
        .await?;
    let environment = stored.environment_id;
    let client_id = stored.database_client_id;
    let configuration_version = stored.configuration_version_id;
    let management = async move {
        patch(
            &app,
            &cookie,
            &uri,
            json!({"baseConfigurationVersionId":configuration_version,"allowedGrantTypes":["client_credentials"],"redirectUris":[]}),
        )
        .await
        .map(Some)
        .map_err(|error| error.to_string())
    };
    let owner = async move {
        owner_mutation(&owner_pool, &stored, delete)
            .await
            .map(|()| None)
    };
    if management_first {
        tasks.spawn(management);
        let pid = wait_blocker(pool, "metadata-management", controller_pid).await?;
        tasks.spawn(owner);
        wait_blocker(pool, "metadata-owner", pid).await?;
        // The waiting owner must not own DCR before the manager reaches it.
        sqlx::query("SELECT client_id FROM aegaeon.dynamic_client_registrations WHERE environment_id=$1 AND client_id=$2 FOR UPDATE NOWAIT")
            .bind(environment).bind(client_id).execute(&mut *controller).await?;
    } else {
        tasks.spawn(owner);
        let pid = wait_blocker(pool, "metadata-owner", controller_pid).await?;
        tasks.spawn(management);
        wait_blocker(pool, "metadata-management", pid).await?;
    }
    controller.commit().await?;
    while let Some(joined) = tokio::time::timeout(Duration::from_secs(5), tasks.join_next()).await?
    {
        if let Some((status, body)) = joined?.map_err(std::io::Error::other)? {
            let expected = if delete && !management_first {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::OK
            };
            assert_eq!(status, expected, "{body}");
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; deterministic real management/owner lock contention"]
async fn pg_registration_metadata_management_owner_lock_order() -> ManagementTestResult {
    for management_first in [true, false] {
        for delete in [false, true] {
            let (control, pool, name) = database().await?;
            let result = scenario(&pool, management_first, delete).await;
            let cleanup_result = cleanup(control, pool, &name).await;
            result?;
            cleanup_result?;
        }
    }
    Ok(())
}
