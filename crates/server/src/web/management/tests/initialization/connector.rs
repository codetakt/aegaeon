use super::*;
use crate::organizations::witness::connector::primary;
use sqlx::{Connection, Executor, PgConnection};

#[derive(Clone, Copy)]
enum Scenario {
    Scope,
    PrivilegeRecovery,
}

async fn normal(pool: &PgPool, environment: Uuid, issuer: &str, name: &str) -> anyhow::Result<()> {
    let connection = PgConnection::connect_with(&pool.connect_options()).await?;
    let mut observed = primary::checked(connection, environment, issuer).await?;
    let value = serde_json::to_value(observed.observation())?;
    let previous = observed.observation().clone();
    let result = observed.recheck(&previous).await;
    let closed = observed.close().await;
    result?;
    closed?;
    anyhow::ensure!(
        value["database_name"] == name,
        "observed another primary database"
    );
    Ok(())
}

async fn refused(pool: &PgPool, environment: Uuid, issuer: &str) -> anyhow::Result<()> {
    let connection = PgConnection::connect_with(&pool.connect_options()).await?;
    if let Ok(observed) = primary::checked(connection, environment, issuer).await {
        observed.close().await?;
        anyhow::bail!("connector primary accepted a refused namespace or privilege");
    }
    Ok(())
}

async fn scenario(
    scenario: Scenario,
    pool: &PgPool,
    admin: &mut PgConnection,
    name: &str,
) -> anyhow::Result<()> {
    let initialized = initialize_management(pool, &input()).await?;
    let environment = initialized.environment_id;
    let issuer = format!("https://{}", initialized.issuer_host);
    let internal: bool = sqlx::query_scalar(
        "SELECT has_function_privilege(session_user,'aegaeon.subject_history_preflight(text)','EXECUTE')",
    )
    .fetch_one(pool)
    .await?;
    anyhow::ensure!(
        !internal,
        "fixture must not grant the maintenance-only preflight"
    );
    let login: String = sqlx::query_scalar("SELECT quote_ident(session_user)")
        .fetch_one(pool)
        .await?;
    admin
        .execute(
            format!("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {login}").as_str(),
        )
        .await?;
    normal(pool, environment, &issuer, name).await?;
    match scenario {
        Scenario::Scope => {
            refused(pool, Uuid::new_v4(), &issuer).await?;
            refused(pool, environment, "https://foreign.example.test").await?;
        }
        Scenario::PrivilegeRecovery => {
            admin
                .execute(format!("REVOKE EXECUTE ON FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid) FROM {login}").as_str())
                .await?;
            refused(pool, environment, &issuer).await?;
            admin
                .execute(format!("GRANT EXECUTE ON FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid) TO {login}").as_str())
                .await?;
        }
    }
    normal(pool, environment, &issuer, name).await
}

async fn exercise(selected: Scenario) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let mut admin =
            PgConnection::connect_with(&control.connect_options().as_ref().clone().database(&name))
                .await?;
        let result = scenario(selected, &pool, &mut admin, &name).await;
        let closed = admin.close().await;
        result?;
        closed?;
        Ok(())
    }
    .await;
    finish(result, cleanup(control, pool, &name).await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual connector namespace validation"]
async fn pg_organizations_connector_runtime_namespace_scope() -> ManagementTestResult {
    exercise(Scenario::Scope).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual connector permission loss and recovery"]
async fn pg_organizations_connector_runtime_namespace_privilege_recovery() -> ManagementTestResult {
    exercise(Scenario::PrivilegeRecovery).await
}
