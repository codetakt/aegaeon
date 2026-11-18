use super::*;
use crate::web::management::initialization::InitializationOutput;

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_explicit_issuer_keeps_api_authority_and_identity() -> ManagementTestResult
{
    let mut explicit = input();
    // Deliberately outside the independent generated-host policy's base domain.
    explicit.issuer_host = Some(" AUTH.Example.COM ".into());
    check_login_and_second_environment(explicit).await
}

pub(super) async fn check_persisted_identity(
    pool: &PgPool,
    initialized: &InitializationOutput,
    initial_input: &InitializationInput,
) -> ManagementTestResult {
    let issuer = format!("https://{}", initialized.issuer_host);
    let state = crate::runtime_configuration::load_database_runtime_configuration(
        pool,
        &initialized.issuer_host,
    )
    .await?;
    assert_eq!(state.environment_id, initialized.environment_id);
    assert_eq!(state.issuer_url, issuer);
    assert_eq!(state.issuer_host, initialized.issuer_host);
    assert!(
        crate::runtime_configuration::load_database_runtime_configuration(
            pool,
            "unknown.example.com"
        )
        .await
        .is_err()
    );
    let document = state.active_configuration_document_fingerprint;
    assert!(!document.is_empty());
    let namespace: (Uuid, String) = sqlx::query_as(
        "SELECT environment_id, issuer_host FROM aegaeon.subject_ownership_namespaces",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(
        namespace,
        (initialized.environment_id, initialized.issuer_host.clone())
    );
    let policy: (Vec<String>, String) = sqlx::query_as("SELECT management_allowed_origins, management_issuer_base_domain FROM aegaeon.control_plane_policies")
        .fetch_one(pool).await?;
    assert_eq!(
        policy,
        (
            initial_input.allowed_origins.clone(),
            initial_input.issuer_base_domain.clone()
        )
    );
    let audit: serde_json::Value = sqlx::query_scalar(
        "SELECT data FROM aegaeon.audit_events WHERE event_type='MANAGEMENT_INITIALIZED'",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(audit["issuerHost"], initialized.issuer_host);
    assert_eq!(
        audit["issuerSelection"],
        if initial_input.issuer_host.is_some() {
            "explicit"
        } else {
            "generated"
        }
    );
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_keys")
        .fetch_one(pool)
        .await?;
    assert_eq!(keys, 0);
    for assignment in ["issuer_host='changed.example.com'", "id=gen_random_uuid()"] {
        let error = sqlx::query(&format!(
            "UPDATE aegaeon.environments SET {assignment} WHERE id=$1"
        ))
        .bind(initialized.environment_id)
        .execute(pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.constraint()),
            Some("environments_subject_namespace_immutable")
        );
    }
    let mut wrong: serde_json::Value = sqlx::query_scalar(
        "SELECT configuration_document FROM aegaeon.configuration_versions WHERE id=$1",
    )
    .bind(initialized.configuration_version_id)
    .fetch_one(pool)
    .await?;
    wrong["issuerHost"] = "changed.example.com".into();
    wrong["issuerUrl"] = "https://changed.example.com".into();
    assert!(
        crate::web::management::configuration_documents::parse_activated_environment_configuration(
            wrong,
            &initialized.issuer_host,
            &issuer,
            "issuer-test"
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATEDB; uses an isolated disposable database"]
async fn pg_initialization_cannot_reuse_a_permanent_issuer_namespace() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let admin = PgPoolOptions::new().max_connections(1)
            .connect_with(control.connect_options().as_ref().clone().database(&name)).await?;
        // Soft deletion preserves the original Environment and permanent namespace.
        // Use the real insertion trigger, including its adoption record and FK.
        let team = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let mut tx = admin.begin().await?;
        sqlx::query("INSERT INTO aegaeon.teams(id,name,slug) VALUES($1,'Retired','retired')")
            .bind(team).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO aegaeon.tenants(id,team_id,name,slug,region) VALUES($1,$2,'Retired','retired','local')")
            .bind(tenant).bind(team).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO aegaeon.environments(tenant_id,name,slug,issuer_host,status,deleted_at) VALUES($1,'Retired','retired','auth.example.com','DELETED',now())")
            .bind(tenant).execute(&mut *tx).await?;
        tx.commit().await?;
        let mut explicit = input(); explicit.issuer_host = Some("auth.example.com".into());
        assert!(initialize_management(&pool, &explicit).await.is_err());
        for (table, expected) in [("administrators", 0), ("control_plane_policies", 0), ("teams", 1), ("tenants", 1), ("environments", 1), ("configuration_versions", 0), ("team_memberships", 0), ("audit_events", 0), ("subject_ownership_adoptions", 1)] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM aegaeon.{table}")).fetch_one(&admin).await?;
            assert_eq!(count, expected, "conflict must preserve existing {table}");
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.subject_ownership_namespaces").fetch_one(&admin).await?;
        assert_eq!(count, 1);
        database_cleanup::close_pool(&admin).await?;
        explicit.issuer_host = Some("available.example.com".into());
        assert!(initialize_management(&pool, &explicit).await.is_ok());
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
