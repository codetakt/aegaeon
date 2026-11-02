use super::*;
use aegaeon_attribute_mapping::Surface;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime and explicit fault injection"]
async fn pg_attribute_mapping_requires_current_permanent_namespace() -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result: ManagementTestResult = async {
        let initialized = initialize_management(&pool, &input()).await?;
        let user = create_user(&pool, initialized.environment_id).await?;
        let subject: String = sqlx::query_scalar("SELECT subject FROM aegaeon.end_users WHERE id=$1")
            .bind(user).fetch_one(&pool).await?;
        let issuer = format!("https://{}", initialized.issuer_host);
        let (management, session) = authenticated_app(&pool).await?;
        let configuration = crate::attribute_mapping::tests::configuration(Surface::Userinfo)?;
        activate_mapping(&management, &pool, initialized.team_id, initialized.environment_id,
            &session, serde_json::to_value(configuration)?).await?;
        let mut tx = pool.begin().await?;
        replace_local_attributes(&mut tx, initialized.environment_id, user, 0,
            &json!({"department":"Owned"}), Uuid::new_v4()).await?;
        tx.commit().await?;
        let load = || crate::attribute_mapping::load_oidc_mapping(
            &pool, &issuer, &subject, "test_client", Surface::Userinfo,
            ["openid".to_string(), "profile".to_string()].into_iter().collect(), None);
        assert!(load().await?.is_some());
        let administrator = crate::web::test_support::test_admin_pool(&pool).await?;
        // Only the explicit fixture administrator may manufacture catalog/data
        // corruption. Product operations below retain the restricted runtime.
        let private_read = sqlx::query("SELECT owner_id FROM aegaeon.end_user_identity_owners LIMIT 1")
            .fetch_optional(&pool).await.unwrap_err();
        assert_eq!(private_read.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref(), Some("42501"));
        let mut fault = administrator.begin().await?;
        sqlx::query("SET LOCAL session_replication_role=replica").execute(&mut *fault).await?;
        sqlx::query("DELETE FROM aegaeon.subject_ownership_namespaces WHERE environment_id=$1")
            .bind(initialized.environment_id).execute(&mut *fault).await?;
        fault.commit().await?;
        // The actual predecessor lookup still resolves a user without the
        // permanent namespace. Product readers must not regain that path.
        let old: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2 AND status='ACTIVE'")
            .bind(initialized.environment_id).bind(&subject).fetch_optional(&pool).await?;
        assert_eq!(old, Some(user));
        assert!(matches!(load().await, Err(AttributeStoreError::OwnerNotFound)));
        administrator.close().await;
        Ok(())
    }.await;
    finish(result, cleanup(control, pool, &name).await)
}
