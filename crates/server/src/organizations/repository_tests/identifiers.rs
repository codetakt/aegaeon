use super::*;

fn request(identifier: &str) -> AccessRequest {
    AccessRequest {
        detail_type: ORGANIZATION_ACCESS_TYPE.into(),
        admin_access_grant_id: None,
        identifier: identifier.into(),
        privileges: None,
    }
}

async fn resolve(
    pool: &PgPool,
    scope: Scope,
    audience: &str,
    identifier: &str,
) -> Result<Organization, RepositoryError> {
    let mut tx = pool.begin().await?;
    let result =
        repository::resolve_access_organization(&mut tx, scope, audience, &request(identifier))
            .await;
    tx.rollback().await?;
    result
}

async fn seed(pool: &PgPool, scope: Scope, identifier: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    // Fixture rows isolate the actual catalog/lookup contract from authority
    // creation. Authorization is checked separately against real membership.
    sqlx::query("INSERT INTO aegaeon.application_organizations (id,environment_id,domain_id,external_id,state) VALUES ($1,$2,$3,$4,'active')")
        .bind(id).bind(scope.environment_id).bind(scope.domain_id).bind(identifier)
        .execute(pool).await?;
    Ok(id)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organization_external_identifiers_remain_exact_within_target_domain() -> TestResult {
    let f = Fixture::new().await?;
    let other = Fixture::new().await?;
    let result = async {
        let scope = f.organization.scope;
        let identifiers = [
            "School", "school", "é", "e\u{0301}", "組織/東京 ?#%+",
            " space ", "space", "school%2F01", "school/01",
            "550e8400-e29b-41d4-a716-446655440000",
            "organization_550e8400-e29b-41d4-a716-446655440000",
        ];
        for identifier in identifiers {
            let id = seed(&f.pool, scope, identifier).await?;
            let row = resolve(&f.pool, scope, "management-api", identifier).await?;
            assert_eq!((row.id, row.external_id.as_str()), (id, identifier));
        }
        let second = Scope { domain_id: Uuid::new_v4(), ..scope };
        sqlx::query("INSERT INTO aegaeon.authorization_domains (id,environment_id,name,enabled) VALUES ($1,$2,'second',true)")
            .bind(second.domain_id).bind(second.environment_id).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.authorization_domain_targets (environment_id,domain_id,audience) VALUES ($1,$2,'second-api')")
            .bind(second.environment_id).bind(second.domain_id).execute(&f.pool).await?;
        let second_id = seed(&f.pool, second, &f.organization.external_id).await?;
        let row = resolve(&f.pool, second, "second-api", &f.organization.external_id).await?;
        assert_eq!(row.id, second_id);
        let row = resolve(&f.pool, scope, "management-api", &f.organization.external_id).await?;
        assert_eq!(row.id, f.organization.id);
        let row = resolve(&other.pool, other.organization.scope, "management-api", &f.organization.external_id).await?;
        assert_eq!(row.id, other.organization.id);
        assert_ne!(row.id, f.organization.id);
        for (wrong_scope, target, identifier) in [
            (scope, "second-api", f.organization.external_id.clone()),
            (second, "management-api", f.organization.external_id.clone()),
            (scope, "unregistered", f.organization.external_id.clone()),
            (Scope { environment_id: other.env.environment_id, ..scope }, "management-api", f.organization.external_id.clone()),
            (scope, "management-api", format!("organization_{}", f.organization.id)),
        ] {
            assert!(matches!(resolve(&f.pool, wrong_scope, target, &identifier).await,
                Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        }
        let decision = f.access().await?;
        assert_eq!(decision.authorization_details()[0]["identifier"], f.organization.external_id);
        Ok(())
    }.await;
    let result = other.cleanup(result).await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organization_external_identifier_tombstone_blocks_lookup_and_reuse() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let decision = f.access().await?;
        let mut tx = f.pool.begin().await?;
        let deleted = repository::transition_organization(
            &mut tx,
            f.organization.scope,
            f.organization.id,
            f.organization.revision,
            OrganizationState::Deleted,
            &f.actor,
        )
        .await?;
        tx.commit().await?;
        assert!(matches!(
            resolve(
                &f.pool,
                deleted.scope,
                "management-api",
                &deleted.external_id
            )
            .await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))
        ));
        let mut tx = f.pool.begin().await?;
        let member = repository::membership(&mut tx, &deleted, f.users[0])
            .await?
            .ok_or("member")?;
        let roles = repository::roles(&mut tx, deleted.scope).await?;
        assert!(!decision.is_current(&deleted, &member, &roles, 100));
        tx.rollback().await?;
        // The real unique constraint retains deleted external identifiers.
        let error = seed(&f.pool, deleted.scope, &deleted.external_id)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("23505")
        );
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organization_external_identifier_lookup_holds_scope_and_fails_closed_on_store_error(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let scope = f.organization.scope;
        let mut reader = f.pool.begin().await?;
        repository::resolve_access_organization(&mut reader, scope, "management-api",
            &request(&f.organization.external_id)).await?;
        let mut writer = f.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout = '100ms'").execute(&mut *writer).await?;
        let error = sqlx::query("UPDATE aegaeon.authorization_domain_targets SET management=false WHERE environment_id=$1 AND audience='management-api'")
            .bind(scope.environment_id).execute(&mut *writer).await.unwrap_err();
        assert_eq!(error.as_database_error().and_then(|e| e.code()).as_deref(), Some("55P03"));
        writer.rollback().await?;
        reader.rollback().await?;

        sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=false WHERE id=$1")
            .bind(scope.domain_id).execute(&f.pool).await?;
        assert!(matches!(resolve(&f.pool, scope, "management-api", &f.organization.external_id).await,
            Err(RepositoryError::Authority(AuthorityError::Forbidden))));
        sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=true WHERE id=$1")
            .bind(scope.domain_id).execute(&f.pool).await?;

        let admin = crate::web::test_support::test_admin_pool(&f.pool).await?;
        let runtime: String = sqlx::query_scalar("SELECT current_user::text").fetch_one(&f.pool).await?;
        let mut tx = admin.begin().await?;
        // A transactional catalog fault exercises the actual SQLx reader.
        sqlx::query("ALTER TABLE aegaeon.authorization_domain_targets RENAME TO identifier_test_unavailable")
            .execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('role',$1,true)").bind(&runtime).execute(&mut *tx).await?;
        assert!(repository::resolve_access_organization(&mut tx, scope, "management-api",
            &request(&f.organization.external_id)).await.is_err());
        tx.rollback().await?;
        admin.close().await;
        let recovered = resolve(&f.pool, scope, "management-api", &f.organization.external_id).await?;
        assert_eq!(recovered.id, f.organization.id);
        Ok(())
    }.await;
    f.cleanup(result).await
}
