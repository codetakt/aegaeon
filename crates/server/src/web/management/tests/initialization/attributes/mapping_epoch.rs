use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use aegaeon_attribute_mapping::Surface;
use anyhow::Context as _;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and explicit Redis observation supplier"]
async fn shared_redis_attribute_mapping_checks_actual_primary_and_environment(
) -> ManagementTestResult {
    let (control, pool, name) = database().await?;
    let result = exercise(&pool).await;
    finish(result, cleanup(control, pool, &name).await)
}

async fn exercise(pool: &PgPool) -> ManagementTestResult {
    let initialized = initialize_management(pool, &input()).await?;
    let user = create_user(pool, initialized.environment_id).await?;
    let subject: String = sqlx::query_scalar("SELECT subject FROM aegaeon.end_users WHERE id=$1")
        .bind(user)
        .fetch_one(pool)
        .await?;
    let issuer = format!("https://{}", initialized.issuer_host);
    let (management, session) = authenticated_app(pool).await?;
    activate_mapping(
        &management,
        pool,
        initialized.team_id,
        initialized.environment_id,
        &session,
        serde_json::to_value(crate::attribute_mapping::tests::configuration(
            Surface::Userinfo,
        )?)?,
    )
    .await?;
    let mut tx = pool.begin().await?;
    replace_local_attributes(
        &mut tx,
        initialized.environment_id,
        user,
        0,
        &json!({"department":"Scoped"}),
        Uuid::new_v4(),
    )
    .await?;
    tx.commit().await?;
    let reader = crate::web::test_support::test_runtime_pool(pool).await?;
    let load = |selected: PgPool| {
        let issuer = issuer.clone();
        let subject = subject.clone();
        async move {
            crate::attribute_mapping::load_oidc_mapping(
                &selected,
                &issuer,
                &subject,
                "test_client",
                Surface::Userinfo,
                ["openid".into(), "profile".into()].into_iter().collect(),
                None,
            )
            .await
        }
    };

    let witness = CallerFixture::with_test_stores(
        initialized.environment_id,
        reader.connect_options().as_ref().clone(),
    )
    .await?;
    let result: ManagementTestResult = async {
        let normal = witness.begin().await?;
        let mapping = normal
            .store_scope(load(reader.clone()))
            .await??
            .ok_or("mapping")?;
        let claims = mapping.claims_for(
            &issuer,
            &subject,
            "test_client",
            &Surface::Userinfo,
            &["openid".into(), "profile".into()].into_iter().collect(),
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )?;
        assert_eq!(claims["organization"], json!({"department":"Scoped"}));
        assert_eq!(normal.complete().await?.pending, 0);

        Ok(())
    }
    .await;
    let finished = witness.finish().await;
    finish(result, finished)?;

    // Fixed control-supplier roles are cluster-wide. Finish each isolated
    // supplier before constructing the next one, including negative cases.
    let (foreign_control, foreign_pool, foreign_name) = database().await?;
    let foreign_result: ManagementTestResult = async {
        let foreign_reader = crate::web::test_support::test_runtime_pool(&foreign_pool).await?;
        let foreign_witness = CallerFixture::with_test_stores(
            initialized.environment_id,
            foreign_reader.connect_options().as_ref().clone(),
        )
        .await
        .context("construct restricted foreign-primary observer")?;
        let result: ManagementTestResult = async {
            // Readable application data from a different physical database
            // must not escape the admitted checkpoint.
            assert!(load(reader.clone()).await?.is_some());
            let work = foreign_witness.begin().await?;
            let closed = work.admission().closure_probe_for_test();
            let refused = work.store_scope(load(reader.clone())).await;
            assert!(refused.is_err());
            assert!(closed.is_closed());
            assert!(work.complete().await.is_err());
            assert_eq!(foreign_witness.pending().await?, 1);
            Ok(())
        }
        .await;
        let finished = foreign_witness.finish().await;
        foreign_reader.close().await;
        finish(result, finished)
    }
    .await;
    let foreign_cleanup = cleanup(foreign_control, foreign_pool, &foreign_name).await;
    finish(foreign_result, foreign_cleanup)?;

    let wrong_environment =
        CallerFixture::with_test_stores(Uuid::new_v4(), reader.connect_options().as_ref().clone())
            .await?;
    let result: ManagementTestResult = async {
        let work = wrong_environment.begin().await?;
        assert!(work.store_scope(load(reader.clone())).await?.is_err());
        assert_eq!(work.complete().await?.pending, 0);
        Ok(())
    }
    .await;
    let finished = wrong_environment.finish().await;
    reader.close().await;
    finish(result, finished)
}
