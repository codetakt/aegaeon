//! Real stored grants must retain their own epoch even with a current root.
use super::*;
use serde_json::Value;

async fn insert_retained(
    f: &Fixture,
    source: &Grant,
    authority: &Value,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.organization_admin_access_grants(id,environment_id,domain_id,organization_id,user_id,client_registration_id,root_id,authority,issued_at,expires_at,creation_key,request_digest) SELECT $1,environment_id,domain_id,organization_id,user_id,client_registration_id,root_id,$2,issued_at,expires_at,$3,request_digest FROM aegaeon.organization_admin_access_grants WHERE id=$4")
        .bind(id).bind(authority).bind(id.to_string()).bind(source.id).execute(&f.pool).await?;
    Ok(id)
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL and actual witness; retained grant epoch isolation"]
async fn pg_organizations_administrative_epoch_refuses_foreign_and_historical_grants() -> TestResult
{
    let f = Fixture::new().await?;
    let result = f
        .in_epoch(async {
            let root = setup(&f).await?;
            let grant = activate(&f, &root, "current").await?;
            assert_eq!(grant.authority.epoch, root.consent.epoch);
            let original = serde_json::to_value(&grant.authority)?;
            let selected = select(&f, &root, Some(grant.id), 130).await?;
            assert!(current(&f, &root, &selected, 130).await?);
            for field in [
                "environment_id",
                "deployment_id",
                "epoch",
                "primary_id",
                "token_store_id",
            ] {
                let mut foreign = original.clone();
                foreign["epoch"][field] = serde_json::json!(Uuid::new_v4());
                let id = insert_retained(&f, &grant, &foreign).await?;
                assert!(
                    select(&f, &root, Some(id), 130).await.is_err(),
                    "foreign grant {field}"
                );
            }
            let mut historical = original.clone();
            historical.as_object_mut().unwrap().remove("epoch");
            let parsed: support::Authority = serde_json::from_value(historical.clone())?;
            assert_eq!(
                serde_json::to_value(parsed)?,
                historical,
                "history is not upgraded"
            );
            let id = insert_retained(&f, &grant, &historical).await?;
            assert!(
                select(&f, &root, Some(id), 130).await.is_err(),
                "missing grant epoch"
            );
            let mut tx = f.pool.begin().await?;
            let retained = support::read(&mut tx, &context(&root, 130), id).await?;
            tx.commit().await?;
            assert!(
                retained.authority.epoch.is_none(),
                "authenticated historical read"
            );
            assert!(!revoke(&f, &root, id, "historical-revoke").await?.active);
            assert!(
                current(&f, &root, &selected, 140).await?,
                "valid grant remains usable"
            );
            Ok(())
        })
        .await;
    f.cleanup(result).await
}
