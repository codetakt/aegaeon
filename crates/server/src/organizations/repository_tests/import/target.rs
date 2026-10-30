use super::*;
use sqlx::postgres::PgConnectOptions;
use std::str::FromStr;

async fn maintenance() -> Result<(PgConnection, String), Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from(std::env::var("AEGAEON_TEST_DATABASE_FIXTURE_DIRECTORY")?)
        .join("suppliers.json");
    let config: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let url = config["urls"]["maintenance"]
        .as_str()
        .ok_or("maintenance fixture")?;
    let runtime = config["names"]["runtime"]
        .as_str()
        .ok_or("runtime fixture")?
        .to_owned();
    let options = PgConnectOptions::from_str(url)?.options([
        ("statement_timeout", "5000"),
        ("lock_timeout", "1000"),
        ("idle_in_transaction_session_timeout", "30000"),
        ("transaction_timeout", "3600000"),
    ]);
    Ok((PgConnection::connect_with(&options).await?, runtime))
}

// Synthetic destination authority with fresh domain/object/audience identities,
// reusing actual native export of existing identity dependencies. Production
// import never rewrites identifiers; this constructs an isolated input fixture.
async fn prospective(f: &Fixture) -> Result<(Vec<u8>, Scope), Box<dyn std::error::Error>> {
    let mut rows = records(&export(f).await?);
    let scope = Scope {
        domain_id: Uuid::new_v4(),
        ..f.organization.scope
    };
    let organization = Uuid::new_v4();
    let before = [
        f.organization.scope.domain_id.to_string(),
        f.organization.id.to_string(),
        "management-api".into(),
    ];
    let after = [
        scope.domain_id.to_string(),
        organization.to_string(),
        format!("target-{}", scope.domain_id),
    ];
    for row in &mut rows {
        // This replaces both JSON strings and canonical compound row keys.
        let text = serde_json::to_string(row)?;
        let text = before
            .iter()
            .zip(after.iter())
            .fold(text, |s, (a, b)| s.replace(a, b));
        *row = serde_json::from_str(&text)?;
        if row["section"] == "domain" {
            row["data"]["is_default"] = json!(false);
        }
    }
    Ok((reframe(rows), scope))
}

async fn check(bytes: &[u8], scope: Scope) -> Result<Value, Box<dyn std::error::Error>> {
    let (connection, runtime) = maintenance().await?;
    let input = Input::new(Cursor::new(bytes), scope, &sha256_hex(bytes))?;
    Ok(serde_json::to_value(
        staging::inspect_target(connection, input, &runtime).await?,
    )?)
}

#[tokio::test]
#[ignore = "requires execute-only maintenance PostgreSQL; native target and credential comparison"]
async fn pg_organizations_import_target_matches_dependencies_without_activation() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let hash = crate::local_credentials::hash_password("target-credential-fixture-password").map_err(std::io::Error::other)?;
        sqlx::query("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES($1,$2)")
            .bind(f.users[0]).bind(&hash).execute(&f.pool).await?;
        let (bytes,scope) = prospective(&f).await?;
        let report = check(&bytes,scope).await?;
        assert_eq!(report["activationAuthorized"],false);
        assert_eq!(report["targetDependenciesChecked"],false);
        assert_eq!(report["target"]["completeDependenciesChecked"],false);
        assert_eq!(report["target"]["compatibleLocalCredentials"],1);
        assert_eq!(report["target"]["credentialsRequiringResetOrQualification"],1);
        assert!(!serde_json::to_string(&report)?.contains(&hash));
        assert!(!String::from_utf8(bytes)?.contains(&hash));
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM aegaeon.authorization_domains WHERE id=$1)")
            .bind(scope.domain_id).fetch_one(&f.pool).await?;
        assert!(!exists,"inspection cannot prepare active rows");
        let (mut maintenance,_) = maintenance().await?;
        assert!(sqlx::query("SELECT owner_id FROM aegaeon.end_user_identity_owners LIMIT 1").fetch_all(&mut maintenance).await.is_err());
        maintenance.close().await?;
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; target identity, ownership and destination conflicts"]
async fn pg_organizations_import_target_refuses_conflicts_and_newer_history() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let (bytes, scope) = prospective(&f).await?;
        check(&bytes, scope).await?;
        // Correct checksums cannot authorize a different namespace or current identity.
        for (section, field, value) in [
            ("namespace", "issuer_host", json!("other.example")),
            ("identities", "organization_identity_revision", json!(999)),
        ] {
            let mut changed = records(&bytes);
            let row = changed
                .iter_mut()
                .find(|r| r["section"] == section)
                .ok_or("row")?;
            row["data"][field] = value;
            assert!(check(&reframe(changed), scope).await.is_err(), "{section}");
        }
        let original = export(&f).await?;
        assert!(
            check(&original, f.organization.scope).await.is_err(),
            "existing domain cannot be overwritten"
        );
        let mut deleted = records(&bytes);
        deleted.retain(|r| {
            !(r["section"] == "identities" && r["data"]["id"] == f.users[0].to_string())
        });
        let rejected = check(&reframe(deleted), scope)
            .await
            .expect_err("a source-deleted identity cannot silently exist in the target");
        assert!(rejected.to_string().contains("deleted identity"));
        sqlx::query("UPDATE aegaeon.end_users SET subject=$2 WHERE id=$1")
            .bind(f.users[0])
            .bind(format!("later-{}", f.users[0]))
            .execute(&f.pool)
            .await?;
        let rejected = check(&bytes, scope)
            .await
            .expect_err("later permanent history must not be discarded");
        assert!(rejected.to_string().contains("permanent subject history"));
        let (fresh, fresh_scope) = prospective(&f).await?;
        check(&fresh, fresh_scope).await?;
        let old_subject = format!("organization-user-{}", f.users[0]);
        let mut truncated = records(&fresh);
        truncated.retain(|r| {
            !(r["section"] == "subject_history" && r["data"]["subject"] == old_subject)
        });
        let rejected = check(&reframe(truncated), fresh_scope)
            .await
            .expect_err("matching current identity does not prove complete history");
        assert!(rejected.to_string().contains("permanent subject history"));
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; unsupported and malformed credential formats require reset"]
async fn pg_organizations_import_target_does_not_claim_unsupported_credentials_compatible(
) -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        let hash=crate::local_credentials::hash_password("native-target-credential-password").map_err(std::io::Error::other)?;
        assert!(crate::local_credentials::verify_password("native-target-credential-password",&hash));
        let id: Uuid=sqlx::query_scalar("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash) VALUES($1,$2) RETURNING id")
            .bind(f.users[0]).bind(&hash).fetch_one(&f.pool).await?;
        let mut malformed=hash.clone();malformed.pop();malformed.push('B');
        for candidate in [hash.replace("m=19456","m=999999999"),hash.replace("argon2id","argon2i"),malformed,"unsupported-legacy-format".into()] {
            sqlx::query("UPDATE aegaeon.end_user_password_credentials SET password_hash=$2 WHERE id=$1").bind(id).bind(&candidate).execute(&f.pool).await?;
            let (bytes,scope)=prospective(&f).await?;
            let report=check(&bytes,scope).await?;
            assert_eq!(report["target"]["compatibleLocalCredentials"],0);
            assert_eq!(report["target"]["credentialsRequiringResetOrQualification"],2);
            assert!(!serde_json::to_string(&report)?.contains(&candidate));
        }
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; restricted actual target supplier admission"]
async fn pg_organizations_import_target_supplier_refuses_runtime_and_unbounded_keys() -> TestResult
{
    let f = Fixture::new().await?;
    let result = async {
        let (mut maint, runtime) = maintenance().await?;
        let query =
            "SELECT row_key,row_data FROM aegaeon.organization_import_target_v1($1,$2,$3,$4)";
        assert!(sqlx::query(query)
            .bind(f.env.environment_id)
            .bind(&runtime)
            .bind("namespace")
            .bind(json!([]))
            .fetch_all(&f.pool)
            .await
            .is_err());
        for keys in [
            json!([]),
            json!(["same", "same"]),
            json!([1]),
            json!(["x".repeat(4097)]),
            json!((0..11).map(|i| i.to_string()).collect::<Vec<_>>()),
        ] {
            let mut tx = maint.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *tx)
                .await?;
            let error = sqlx::query(query)
                .bind(f.env.environment_id)
                .bind(&runtime)
                .bind("owners")
                .bind(keys)
                .fetch_all(&mut *tx)
                .await
                .expect_err("bounded exact supplier keys");
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("22023")
            );
            tx.rollback().await?;
        }
        maint.close().await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires execute-only maintenance PostgreSQL; exact provider and absent registration reconciliation"]
async fn pg_organizations_import_target_provider_drift_and_absent_registration_revival(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let (policy, _) = super::super::support_policy::setup(&f).await?;
        let provider = policy.providers[0].connection_id;
        super::super::support_policy::configure(&f,"target-dependencies",1,Some(policy)).await?;
        let registration = super::super::clients::registration(&f,"retained-absence").await?;
        sqlx::query("UPDATE aegaeon.authorization_domain_targets SET introspection_clients=$1 WHERE environment_id=$2 AND audience='management-api'")
            .bind(json!([{"clientRegistrationId":registration,"clientIdentifier":"retained-absence"}])).bind(f.env.environment_id).execute(&f.pool).await?;
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1").bind(registration).execute(&f.pool).await?;
        let (bytes,scope)=prospective(&f).await?;
        check(&bytes,scope).await?;
        sqlx::query("UPDATE aegaeon.connections SET client_auth_method='private_key_jwt' WHERE id=$1").bind(provider).execute(&f.pool).await?;
        assert!(check(&bytes,scope).await.is_err(),"provider drift must refuse target");
        sqlx::query("UPDATE aegaeon.connections SET client_auth_method='none' WHERE id=$1").bind(provider).execute(&f.pool).await?;
        let replacement=super::super::clients::registration(&f,"retained-absence").await?;
        check(&bytes,scope).await?; // Same string under another UUID is not a revival.
        sqlx::query("UPDATE aegaeon.clients SET id=$1 WHERE id=$2").bind(registration).bind(replacement).execute(&f.pool).await?;
        assert!(check(&bytes,scope).await.is_err(),"source-absent UUID revived in target");
        Ok(())
    }.await;
    f.cleanup(result).await
}
