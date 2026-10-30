use super::*;

fn has(rows: &[Value], section: &str, user: Uuid) -> bool {
    rows.iter()
        .any(|r| r["section"] == section && r["key"] == user.to_string())
}

async fn rejects_missing_history(f: &Fixture, rows: &[Value], user: Uuid) -> TestResult {
    let without = rows
        .iter()
        .filter(|r| {
            !((r["section"] == "owners" || r["section"] == "identities")
                && r["key"] == user.to_string()
                || r["section"] == "subject_history" && r["data"]["owner_id"] == user.to_string())
        })
        .cloned()
        .collect();
    assert!(
        inspect(f, &reframe(without)).await.is_err(),
        "fresh hashes must not excuse missing referenced owner history"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires restricted PostgreSQL; permanent support and audit owner dependencies"]
async fn pg_organizations_import_retains_support_and_deleted_audit_owner_history() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let (policy, evidence) = super::super::support_policy::setup(&f).await?;
        let user = evidence.user_id;
        super::super::support_policy::configure(&f, "snapshot-support", 1, Some(policy)).await?;
        let member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM aegaeon.organization_memberships WHERE end_user_id=$1)",
        )
        .bind(user)
        .fetch_one(&f.pool)
        .await?;
        assert!(
            !member,
            "support entitlement has no membership or access grant"
        );
        let bytes = export(&f).await?;
        let rows = records(&bytes);
        assert!(
            has(&rows, "owners", user),
            "policy-only support owner omitted"
        );
        assert!(has(&rows, "identities", user));
        assert!(inspect(&f, &bytes).await.is_ok());
        rejects_missing_history(&f, &rows, user).await?;

        // A past member actor remains a historical identity dependency even
        // after policy removal and physical current-identity deletion.
        let actor = AuditActor {
            id: user,
            kind: ActorKind::Member,
            client_id: "historical-client".into(),
            client_registration_id: Some(Uuid::new_v4()),
            request_id: "snapshot-retained-actor".into(),
            reason: "historical operation".into(),
            basis: None,
        };
        let mut tx = f.pool.begin().await?;
        repository::event(
            &mut tx,
            &f.organization,
            &actor,
            "retained-actor-fixture",
            json!({}),
        )
        .await?;
        tx.commit().await?;
        super::super::support_policy::configure(&f, "snapshot-remove-support", 2, None).await?;
        sqlx::query("DELETE FROM aegaeon.account_links WHERE end_user_id=$1")
            .bind(user)
            .execute(&f.pool)
            .await?;
        sqlx::query("DELETE FROM aegaeon.end_users WHERE id=$1")
            .bind(user)
            .execute(&f.pool)
            .await?;
        let bytes = export(&f).await?;
        let rows = records(&bytes);
        assert!(
            has(&rows, "owners", user),
            "deleted historical actor omitted"
        );
        assert!(
            !has(&rows, "identities", user),
            "must not revive deleted identity"
        );
        assert!(rows.iter().any(
            |r| r["section"] == "subject_history" && r["data"]["owner_id"] == user.to_string()
        ));
        assert!(inspect(&f, &bytes).await.is_ok());
        rejects_missing_history(&f, &rows, user).await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
