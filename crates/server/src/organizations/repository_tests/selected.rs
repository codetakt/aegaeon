use super::*;
use crate::organizations::{
    consent::RootAuthority,
    selected::{self, SelectedAuthority, SelectionInput},
};

async fn select(f: &Fixture, root: &RootAuthority) -> Result<SelectedAuthority, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = selected::authorize(
        &mut tx,
        SelectionInput {
            original: root,
            authenticated: &root.ceiling.binding,
            request: &AccessRequest {
                detail_type: ORGANIZATION_ACCESS_TYPE.into(),
                admin_access_grant_id: None,
                identifier: f.organization.external_id.clone(),
                privileges: None,
            },
            audience: "management-api",
            parent_expires_at: 300,
            now: 120,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}
async fn current(
    f: &Fixture,
    root: &RootAuthority,
    selected: &SelectedAuthority,
    now: i64,
) -> Result<bool, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = selected::is_current(&mut tx, selected, root, &root.ceiling.binding, now).await?;
    tx.commit().await?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_selected_currentness_preserves_unrelated_membership_and_exact_output(
) -> TestResult {
    let f = Fixture::new().await?;
    let result=async {
        consent::setup(&f).await?;
        let other=Uuid::new_v4();
        sqlx::query("INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state) VALUES($1,$2,$3,'別の組織','active')")
            .bind(other).bind(f.env.environment_id).bind(f.organization.scope.domain_id).execute(&f.pool).await?;
        sqlx::query("INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,roles) VALUES($1,$2,$3,$4,$5,'active','[\"reader\"]')")
            .bind(f.env.environment_id).bind(f.organization.scope.domain_id).bind(other).bind(f.users[1]).bind(Uuid::new_v4()).execute(&f.pool).await?;
        let mut request=consent::request(&f);
        request.organizations.push(crate::organizations::consent::Selection{administrative_access:false,identifier:"別の組織".into(),privileges:vec!["documents.read".into()]});
        let root=consent::capture(&f,&request).await?.bind("actual-test-root",1000)?;
        let selected=select(&f,&root).await?;
        assert_eq!(selected.decision.authorization_details()[0]["identifier"],f.organization.external_id);
        assert_eq!(selected.decision.expires_at,300);
        assert!(current(&f,&root,&selected,299).await?);
        assert!(!current(&f,&root,&selected,300).await?);
        sqlx::query("UPDATE aegaeon.organization_memberships SET state='suspended',revision=revision+1 WHERE organization_id=$1 AND end_user_id=$2")
            .bind(other).bind(f.users[1]).execute(&f.pool).await?;
        assert!(current(&f,&root,&selected,130).await?,"other organization cancellation must not cancel this membership");
        sqlx::query("UPDATE aegaeon.organization_memberships SET state='suspended',revision=revision+1 WHERE organization_id=$1 AND end_user_id=$2")
            .bind(f.organization.id).bind(f.users[1]).execute(&f.pool).await?;
        assert!(!current(&f,&root,&selected,130).await?);
        assert!(select(&f,&root).await.is_err());
        Ok(())
    }.await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_selected_refuses_tampering_stale_policy_and_read_only_supplier(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        consent::setup(&f).await?;
        let root = consent::capture(&f, &consent::request(&f))
            .await?
            .bind("root", 1000)?;
        let original = select(&f, &root).await?;
        for (field, value) in [
            (
                "domain_revision",
                serde_json::json!(original.domain_revision + 1),
            ),
            ("client_binding_id", serde_json::json!(Uuid::new_v4())),
            ("issued_at", serde_json::json!(20)),
        ] {
            let mut encoded = serde_json::to_value(&original)?;
            encoded[field] = value;
            let tampered: SelectedAuthority = serde_json::from_value(encoded)?;
            assert!(!current(&f, &root, &tampered, 130).await?);
        }
        let mut changed = original.clone();
        changed.decision.privileges.insert("documents.write".into());
        assert!(!current(&f, &root, &changed, 130).await?);
        changed = original.clone();
        changed.decision.expires_at = 301;
        assert!(!current(&f, &root, &changed, 130).await?);
        changed = original.clone();
        changed.decision.organization_identifier = "another".into();
        assert!(!current(&f, &root, &changed, 130).await?);
        let mut tx = f.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        assert!(matches!(
            selected::is_current(&mut tx, &original, &root, &root.ceiling.binding, 130).await,
            Err(RepositoryError::Storage(sqlx::Error::Protocol(_)))
        ));
        tx.rollback().await?;
        assert!(
            current(&f, &root, &original, 130).await?,
            "healthy primary remains usable"
        );
        sqlx::query(
            "UPDATE aegaeon.organization_client_bindings SET revision=revision+1 WHERE id=$1",
        )
        .bind(root.consent.client_binding_id)
        .execute(&f.pool)
        .await?;
        assert!(!current(&f, &root, &original, 130).await?);
        assert!(select(&f, &root).await.is_err());
        Ok(())
    }
    .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_selected_introspection_recipients_do_not_inherit_recreated_ids(
) -> TestResult {
    use crate::organizations::operators::mutations::targets::recipients::{
        self, ConfigureRecipients, Recipient,
    };
    let f = Fixture::new().await?;
    let result = async {
        consent::setup(&f).await?;
        let id = clients::registration(&f, "actual-rs").await?;
        let mut tx = f.pool.begin().await?;
        recipients::apply(
            &mut tx,
            f.organization.scope,
            f.env.team_id,
            &f.actor,
            "rs",
            &ConfigureRecipients {
                expected_revision: 2,
                audience: "management-api".into(),
                registrations: Some(vec![id]),
            },
        )
        .await?;
        tx.commit().await?;
        let receiver = Recipient {
            client_registration_id: id,
            client_identifier: "actual-rs".into(),
        };
        let mut tx = f.pool.begin().await?;
        assert!(
            selected::recipient_current(&mut tx, f.organization.scope, "management-api", &receiver)
                .await?
        );
        assert!(
            !selected::recipient_current(
                &mut tx,
                f.organization.scope,
                "another-target",
                &receiver
            )
            .await?
        );
        tx.commit().await?;
        sqlx::query("DELETE FROM aegaeon.clients WHERE id=$1")
            .bind(id)
            .execute(&f.pool)
            .await?;
        let replacement = clients::registration(&f, "actual-rs").await?;
        let mut tx = f.pool.begin().await?;
        assert!(
            !selected::recipient_current(
                &mut tx,
                f.organization.scope,
                "management-api",
                &receiver
            )
            .await?
        );
        assert!(
            !selected::recipient_current(
                &mut tx,
                f.organization.scope,
                "management-api",
                &Recipient {
                    client_registration_id: replacement,
                    ..receiver
                }
            )
            .await?
        );
        tx.commit().await?;
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
