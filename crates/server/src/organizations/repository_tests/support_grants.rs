use super::*;
use crate::organizations::{
    consent::RootAuthority,
    selected::{self, SelectedAuthority, SelectionInput},
    support::{self, Activation, Context, Grant, Revoke},
};

pub(super) async fn setup(f: &Fixture) -> Result<RootAuthority, Box<dyn std::error::Error>> {
    let (policy, evidence) = support_policy::setup(f).await?;
    support_policy::configure(f, "support", 1, Some(policy)).await?;
    let mut request = consent::request(f);
    request.organizations[0].administrative_access = true;
    Ok(support_policy::capture(f, Some(&evidence), 110, &request)
        .await?
        .bind("support-root", 1000)?)
}
fn context(root: &RootAuthority, now: i64) -> Context<'_> {
    Context {
        original: root,
        binding: &root.ceiling.binding,
        parent_expires_at: 500,
        now,
    }
}
fn activation(f: &Fixture) -> Activation {
    Activation {
        organization_id: f.organization.id,
        audience: "management-api".into(),
        roles: vec!["reader".into()],
        expected_revision: f.organization.revision,
        reason: "Resolve authorized support request".into(),
    }
}
pub(super) async fn activate(
    f: &Fixture,
    root: &RootAuthority,
    key: &str,
) -> Result<Grant, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = support::activate(
        &mut tx,
        &context(root, 120),
        &activation(f),
        key,
        "support-request",
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}
async fn select(
    f: &Fixture,
    root: &RootAuthority,
    id: Option<Uuid>,
    now: i64,
) -> Result<SelectedAuthority, RepositoryError> {
    let request = AccessRequest {
        detail_type: ORGANIZATION_ACCESS_TYPE.into(),
        identifier: f.organization.external_id.clone(),
        admin_access_grant_id: id,
        privileges: None,
    };
    let mut tx = f.pool.begin().await?;
    let result = selected::authorize(
        &mut tx,
        SelectionInput {
            original: root,
            authenticated: &root.ceiling.binding,
            request: &request,
            audience: "management-api",
            parent_expires_at: 500,
            now,
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
async fn revoke(
    f: &Fixture,
    root: &RootAuthority,
    id: Uuid,
    key: &str,
) -> Result<Grant, RepositoryError> {
    let mut tx = f.pool.begin().await?;
    let result = support::revoke(
        &mut tx,
        &context(root, 140),
        &Revoke {
            id,
            expected_revision: 1,
            reason: "Support completed".into(),
        },
        key,
        "revoke-request",
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_support_grants_explicit_activation_root_binding_expiry_and_revoke(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = f.in_epoch(async {
        let root=setup(&f).await?;
        assert!(root.ceiling.memberships.is_empty());
        assert!(select(&f,&root,None,120).await.is_err(),"support cannot implicitly become membership");
        assert!(select(&f,&root,Some(Uuid::new_v4()),120).await.is_err());
        let grant=activate(&f,&root,"once").await?;
        assert_eq!(grant.expires_at,400,"original MFA is the absolute deadline");
        assert_eq!(activate(&f,&root,"once").await?,grant);
        let selected=select(&f,&root,Some(grant.id),130).await?;
        let detail=selected.decision.authorization_details();
        assert_eq!(detail[0]["access_basis"],"administrative_grant");
        assert_eq!(detail[0]["admin_access_grant_id"],grant.id.to_string());
        assert_eq!(detail[0]["identifier"],f.organization.external_id);
        assert!(current(&f,&root,&selected,399).await?);
        assert!(!current(&f,&root,&selected,400).await?);
        let other=root.consent.bind("another-root",1000)?;
        assert!(select(&f,&other,Some(grant.id),130).await.is_err());
        assert!(revoke(&f,&other,grant.id,"foreign").await.is_err());
        for case in 0..5 {
            let mut bad=selected.clone();
            match case {
                0=>bad.decision.privileges.insert("documents.write".into()),
                1=>{bad.decision.organization_id=Uuid::new_v4();true},
                2=>{bad.decision.organization_identifier="other".into();true},
                3=>{bad.decision.expires_at=401;true},
                _=>{bad.decision.authority=AccessAuthority::AdministrativeGrant{grant_id:Uuid::new_v4(),grant_revision:1};true},
            };
            assert!(!current(&f,&root,&bad,140).await?,"tampered {case}");
        }
        let(a,b)=tokio::join!(revoke(&f,&root,grant.id,"done"),revoke(&f,&root,grant.id,"done"));
        let revoked=a?;assert_eq!(revoked,b?);assert!(!revoked.active);assert_eq!(revoked.revision,2);
        assert!(!current(&f,&root,&selected,140).await?);
        assert!(select(&f,&root,Some(grant.id),140).await.is_err());
        assert!(activate(&f,&root,"once").await.is_err(),"replay cannot revive a revoked grant");
        assert!(sqlx::query("UPDATE aegaeon.organization_admin_access_grants SET active=true WHERE id=$1").bind(grant.id).execute(&f.pool).await.is_err());
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events e JOIN aegaeon.organization_authority_outbox o ON o.event_id=e.id WHERE e.domain_id=$1 AND event_type LIKE 'organization.support.%'").bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;assert_eq!(count,2);
        Ok(())
    }).await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn pg_organizations_support_grants_policy_disable_stays_revocable_and_never_revives(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = f
        .in_epoch(async {
            let root = setup(&f).await?;
            let grant = activate(&f, &root, "once").await?;
            let selected = select(&f, &root, Some(grant.id), 130).await?;
            let mut tx = f.pool.begin().await?;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *tx)
                .await?;
            assert!(
                selected::is_current(&mut tx, &selected, &root, &root.ceiling.binding, 140)
                    .await
                    .is_err()
            );
            tx.rollback().await?;
            assert!(
                current(&f, &root, &selected, 140).await?,
                "healthy primary recovery"
            );
            let policy = support_policy::configure(&f, "support", 1, None)
                .await
                .err();
            assert!(policy.is_some(), "changed idempotency body rejected");
            support_policy::configure(&f, "off", 2, None).await?;
            assert!(!current(&f, &root, &selected, 140).await?);
            assert!(activate(&f, &root, "after-disable").await.is_err());
            assert!(
                !revoke(&f, &root, grant.id, "stop").await?.active,
                "revocation survives disabled policy"
            );
            Ok(())
        })
        .await;
    f.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL and owned audit fault"]
async fn pg_organizations_support_grants_creation_race_audit_rollback_and_finite_root_capacity(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = f.in_epoch(async {
        let root=setup(&f).await?;
        let admin=crate::web::test_support::test_admin_pool(&f.pool).await?;
        let guard=format!("support_fault_{}",Uuid::new_v4().simple());
        sqlx::query(&format!("ALTER TABLE aegaeon.organization_authority_events ADD CONSTRAINT {guard} CHECK(organization_id<>'{}'::uuid OR event_type<>'organization.support.activated') NOT VALID",f.organization.id)).execute(&admin).await?;
        let failed=activate(&f,&root,"fault").await;
        sqlx::query(&format!("ALTER TABLE aegaeon.organization_authority_events DROP CONSTRAINT {guard}")).execute(&admin).await?;
        assert!(matches!(failed,Err(RepositoryError::Storage(_))));
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_admin_access_grants WHERE domain_id=$1").bind(f.organization.scope.domain_id).fetch_one(&f.pool).await?;assert_eq!(count,0);
        let(a,b)=tokio::join!(activate(&f,&root,"fault"),activate(&f,&root,"fault"));assert_eq!(a?,b?);
        for i in 1..16{activate(&f,&root,&format!("bounded-{i}")).await?;}
        assert!(matches!(activate(&f,&root,"over-capacity").await,Err(RepositoryError::Authority(AuthorityError::Exhausted))));
        let grant=activate(&f,&root,"fault").await?;
        assert!(!revoke(&f,&root,grant.id,"full-capacity-revoke").await?.active);
        assert!(activate(&f,&root,"still-full").await.is_err(),"permanent receipts bound history and replay");
        Ok(())
    }).await;
    f.cleanup(result).await
}

#[test]
fn organizations_support_grants_selector_requires_explicit_non_null_uuid() {
    for value in [
        serde_json::Value::Null,
        serde_json::json!("organization_00000000-0000-0000-0000-000000000001"),
        serde_json::json!(Uuid::nil()),
    ] {
        let json=serde_json::json!([{"type":ORGANIZATION_ACCESS_TYPE,"identifier":"external","admin_access_grant_id":value}]).to_string();
        assert!(AccessRequest::parse(&json).is_err());
    }
    let json=serde_json::json!([{"type":ORGANIZATION_ACCESS_TYPE,"identifier":"外部ID","admin_access_grant_id":Uuid::new_v4()}]).to_string();
    assert!(AccessRequest::parse(&json).is_ok());
}

mod epochs;
