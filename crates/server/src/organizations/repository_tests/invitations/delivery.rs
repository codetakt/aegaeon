use super::*;
use crate::organizations::{
    invitations::worker,
    operators::mutations::delivery::{self as config, Change, Channel},
};

async fn setup(f: &InvitationFixture) -> Result<Uuid, Box<dyn std::error::Error>> {
    sqlx::query("UPDATE aegaeon.organization_operator_grants SET capabilities='[\"provision\",\"configure\"]'::jsonb WHERE environment_id=$1")
        .bind(f.base.env.environment_id).execute(&f.base.pool).await?;
    let mut tx = f.base.pool.begin().await?;
    config::apply(
        &mut tx,
        f.base.organization.scope,
        f.base.env.team_id,
        &f.base.actor,
        "configure-mail",
        &Change {
            expected_revision: 1,
            channel: Some(channel()),
        },
    )
    .await?;
    let invitation = invite::issue_first_admin(&mut tx, f.issuance()).await?;
    tx.commit().await?;
    Ok(invitation.id)
}
fn channel() -> Channel {
    Channel {
        endpoint: "https://delivery.example.test/envelopes".into(),
        credential_sha256: "a".repeat(64),
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_delivery_rollback_recovery_and_late_completion() -> TestResult {
    let f = InvitationFixture::new().await?;
    let result=f.base.in_epoch(async {
        let id=setup(&f).await?;let scope=f.base.organization.scope;
        let mut tx=f.base.pool.begin().await?;
        assert!(worker::claim(&mut tx,scope,id,None,&"b".repeat(64),101).await.is_err());tx.rollback().await?;
        let mut tx=f.base.pool.begin().await?;
        let (lost,_)=worker::claim(&mut tx,scope,id,None,&"a".repeat(64),101).await?.ok_or("claim")?;
        tx.rollback().await?;
        let mut tx=f.base.pool.begin().await?;
        assert!(worker::admit_send(&mut tx,&lost,101).await.is_err());tx.rollback().await?;
        let mut tx=f.base.pool.begin().await?;
        let (old,_)=worker::claim(&mut tx,scope,id,None,&"a".repeat(64),101).await?.ok_or("claim")?;tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        worker::admit_send(&mut tx,&old,101).await?;
        assert!(worker::admit_send(&mut tx,&lost,101).await.is_err());
        assert!(!worker::complete(&mut tx,&lost,worker::Outcome::Acknowledged).await?);
        assert!(worker::claim(&mut tx,scope,id,None,&"a".repeat(64),160).await?.is_none());tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        let (new,_)=worker::claim(&mut tx,scope,id,None,&"a".repeat(64),161).await?.ok_or("recovery")?;
        assert!(!worker::complete(&mut tx,&old,worker::Outcome::Acknowledged).await?);
        assert!(worker::admit_send(&mut tx,&old,161).await.is_err());tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        worker::admit_send(&mut tx,&new,161).await?;
        assert!(worker::complete(&mut tx,&new,worker::Outcome::Acknowledged).await?);tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        assert!(!worker::complete(&mut tx,&new,worker::Outcome::Rejected).await?);
        assert!(worker::claim(&mut tx,scope,id,None,&"a".repeat(64),221).await?.is_none());tx.commit().await?;
        let (request_id,event):(String,serde_json::Value)=sqlx::query_as("SELECT request_id,data FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.invitation_transport_result'")
            .bind(f.request.organization_id).fetch_one(&f.base.pool).await?;
        assert_eq!(request_id,format!("delivery:{id}:2"));
        assert_eq!(event["authorityBasis"]["executor"]["kind"],"service");
        assert_eq!(event["authorityBasis"]["executor"]["deliveryRevision"],2);
        assert_eq!(event["authorityBasis"]["originatingPrincipal"]["id"],f.base.actor.id.to_string());
        assert_eq!(event["before"]["outcome"],"uncertain");
        assert_eq!(event["after"]["outcome"],"acknowledged");
        let n:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_authority_events WHERE organization_id=$1 AND event_type='organization.invitation_transport_result'").bind(f.request.organization_id).fetch_one(&f.base.pool).await?;assert_eq!(n,1);
        Ok(())
    }).await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_delivery_current_channel_inviter_and_completion_after_disable(
) -> TestResult {
    let f = InvitationFixture::new().await?;
    let result=f.base.in_epoch(async {
        let id=setup(&f).await?;let scope=f.base.organization.scope;
        let mut tx=f.base.pool.begin().await?;
        let (claim,_)=worker::claim(&mut tx,scope,id,None,&"a".repeat(64),101).await?.ok_or("claim")?;tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        config::apply(&mut tx,scope,f.base.env.team_id,&f.base.actor,"disable-mail",&Change{expected_revision:2,channel:None}).await?;tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        assert!(worker::admit_send(&mut tx,&claim,102).await.is_err());tx.rollback().await?;
        sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=false,revision=revision+1 WHERE environment_id=$1").bind(f.base.env.environment_id).execute(&f.base.pool).await?;
        let mut tx=f.base.pool.begin().await?;
        assert!(worker::complete(&mut tx,&claim,worker::Outcome::Acknowledged).await?);tx.commit().await?;
        let mut tx=f.base.pool.begin().await?;
        assert!(worker::claim(&mut tx,scope,id,None,&"a".repeat(64),161).await.is_err());tx.rollback().await?;
        let state:String=sqlx::query_scalar("SELECT state FROM aegaeon.organization_invitations WHERE id=$1").bind(id).fetch_one(&f.base.pool).await?;assert_eq!(state,"pending");
        Ok(())
    }).await;
    f.base.cleanup(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn pg_organizations_delivery_concurrent_claim_has_one_effect() -> TestResult {
    let f = InvitationFixture::new().await?;
    let result = f
        .base
        .in_epoch(async {
            let id = setup(&f).await?;
            let scope = f.base.organization.scope;
            let attempt = || async {
                let mut tx = f.base.pool.begin().await?;
                let claimed = worker::claim(&mut tx, scope, id, None, &"a".repeat(64), 101)
                    .await?
                    .is_some();
                tx.commit().await?;
                Ok::<_, Box<dyn std::error::Error>>(claimed)
            };
            let (a, b) = tokio::join!(attempt(), attempt());
            assert_ne!(a?, b?);
            let revision: i64 = sqlx::query_scalar(
                "SELECT delivery_revision FROM aegaeon.organization_invitations WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&f.base.pool)
            .await?;
            assert_eq!(revision, 1);
            Ok(())
        })
        .await;
    f.base.cleanup(result).await
}

#[test]
fn organizations_delivery_channel_rejects_untrusted_url_and_bad_credential_digest() {
    for endpoint in [
        "http://delivery.example.test/a",
        "https://127.0.0.1/a",
        "https://localhost/a",
        "https://user@delivery.example.test/a",
        "https://delivery.example.test:8443/a",
        "https://delivery.example.test/a?q=secret",
        "https://delivery.example.test/a#secret",
        "https://DELIVERY.example.test/a",
        "https://delivery.example.test./a",
    ] {
        let mut c = channel();
        c.endpoint = endpoint.into();
        assert!(c.validate().is_err(), "{endpoint}");
    }
    assert!(channel().validate().is_ok());
    let mut c = channel();
    c.credential_sha256 = "A".repeat(64);
    assert!(c.validate().is_err());
}
