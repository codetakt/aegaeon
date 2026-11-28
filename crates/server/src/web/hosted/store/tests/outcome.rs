use super::*;
use crate::organizations::lifecycle::tests::Fixture;
use crate::web::hosted::{
    actions::record_intent,
    flow::{Allocated, Display},
    Action,
};
use serde_json::json;

fn awaiting_response(
    store: &Store,
    now: i64,
    expires: i64,
    hard_deadline: bool,
) -> anyhow::Result<(Flow, Action)> {
    let mut f = Flow::start(
        "browser",
        generation(),
        Uuid::new_v4(),
        invitation(store.environment, now),
        None,
        now,
    );
    if hard_deadline {
        f.deadline = expires;
    }
    f.session = Some(hash("session binding"));
    f.session_subject = Some("private subject".into());
    f.session_until = f.deadline;
    let auth = oauth::Authorization::begin(&store.issuer, f.domain, f.deadline).unwrap();
    f.grant = Some(serde_json::from_value(json!({
        "subject":"private subject", "user_id":Uuid::new_v4(), "account":"private account",
        "sid":"private issuer session", "auth_time":now, "parent_expires_at":f.deadline,
        "cleanup":{"client_id":"fixture-client","deadline":f.deadline,"issuer":store.issuer,"refresh":"refresh secret"},
        "parent":"parent secret", "key":serde_json::to_value(auth)?["key"],
    }))?);
    let proof = MailLink {
        domain_id: f.domain,
        invitation_id: f.invitation,
        object_id: Uuid::new_v4(),
        template: "organization_recipient_challenge".into(),
        expires_at: expires,
        ..invitation(store.environment, now)
    };
    f.challenge = Some(Allocated {
        id: proof.object_id,
        key: "allocation".into(),
        remaining: 4,
        expires,
        child: serde_json::from_value(json!({"access":"recipient secret","expires_at":expires}))?,
        proof: Some(proof),
    });
    f.display = Some(Display {
        etag: "validator".into(),
        view: json!({"organization":"private organization"}),
    });
    f.step = Step::Confirm;
    let action = Action::Confirm {
        flow: f.handle,
        confirmation: f.view(store, now)["confirmation"].as_str().unwrap().into(),
    };
    anyhow::ensure!(record_intent(store, &mut f, &action, now).unwrap());
    anyhow::ensure!(f.step == Step::AcceptPending);
    Ok((f, action))
}

async fn check_outcome(pool: &PgPool, hard_deadline: bool) -> anyhow::Result<()> {
    let environment = Uuid::new_v4();
    let store = replica(pool.clone(), 1, environment);
    let now = crate::web::hosted::now().unwrap();
    let expires = now + 60;
    let (pending, confirm) = awaiting_response(&store, now, expires, hard_deadline)?;
    let mut tx = store.begin().await.unwrap();
    store.save(&mut tx, &pending).await.unwrap();
    tx.commit().await?;
    // The recipient response was never recorded. Resume the persisted intent.
    let mut tx = store.begin().await.unwrap();
    let mut f = store
        .find(&mut tx, Find::Handle(pending.handle))
        .await
        .unwrap()
        .unwrap();
    f.finish_interaction(&store, &mut tx, expires - 1)
        .await
        .unwrap();
    anyhow::ensure!(f.step == Step::AcceptPending && f.grant.is_some());
    f.finish_interaction(&store, &mut tx, expires)
        .await
        .unwrap();
    anyhow::ensure!(f.step == Step::Unconfirmed && f.capability.is_none() && f.grant.is_none());
    let generic = json!({"step":"unconfirmed","flow":f.handle,"csrfToken":f.csrf(&store)});
    anyhow::ensure!(f.view(&store, expires) == generic);
    anyhow::ensure!(!record_intent(&store, &mut f, &confirm, expires).unwrap());
    store.save(&mut tx, &f).await.unwrap();
    tx.commit().await?;
    let mut tx = store.begin().await.unwrap();
    let mut f = store
        .find(&mut tx, Find::Handle(pending.handle))
        .await
        .unwrap()
        .unwrap();
    f.finish_interaction(&store, &mut tx, expires + 1)
        .await
        .unwrap();
    anyhow::ensure!(f.view(&store, expires + 1) == generic);
    let cleanups: i64 =
        sqlx::query_scalar("SELECT count(*) FROM hosted_invitation.cleanup WHERE environment=$1")
            .bind(environment)
            .fetch_one(&mut *tx)
            .await?;
    // At the hard deadline the issuer has already expired the root and family.
    anyhow::ensure!(cleanups == i64::from(!hard_deadline));
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; persistence and expiration of unconfirmed acceptance"]
async fn pg_hosted_store_unobserved_acceptance_at_deadline_returns_only_unconfirmed(
) -> anyhow::Result<()> {
    let f = Fixture::new().await?;
    let result = async {
        setup_schema(&f.database, f.endpoint.get_username()).await?;
        check_outcome(&f.database, false).await?;
        check_outcome(&f.database, true).await
    }
    .await;
    f.finish().await?;
    result
}
