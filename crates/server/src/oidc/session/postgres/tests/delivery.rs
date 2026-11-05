use super::*;
use crate::oidc::session::delivery::{
    Binding, Candidate, Command, Completion, Identity, Outcome, Request,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;

async fn request(fixture: &Fixture) -> anyhow::Result<Request> {
    let backend = fixture.backend();
    let sid = backend
        .get_or_create(OidcSessionContext {
            user_id: "subject",
            auth_session_id: "browser",
        })
        .await
        .map_err(anyhow::Error::msg)?;
    backend
        .add_client(&sid, "client")
        .await
        .map_err(anyhow::Error::msg)?;
    let event = backend
        .logout_sid(&sid, 60)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("event missing"))?;
    let identity = Identity {
        sid,
        event_jti: event.jti,
        subject: "subject".into(),
        client_id: "client".into(),
    };
    let binding = Binding {
        issuer: "https://issuer.example".into(),
        uri: "https://client.example/logout".into(),
        session_required: true,
    };
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch from clock_timestamp()))::bigint")
            .fetch_one(&fixture.pool)
            .await?;
    let now = u64::try_from(now)?;
    let jti = Uuid::new_v4().to_string();
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"alg":"RS256","typ":"logout+jwt","kid":"fixture"}),
    )?);
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":binding.issuer,"aud":identity.client_id,"iat":now,"exp":now+300,"jti":jti,"sid":identity.sid,"events":{"http://schemas.openid.net/event/backchannel-logout":{}}}))?);
    // Storage validates shape/binding; the real sender supplies a signed token.
    let candidate = Candidate::new(format!("{header}.{claims}.c2ln"), jti, now, now + 300);
    Ok(Request::new(
        identity,
        Some(binding),
        Command::Claim {
            candidate: Some(candidate),
            owner: "owner".into(),
            timeout: 30,
        },
    ))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; concurrent send ownership and stale completion fencing"]
async fn pg_oidc_delivery_concurrency_and_completion() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let backend = Arc::new(fixture.backend());
        let request = request(&fixture).await?;
        let mut jobs = tokio::task::JoinSet::new();
        for i in 0..32 {
            let backend = backend.clone();
            let mut request = request.clone();
            if let Command::Claim { owner, .. } = &mut request.command {
                *owner = format!("owner-{i}");
            }
            jobs.spawn(async move { backend.delivery_transition(&request).await });
        }
        let mut permits = Vec::new();
        let mut deferred = 0;
        while let Some(result) = jobs.join_next().await {
            match result?.map_err(anyhow::Error::msg)? {
                Outcome::Granted(permit) => permits.push(permit),
                Outcome::Deferred => deferred += 1,
                _ => anyhow::bail!("unexpected claim result"),
            }
        }
        anyhow::ensure!(permits.len() == 1 && deferred == 31);
        let permit = permits.remove(0);
        anyhow::ensure!(permit
            .send_deadline
            .is_some_and(|deadline| deadline > std::time::Instant::now()));
        let mut current = request.clone();
        current.command = Command::Check(permit.clone());
        anyhow::ensure!(matches!(
            backend
                .delivery_transition(&current)
                .await
                .map_err(anyhow::Error::msg)?,
            Outcome::Granted(_)
        ));
        let mut stale = permit.clone();
        stale.owner = "stale-owner".into();
        current.command = Command::Complete(stale, Completion::Delivered);
        anyhow::ensure!(matches!(
            backend
                .delivery_transition(&current)
                .await
                .map_err(anyhow::Error::msg)?,
            Outcome::Deferred
        ));
        current.command = Command::Complete(permit, Completion::Delivered);
        anyhow::ensure!(matches!(
            backend
                .delivery_transition(&current)
                .await
                .map_err(anyhow::Error::msg)?,
            Outcome::Completed
        ));
        anyhow::ensure!(matches!(
            backend
                .delivery_transition(&request)
                .await
                .map_err(anyhow::Error::msg)?,
            Outcome::AlreadyDelivered
        ));
        let mut wrong = request.clone();
        wrong.identity.subject = "other".into();
        anyhow::ensure!(backend.delivery_transition(&wrong).await.is_err());
        sqlx::query("UPDATE aegaeon.runtime_oidc_clients SET delivery='invalid'")
            .execute(&fixture.pool)
            .await?;
        anyhow::ensure!(backend.delivery_transition(&request).await.is_err());
        Ok(())
    }
    .await;
    fixture.finish().await?;
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL; authority clock after row lock and rollback on unavailable storage"]
async fn pg_oidc_delivery_expiry_while_waiting() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let result=async {
        let request=request(&fixture).await?;
        // Retain a valid parent duration while moving its expiry within this lock wait.
        sqlx::query("UPDATE aegaeon.runtime_oidc_sessions SET logged_out_at=floor(extract(epoch from clock_timestamp()))::bigint-10,expires_at=clock_timestamp()+interval '1 second'").execute(&fixture.pool).await?;
        let mut tx=fixture.pool.begin().await?;
        sqlx::query("SELECT sid FROM aegaeon.runtime_oidc_clients FOR UPDATE").fetch_all(&mut *tx).await?;
        let backend=fixture.backend();let pending=request.clone();
        let job=tokio::spawn(async move {backend.delivery_transition(&pending).await});
        // The DB lock and clock are real; no model-only clock override is consulted.
        sqlx::query("SELECT pg_sleep(1.1)").execute(&mut *tx).await?;
        tx.commit().await?;
        anyhow::ensure!(matches!(job.await?.map_err(anyhow::Error::msg)?,Outcome::Terminal));
        let stored:Option<String>=sqlx::query_scalar("SELECT delivery FROM aegaeon.runtime_oidc_clients").fetch_one(&fixture.pool).await?;
        anyhow::ensure!(stored.is_none());
        sqlx::query("DROP TABLE aegaeon.runtime_oidc_clients").execute(&fixture.pool).await?;
        anyhow::ensure!(fixture.backend().delivery_transition(&request).await.is_err());
        Ok(())
    }.await;
    fixture.finish().await?;
    result
}
