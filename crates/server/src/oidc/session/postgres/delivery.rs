use super::*;
use crate::oidc::session::delivery::{self, Outcome, Parent, Request, STORAGE_ERROR};
use sqlx::Connection;

fn invalid() -> String {
    STORAGE_ERROR.into()
}

impl PostgresOidcSessionBackend {
    pub(in crate::oidc::session::imp) async fn delivery_transition(
        &self,
        request: &Request,
    ) -> Result<Outcome, String> {
        let sid = Uuid::parse_str(&request.identity.sid).map_err(|_| invalid())?;
        let started = std::time::Instant::now();
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| invalid())?;
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            self.transition_on(
                connection.as_mut().map_err(|_| invalid())?,
                sid,
                request,
                started,
            ),
        )
        .await
        .map_err(|_| invalid())
        .and_then(|result| result);
        connection.release().await;
        result
    }

    async fn transition_on(
        &self,
        connection: &mut sqlx::PgConnection,
        sid: Uuid,
        request: &Request,
        started: std::time::Instant,
    ) -> Result<Outcome, String> {
        crate::organizations::request_work::async_store::admit_current_commit()
            .map_err(|_| invalid())?;
        let mut tx = connection.begin().await.map_err(|_| invalid())?;
        let row=sqlx::query_as::<_,(String,Option<Uuid>,Option<i64>,Option<i64>)>("SELECT user_id,logout_jti,logged_out_at,floor(extract(epoch from expires_at))::bigint FROM aegaeon.runtime_oidc_sessions WHERE namespace=$1 AND sid=$2 FOR SHARE")
            .bind(self.database.namespace.as_ref()).bind(sid).fetch_optional(&mut *tx).await.map_err(|_|invalid())?;
        let Some((user, Some(jti), Some(logged_out), Some(deadline))) = row else {
            tx.rollback().await.map_err(|_| invalid())?;
            return Ok(Outcome::Missing);
        };
        if user != request.identity.subject || jti.to_string() != request.identity.event_jti {
            return Err(invalid());
        }
        let prior=sqlx::query_scalar::<_,Option<String>>("SELECT delivery FROM aegaeon.runtime_oidc_clients WHERE namespace=$1 AND sid=$2 AND client_id=$3 FOR UPDATE")
            .bind(self.database.namespace.as_ref()).bind(sid).bind(&request.identity.client_id).fetch_optional(&mut *tx).await.map_err(|_|invalid())?.ok_or_else(invalid)?;
        let time = clock(&mut tx).await?;
        let parent = Parent {
            user_id: user,
            event_jti: jti.to_string(),
            logged_out_at: u64::try_from(logged_out).map_err(|_| invalid())?,
            deadline: u64::try_from(deadline).map_err(|_| invalid())?,
        };
        let mut transition = delivery::transition(
            &parent,
            prior.as_deref(),
            request,
            time.as_secs(),
            time.subsec_nanos() != 0,
        )?;
        if time.as_secs() < transition.valid_before {
            if let Some(record) = &transition.record {
                sqlx::query("UPDATE aegaeon.runtime_oidc_clients SET delivery=$4 WHERE namespace=$1 AND sid=$2 AND client_id=$3")
                    .bind(self.database.namespace.as_ref()).bind(sid).bind(&request.identity.client_id).bind(record).execute(&mut *tx).await.map_err(|_|invalid())?;
            }
            let final_time = clock(&mut tx).await?;
            if final_time.as_secs() >= transition.valid_before || final_time < time {
                tx.rollback().await.map_err(|_| invalid())?;
                return Ok(Outcome::Deferred);
            }
            if let Outcome::Granted(permit) = &mut transition.outcome {
                permit.bind_send_deadline(started, final_time, None)?;
            }
        }
        tx.commit().await.map_err(|_| invalid())?;
        if matches!(&transition.outcome,Outcome::Granted(permit) if permit.send_deadline.is_none_or(|deadline|std::time::Instant::now()>=deadline))
        {
            return Ok(Outcome::Deferred);
        }
        Ok(transition.outcome)
    }
}

async fn clock(connection: &mut sqlx::PgConnection) -> Result<Duration, String> {
    let micros: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch from clock_timestamp())*1000000)::bigint")
            .fetch_one(connection)
            .await
            .map_err(|_| invalid())?;
    Ok(Duration::from_micros(
        u64::try_from(micros).map_err(|_| invalid())?,
    ))
}
