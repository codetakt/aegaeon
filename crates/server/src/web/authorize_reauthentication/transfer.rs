//! Transfer a single browser interaction while retaining the original expiry.
use super::*;

pub(in crate::web) struct CompletedLogin {
    pub(super) pending: storage::Pending,
    pub(super) token: String,
    pub(super) browser: String,
}

impl CompletedLogin {
    pub(in crate::web) async fn consume(
        &self,
        state: &AppState,
        session: Option<&Value>,
    ) -> Result<(), Response> {
        storage::consume(
            state,
            &self.pending,
            &self.token,
            &self.browser,
            session.ok_or_else(invalid)?,
        )
        .await
    }

    async fn rotate(
        &self,
        state: &AppState,
        session: &Value,
        token: &str,
        browser: &str,
    ) -> Result<(), Response> {
        let mut connection =
            crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(
                &state.db_pool,
            )
            .await
            .map_err(|_| unavailable())?;
        crate::organizations::request_work::async_store::admit_current_commit()
            .map_err(|_| unavailable())?;
        // The same live slot changes hands in one primary write. Compare the
        // old handles too, so a late replay can never rotate the new receipt.
        let count = sqlx::query("UPDATE aegaeon.authorization_logins
            SET token_sha256=$1,browser_sha256=$2,csrf_sha256=NULL,session_snapshot=NULL,completed_at=NULL
            WHERE id=$3 AND environment_id=$4 AND issuer=$5 AND client_id=$6
            AND authorize_uri='/authorize' AND request_snapshot=$7 AND session_snapshot=$8
            AND token_sha256=$9 AND browser_sha256=$10 AND completed_at IS NOT NULL
            AND consumed_at IS NULL AND expires_at>clock_timestamp()")
            .bind(digest(token)).bind(digest(browser)).bind(self.pending.id)
            .bind(state.environment_id).bind(state.issuer.as_str()).bind(&self.pending.client_id)
            .bind(&self.pending.snapshot).bind(session).bind(digest(&self.token)).bind(digest(&self.browser))
            .execute(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?
            .rows_affected();
        connection.release().await;
        if count == 1 {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

pub(in crate::web) struct PreviousConsent<'a> {
    pub(in crate::web) id: uuid::Uuid,
    pub(in crate::web) subject: &'a str,
    pub(in crate::web) sid: &'a str,
    pub(in crate::web) snapshot: &'a Value,
}

impl PreviousConsent<'_> {
    pub(super) async fn retire(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        state: &AppState,
    ) -> Result<(), Response> {
        let count = sqlx::query(
            "UPDATE aegaeon.authorization_consents SET decision='deny',decided_at=now()
            WHERE id=$1 AND environment_id=$2 AND issuer=$3 AND subject=$4 AND session_sha256=$5
            AND request_snapshot=$6 AND decision IS NULL AND expires_at>clock_timestamp()",
        )
        .bind(self.id)
        .bind(state.environment_id)
        .bind(state.issuer.as_str())
        .bind(self.subject)
        .bind(digest(self.sid))
        .bind(self.snapshot)
        .execute(&mut **tx)
        .await
        .map_err(|_| unavailable())?
        .rows_affected();
        if count == 1 {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

pub(in crate::web) async fn start(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    consent: Option<&PreviousConsent<'_>>,
    upstream: Option<&crate::organizations::authentication::OriginalAuthentication>,
) -> Result<(String, String), Response> {
    let token = random_token()?;
    let browser = random_token()?;
    if let Some(login) = &ctx.pending_organization_login {
        login
            .rotate(
                state,
                ctx.reauthentication_session.as_ref().ok_or_else(invalid)?,
                &token,
                &browser,
            )
            .await?;
    } else {
        storage::create(state, ctx, &token, &browser, consent, upstream).await?;
    }
    Ok(login_handles(&token, &browser))
}
