//! Retained allocation and callback persistence each keep their actual owner.
use super::super::upstream_callback_exchange::UpstreamCallbackExchange;
use super::super::upstream_callback_users::{
    prepare_retained_upstream, provision_retained_upstream, resolve_linked_upstream_callback_user,
    upstream_callback_auth_time,
};
use super::*;
use crate::organizations::{
    authentication::OriginalAuthentication,
    request_work::Admission,
    witness::creation::{primary, Receipt},
};
use crate::runtime_configuration::RuntimeAuthorityRevision;
use sqlx::{Postgres, Transaction};
mod binding;
mod current;
type Output = (
    UpstreamCallbackUserResolution,
    Option<OriginalAuthentication>,
);

pub(super) fn unavailable(state: &AppState) -> Response {
    json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("upstream callback storage is unavailable"),
        &state.issuer,
    )
}
fn denied(state: &AppState) -> Response {
    json_error_with_iss(
        StatusCode::FORBIDDEN,
        "access_denied",
        Some("upstream authentication is no longer current"),
        &state.issuer,
    )
}
struct Cleanup<'a> {
    owner: &'a Admission,
    confirmed: bool,
}
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.owner.close_until_restart();
        }
    }
}
struct Callback<'a> {
    state: &'a AppState,
    request: &'a UpstreamAuthRequest,
    exchange: &'a UpstreamCallbackExchange,
    request_id: &'a str,
    owner: Admission,
    expected: RuntimeAuthorityRevision,
    started: u64,
}

pub(super) async fn persist(
    state: &AppState,
    request: &UpstreamAuthRequest,
    exchange: &UpstreamCallbackExchange,
    request_id: &str,
    owner: Admission,
) -> Response {
    let result = async {
        async_store::ensure_environment_if_scoped(request.context.environment_id)
            .map_err(|_| unavailable(state))?;
        if request.context.environment_id != state.environment_id {
            return Err(unavailable(state));
        }
        state.require_subject_namespace()?;
        let callback = Callback {
            state,
            request,
            exchange,
            request_id,
            owner,
            expected: super::super::organization_authority::projection(state)?,
            started: now_epoch_secs().map_err(|_| unavailable(state))?,
        };
        callback.run().await
    }
    .await;
    match result {
        Ok((user, original)) => {
            finalize_upstream_callback_response(
                state,
                request,
                &exchange.discovery,
                &exchange.id_token,
                &user,
                original,
                request_id,
            )
            .await
        }
        Err(response) => response,
    }
}

impl Callback<'_> {
    fn user(
        &self,
        id: uuid::Uuid,
        subject: String,
    ) -> Result<UpstreamCallbackUserResolution, Response> {
        Ok(UpstreamCallbackUserResolution {
            local_end_user_id: Some(id),
            user_id: subject,
            auth_time: upstream_callback_auth_time(&self.exchange.id_token, &self.state.issuer)?,
        })
    }
    async fn preflight(&self) -> Result<Option<current::Linked>, Response> {
        let mut cleanup = Cleanup {
            owner: &self.owner,
            confirmed: false,
        };
        let mut connection = self
            .owner
            .connection(&self.state.db_pool)
            .await
            .map_err(|_| unavailable(self.state))?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable(self.state))?
            .begin()
            .await
            .map_err(|_| unavailable(self.state))?;
        let result = async {
            current::check(self, &mut tx).await?;
            let linked = current::linked(self, &mut tx).await?;
            if linked.is_none() {
                prepare_retained_upstream(
                    &mut tx,
                    self.request,
                    &self.exchange.id_token,
                    &self.state.issuer,
                )
                .await?;
                // Validate the complete bounded canonical payload before allocation.
                binding::input(self)?;
            }
            Ok(linked)
        }
        .await;
        tx.rollback().await.map_err(|_| unavailable(self.state))?;
        connection.release().await;
        self.owner
            .ensure_open()
            .map_err(|_| unavailable(self.state))?;
        cleanup.confirmed = true;
        result
    }
    async fn history(&self, linked: &current::Linked) -> Result<Option<Receipt>, Response> {
        self.owner
            .check_history(self.state.environment_id, linked.id, &linked.subject)
            .await
            .map_err(|_| unavailable(self.state))?;
        let receipt = self
            .owner
            .lookup_creation(
                self.state.environment_id,
                crate::organizations::witness::creation::Kind::Upstream,
                binding::selector(self)?,
            )
            .await
            .map_err(|_| unavailable(self.state))?;
        if receipt.as_ref().is_some_and(|r| {
            r.state() != crate::organizations::witness::creation::State::Committed
                || r.owner_id() != linked.id
        }) {
            return Err(unavailable(self.state));
        }
        Ok(receipt)
    }
    async fn run(&self) -> Result<Output, Response> {
        if let Some(linked) = self.preflight().await? {
            let receipt = self.history(&linked).await?;
            return self.existing(&linked, receipt.as_ref()).await;
        }
        let input = binding::input(self)?;
        let receipt = self
            .owner
            .prepare_creation(self.state.environment_id, &input)
            .await
            .map_err(|_| unavailable(self.state))?;
        let (output, created) =
            primary::execute(&self.state.db_pool, &self.owner, &input, &receipt, self)
                .await
                .map_err(|failure| match failure {
                    primary::Failure::Mutation(response) => response,
                    _ => unavailable(self.state),
                })?;
        if created {
            return Ok(output);
        }
        let linked = current::Linked {
            id: output
                .0
                .local_end_user_id
                .ok_or_else(|| unavailable(self.state))?,
            subject: output.0.user_id,
        };
        let receipt = self.history(&linked).await?;
        self.existing(&linked, receipt.as_ref()).await
    }
    async fn existing(
        &self,
        expected: &current::Linked,
        receipt: Option<&Receipt>,
    ) -> Result<Output, Response> {
        let mut cleanup = Cleanup {
            owner: &self.owner,
            confirmed: false,
        };
        let mut connection = self
            .owner
            .connection(&self.state.db_pool)
            .await
            .map_err(|_| unavailable(self.state))?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable(self.state))?
            .begin()
            .await
            .map_err(|_| unavailable(self.state))?;
        let result = async {
            current::check(self, &mut tx).await?;
            let linked = current::linked(self, &mut tx)
                .await?
                .ok_or_else(|| denied(self.state))?;
            if &linked != expected {
                return Err(denied(self.state));
            }
            match receipt {
                Some(receipt) => if !primary::check_committed(&mut tx,receipt).await.map_err(|_|unavailable(self.state))? {return Err(unavailable(self.state));},
                None => {
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM aegaeon.organization_creation_receipts WHERE environment_id=$1 AND owner_id=$2 AND kind='upstream')")
                        .bind(self.state.environment_id).bind(linked.id).fetch_one(&mut *tx).await.map_err(|_|unavailable(self.state))?;
                    if exists {return Err(unavailable(self.state));}
                }
            }
            let linked = resolve_linked_upstream_callback_user(
                &mut tx,
                self.request,
                &self.exchange.upstream_sub_hash,
                &self.state.issuer,
                self.request_id,
            )
            .await?
            .ok_or_else(|| denied(self.state))?;
            let user = self.user(linked.end_user_id, linked.subject)?;
            let original = persist_callback_effects(
                &mut tx,
                self.request,
                self.exchange,
                &user,
                &self.state.issuer,
                self.request_id,
            )
            .await?;
            current::check(self, &mut tx).await?;
            self.owner
                .admit_commit()
                .map_err(|_| unavailable(self.state))?;
            Ok((user, original))
        }
        .await;
        if result.is_ok() {
            tx.commit().await.map_err(|_| unavailable(self.state))?;
        } else {
            tx.rollback().await.map_err(|_| unavailable(self.state))?;
        }
        connection.release().await;
        self.owner
            .ensure_open()
            .map_err(|_| unavailable(self.state))?;
        cleanup.confirmed = true;
        result
    }
}

impl primary::Mutation for Callback<'_> {
    type Output = (Output, bool);
    type Error = Response;
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(async move {
            current::check(self, tx).await?;
            if current::linked(self, tx).await?.is_some() {
                return Err(denied(self.state));
            }
            let linked = provision_retained_upstream(
                tx,
                self.request,
                &self.exchange.id_token,
                &self.exchange.upstream_sub_hash,
                receipt,
                &self.state.issuer,
                self.request_id,
            )
            .await?;
            let user = self.user(linked.end_user_id, linked.subject)?;
            let original = persist_callback_effects(
                tx,
                self.request,
                self.exchange,
                &user,
                &self.state.issuer,
                self.request_id,
            )
            .await?;
            Ok(((user, original), true))
        })
    }
    fn replay<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(async move {
            current::check(self, tx).await?;
            let linked = current::linked(self, tx)
                .await?
                .ok_or_else(|| denied(self.state))?;
            if linked.id != receipt.owner_id() {
                return Err(denied(self.state));
            }
            let user = self.user(linked.id, linked.subject)?;
            let original = authentication::capture(tx, self.request, self.exchange, &user)
                .await
                .map_err(|_| unavailable(self.state))?;
            Ok(((user, original), false))
        })
    }
    fn recheck<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
    ) -> primary::MutationFuture<'a, (), Response> {
        Box::pin(current::check(self, tx))
    }
}
