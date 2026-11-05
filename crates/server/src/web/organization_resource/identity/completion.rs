//! Own preflight cleanup before independent allocation, then the actual commit.
use super::*;
use crate::organizations::{
    invitations::delegated::Runtime,
    request_work::Admission,
    witness::creation::{primary, Receipt},
};
use crate::runtime_configuration::RuntimeAuthorityRevision;
use sqlx::{Postgres, Transaction};

pub(super) struct Command<'a> {
    pub state: &'a AppState,
    pub admission: &'a ResourceAdmission,
    pub scope: Scope,
    pub invitation: Uuid,
    pub object_id: Uuid,
    pub proof: String,
    pub password: String,
    pub password_confirmation: String,
    pub request_id: &'a str,
}

struct Completion<'a> {
    command: Command<'a>,
    expected: RuntimeAuthorityRevision,
    started: i64,
}

// An uncertain cleanup or commit must not leave this local work usable.
struct Cleanup<'a> {
    admission: &'a Admission,
    confirmed: bool,
}
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.admission.close_until_restart();
        }
    }
}

pub(super) async fn execute(command: Command<'_>) -> Result<serde_json::Value, Response> {
    let state = command.state;
    if command.password != command.password_confirmation
        || crate::local_credentials::validate_password(&command.password).is_err()
    {
        return Err(invalid(state));
    }
    let mutation = Completion {
        expected: crate::web::organization_authority::projection(state)?,
        started: now(state)?,
        command,
    };
    let admission = &mutation.command.admission.0;
    let result = match mutation.preflight().await? {
        service::Preparation::Registration(input) => {
            let receipt = admission
                .prepare_creation(state.environment_id, &input)
                .await
                .map_err(|e| witness_error(state, &e))?;
            primary::execute(&state.db_pool, admission, &input, &receipt, &mutation)
                .await
                .map_err(|e| match e {
                    primary::Failure::Mutation(response) => response,
                    primary::Failure::Witness(error) => witness_error(state, &error),
                    primary::Failure::Storage(_) | primary::Failure::Reconciliation => {
                        unavailable(state)
                    }
                })?
        }
        service::Preparation::Recovery => mutation.recover().await?,
    };
    Ok(
        serde_json::json!({"subject":result.subject,"message":"Credential updated. Sign in again through your application, then accept the invitation."}),
    )
}

fn witness_error(state: &AppState, failure: &crate::organizations::witness::Error) -> Response {
    if matches!(failure,crate::organizations::witness::Error::Storage(sqlx::Error::Database(error))
        if matches!(error.message(),"permanent owner conflict"|"permanent subject conflict"|"creation conflict"))
    {
        error(state, StatusCode::CONFLICT, "conflict")
    } else {
        unavailable(state)
    }
}

impl Completion<'_> {
    fn runtime(&self) -> Runtime<'_> {
        Runtime {
            store: &self.command.state.tokens.store,
            admission: &self.command.admission.0,
            issuer: &self.command.state.issuer,
        }
    }
    fn input(&self, time: i64) -> service::Completion<'_> {
        service::Completion {
            request_id: self.command.request_id,
            scope: self.command.scope,
            invitation: self.command.invitation,
            request: self.command.object_id,
            proof: &self.command.proof,
            now: time,
        }
    }
    async fn preflight(&self) -> Result<service::Preparation, Response> {
        let state = self.command.state;
        let admission = &self.command.admission.0;
        let mut cleanup = Cleanup {
            admission,
            confirmed: false,
        };
        let mut connection = admission
            .connection(&state.db_pool)
            .await
            .map_err(|_| unavailable(state))?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable(state))?
            .begin()
            .await
            .map_err(|_| unavailable(state))?;
        let result = async {
            crate::web::organization_authority::recheck_projection(state, &mut tx, &self.expected)
                .await?;
            let current = now(state)?;
            if current < self.started {
                return Err(unavailable(state));
            }
            service::prepare_completion(&mut tx, &self.input(current), Some(&self.runtime()))
                .await
                .map_err(|e| members::storage_error(state, &e))
        }
        .await;
        tx.rollback().await.map_err(|_| unavailable(state))?;
        connection.release().await;
        admission.ensure_open().map_err(|_| unavailable(state))?;
        cleanup.confirmed = true;
        result
    }
    async fn complete(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        creation: Option<service::Creation<'_>>,
    ) -> Result<service::CompletionResult, Response> {
        let state = self.command.state;
        crate::web::organization_authority::recheck_projection(state, tx, &self.expected).await?;
        let current = now(state)?;
        if current < self.started {
            return Err(unavailable(state));
        }
        service::complete(
            tx,
            &self.input(current),
            self.command.password.clone(),
            &self.command.admission.0,
            Some(&self.runtime()),
            creation,
        )
        .await
        .map_err(|e| members::storage_error(state, &e))
    }
    async fn current(&self, tx: &mut Transaction<'_, Postgres>) -> Result<(), Response> {
        let state = self.command.state;
        crate::web::organization_authority::recheck_projection(state, tx, &self.expected).await?;
        let current = now(state)?;
        if current < self.started {
            return Err(unavailable(state));
        }
        service::recheck_completion(tx, &self.input(current), Some(&self.runtime()))
            .await
            .map_err(|e| members::storage_error(state, &e))
    }
    async fn recover(&self) -> Result<service::CompletionResult, Response> {
        let state = self.command.state;
        let admission = &self.command.admission.0;
        let mut cleanup = Cleanup {
            admission,
            confirmed: false,
        };
        let mut connection = admission
            .connection(&state.db_pool)
            .await
            .map_err(|_| unavailable(state))?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable(state))?
            .begin()
            .await
            .map_err(|_| unavailable(state))?;
        let result = async {
            let value = self.complete(&mut tx, None).await?;
            self.current(&mut tx).await?;
            admission.admit_commit().map_err(|_| unavailable(state))?;
            Ok(value)
        }
        .await;
        if result.is_ok() {
            tx.commit().await.map_err(|_| unavailable(state))?;
        } else {
            tx.rollback().await.map_err(|_| unavailable(state))?;
        }
        connection.release().await;
        admission.ensure_open().map_err(|_| unavailable(state))?;
        cleanup.confirmed = true;
        result
    }
}

impl primary::Mutation for Completion<'_> {
    type Output = service::CompletionResult;
    type Error = Response;
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(self.complete(tx, Some(service::Creation::New(receipt))))
    }
    fn replay<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> primary::MutationFuture<'a, Self::Output, Response> {
        Box::pin(self.complete(tx, Some(service::Creation::Replay(receipt))))
    }
    fn recheck<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
    ) -> primary::MutationFuture<'a, (), Response> {
        Box::pin(self.current(tx))
    }
}
