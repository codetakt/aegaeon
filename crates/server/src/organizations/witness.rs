//! Independent control-store client. Pending admissions survive this client's
//! loss; Drop never completes them. Production activation additionally requires
//! the qualified history, store-identity and runtime integration in the design.
#[cfg(test)]
use aegaeon_pure::organization_witness::{self, Action, Phase};
#[cfg(test)]
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sqlx::{Connection, PgConnection};
#[cfg(test)]
use std::{path::Path, time::Duration};
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
mod attribution;
#[cfg(test)]
mod catalog;
#[cfg(test)]
pub mod cli;
pub(in crate::organizations) mod connection;
#[cfg(test)]
pub mod connector;
pub mod creation;
#[cfg(test)]
pub mod cutover;
pub mod deployment;
mod dispatch;
pub mod epoch;
pub mod history;
#[cfg(test)]
pub(crate) mod maintenance;
#[cfg(test)]
mod pending;
#[cfg(test)]
pub use pending::{PendingAdmission, PendingWork};
#[cfg(test)]
pub mod store_progress;
#[cfg(test)]
pub(crate) mod tests;
pub mod work;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("organization admission capacity exhausted before work")]
    CapacityExhausted,
    #[error("organization admission closed")]
    AdmissionClosed,
    #[error("organization domain operation conflicts with selected state")]
    Conflict,
    #[error("organization control-store boundary refused")]
    Refused,
    #[error("organization control-store deadline")]
    Deadline,
    #[error("organization primary incarnation changed")]
    PrimaryIncarnationChanged,
    #[error("organization primary progress is behind the retained checkpoint")]
    PrimaryProgressBehind,
    #[error("organization token-store incarnation changed")]
    TokenIncarnationChanged,
    #[error("organization durable store continuity differs")]
    StoreContinuityMismatch,
    #[error("organization store restart has unresolved work")]
    StoreRestartPending,
    #[error("organization control-store storage unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("invalid control-store response")]
    Decode(#[from] serde_json::Error),
}

impl Error {
    /// Fixed operator diagnostic without endpoints, observations or source errors.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::CapacityExhausted => "capacity_exhausted",
            Self::AdmissionClosed => "admission_closed",
            Self::Conflict => "domain_conflict",
            Self::Refused => "boundary_refused",
            Self::Deadline => "deadline",
            Self::PrimaryIncarnationChanged => "primary_incarnation_changed",
            Self::PrimaryProgressBehind => "primary_progress_behind",
            Self::TokenIncarnationChanged => "token_incarnation_changed",
            Self::StoreContinuityMismatch => "store_continuity_mismatch",
            Self::StoreRestartPending => "store_restart_pending",
            Self::Storage(_) => "storage_unavailable",
            Self::Decode(_) => "invalid_control_response",
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub enum Role {
    Runtime,
    Maintenance,
}

/// Independently expected identifiers; these do not confer authority by themselves.
#[derive(Clone, Copy, Debug)]
#[cfg(test)]
pub struct Scope {
    pub environment_id: Uuid,
    pub deployment_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
pub struct Selection {
    pub epoch: Uuid,
    pub primary: Uuid,
    pub token_store: Uuid,
    pub source_sha256: String,
    pub history_sha256: String,
    pub acceptance_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
pub struct State {
    pub environment_id: Uuid,
    pub deployment_id: Uuid,
    pub revision: i64,
    pub phase: String,
    pub operation_id: Uuid,
    pub epoch: Option<Uuid>,
    pub primary_id: Option<Uuid>,
    pub token_store_id: Option<Uuid>,
    pub source_sha256: Option<String>,
    pub history_sha256: Option<String>,
    pub acceptance_sha256: Option<String>,
    pub pending: u32,
}
#[cfg(test)]
impl State {
    fn phase(&self) -> Result<Phase> {
        match self.phase.as_str() {
            "fenced" => Ok(Phase::Fenced),
            "prepared" => Ok(Phase::Prepared),
            "active" => Ok(Phase::Active),
            _ => Err(Error::Refused),
        }
    }
    pub fn is_drained_fence(&self) -> bool {
        self.phase == "fenced" && self.pending == 0
    }
    fn transition(&self, action: Action) -> Result<()> {
        organization_witness::transition_revision(
            self.phase()?,
            self.revision,
            self.pending,
            action,
        )
        .map(|_| ())
        .ok_or(Error::Refused)
    }
}

/// Only the live store creates this handle. It is deliberately not Clone or
/// publicly deserializable; dropping it leaves durable pending work behind.
#[derive(Debug)]
#[cfg(test)]
pub struct Admission {
    binding: epoch::EpochBinding,
    scope: Scope,
    slot: Slot,
}
#[cfg(test)]
impl Admission {
    pub(super) fn store_label(&self) -> String {
        attribution::label(
            self.scope,
            self.slot.epoch,
            self.slot.worker_id,
            self.slot.slot,
            self.slot.generation,
            &self.slot.principal,
        )
    }

    pub(super) fn epoch_binding(&self) -> &epoch::EpochBinding {
        &self.binding
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct Slot {
    environment_id: Uuid,
    slot: i32,
    generation: i64,
    pending: bool,
    epoch: Uuid,
    worker_id: Uuid,
    principal: String,
}

#[cfg(test)]
pub struct Control {
    connection: Option<PgConnection>,
    role: Role,
}
#[cfg(test)]
impl Control {
    /// There is no ambient URL, unverified TLS or automatic reconnect fallback.
    pub async fn connect(endpoint: &str, ca: &Path, role: Role) -> Result<Self> {
        if endpoint.is_empty()
            || std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("PG"))
        {
            return Err(Error::Refused);
        }
        let bytes = crate::organizations::store_observation::transport::certificate(ca)
            .map_err(|_| Error::Refused)?;
        let options = crate::organizations::store_observation::transport::postgres_options(
            endpoint, ca, bytes,
        )
        .map_err(|_| Error::Refused)?;
        let connection =
            tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(&options))
                .await
                .map_err(|_| Error::Deadline)??;
        Self::checked(connection, role).await
    }
    async fn checked(mut connection: PgConnection, role: Role) -> Result<Self> {
        tokio::time::timeout(
            Duration::from_secs(5),
            catalog::verify(&mut connection, role),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        Ok(Self {
            connection: Some(connection),
            role,
        })
    }
    pub async fn close(mut self) -> Result<()> {
        if let Some(connection) = self.connection.take() {
            tokio::time::timeout(Duration::from_secs(5), connection.close())
                .await
                .map_err(|_| Error::Deadline)??;
        }
        Ok(())
    }
    async fn value(
        &mut self,
        query: sqlx::query::QueryScalar<
            '_,
            sqlx::Postgres,
            serde_json::Value,
            sqlx::postgres::PgArguments,
        >,
    ) -> Result<serde_json::Value> {
        let connection = self.connection.as_mut().ok_or(Error::Refused)?;
        let result =
            tokio::time::timeout(Duration::from_secs(5), query.fetch_one(connection)).await;
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(sqlx::Error::Database(error))) => {
                let reusable = error
                    .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                    .is_some_and(|error| {
                        error.severity() == sqlx::postgres::PgSeverity::Error
                            && !error.code().starts_with("08")
                            && !matches!(error.code(), "57P01" | "57P02" | "57P03")
                    });
                if !reusable {
                    self.connection.take();
                }
                Err(Error::Storage(sqlx::Error::Database(error)))
            }
            Ok(Err(error)) => {
                self.connection.take();
                Err(Error::Storage(error))
            }
            Err(_) => {
                self.connection.take();
                Err(Error::Deadline)
            }
        }
    }
    fn maintenance(&self) -> Result<()> {
        if self.role == Role::Maintenance {
            Ok(())
        } else {
            Err(Error::Refused)
        }
    }
    pub async fn current(&mut self, scope: Scope) -> Result<State> {
        decode(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.current_state($1,$2)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id),
            )
            .await?,
        )
    }
    pub async fn initialize(&mut self, scope: Scope, operation: Uuid) -> Result<State> {
        self.maintenance()?;
        decode(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.initialize($1,$2,$3)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
                    .bind(operation),
            )
            .await?,
        )
    }
    pub async fn fence(&mut self, scope: Scope, operation: Uuid, expected: i64) -> Result<State> {
        self.maintenance()?;
        let current = self.current(scope).await?;
        if current.operation_id != operation || current.phase != "fenced" {
            current.transition(Action::Fence)?;
        }
        decode(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.fence($1,$2,$3,$4)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
                    .bind(operation)
                    .bind(expected),
            )
            .await?,
        )
    }
    pub async fn prepare(
        &mut self,
        scope: Scope,
        operation: Uuid,
        expected: i64,
        selection: &Selection,
    ) -> Result<State> {
        self.maintenance()?;
        let current = self.current(scope).await?;
        if current.operation_id != operation || current.phase != "prepared" {
            current.transition(Action::Prepare)?;
        }
        decode(
            self.value(
                sqlx::query_scalar(
                    "SELECT organization_witness.prepare($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                )
                .bind(scope.environment_id)
                .bind(scope.deployment_id)
                .bind(operation)
                .bind(expected)
                .bind(selection.epoch)
                .bind(selection.primary)
                .bind(selection.token_store)
                .bind(&selection.source_sha256)
                .bind(&selection.history_sha256)
                .bind(&selection.acceptance_sha256),
            )
            .await?,
        )
    }
    pub async fn activate(
        &mut self,
        scope: Scope,
        operation: Uuid,
        expected: i64,
        acceptance_sha256: &str,
    ) -> Result<State> {
        self.maintenance()?;
        let current = self.current(scope).await?;
        if current.operation_id != operation || current.phase != "active" {
            current.transition(Action::Activate)?;
        }
        decode(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.activate($1,$2,$3,$4,$5)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
                    .bind(operation)
                    .bind(expected)
                    .bind(acceptance_sha256),
            )
            .await?,
        )
    }
    /// Retained only to prove standalone SQL acquisition stays forbidden.
    #[cfg(test)]
    pub(super) async fn acquire(
        &mut self,
        scope: Scope,
        selection: &Selection,
        worker: Uuid,
    ) -> Result<Admission> {
        if self.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let binding = epoch::EpochBinding::selected(scope, selection)?;
        let slot: Slot = serde_json::from_value(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.acquire($1,$2,$3,$4,$5,$6)")
                    .bind(scope.environment_id)
                    .bind(scope.deployment_id)
                    .bind(selection.epoch)
                    .bind(selection.primary)
                    .bind(selection.token_store)
                    .bind(worker),
            )
            .await?,
        )?;
        if slot.environment_id != scope.environment_id
            || slot.epoch != selection.epoch
            || slot.worker_id != worker
            || !slot.pending
            || !(0..64).contains(&slot.slot)
            || slot.generation <= 0
            || slot.principal.is_empty()
        {
            return Err(Error::Refused);
        }
        Ok(Admission {
            binding,
            scope,
            slot,
        })
    }
    /// Only after all owned primary/Redis work and cleanup have finished. This
    /// method never infers completion from a request timeout or disconnected client.
    pub async fn complete(&mut self, admission: &Admission) -> Result<State> {
        if self.role != Role::Runtime {
            return Err(Error::Refused);
        }
        let s = &admission.slot;
        decode(
            self.value(
                sqlx::query_scalar("SELECT organization_witness.release($1,$2,$3,$4,$5,$6)")
                    .bind(admission.scope.environment_id)
                    .bind(admission.scope.deployment_id)
                    .bind(s.slot)
                    .bind(s.generation)
                    .bind(s.epoch)
                    .bind(s.worker_id),
            )
            .await?,
        )
    }
}
#[cfg(test)]
fn decode(value: serde_json::Value) -> Result<State> {
    Ok(serde_json::from_value(value)?)
}
