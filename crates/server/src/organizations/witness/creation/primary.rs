//! The actual owned transaction is the only production primary-outcome producer.
use super::{history, Input, PrimaryOutcome, Receipt, State};
use crate::organizations::request_work::Admission;
use sqlx::{Connection, PgPool, Postgres, Transaction};
use std::{future::Future, pin::Pin};
use tokio::sync::OwnedSemaphorePermit;

pub(crate) mod batch;
mod record;
mod transaction;

/// A caller with separately authenticated current identity can validate the
/// immutable primary record against an independent, committed receipt.
pub(crate) async fn check_committed(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &Receipt,
) -> Result<bool, sqlx::Error> {
    if receipt.state() != State::Committed {
        return Ok(false);
    }
    record::read(tx, receipt).await
}

pub(crate) type MutationFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Each caller supplies its current authorization and application semantics.
/// Replay may read and lock current state, but may not issue a new credential.
pub(crate) trait Mutation: Sync {
    type Output: Send;
    type Error: Send;
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> MutationFuture<'a, Self::Output, Self::Error>;
    /// Required final current-state check, after receipt persistence and after
    /// successful replay verification. No permissive default for timed callers.
    fn recheck<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
    ) -> MutationFuture<'a, (), Self::Error>;
    fn replay<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipt: &'a Receipt,
    ) -> MutationFuture<'a, Self::Output, Self::Error>;
}

#[derive(Debug)]
pub(crate) enum Failure<E> {
    Mutation(E),
    Storage(sqlx::Error),
    Witness(super::super::Error),
    Reconciliation,
}

struct Owner {
    admission: Admission,
    _permit: OwnedSemaphorePermit,
    confirmed: bool,
}
impl Drop for Owner {
    fn drop(&mut self) {
        if !self.confirmed {
            self.admission.close_until_restart();
        }
    }
}

pub(crate) async fn execute<M: Mutation>(
    pool: &PgPool,
    admission: &Admission,
    input: &Input,
    receipt: &Receipt,
    mutation: &M,
) -> Result<M::Output, Failure<M::Error>> {
    admission.require_store_scope().map_err(Failure::Storage)?;
    let environment = admission
        .epoch_binding()
        .map_err(Failure::Storage)?
        .environment_id();
    if environment != receipt.0.environment_id || !receipt.matches(input) {
        return Err(Failure::Reconciliation);
    }
    let mut owner = Owner {
        admission: admission.clone(),
        _permit: admission
            .primary_creation_permit()
            .map_err(Failure::Witness)?,
        confirmed: false,
    };
    let current = admission
        .prepare_creation(environment, input)
        .await
        .map_err(Failure::Witness)?;
    if current.operation_id() != receipt.operation_id()
        || current.owner_id() != receipt.owner_id()
        || current.subject() != receipt.subject()
        || current.attempt() != receipt.attempt()
    {
        return Err(Failure::Reconciliation);
    }
    let mut connection = admission.connection(pool).await.map_err(Failure::Storage)?;
    let result = transaction::run(&mut connection, admission, &current, mutation).await;
    connection.release().await;
    admission.ensure_open().map_err(Failure::Storage)?;
    let result = match result? {
        transaction::Disposition::Committed(value, digest) => {
            let outcome = PrimaryOutcome {
                operation_id: current.operation_id(),
                attempt: current.attempt(),
                receipt: Some(digest),
            };
            admission
                .finish_creation(environment, &current, &outcome)
                .await
                .map_err(Failure::Witness)?;
            Ok(value)
        }
        transaction::Disposition::RolledBack(error) => {
            let outcome = PrimaryOutcome {
                operation_id: current.operation_id(),
                attempt: current.attempt(),
                receipt: None,
            };
            admission
                .finish_creation(environment, &current, &outcome)
                .await
                .map_err(Failure::Witness)?;
            Err(error)
        }
        transaction::Disposition::Replay(result) => result,
    };
    owner.confirmed = true;
    result
}
