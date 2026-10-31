//! One primary transaction and one shared permit for the complete retained batch.
use super::*;
mod transaction;

pub(crate) trait Mutation: Sync {
    type Output: Send;
    type Error: Send;
    fn apply<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipts: &'a [Receipt],
    ) -> MutationFuture<'a, Self::Output, Self::Error>;
    fn replay<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        receipts: &'a [Receipt],
    ) -> MutationFuture<'a, Self::Output, Self::Error>;
}

pub(crate) async fn execute<M: Mutation>(
    pool: &PgPool,
    admission: &Admission,
    inputs: &[Input],
    mutation: &M,
) -> Result<M::Output, Failure<M::Error>> {
    super::super::validate_batch(inputs).map_err(Failure::Witness)?;
    admission.require_store_scope().map_err(Failure::Storage)?;
    let environment = admission
        .epoch_binding()
        .map_err(Failure::Storage)?
        .environment_id();
    let mut owner = Owner {
        admission: admission.clone(),
        _permit: admission
            .primary_creation_permit()
            .map_err(Failure::Witness)?,
        confirmed: false,
    };
    let receipts = match admission.prepare_creation_batch(environment, inputs).await {
        Ok(receipts) => receipts,
        Err(error) => {
            // The detached control owner keeps admission open only after a
            // confirmed statement refusal (or refusal before starting SQL).
            owner.confirmed = admission.ensure_open().is_ok();
            return Err(Failure::Witness(error));
        }
    };
    if receipts.len() != inputs.len()
        || receipts.iter().zip(inputs).any(|(r, i)| {
            r.0.environment_id != environment || !r.matches(i) || r.state() != receipts[0].state()
        })
    {
        return Err(Failure::Reconciliation);
    }
    let mut connection = admission.connection(pool).await.map_err(Failure::Storage)?;
    let result = transaction::run(&mut connection, admission, &receipts, mutation).await;
    connection.release().await;
    admission.ensure_open().map_err(Failure::Storage)?;
    let result = match result? {
        transaction::Disposition::Committed(value, digests) => {
            let outcomes = receipts
                .iter()
                .zip(digests)
                .map(|(receipt, digest)| PrimaryOutcome {
                    operation_id: receipt.operation_id(),
                    attempt: receipt.attempt(),
                    receipt: Some(digest),
                })
                .collect::<Vec<_>>();
            admission
                .finish_creation_batch(environment, &receipts, &outcomes)
                .await
                .map_err(Failure::Witness)?;
            Ok(value)
        }
        transaction::Disposition::RolledBack(error) => {
            let outcomes = receipts
                .iter()
                .map(|receipt| PrimaryOutcome {
                    operation_id: receipt.operation_id(),
                    attempt: receipt.attempt(),
                    receipt: None,
                })
                .collect::<Vec<_>>();
            admission
                .finish_creation_batch(environment, &receipts, &outcomes)
                .await
                .map_err(Failure::Witness)?;
            Err(error)
        }
        transaction::Disposition::Replay(result) => result,
    };
    owner.confirmed = true;
    result
}
