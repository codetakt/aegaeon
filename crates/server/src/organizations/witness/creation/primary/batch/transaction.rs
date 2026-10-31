use super::*;
use crate::organizations::request_work::AdmittedConnection;

pub(super) enum Disposition<T, E> {
    Committed(T, Vec<[u8; 32]>),
    RolledBack(Failure<E>),
    Replay(Result<T, Failure<E>>),
}

pub(super) async fn run<M: Mutation>(
    connection: &mut AdmittedConnection,
    admission: &Admission,
    receipts: &[Receipt],
    mutation: &M,
) -> Result<Disposition<M::Output, M::Error>, Failure<M::Error>> {
    let mut tx = connection
        .as_mut()
        .map_err(Failure::Storage)?
        .begin()
        .await
        .map_err(Failure::Storage)?;
    let state = receipts.first().ok_or(Failure::Reconciliation)?.state();
    for receipt in receipts {
        let exists = record::read(&mut tx, receipt)
            .await
            .map_err(Failure::Storage)?;
        if receipt.state() != state
            || state == State::Retryable
            || exists != (state == State::Committed)
        {
            return Err(Failure::Reconciliation);
        }
    }
    if state == State::Committed {
        let result = mutation
            .replay(&mut tx, receipts)
            .await
            .map_err(Failure::Mutation);
        tx.rollback().await.map_err(Failure::Storage)?;
        return Ok(Disposition::Replay(result));
    }
    let result = async {
        let value = mutation
            .apply(&mut tx, receipts)
            .await
            .map_err(Failure::Mutation)?;
        let mut digests = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            digests.push(
                record::append(&mut tx, receipt)
                    .await
                    .map_err(Failure::Storage)?,
            );
        }
        admission.admit_commit().map_err(Failure::Storage)?;
        Ok((value, digests))
    }
    .await;
    match result {
        Ok((value, digests)) => {
            tx.commit().await.map_err(Failure::Storage)?;
            Ok(Disposition::Committed(value, digests))
        }
        Err(error) => {
            tx.rollback().await.map_err(Failure::Storage)?;
            Ok(Disposition::RolledBack(error))
        }
    }
}
