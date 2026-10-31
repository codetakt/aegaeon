use super::*;
use crate::organizations::request_work::AdmittedConnection;
use aegaeon_pure::organization_creation::Decision;

pub(super) enum Disposition<T, E> {
    Committed(T, [u8; 32]),
    RolledBack(Failure<E>),
    Replay(Result<T, Failure<E>>),
}

pub(super) async fn run<M: Mutation>(
    connection: &mut AdmittedConnection,
    admission: &Admission,
    receipt: &Receipt,
    mutation: &M,
) -> Result<Disposition<M::Output, M::Error>, Failure<M::Error>> {
    let mut tx = connection
        .as_mut()
        .map_err(Failure::Storage)?
        .begin()
        .await
        .map_err(Failure::Storage)?;
    let existing = record::read(&mut tx, receipt)
        .await
        .map_err(Failure::Storage)?;
    let decision = receipt.state().decision(existing);
    if decision == Decision::Reconcile {
        return Err(Failure::Reconciliation);
    }
    if decision == Decision::Replay {
        let result = async {
            let value = mutation
                .replay(&mut tx, receipt)
                .await
                .map_err(Failure::Mutation)?;
            mutation.recheck(&mut tx).await.map_err(Failure::Mutation)?;
            Ok(value)
        }
        .await;
        tx.rollback().await.map_err(Failure::Storage)?;
        return Ok(Disposition::Replay(result));
    }
    // A receipt under an unfinalized independent attempt may represent a lost
    // commit acknowledgement. Even confirmed rollback here cannot undo it.
    if decision != Decision::Apply {
        return Err(Failure::Reconciliation);
    }
    let result = async {
        let value = mutation
            .apply(&mut tx, receipt)
            .await
            .map_err(Failure::Mutation)?;
        let digest = record::append(&mut tx, receipt)
            .await
            .map_err(Failure::Storage)?;
        mutation.recheck(&mut tx).await.map_err(Failure::Mutation)?;
        admission.admit_commit().map_err(Failure::Storage)?;
        Ok((value, digest))
    }
    .await;
    match result {
        Ok((value, digest)) => {
            // Never classify an Err from COMMIT as a confirmed rollback.
            tx.commit().await.map_err(Failure::Storage)?;
            Ok(Disposition::Committed(value, digest))
        }
        Err(error) => {
            tx.rollback().await.map_err(Failure::Storage)?;
            Ok(Disposition::RolledBack(error))
        }
    }
}
