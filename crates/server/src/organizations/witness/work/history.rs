//! One live control link, shared only through owners of its actual admission.
use super::*;
use crate::organizations::witness::{history::Progress, Error};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

mod operation;
use crate::organizations::witness::creation::{Input, PrimaryOutcome, Receipt};
use operation::{
    FinishCreation, FinishCreationBatch, Identity, Operation, PrepareCreation, PrepareCreationBatch,
};

pub(in crate::organizations) struct HistoryOwner {
    pub(super) durable: DurableAdmission,
    control: Mutex<Option<Control>>,
    capacity: Arc<Semaphore>,
    primary_creation: Arc<Semaphore>,
}

struct OperationOwner {
    local: Admission,
    confirmed: bool,
}
impl Drop for OperationOwner {
    fn drop(&mut self) {
        if !self.confirmed {
            self.local.close_until_restart();
        }
    }
}

impl HistoryOwner {
    pub(in crate::organizations) async fn lookup_creation(
        self: Arc<Self>,
        local: Admission,
        kind: crate::organizations::witness::creation::Kind,
        selector: [u8; 32],
    ) -> Result<Option<Receipt>> {
        self.operation(local, || operation::LookupCreation(kind, selector))
            .await
    }
    pub(super) fn new(control: Control, durable: DurableAdmission) -> Self {
        Self {
            durable,
            control: Mutex::new(Some(control)),
            capacity: Arc::new(Semaphore::new(4)),
            primary_creation: Arc::new(Semaphore::new(1)),
        }
    }

    pub(in crate::organizations) fn admission(&self) -> &DurableAdmission {
        &self.durable
    }

    pub(in crate::organizations) fn primary_creation_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.primary_creation
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Refused)
    }

    /// The retained local owner is captured before detaching. The response
    /// waiter cannot abort this worker or release its durable admission.
    pub(in crate::organizations) async fn identity(
        self: Arc<Self>,
        local: Admission,
        owner: Uuid,
        subject: &str,
        reserve: bool,
    ) -> Result<Progress> {
        self.operation(local, || Identity {
            owner,
            subject: subject.to_owned(),
            reserve,
        })
        .await
    }

    pub(in crate::organizations) async fn prepare_creation(
        self: Arc<Self>,
        local: Admission,
        input: &Input,
    ) -> Result<Receipt> {
        self.operation(local, || PrepareCreation(input.clone()))
            .await
    }

    pub(in crate::organizations) async fn finish_creation(
        self: Arc<Self>,
        local: Admission,
        receipt: &Receipt,
        outcome: &PrimaryOutcome,
    ) -> Result<Receipt> {
        self.operation(local, || FinishCreation(receipt.clone(), outcome.clone()))
            .await
    }

    pub(in crate::organizations) async fn prepare_creation_batch(
        self: Arc<Self>,
        local: Admission,
        inputs: &[Input],
    ) -> Result<Vec<Receipt>> {
        crate::organizations::witness::creation::validate_batch(inputs)?;
        self.operation(local, || PrepareCreationBatch(inputs.to_vec()))
            .await
    }

    pub(in crate::organizations) async fn finish_creation_batch(
        self: Arc<Self>,
        local: Admission,
        receipts: &[Receipt],
        outcomes: &[PrimaryOutcome],
    ) -> Result<Vec<Receipt>> {
        if receipts.is_empty()
            || receipts.len() > crate::organizations::witness::creation::MAX_BATCH
            || receipts.len() != outcomes.len()
        {
            return Err(Error::Refused);
        }
        self.operation(local, || {
            FinishCreationBatch(receipts.to_vec(), outcomes.to_vec())
        })
        .await
    }

    async fn operation<O: Operation>(
        self: Arc<Self>,
        local: Admission,
        construct: impl FnOnce() -> O + Send,
    ) -> Result<O::Output> {
        let capacity = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Refused)?;
        let request = construct();
        let mut operation = OperationOwner {
            local,
            confirmed: false,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        tokio::spawn(async move {
            let _capacity = capacity;
            let mut locked = tokio::time::timeout_at(deadline, self.control.lock())
                .await
                .map_err(|_| Error::Deadline)?;
            let control = locked.as_mut().ok_or(Error::Refused)?;
            operation.local.ensure_open()?;
            operation.local.admit_commit()?;
            let result = tokio::time::timeout_at(deadline, request.execute(control, &self.durable))
                .await
                .unwrap_or(Err(Error::Deadline));
            // The existing Control adapter retains a connection only after a
            // nonfatal PostgreSQL Error response. Its fixed statement rolled
            // back; later completion still must succeed on this same link.
            let confirmed_refusal =
                matches!(&result, Err(Error::Storage(sqlx::Error::Database(_))))
                    && control.connection.is_some();
            if result.is_ok() || confirmed_refusal {
                operation.confirmed = true;
            } else {
                // Includes cancellation at our outer deadline. Never reuse a
                // connection with an unconfirmed statement or decoded result.
                locked.take();
            }
            // Capture and drop the complete guard in this worker. Field-only
            // async capture must not leave its destructor with the waiter.
            drop(operation);
            result
        })
        .await
        .map_err(|_| Error::Refused)?
    }

    pub(super) async fn complete(&self) -> Result<State> {
        let mut control = tokio::time::timeout(Duration::from_secs(5), self.control.lock())
            .await
            .map_err(|_| Error::Deadline)?
            .take()
            .ok_or(Error::Refused)?;
        let result = control.complete(&self.durable).await;
        let close = control.close().await;
        let state = result?;
        close?;
        Ok(state)
    }
}
