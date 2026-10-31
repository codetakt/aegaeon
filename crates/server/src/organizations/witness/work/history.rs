//! One live control link, shared only through owners of its actual admission.
use super::*;
use crate::organizations::witness::{history::Progress, Error};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

pub(in crate::organizations) struct HistoryOwner {
    pub(super) durable: DurableAdmission,
    control: Mutex<Option<Control>>,
    capacity: Arc<Semaphore>,
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
    pub(super) fn new(control: Control, durable: DurableAdmission) -> Self {
        Self {
            durable,
            control: Mutex::new(Some(control)),
            capacity: Arc::new(Semaphore::new(4)),
        }
    }

    pub(in crate::organizations) fn admission(&self) -> &DurableAdmission {
        &self.durable
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
        let capacity = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Refused)?;
        let subject = subject.to_owned();
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
            let result = tokio::time::timeout_at(deadline, async {
                if reserve {
                    control
                        .history_reserve(&self.durable, owner, &subject)
                        .await
                } else {
                    control.history_check(&self.durable, owner, &subject).await
                }
            })
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
