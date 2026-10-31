use super::*;
use std::{future::Future, pin::Pin};

type OperationFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub(super) trait Operation: Send + Sync + 'static {
    type Output: Send + 'static;
    fn execute<'a>(
        &'a self,
        control: &'a mut Control,
        admission: &'a DurableAdmission,
    ) -> OperationFuture<'a, Self::Output>;
}

pub(super) struct Identity {
    pub(super) owner: Uuid,
    pub(super) subject: String,
    pub(super) reserve: bool,
}
impl Operation for Identity {
    type Output = Progress;
    fn execute<'a>(
        &'a self,
        control: &'a mut Control,
        admission: &'a DurableAdmission,
    ) -> OperationFuture<'a, Progress> {
        Box::pin(async move {
            if self.reserve {
                control
                    .history_reserve(admission, self.owner, &self.subject)
                    .await
            } else {
                control
                    .history_check(admission, self.owner, &self.subject)
                    .await
            }
        })
    }
}

pub(super) struct PrepareCreation(pub(super) Input);
impl Operation for PrepareCreation {
    type Output = Receipt;
    fn execute<'a>(
        &'a self,
        control: &'a mut Control,
        admission: &'a DurableAdmission,
    ) -> OperationFuture<'a, Receipt> {
        Box::pin(control.prepare_creation(admission, &self.0))
    }
}

pub(super) struct FinishCreation(pub(super) Receipt, pub(super) PrimaryOutcome);
impl Operation for FinishCreation {
    type Output = Receipt;
    fn execute<'a>(
        &'a self,
        control: &'a mut Control,
        admission: &'a DurableAdmission,
    ) -> OperationFuture<'a, Receipt> {
        Box::pin(control.finish_creation(admission, &self.0, &self.1))
    }
}
