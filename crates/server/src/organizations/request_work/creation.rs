use super::Admission;
use crate::organizations::witness::{
    creation::{Input, PrimaryOutcome, Receipt},
    Error,
};
use uuid::Uuid;

impl Admission {
    /// Allocate or recover an exact retained creation operation. No primary user
    /// or credential is created and no caller authority follows from the result.
    pub async fn prepare_creation(
        &self,
        environment: Uuid,
        input: &Input,
    ) -> Result<Receipt, Error> {
        if self.epoch_binding()?.environment_id() != environment {
            return Err(Error::Refused);
        }
        self.start_store_work()?;
        let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
        history.prepare_creation(self.clone(), input).await
    }

    /// Outcome evidence is opaque; only the actual primary integration can
    /// produce it. A missing result leaves the durable attempt reserved.
    pub async fn finish_creation(
        &self,
        environment: Uuid,
        receipt: &Receipt,
        outcome: &PrimaryOutcome,
    ) -> Result<Receipt, Error> {
        if self.epoch_binding()?.environment_id() != environment {
            return Err(Error::Refused);
        }
        let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
        receipt.validate_finish(history.admission(), outcome)?;
        self.start_store_work()?;
        history
            .finish_creation(self.clone(), receipt, outcome)
            .await
    }
}
