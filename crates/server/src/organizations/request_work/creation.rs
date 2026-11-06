use super::Admission;
use crate::organizations::witness::{
    creation::{current, Input, PrimaryOutcome, Receipt},
    Error,
};
use uuid::Uuid;

impl Admission {
    pub async fn lookup_creation(
        &self,
        environment: Uuid,
        kind: crate::organizations::witness::creation::Kind,
        selector: [u8; 32],
    ) -> Result<Option<Receipt>, Error> {
        if self.epoch_binding()?.environment_id() != environment {
            return Err(Error::Refused);
        }
        self.start_store_work()?;
        if self.current.is_some() {
            self.require_store_scope()?;
            return current::lookup(self, environment, kind, selector).await;
        }
        #[cfg(test)]
        {
            let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
            history.lookup_creation(self.clone(), kind, selector).await
        }
        #[cfg(not(test))]
        {
            Err(Error::Refused)
        }
    }
    pub(in crate::organizations) fn primary_creation_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Error> {
        self.ensure_open()?;
        if let Some(binding) = &self.current {
            return binding
                .creation
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Refused);
        }
        #[cfg(test)]
        {
            self.witness
                .get()
                .ok_or(Error::Refused)?
                .history
                .primary_creation_permit()
        }
        #[cfg(not(test))]
        {
            Err(Error::Refused)
        }
    }
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
        if self.current.is_some() {
            self.require_store_scope()?;
            return current::prepare(self, environment, input).await;
        }
        #[cfg(test)]
        {
            let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
            history.prepare_creation(self.clone(), input).await
        }
        #[cfg(not(test))]
        {
            Err(Error::Refused)
        }
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
        if self.current.is_some() {
            self.require_store_scope()?;
            return current::finish(self, environment, receipt, outcome).await;
        }
        #[cfg(test)]
        {
            let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
            receipt.validate_finish(history.admission(), outcome)?;
            self.start_store_work()?;
            history
                .finish_creation(self.clone(), receipt, outcome)
                .await
        }
        #[cfg(not(test))]
        {
            Err(Error::Refused)
        }
    }
}

impl Admission {
    pub async fn prepare_creation_batch(
        &self,
        environment: Uuid,
        inputs: &[Input],
    ) -> Result<Vec<Receipt>, Error> {
        if self.epoch_binding()?.environment_id() != environment {
            return Err(Error::Refused);
        }
        crate::organizations::witness::creation::validate_batch(inputs)?;
        self.start_store_work()?;
        if self.current.is_some() {
            self.require_store_scope()?;
            let mut receipts = Vec::with_capacity(inputs.len());
            for input in inputs {
                receipts.push(current::prepare(self, environment, input).await?);
            }
            return Ok(receipts);
        }
        #[cfg(test)]
        {
            let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
            history.prepare_creation_batch(self.clone(), inputs).await
        }
        #[cfg(not(test))]
        {
            Err(Error::Refused)
        }
    }
    pub async fn finish_creation_batch(
        &self,
        environment: Uuid,
        receipts: &[Receipt],
        outcomes: &[PrimaryOutcome],
    ) -> Result<Vec<Receipt>, Error> {
        if self.epoch_binding()?.environment_id() != environment
            || receipts.is_empty()
            || receipts.len() > crate::organizations::witness::creation::MAX_BATCH
            || receipts.len() != outcomes.len()
        {
            return Err(Error::Refused);
        }
        if self.current.is_some() {
            self.require_store_scope()?;
            let mut finished = Vec::with_capacity(receipts.len());
            for (receipt, outcome) in receipts.iter().zip(outcomes) {
                finished.push(current::finish(self, environment, receipt, outcome).await?);
            }
            return Ok(finished);
        }
        #[cfg(test)]
        {
            let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
            for (receipt, outcome) in receipts.iter().zip(outcomes) {
                receipt.validate_finish(history.admission(), outcome)?;
            }
            self.start_store_work()?;
            history
                .finish_creation_batch(self.clone(), receipts, outcomes)
                .await
        }
        #[cfg(not(test))]
        {
            Err(Error::Refused)
        }
    }
}
