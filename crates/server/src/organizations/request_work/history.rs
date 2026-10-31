use super::Admission;
use crate::organizations::witness::{
    history::{validate_subject, Progress},
    Error,
};
use uuid::Uuid;

impl Admission {
    /// Checks retained ownership only; current identity and authorization must
    /// still be established by the caller within this same owned work.
    pub async fn check_history(
        &self,
        environment: Uuid,
        owner: Uuid,
        subject: &str,
    ) -> Result<Progress, Error> {
        self.history_identity(environment, owner, subject, false)
            .await
    }

    /// A successful append survives a later primary failure. Callers must retain
    /// their operation/owner identity for recovery; this is not a primary commit.
    pub async fn reserve_history(
        &self,
        environment: Uuid,
        owner: Uuid,
        subject: &str,
    ) -> Result<Progress, Error> {
        self.history_identity(environment, owner, subject, true)
            .await
    }

    async fn history_identity(
        &self,
        environment: Uuid,
        owner: Uuid,
        subject: &str,
        reserve: bool,
    ) -> Result<Progress, Error> {
        validate_subject(subject)?;
        if self.epoch_binding()?.environment_id() != environment {
            return Err(Error::Refused);
        }
        self.start_store_work()?;
        let history = self.witness.get().ok_or(Error::Refused)?.history.clone();
        history
            .identity(self.clone(), owner, subject, reserve)
            .await
    }
}
