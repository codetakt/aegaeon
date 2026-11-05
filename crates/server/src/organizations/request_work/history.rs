use super::Admission;
#[cfg(test)]
use crate::organizations::witness::history::Progress;
use crate::organizations::witness::{history::validate_subject, Error};
use uuid::Uuid;

impl Admission {
    /// Current ownership is selected database state. The final identity mutation
    /// retains its existing transaction/constraint checks; no audit union follows.
    pub async fn check_identity(
        &self,
        environment: Uuid,
        owner: Uuid,
        subject: &str,
    ) -> Result<(), Error> {
        #[cfg(test)]
        if self.current.is_none() {
            return self
                .check_history(environment, owner, subject)
                .await
                .map(|_| ());
        }
        self.selected_identity(environment, owner, subject, false)
            .await
    }

    /// Preliminary conflict check. The application's ownership trigger reserves
    /// the new subject in the same transaction as the actual identity update.
    pub async fn check_subject_change(
        &self,
        environment: Uuid,
        owner: Uuid,
        subject: &str,
    ) -> Result<(), Error> {
        #[cfg(test)]
        if self.current.is_none() {
            return self
                .reserve_history(environment, owner, subject)
                .await
                .map(|_| ());
        }
        self.selected_identity(environment, owner, subject, true)
            .await
    }

    async fn selected_identity(
        &self,
        environment: Uuid,
        owner: Uuid,
        subject: &str,
        changing: bool,
    ) -> Result<(), Error> {
        validate_subject(subject)?;
        if self.epoch_binding()?.environment_id() != environment {
            return Err(Error::Refused);
        }
        self.require_store_scope()?;
        let runtime = self.current_runtime()?.ok_or(Error::Refused)?;
        let mut connection = self.connection(&runtime.pool).await?;
        let (known,recorded):(bool,Option<Uuid>)=sqlx::query_as("SELECT EXISTS(SELECT FROM aegaeon.end_user_identity_owners WHERE environment_id=$1 AND owner_id=$2),(SELECT owner_id FROM aegaeon.end_user_subject_reservations WHERE environment_id=$1 AND subject=$3 COLLATE \"C\")")
            .bind(environment).bind(owner).bind(subject).fetch_one(connection.as_mut()?).await?;
        connection.release().await;
        if !known {
            return Err(Error::Refused);
        }
        if changing {
            if recorded.is_some_and(|id| id != owner) {
                return Err(Error::Conflict);
            }
        } else if recorded != Some(owner) {
            return Err(Error::Refused);
        }
        Ok(())
    }

    /// Checks retained ownership only; current identity and authorization must
    /// still be established by the caller within this same owned work.
    #[cfg(test)]
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
    #[cfg(test)]
    pub async fn reserve_history(
        &self,
        environment: Uuid,
        owner: Uuid,
        subject: &str,
    ) -> Result<Progress, Error> {
        self.history_identity(environment, owner, subject, true)
            .await
    }

    #[cfg(test)]
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
