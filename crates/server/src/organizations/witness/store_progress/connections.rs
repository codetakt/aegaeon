//! Shared physical observations; these cannot create either kind of admission.
use super::{values, Error, Postgres, Redis, Result, Value};
use aegaeon_pure::organization_progress;
use std::sync::{Arc, Mutex};

pub(in crate::organizations) struct ObservedStores {
    primary_incarnation: Value,
    token_incarnation: Value,
    minimum: u64,
    maximum: Mutex<u64>,
    links: tokio::sync::Mutex<Option<(Postgres, Redis)>>,
}

impl ObservedStores {
    pub(in crate::organizations::witness) async fn connect(
        primary_incarnation: Value,
        token_incarnation: Value,
        minimum: u64,
        mut primary: Postgres,
        mut token: Redis,
    ) -> Result<Arc<Self>> {
        let (primary_value, token_value) = values(&mut primary, &mut token).await?;
        let observed = Self {
            primary_incarnation,
            token_incarnation,
            minimum,
            maximum: Mutex::new(minimum),
            links: tokio::sync::Mutex::new(Some((primary, token))),
        };
        observed.primary_value(primary_value)?;
        observed.token_value(&token_value)?;
        Ok(Arc::new(observed))
    }

    fn primary_value(&self, primary: Value) -> Result<u64> {
        let position = Self::check_primary(&self.primary_incarnation, self.minimum, primary)?;
        let mut maximum = self.maximum.lock().map_err(|_| Error::Refused)?;
        *maximum = organization_progress::retain(self.minimum, *maximum, position)
            .ok_or(Error::Refused)?;
        Ok(position)
    }

    fn check_primary(incarnation: &Value, minimum: u64, mut primary: Value) -> Result<u64> {
        let position = primary["wal_position"].as_u64().ok_or(Error::Refused)?;
        primary
            .as_object_mut()
            .ok_or(Error::Refused)?
            .remove("wal_position");
        if primary != *incarnation {
            return Err(Error::PrimaryIncarnationChanged);
        }
        if position < minimum {
            return Err(Error::PrimaryProgressBehind);
        }
        Ok(position)
    }

    /// Startup diagnosis and admitted work share the same refusal predicate.
    /// This comparison never grants authority or advances a checkpoint.
    pub(in crate::organizations::witness) fn check_values(
        primary_incarnation: &Value,
        token_incarnation: &Value,
        minimum: u64,
        primary: Value,
        token: &Value,
    ) -> Result<u64> {
        let position = Self::check_primary(primary_incarnation, minimum, primary)?;
        if token != token_incarnation {
            return Err(Error::TokenIncarnationChanged);
        }
        Ok(position)
    }

    fn token_value(&self, token: &Value) -> Result<()> {
        if token == &self.token_incarnation {
            Ok(())
        } else {
            Err(Error::TokenIncarnationChanged)
        }
    }

    pub(in crate::organizations) async fn primary(
        &self,
        connection: &mut sqlx::PgConnection,
    ) -> Result<()> {
        let observed = crate::organizations::store_observation::primary(connection)
            .await
            .map_err(|_| Error::Refused)?;
        self.primary_value(serde_json::to_value(observed)?)?;
        Ok(())
    }

    pub(in crate::organizations) async fn token(
        &self,
        connection: &mut ::redis::aio::MultiplexedConnection,
    ) -> Result<()> {
        let observed = crate::organizations::store_observation::token(connection)
            .await
            .map_err(|_| Error::Refused)?;
        self.token_value(&serde_json::to_value(observed)?)
    }

    /// Requires exclusive ownership of actual workers. Close the dedicated
    /// observer links before recording completion. Any error leaves work pending.
    pub(in crate::organizations::witness) async fn finish_values(&self) -> Result<(Value, Value)> {
        self.finish(None).await
    }

    pub(in crate::organizations::witness) async fn finish_values_with_seal(
        &self,
        deployment: uuid::Uuid,
        previous: uuid::Uuid,
        next: uuid::Uuid,
    ) -> Result<(Value, Value)> {
        self.finish(Some((deployment, previous, next))).await
    }

    async fn finish(
        &self,
        seal: Option<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
    ) -> Result<(Value, Value)> {
        let (mut primary, mut token) =
            tokio::time::timeout(std::time::Duration::from_secs(5), self.links.lock())
                .await
                .map_err(|_| Error::Deadline)?
                .take()
                .ok_or(Error::Refused)?;
        if let Some((deployment, previous, next)) = seal {
            // The parent control row is locked until the caller commits the seal,
            // observation and release together. All effect owners have drained.
            let (observed_primary, observed_token) = values(&mut primary, &mut token).await?;
            self.primary_value(observed_primary)?;
            self.token_value(&observed_token)?;
            if primary
                .continuity_read(deployment)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?
                != Some(previous)
                || token
                    .continuity_read(deployment)
                    .await
                    .map_err(|_| Error::StoreContinuityMismatch)?
                    != Some(previous)
            {
                return Err(Error::StoreContinuityMismatch);
            }
            primary
                .continuity_replace(deployment, Some(previous), next)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?;
            token
                .continuity_replace(deployment, Some(previous), next)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?;
            if primary
                .continuity_read(deployment)
                .await
                .map_err(|_| Error::StoreContinuityMismatch)?
                != Some(next)
                || token
                    .continuity_read(deployment)
                    .await
                    .map_err(|_| Error::StoreContinuityMismatch)?
                    != Some(next)
            {
                return Err(Error::StoreContinuityMismatch);
            }
        }
        let (primary_value, token_value) = values(&mut primary, &mut token).await?;
        let position = self.primary_value(primary_value.clone())?;
        self.token_value(&token_value)?;
        if !organization_progress::can_complete(
            self.minimum,
            *self.maximum.lock().map_err(|_| Error::Refused)?,
            position,
        ) {
            return Err(Error::Refused);
        }
        primary.close().await.map_err(|_| Error::Refused)?;
        token.close();
        Ok((primary_value, token_value))
    }
}
