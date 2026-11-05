use super::*;

#[cfg(test)]
impl Admission {
    pub(crate) async fn observe_primary(
        &self,
        connection: &mut PgConnection,
    ) -> Result<(), sqlx::Error> {
        self.ensure_open()?;
        if let Some(parent) = &self.deployment {
            self.observe_result(&parent.observations().primary(connection).await)?;
        }
        let Some(observed) = self
            .witness
            .get()
            .and_then(|binding| binding.history.observations())
        else {
            return Ok(());
        };
        self.ensure_open()?;
        self.observe_result(&observed.primary(connection).await)
    }

    pub(crate) async fn observe_token(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
    ) -> Result<(), sqlx::Error> {
        self.ensure_open()?;
        if let Some(parent) = &self.deployment {
            self.observe_result(&parent.observations().token(connection).await)?;
        }
        let Some(observed) = self
            .witness
            .get()
            .and_then(|binding| binding.history.observations())
        else {
            return Ok(());
        };
        self.ensure_open()?;
        self.observe_result(&observed.token(connection).await)
    }

    fn observe_result(
        &self,
        result: &Result<(), super::super::witness::Error>,
    ) -> Result<(), sqlx::Error> {
        if result.is_err() {
            self.close_until_restart();
            return Err(sqlx::Error::Protocol(
                "Organizations actual store observation refused".into(),
            ));
        }
        self.ensure_open()
    }
}

#[cfg(not(test))]
impl Admission {
    pub(crate) async fn observe_primary(
        &self,
        _connection: &mut PgConnection,
    ) -> Result<(), sqlx::Error> {
        self.ensure_open()
    }
    pub(crate) async fn observe_token(
        &self,
        _connection: &mut redis::aio::MultiplexedConnection,
    ) -> Result<(), sqlx::Error> {
        self.ensure_open()
    }
}
