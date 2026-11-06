//! Bounded diagnostic links. These confer no serving or activation authority.
use super::*;
use crate::organizations::store_observation::{Postgres, Redis};

/// Owned links for an observed execution. This value does not itself establish
/// transport, role separation or independent nonrollback supplier qualification.
pub struct ObservedConnections {
    pub(super) control: Control,
    pub(super) primary: Postgres,
    pub(super) token: Redis,
}
impl ObservedConnections {
    pub fn new(control: Control, primary: Postgres, token: Redis) -> Self {
        Self {
            control,
            primary,
            token,
        }
    }

    /// Diagnostic close before admission. No Work or authority has been created.
    pub(in crate::organizations) async fn inspect(mut self) -> Result<serde_json::Value> {
        let control_identity = crate::organizations::store_observation::primary(
            self.control
                .connection
                .as_mut()
                .ok_or(super::super::Error::Refused)?,
        )
        .await
        .map_err(|_| super::super::Error::Refused)?;
        let observed = serde_json::json!({
            "control": control_identity,
            "primary": self.primary.observation(),
            "tokenStore": self.token.observation(),
        });
        let control = self.control.close().await;
        let primary = self
            .primary
            .close()
            .await
            .map_err(|_| super::super::Error::Refused);
        self.token.close();
        control.and(primary)?;
        Ok(observed)
    }
}
