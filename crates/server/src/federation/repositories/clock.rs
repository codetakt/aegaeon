use crate::federation::FederationError;

pub(in crate::federation) fn current_unix_epoch_secs() -> Result<i64, FederationError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| FederationError::Validation("system time is before Unix epoch".into()))?;
    i64::try_from(duration.as_secs()).map_err(|_| {
        FederationError::Validation("system time is outside representable range".into())
    })
}
