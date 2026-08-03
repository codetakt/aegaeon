use crate::authcode::store::TokenStoreStorageError;

pub(super) fn reject_existing_token_keys(
    conn: &mut redis::Connection,
    keys: &[String],
    context: &str,
) -> Result<(), TokenStoreStorageError> {
    let collisions = redis::cmd("EXISTS")
        .arg(keys)
        .query::<u64>(conn)
        .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?;
    if collisions == 0 {
        Ok(())
    } else {
        Err(TokenStoreStorageError::InvariantViolation(format!(
            "{context} would overwrite existing token store key"
        )))
    }
}
