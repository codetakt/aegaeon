use crate::authcode::store::TokenStoreStorageError;

pub(super) fn authorization_code_grant_commit_result(
    outcome: &str,
) -> Result<bool, TokenStoreStorageError> {
    match outcome {
        "ok" => Ok(true),
        "missing_code" => Ok(false),
        "code_mismatch" => Err(TokenStoreStorageError::InvariantViolation(
            "authorization code payload changed before grant commit".to_string(),
        )),
        "token_collision" => Err(TokenStoreStorageError::InvariantViolation(
            "issued token key collision during authorization-code grant commit".to_string(),
        )),
        "refresh_children_decode" => Err(TokenStoreStorageError::Codec(
            "refresh children payload cannot be decoded".to_string(),
        )),
        "oidc_session_invalid" => Err(TokenStoreStorageError::BackendUnavailable(
            "OIDC session commit arguments are invalid".to_string(),
        )),
        "oidc_session_conflict" => Err(TokenStoreStorageError::BackendUnavailable(
            "OIDC session changed before authorization-code grant commit".to_string(),
        )),
        "oidc_session_collision" => Err(TokenStoreStorageError::BackendUnavailable(
            "OIDC session id collision during authorization-code grant commit".to_string(),
        )),
        other => Err(TokenStoreStorageError::BackendUnavailable(format!(
            "unexpected Redis authorization-code grant commit response: {other}"
        ))),
    }
}
