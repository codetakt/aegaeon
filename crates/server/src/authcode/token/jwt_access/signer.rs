use crate::kms::{KeyManager, KeyManagerError};
use serde_json::{json, Value};

pub(in crate::authcode::token) fn sign_jwt(
    payload: &Value,
    key_manager: &dyn KeyManager,
    typ: &str,
) -> Result<String, KeyManagerError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let header = json!({
        "alg": key_manager.jwt_signing_alg(),
        "typ": typ,
        "kid": key_manager.key_id(),
    });
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|_| KeyManagerError::OperationFailed)?);
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(payload).map_err(|_| KeyManagerError::OperationFailed)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = key_manager.sign(signing_input.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}
