use axum::response::Response;

use super::super::validation::runtime_key_bad_request;

const MAX_RUNTIME_KEY_PEM_BYTES: usize = 64 * 1024;

pub(in crate::web::management::runtime_keys::input) fn parse_runtime_key_pkcs8_der(
    private_key_pem: Option<&str>,
    request_id: &str,
) -> Result<Vec<u8>, Response> {
    let Some(private_key_pem) = private_key_pem
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(runtime_key_bad_request(
            request_id,
            "privateKeyPem is required for databaseEncrypted runtime keys",
            None,
        ));
    };
    if private_key_pem.len() > MAX_RUNTIME_KEY_PEM_BYTES {
        return Err(runtime_key_bad_request(
            request_id,
            "privateKeyPem is too large",
            Some(serde_json::json!({
                "maxBytes": MAX_RUNTIME_KEY_PEM_BYTES,
            })),
        ));
    }

    let parsed = pem::parse(private_key_pem).map_err(|_| {
        runtime_key_bad_request(
            request_id,
            "privateKeyPem must be a valid PKCS#8 RSA private key PEM",
            None,
        )
    })?;
    if parsed.tag() != "PRIVATE KEY" {
        return Err(runtime_key_bad_request(
            request_id,
            "privateKeyPem must use PKCS#8 PRIVATE KEY PEM encoding",
            None,
        ));
    }

    Ok(parsed.contents().to_vec())
}
