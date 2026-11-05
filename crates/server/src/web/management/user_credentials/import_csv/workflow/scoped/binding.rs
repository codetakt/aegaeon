use super::*;
use crate::organizations::witness::creation::{Input, Kind};
use aegaeon_crypto::hash::sha256_digest;

fn text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend((value.len() as u32).to_be_bytes());
    bytes.extend(value.as_bytes());
}

pub(super) fn inputs(
    context: &UserManagementContext,
    body: &ImportUsersCsvRequest,
    headers: &HeaderMap,
    rows: &[ParsedCsvUserRow],
    request_id: &str,
) -> Result<Vec<Input>, Response> {
    let invalid = || {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Bounded CSV creation fields are required",
            None,
            Some(request_id),
        )
    };
    let key = creation::management_key(headers, request_id)?;
    if rows.is_empty()
        || rows.len() > crate::organizations::witness::creation::MAX_BATCH
        || rows.iter().any(|r| {
            r.subject.len() > 255 || r.email.as_deref().is_some_and(|e| e.len() > 1_048_576)
        })
        || local_credentials::sanitize_recovery_token_ttl(
            body.activation_token_expires_in_seconds,
            RecoveryTokenPurpose::Activation,
            local_credentials::RecoveryTokenTtlPolicy::baseline(),
        )
        .is_err()
    {
        return Err(invalid());
    }
    let mut batch = b"aegaeon-creation-management-csv-v1\0".to_vec();
    batch.push(u8::from(body.issue_activation_tokens));
    match body.activation_token_expires_in_seconds {
        Some(ttl) => {
            batch.push(1);
            batch.extend((ttl as u64).to_be_bytes());
        }
        None => batch.push(0),
    }
    batch.extend((rows.len() as u32).to_be_bytes());
    for row in rows {
        batch.extend((row.row_number as u64).to_be_bytes());
        text(&mut batch, &row.subject);
        match row.email.as_deref() {
            Some(email) => {
                batch.push(1);
                text(&mut batch, email);
            }
            None => batch.push(0),
        }
    }
    let batch = sha256_digest(&batch);
    let actor = creation::management_actor(context);
    rows.iter()
        .enumerate()
        .map(|(index, row)| {
            let mut selector = b"aegaeon-creation-management-selector-v1\0".to_vec();
            selector.extend(context.environment_id.as_bytes());
            selector.push(3);
            selector.extend(key.as_bytes());
            selector.extend((index as u32).to_be_bytes());
            let mut payload = b"aegaeon-creation-management-csv-row-v1\0".to_vec();
            payload.extend(batch);
            payload.extend((index as u32).to_be_bytes());
            Input::new(
                Kind::ManagementCsv,
                sha256_digest(&selector),
                actor,
                sha256_digest(&payload),
                Some(&row.subject),
            )
            .map_err(|_| invalid())
        })
        .collect()
}
