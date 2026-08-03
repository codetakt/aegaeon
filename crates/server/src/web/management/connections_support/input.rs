use super::ConnectionInput;
use crate::management::types::{Connection, CreateConnectionRequest, UpdateConnectionRequest};
use crate::web::management::{normalize_optional_text, normalize_text};

pub(in crate::web::management) fn connection_input_from_create(
    req: &CreateConnectionRequest,
) -> ConnectionInput {
    ConnectionInput {
        connection_identifier: req.connection_identifier.trim().to_string(),
        name: req.name.trim().to_string(),
        connection_type: req
            .connection_type
            .clone()
            .unwrap_or_else(|| "OIDC".to_string()),
        issuer_url: req.issuer_url.trim().to_string(),
        client_id: req.client_id.trim().to_string(),
        client_auth_method: req
            .client_auth_method
            .clone()
            .unwrap_or_else(|| "client_secret_basic".to_string()),
        status: req.status.clone().unwrap_or_else(|| "ACTIVE".to_string()),
        oauth_profile_id: normalize_optional_text(req.oauth_profile_id.as_deref()),
    }
}

pub(in crate::web::management) fn connection_input_from_update(
    existing: &Connection,
    req: &UpdateConnectionRequest,
) -> ConnectionInput {
    let oauth_profile_id = match req.oauth_profile_id.as_ref() {
        Some(value) => normalize_optional_text(value.as_deref()),
        None => existing.oauth_profile_id.clone(),
    };

    ConnectionInput {
        connection_identifier: req
            .connection_identifier
            .as_deref()
            .map_or_else(|| existing.connection_identifier.clone(), normalize_text),
        name: req
            .name
            .as_deref()
            .map_or_else(|| existing.name.clone(), normalize_text),
        connection_type: req
            .connection_type
            .as_deref()
            .map_or_else(|| existing.connection_type.clone(), normalize_text),
        issuer_url: req
            .issuer_url
            .as_deref()
            .map_or_else(|| existing.issuer_url.clone(), normalize_text),
        client_id: req
            .client_id
            .as_deref()
            .map_or_else(|| existing.client_id.clone(), normalize_text),
        client_auth_method: req
            .client_auth_method
            .as_deref()
            .map_or_else(|| existing.client_auth_method.clone(), normalize_text),
        status: req
            .status
            .as_deref()
            .map_or_else(|| existing.status.clone(), normalize_text),
        oauth_profile_id,
    }
}
