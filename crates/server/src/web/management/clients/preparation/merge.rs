use super::super::super::client_input::{validate_management_client_input, ClientInput};
use super::super::super::parse_optional_stored_uuid;
use super::{ClientOAuthProfileChange, ClientUpdateInput};
use crate::management::types::Client;
use axum::response::Response;

pub(in crate::web::management::clients) fn merge_client_update(
    existing_client: &Client,
    input: &ClientUpdateInput,
    request_id: &str,
) -> Result<ClientInput, Response> {
    let mut merged = ClientInput {
        client_identifier: existing_client.client_identifier.clone(),
        name: input
            .name
            .clone()
            .unwrap_or_else(|| existing_client.name.clone()),
        client_type: existing_client.client_type.clone(),
        redirect_uris: input
            .redirect_uris
            .clone()
            .unwrap_or_else(|| existing_client.redirect_uris.clone()),
        allowed_grant_types: input
            .allowed_grant_types
            .clone()
            .unwrap_or_else(|| existing_client.allowed_grant_types.clone()),
        allowed_scopes: input
            .allowed_scopes
            .clone()
            .unwrap_or_else(|| existing_client.allowed_scopes.clone()),
        token_endpoint_authentication_method: input
            .token_endpoint_authentication_method
            .clone()
            .unwrap_or_else(|| existing_client.token_endpoint_authentication_method.clone()),
        oauth_profile_id: match input.oauth_profile_change {
            Some(ClientOAuthProfileChange::Assign(profile_id)) => Some(profile_id),
            Some(ClientOAuthProfileChange::Clear) => None,
            None => parse_optional_stored_uuid(
                existing_client.oauth_profile_id.as_deref(),
                "client oauthProfileId",
                request_id,
            )?,
        },
    };
    validate_management_client_input(&mut merged, request_id)?;
    Ok(merged)
}
