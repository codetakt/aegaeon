use crate::management::types::Client;

pub(super) fn client_audit_snapshot(client: &Client) -> serde_json::Value {
    serde_json::json!({
        "clientIdentifier": &client.client_identifier,
        "name": &client.name,
        "clientType": &client.client_type,
        "redirectUris": &client.redirect_uris,
        "allowedGrantTypes": &client.allowed_grant_types,
        "allowedScopes": &client.allowed_scopes,
        "tokenEndpointAuthenticationMethod": &client.token_endpoint_authentication_method,
        "oauthProfileId": &client.oauth_profile_id,
    })
}
