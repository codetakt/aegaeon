use crate::management::types::Connection;

pub(in crate::web::management::connections_audit) fn connection_audit_snapshot(
    connection: &Connection,
) -> serde_json::Value {
    serde_json::json!({
        "connectionIdentifier": &connection.connection_identifier,
        "name": &connection.name,
        "connectionType": &connection.connection_type,
        "issuerUrl": &connection.issuer_url,
        "clientId": &connection.client_id,
        "clientAuthMethod": &connection.client_auth_method,
        "status": &connection.status,
        "oauthProfileId": &connection.oauth_profile_id,
    })
}
