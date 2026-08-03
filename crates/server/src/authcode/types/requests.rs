use aegaeon_jose::RequestObjectClaims;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Authorization Request per RFC 6749
#[derive(Debug, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    #[serde(default)]
    pub iss: Option<String>,
    pub redirect_uri: Option<String>,
    /// RFC 8707 Resource Indicators: requested target resource (single value).
    #[serde(default)]
    pub resource: Option<String>,
    /// RFC 9396 Rich Authorization Requests (`authorization_details`).
    #[serde(default)]
    pub authorization_details: Option<Value>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub request_uri: Option<String>,
    #[serde(default)]
    pub request_object: Option<String>,
    #[serde(default)]
    pub request_object_claims: Option<RequestObjectClaims>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub max_age: Option<u64>,
}

/// Token Request
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>, // PKCE
    /// RFC 8707 Resource Indicators: requested target resource (single value).
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub request_object_claims: Option<RequestObjectClaims>,
}

/// Token Response
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum TokenResponse {
    Success {
        access_token: String,
        token_type: String,
        expires_in: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authorization_details: Option<Value>,
    },
    Error {
        error: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,
    },
}
