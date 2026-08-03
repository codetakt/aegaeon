use aegaeon_jose::RequestObjectClaims;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;

/// PAR request as per RFC 9126
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    #[serde(default)]
    pub iss: Option<String>,
    /// RFC 8707 Resource Indicators: requested target resource (single value).
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub max_age: Option<u64>,
    /// RFC 9396 Rich Authorization Requests (`authorization_details`).
    #[serde(default)]
    pub authorization_details: Option<Value>,
    // Client authentication
    #[serde(default)]
    pub client_secret: Option<String>,
    /// True only when endpoint-layer client authentication already succeeded with a non-secret
    /// method such as `private_key_jwt`.
    #[serde(default)]
    pub client_authenticated: bool,
    /// Raw Request Object (signed JWT) provided via JAR.
    #[serde(default)]
    pub request_object: Option<String>,
    #[serde(default)]
    pub request_object_claims: Option<RequestObjectClaims>,
}

/// PAR response as per RFC 9126
#[derive(Debug, Serialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

/// PAR error response
#[derive(Debug, Serialize)]
pub struct ParError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Registered OAuth client
#[derive(Debug, Clone)]
#[cfg(test)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint_auth_method: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
}

/// Stored PAR request
#[derive(Debug, Clone)]
pub struct StoredParRequest {
    pub request: ParRequest,
    pub expires_at: SystemTime,
    pub client_id: String,
    pub authorize_continuation: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ValidatedParRequest(ParRequest);

impl ValidatedParRequest {
    pub(super) fn new(request: ParRequest) -> Self {
        Self(request)
    }

    pub(super) fn into_inner(self) -> ParRequest {
        self.0
    }
}

/// PAR request reserved by the first front-channel `/authorize` use.
#[derive(Debug, Clone)]
pub struct ReservedParRequest {
    pub request: ParRequest,
    pub continuation: String,
}
