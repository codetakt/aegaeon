use aegaeon_jose::RequestObjectClaims;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;

/// PAR request as per RFC 9126
#[derive(Clone, Deserialize, Serialize)]
pub struct ParRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    /// AS recipient binding; independent of the issuer of a signed Request Object.
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
    /// OIDC prompt from the pushed request, never from the later outer query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub max_age: Option<u64>,
    /// RFC 9396 Rich Authorization Requests (`authorization_details`).
    #[serde(default)]
    pub authorization_details: Option<Value>,
    /// Transient credential for local validation; never serialized or restored from storage.
    #[serde(skip)]
    pub client_secret: Option<String>,
    /// Internal outcome of successful endpoint-layer client authentication.
    /// The HTTP form parser never accepts this field from the client.
    #[serde(default)]
    pub client_authenticated: bool,
    /// Raw Request Object (signed JWT) provided via JAR.
    #[serde(default)]
    pub request_object: Option<String>,
    #[serde(default)]
    pub request_object_claims: Option<RequestObjectClaims>,
}

impl std::fmt::Debug for ParRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParRequest")
            .field("client_id", &self.client_id)
            .field("response_type", &self.response_type)
            .field("client_authenticated", &self.client_authenticated)
            .finish_non_exhaustive()
    }
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
    pub(super) fn new(mut request: ParRequest) -> Self {
        request.client_secret = None;
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
