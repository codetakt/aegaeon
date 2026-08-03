use aegaeon_jose::RequestObjectClaims;
use serde_json::Value;
use std::sync::Arc;

use crate::client_registry::ClientRegistry;
use crate::request_object_store::RequestObjectJtiStore;

pub(in crate::web) struct RequestObjectAuthorizeDeps<'a> {
    pub(in crate::web) clients: &'a ClientRegistry,
    pub(in crate::web) request_object_jti_store: &'a RequestObjectJtiStore,
    pub(in crate::web) jose_header_max_len: usize,
    pub(in crate::web) request_object_decryption_key_pkcs8_der: Option<&'a [u8]>,
    pub(in crate::web) crypto_profile: aegaeon_jose::algorithms::CryptoProfile,
    pub(in crate::web) jwt_leeway_secs: u64,
    pub(in crate::web) request_object_everparse_runtime_enabled: bool,
}

#[derive(Clone)]
pub(in crate::web) struct OwnedRequestObjectAuthorizeDeps {
    pub(in crate::web) clients: Arc<ClientRegistry>,
    pub(in crate::web) request_object_jti_store: Arc<RequestObjectJtiStore>,
    pub(in crate::web) jose_header_max_len: usize,
    pub(in crate::web) request_object_decryption_key_pkcs8_der: Option<Vec<u8>>,
    pub(in crate::web) crypto_profile: aegaeon_jose::algorithms::CryptoProfile,
    pub(in crate::web) jwt_leeway_secs: u64,
    pub(in crate::web) request_object_everparse_runtime_enabled: bool,
}

impl OwnedRequestObjectAuthorizeDeps {
    pub(in crate::web) fn as_borrowed(&self) -> RequestObjectAuthorizeDeps<'_> {
        RequestObjectAuthorizeDeps {
            clients: self.clients.as_ref(),
            request_object_jti_store: self.request_object_jti_store.as_ref(),
            jose_header_max_len: self.jose_header_max_len,
            request_object_decryption_key_pkcs8_der: self
                .request_object_decryption_key_pkcs8_der
                .as_deref(),
            crypto_profile: self.crypto_profile,
            jwt_leeway_secs: self.jwt_leeway_secs,
            request_object_everparse_runtime_enabled: self.request_object_everparse_runtime_enabled,
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::web) enum RequestObjectReplayPolicy {
    Consume,
    Defer,
}

#[derive(Debug)]
pub(in crate::web) struct ResolvedAuthorizeRequestObject {
    pub(in crate::web) redirect_uri: String,
    pub(in crate::web) response_type: String,
    pub(in crate::web) scope: String,
    pub(in crate::web) state: Option<String>,
    pub(in crate::web) nonce: Option<String>,
    pub(in crate::web) acr_values: Option<String>,
    pub(in crate::web) max_age: Option<u64>,
    pub(in crate::web) code_challenge: String,
    pub(in crate::web) code_challenge_method: String,
    pub(in crate::web) resource: Option<String>,
    pub(in crate::web) authorization_details: Option<Value>,
    pub(in crate::web) request_object: String,
    pub(in crate::web) request_object_claims: RequestObjectClaims,
}
