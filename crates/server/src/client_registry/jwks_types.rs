use std::collections::HashMap;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct FetchedJwks {
    pub(super) keys: Vec<FetchedJwk>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct FetchedJwk {
    pub(super) kty: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub(super) key_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) key_ops: Option<Vec<String>>,
    pub(super) kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) alg: Option<String>,
    pub(super) n: Option<String>,
    pub(super) e: Option<String>,
    pub(super) x: Option<String>,
    pub(super) y: Option<String>,
    pub(super) crv: Option<String>,
}

#[derive(Clone)]
pub(super) struct CacheEntry {
    pub(super) etag: Option<String>,
    pub(super) expires_at: Option<std::time::Instant>,
    pub(super) fetched_at: std::time::Instant,
    pub(super) jwks: FetchedJwks,
    pub(super) kid_fps: HashMap<String, String>,
    pub(super) last_modified: Option<String>,
}
