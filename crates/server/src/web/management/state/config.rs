mod bootstrap_env;
mod construction;
mod origin;

pub(in crate::web::management) use origin::normalize_management_allowed_origin;

#[derive(Clone, Debug)]
pub struct ManagementConfig {
    pub allowed_origins: Vec<String>,
    pub issuer_base_domain: String,
    pub cookie_secure: bool,
    pub session_ttl_secs: u64,
    pub max_sessions: usize,
    pub(in crate::web::management) bootstrap_token_sha256: Option<[u8; 32]>,
}

impl ManagementConfig {
    pub(in crate::web::management) fn bootstrap_token_sha256(&self) -> Option<&[u8; 32]> {
        self.bootstrap_token_sha256.as_ref()
    }
}
