#[allow(clippy::struct_excessive_bools)] // Management input mirrors individually editable OAuth profile toggles.
#[derive(Clone, Debug)]
pub(in crate::web::management) struct OAuthProfileInput {
    pub(in crate::web::management) name: String,
    pub(in crate::web::management) description: Option<String>,
    pub(in crate::web::management) profile_type: String,
    pub(in crate::web::management) is_default: bool,
    pub(in crate::web::management) require_pkce: bool,
    pub(in crate::web::management) require_state_parameter: bool,
    pub(in crate::web::management) require_iss_parameter: bool,
    pub(in crate::web::management) sender_constrained: String,
    pub(in crate::web::management) enforce_refresh_sender_binding: bool,
    pub(in crate::web::management) allowed_grant_types: Vec<String>,
    pub(in crate::web::management) token_endpoint_auth_methods_allowed: Vec<String>,
    pub(in crate::web::management) expires_at: Option<String>,
}
