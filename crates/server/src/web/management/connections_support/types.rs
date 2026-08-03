#[derive(Clone, Debug)]
pub(in crate::web::management) struct ConnectionInput {
    pub(in crate::web::management) connection_identifier: String,
    pub(in crate::web::management) name: String,
    pub(in crate::web::management) connection_type: String,
    pub(in crate::web::management) issuer_url: String,
    pub(in crate::web::management) client_id: String,
    pub(in crate::web::management) client_auth_method: String,
    pub(in crate::web::management) status: String,
    pub(in crate::web::management) oauth_profile_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::web::management) enum ConnectionClientSecretAction {
    Preserve,
    Set(String),
    Clear,
}
