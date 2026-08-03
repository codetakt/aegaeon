use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::web::management::oauth_profiles) struct OAuthProfileListQuery {
    pub(in crate::web::management::oauth_profiles) page_size: Option<u32>,
    pub(in crate::web::management::oauth_profiles) page_token: Option<String>,
    pub(in crate::web::management::oauth_profiles) configuration_version_id: Option<String>,
}
