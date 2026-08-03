use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConnectionListQuery {
    pub(super) page_size: Option<u32>,
    pub(super) page_token: Option<String>,
    pub(super) configuration_version_id: Option<String>,
}
