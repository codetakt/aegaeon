use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RuntimeActivationStatus {
    pub runtime_reloaded: bool,
    pub runtime_authority: String,
    pub persistence_authority: String,
    pub message: String,
}
