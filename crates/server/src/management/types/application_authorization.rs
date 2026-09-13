use crate::application_authorization::inorii::Claims;

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationAuthorizationUpdate {
    pub client_id: String,
    pub subject: String,
    /// Current revision, or zero for creation. With enabled=true, at most
    /// 9223372036854775804; disabling permits 9223372036854775805.
    #[cfg_attr(
        feature = "openapi",
        schema(minimum = 0, maximum = 9223372036854775805_i64)
    )]
    pub base_revision: i64,
    pub authority: String,
    /// Strictly newer authority revision. With enabled=true, at most
    /// 9223372036854775805; 9223372036854775806 is reserved for disabling.
    #[cfg_attr(
        feature = "openapi",
        schema(minimum = 1, maximum = 9223372036854775806_i64)
    )]
    pub source_revision: i64,
    pub audiences: Vec<String>,
    pub claims: Claims,
    /// Enabling must leave room in both counters for a later audited disable.
    /// Exhausted disabled projections cannot be reactivated.
    pub enabled: bool,
    pub reason: String,
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApplicationAuthorizationResponse {
    /// New revision. The terminal value 9223372036854775806 is used only by a
    /// disabled projection and cannot be reset or reused for reauthorization.
    #[cfg_attr(
        feature = "openapi",
        schema(minimum = 1, maximum = 9223372036854775806_i64)
    )]
    pub revision: i64,
}
