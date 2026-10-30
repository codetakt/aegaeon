#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfigureIdentityPolicyRequest {
    pub policy: crate::organizations::operators::mutations::identity_policy::Policy,
    pub reason: String,
}
