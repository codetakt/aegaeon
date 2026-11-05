#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfigureInvitationDeliveryRequest {
    pub channel: crate::organizations::operators::mutations::delivery::Channel,
    pub reason: String,
}
