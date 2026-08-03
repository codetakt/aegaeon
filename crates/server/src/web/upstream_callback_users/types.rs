pub(in crate::web) struct UpstreamCallbackUserResolution {
    pub(in crate::web) user_id: String,
    pub(in crate::web) local_end_user_id: Option<uuid::Uuid>,
    pub(in crate::web) auth_time: i64,
}
