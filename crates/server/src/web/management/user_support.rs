mod audit;
mod context;
mod errors;
mod mapper;
mod normalization;
mod params;
mod store;

#[derive(Debug, Clone)]
pub(in crate::web::management) struct ManagedUserIdentity {
    pub(in crate::web::management) subject: String,
    pub(in crate::web::management) email: Option<String>,
    pub(in crate::web::management) status: String,
}

pub(in crate::web::management) use audit::{
    insert_user_management_runtime_command, mark_user_management_runtime_command_executing,
    write_user_management_audit_event, write_user_management_audit_event_with_outcome,
    write_user_management_runtime_command_outcome, EndUserAuditEvent, EndUserRuntimeCommandOutcome,
    EndUserRuntimeCommandStatus,
};
pub(in crate::web::management) use context::{
    require_user_management_context, require_user_management_scope, UserManagementContext,
};
pub(in crate::web::management) use errors::{
    invalid_email_response, is_unique_violation, user_not_found, user_profile_not_found,
};
pub(in crate::web::management) use mapper::{user_from_row_result, user_profile_from_record};
pub(in crate::web::management) use normalization::{
    ensure_user_profile_update_requested, normalize_email, normalize_optional_email,
    normalize_required_subject, normalize_subject,
};
pub(in crate::web::management) use params::{require_token_id_param, require_user_id_param};
pub(in crate::web::management) use store::{
    insert_invited_user, load_managed_user_identity, load_managed_user_identity_for_update,
    load_user_identity,
};

#[cfg(test)]
pub(in crate::web::management) use store::LOAD_USER_IDENTITY_SQL;
