mod claims;
mod model;
mod rows;
mod store;

pub(crate) use claims::is_reserved_custom_claim_name;
pub use claims::{
    empty_custom_claims, normalize_display_name, oidc_profile_claims_from_record,
    validate_custom_claims,
};
pub use model::{
    EndUserProfileRecord, OidcProfileClaims, UpdateProfileError, SUBJECT_POLICY_EXPLICIT,
};
pub use store::{
    ensure_profile_row, load_user_profile, load_user_profile_for_subject,
    load_user_profile_for_update, update_user_profile, update_user_profile_with_previous,
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_display_name_trims_blank_values() {
        assert_eq!(normalize_display_name("  "), None);
        assert_eq!(
            normalize_display_name("  Example User  "),
            Some("Example User".to_string())
        );
    }

    #[test]
    fn validate_custom_claims_rejects_reserved_claim_names() {
        assert_eq!(
            validate_custom_claims(&json!({ "email": "user@example.com" })),
            Err("customClaims contains reserved claim names")
        );
        let authority_claim = crate::application_authorization::inorii::CLAIM_NAME;
        for name in [
            authority_claim.to_string(),
            authority_claim.to_ascii_uppercase(),
            format!(" {authority_claim} "),
        ] {
            assert_eq!(
                validate_custom_claims(&json!({ name: { "roles": ["SUPER_ADMIN"] } })),
                Err("customClaims contains reserved claim names"),
            );
        }
    }

    #[test]
    fn validate_custom_claims_accepts_custom_object() {
        assert_eq!(
            validate_custom_claims(&json!({ "department": "platform", "employee_id": 7 })),
            Ok(())
        );
    }
}
