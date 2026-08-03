use crate::management::types::AccountLinkInactiveTargetHandling;

pub(in crate::web::management) fn resolve_account_link_inactive_target_handling(
    requires_explicit_override: bool,
    requested: Option<AccountLinkInactiveTargetHandling>,
) -> Result<Option<AccountLinkInactiveTargetHandling>, &'static str> {
    if !requires_explicit_override {
        return Ok(None);
    }

    match requested {
        Some(AccountLinkInactiveTargetHandling::AllowInactive) => {
            Ok(Some(AccountLinkInactiveTargetHandling::AllowInactive))
        }
        None => {
            Err("Inactive target user handling must be set to allow_inactive before reassignment")
        }
    }
}

pub(in crate::web::management) fn account_link_inactive_target_handling_label(
    action: Option<AccountLinkInactiveTargetHandling>,
) -> &'static str {
    match action {
        Some(AccountLinkInactiveTargetHandling::AllowInactive) => "allow_inactive",
        None => "unchanged",
    }
}
