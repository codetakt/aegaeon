use crate::management::types::AccountLinkRefreshTokenHandling;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web::management) enum AccountLinkRefreshTokenAction {
    Clear,
    Retain,
}

pub(in crate::web::management) fn resolve_account_link_refresh_token_action(
    moving_refresh_token_count: usize,
    requested: Option<AccountLinkRefreshTokenHandling>,
) -> Result<Option<AccountLinkRefreshTokenAction>, &'static str> {
    if moving_refresh_token_count == 0 {
        return Ok(None);
    }

    match requested {
        Some(AccountLinkRefreshTokenHandling::Clear) => {
            Ok(Some(AccountLinkRefreshTokenAction::Clear))
        }
        Some(AccountLinkRefreshTokenHandling::Retain) => {
            Ok(Some(AccountLinkRefreshTokenAction::Retain))
        }
        None => Err(
            "Stored upstream refresh token handling must be set to clear or retain before reassignment",
        ),
    }
}

pub(in crate::web::management) fn account_link_refresh_token_action_label(
    action: Option<AccountLinkRefreshTokenAction>,
) -> &'static str {
    match action {
        Some(AccountLinkRefreshTokenAction::Clear) => "clear",
        Some(AccountLinkRefreshTokenAction::Retain) => "retain",
        None => "unchanged",
    }
}
