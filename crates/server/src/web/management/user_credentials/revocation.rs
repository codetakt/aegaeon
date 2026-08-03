mod password;
mod recovery;

pub(super) use password::revoke_user_password_credential;
pub(super) use recovery::revoke_user_recovery_token;
