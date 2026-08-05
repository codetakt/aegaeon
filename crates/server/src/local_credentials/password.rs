use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::sync::LazyLock;

pub const MIN_PASSWORD_BYTES: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// # Errors
///
/// Returns an error when the password is shorter than the minimum or exceeds
/// the supported maximum length.
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    let len = password.len();
    if len < MIN_PASSWORD_BYTES {
        return Err("Password must be at least 12 bytes long");
    }
    if len > MAX_PASSWORD_BYTES {
        return Err("Password is too long");
    }
    Ok(())
}

/// # Errors
///
/// Returns an error when the password violates the configured bounds.
pub fn hash_password(password: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    aegaeon_crypto::rand::fill_random(&mut salt_bytes)
        .map_err(|_| "Failed to generate password salt".to_string())?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|_| "Failed to encode password salt".to_string())?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "Failed to hash password".to_string())
}

fn dummy_password_hash() -> Option<&'static str> {
    static DUMMY_HASH: LazyLock<Option<String>> =
        LazyLock::new(|| hash_password("aegaeon-dummy-password-verifier").ok());
    DUMMY_HASH.as_deref()
}

#[must_use]
pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[must_use]
pub(crate) fn verify_password_or_dummy(password: &str, encoded_hash: Option<&str>) -> bool {
    let verified = match encoded_hash {
        Some(hash) => verify_password(password, hash),
        None => dummy_password_hash().is_some_and(|hash| verify_password(password, hash)),
    };
    verified && encoded_hash.is_some()
}
