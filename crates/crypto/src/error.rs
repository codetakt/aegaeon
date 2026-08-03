/// Errors from the unified crypto abstraction layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("SHA-256 digest failed")]
    DigestFailed,

    #[error("random number generation failed: {0}")]
    RngFailed(String),

    #[error("HMAC operation failed: {0}")]
    HmacFailed(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("JWE decryption failed: {0}")]
    DecryptionFailed(String),
}
