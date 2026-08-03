use aegaeon_crypto::hash::Sha256Hasher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Characters used for user code generation.
/// Excludes confusable characters: 0/O, 1/I/L, 2/Z, 5/S, 8/B
/// Resulting alphabet: A C D E F G H J K M N P Q R T U V W X Y (20 chars)
/// Entropy per char: log2(20) ~= 4.322 bits
/// 8 chars -> 34.6 bits (exceeds DA-2 requirement of >= 31 bits)
pub(super) const USER_CODE_ALPHABET: &[u8] = b"ACDEFGHJKMNPQRTUVWXY";

/// User code length (8 characters).
const USER_CODE_LENGTH: usize = 8;
const USER_CODE_ALPHABET_LEN: usize = USER_CODE_ALPHABET.len();
const USER_CODE_REJECTION_BOUND: usize =
    (u8::MAX as usize + 1) / USER_CODE_ALPHABET_LEN * USER_CODE_ALPHABET_LEN;

pub(super) const USER_CODE_GENERATION_ATTEMPTS: usize = 16;

fn fill_random(bytes: &mut [u8], context: &str) -> Result<(), String> {
    aegaeon_crypto::rand::fill_random(bytes).map_err(|err| {
        let message = format!("device authorization entropy generation failed: {context}");
        tracing::error!(error = ?err, %message);
        message
    })
}

/// Generate a device code with 256 bits of entropy (DA-4).
pub(super) fn generate_device_code() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes, "device_code")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Hash a device code using SHA-256 (DA-3). Returns base64url-encoded hash.
pub(super) fn hash_device_code(device_code: &str) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(device_code.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize().as_ref())
}

/// Generate a user code with >= 31 bits of entropy (DA-2).
///
/// Uses an alphabet of 20 non-confusable uppercase characters and 8-character length,
/// yielding log2(20^8) ~= 34.6 bits of entropy.
pub(super) fn generate_user_code() -> Result<String, String> {
    let mut code = String::with_capacity(USER_CODE_LENGTH);
    let mut bytes = [0u8; USER_CODE_LENGTH * 2];
    while code.len() < USER_CODE_LENGTH {
        fill_random(&mut bytes, "user_code")?;
        bytes
            .iter()
            .filter_map(|byte| user_code_char_from_random_byte(*byte))
            .take(USER_CODE_LENGTH - code.len())
            .for_each(|ch| code.push(ch));
    }
    Ok(code)
}

pub(super) fn user_code_char_from_random_byte(byte: u8) -> Option<char> {
    let value = usize::from(byte);
    (value < USER_CODE_REJECTION_BOUND).then(|| {
        let idx = value % USER_CODE_ALPHABET_LEN;
        USER_CODE_ALPHABET[idx] as char
    })
}

/// Normalize a user code for comparison: uppercase, strip hyphens and whitespace.
pub(super) fn normalize_user_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Format a user code as `XXXX-XXXX` for display.
pub(super) fn format_user_code(code: &str) -> String {
    if code.len() == USER_CODE_LENGTH {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code.to_string()
    }
}
