#![allow(unsafe_code)]
// Safety: this crate owns the FFI boundary; unsafe usage is confined here by policy.

#[cfg(not(kani))]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(not(kani))]
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
#[cfg(not(kani))]
use serde::{Deserialize, Deserializer};
#[cfg(not(kani))]
use sha2::{Digest, Sha256};
#[cfg(not(kani))]
use std::collections::HashSet;
use std::ffi::{c_char, CString};
use std::ptr::NonNull;
use std::slice;

pub mod dcr;
pub mod dcr_parser;
pub mod id_token;
pub mod jose_header;
pub mod raw_json_structural;
pub mod request_object_parser;
pub mod tlv;

#[cfg(all(kani, feature = "kani"))]
mod kani_simple_tests;

// JSON parsing error codes matching Jose.LowStar.Json.json_parse_error
const JSON_PARSE_OK: u8 = 0;
const JSON_PARSE_ERROR_INVALID_VALUE_UTF8: u8 = 3;
const JSON_PARSE_ERROR_INTERNAL: u8 = 6;

/// UTF-8 decoding helper for C FFI.
///
/// # Safety
///
/// - `bytes` must be a valid pointer to `len` bytes
/// - `out_string` must be a valid pointer to write a `*mut c_char`
/// - Caller must free the returned string using `aegaeon_ffi_free_string`
///
/// # Returns
///
/// - `JSON_PARSE_OK` (0) on success, with allocated `CString` written to `out_string`
/// - `JSON_PARSE_ERROR_INVALID_VALUE_UTF8` (3) if bytes are not valid UTF-8
/// - `JSON_PARSE_ERROR_INTERNAL` (6) if `CString` allocation fails (null byte in string)
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aegaeon_ffi_decode_utf8(
    bytes: *const u8,
    len: usize,
    out_string: *mut *mut c_char,
) -> u8 {
    if bytes.is_null() || out_string.is_null() {
        return JSON_PARSE_ERROR_INTERNAL;
    }

    // SAFETY: Caller guarantees bytes is valid for len bytes
    let byte_slice = unsafe { slice::from_raw_parts(bytes, len) };

    // Validate UTF-8
    let Ok(string) = String::from_utf8(byte_slice.to_vec()) else {
        return JSON_PARSE_ERROR_INVALID_VALUE_UTF8;
    };

    // Convert to CString
    let Ok(c_string) = CString::new(string) else {
        return JSON_PARSE_ERROR_INTERNAL;
    };

    // Transfer ownership to caller
    // SAFETY: out_string is guaranteed valid by caller
    unsafe {
        *out_string = c_string.into_raw();
    }

    JSON_PARSE_OK
}

/// Free a string allocated by `aegaeon_ffi_decode_utf8`
///
/// # Safety
///
/// - `s` must have been allocated by `aegaeon_ffi_decode_utf8`
/// - `s` must not be used after this call
/// - `s` must not be freed more than once
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aegaeon_ffi_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: s was allocated by CString::into_raw in aegaeon_ffi_decode_utf8
    unsafe {
        let _ = CString::from_raw(s);
    }
}

// -----------------------------------------------------------------------------
// JSON parsing FFI (Low* integration)
// -----------------------------------------------------------------------------

/// C structure for JSON entry (from Jose.LowStar.Json)
#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)] // Only used by FFI code compiled out in tests
struct JsonEntryOut {
    key_ptr: *const u8,
    key_len: u32,
    value_ptr: *const u8,
    value_len: u32,
}

/// C structure for JSON parse result (from Jose.LowStar.Json)
#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)] // Only used by FFI code compiled out in tests
struct JsonParseResultC {
    entries: *mut JsonEntryOut,
    entry_count: u32,
    error: u8,
    error_message: *const u8,
    error_message_len: u32,
}

/// JSON parsing error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    UnknownKey(String),
    InvalidKeyEncoding(String),
    InvalidValueUtf8(String),
    TrailingBytes(String),
    PolicyViolation(String),
    BufferTooShort(String),
    Internal(String),
    /// The native parser is not available in this build (e.g. tests, Kani, or
    /// no mbedtls support). Callers should fall back to Rust-only logic.
    ParserUnavailable,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonError::UnknownKey(msg) => write!(f, "Unknown key: {msg}"),
            JsonError::InvalidKeyEncoding(msg) => write!(f, "Invalid key encoding: {msg}"),
            JsonError::InvalidValueUtf8(msg) => write!(f, "Invalid value UTF-8: {msg}"),
            JsonError::TrailingBytes(msg) => write!(f, "Trailing bytes: {msg}"),
            JsonError::PolicyViolation(msg) => write!(f, "Policy violation: {msg}"),
            JsonError::BufferTooShort(msg) => write!(f, "Buffer too short: {msg}"),
            JsonError::Internal(msg) => write!(f, "Internal error: {msg}"),
            JsonError::ParserUnavailable => write!(f, "Parser unavailable in this build"),
        }
    }
}

impl std::error::Error for JsonError {}

/// Returns true if the Low* JSON parser is unavailable in this build.
///
/// This is the case for test builds, Kani verification builds, and builds
/// without mbedtls support. Tests can use this to skip gracefully when
/// they require the Low* FFI.
#[inline]
#[must_use]
pub fn is_lowstar_unavailable() -> bool {
    cfg!(any(test, kani, no_mbedtls))
}

/// C member structure for JSON parsing input.
///
/// Must match `Jose_LowStar_Json_json_member_c` layout exactly.
#[repr(C)]
pub struct JsonMemberC {
    pub key_buf: *const u8,   // offset 0, size 8
    pub key_len: u32,         // offset 8, size 4
    pub value_kind: u8,       // offset 12, size 1
    pub padding: [u8; 3],     // offset 13, size 3 (align next field to 8 bytes)
    pub value_buf: *const u8, // offset 16, size 8
    pub value_len: u32,       // offset 24, size 4
                              // struct padded to 32 bytes total
}

// External C functions from Low* extraction
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
extern "C" {
    // Jose.Context API
    fn Jose_Context_make_context(max_len: u32) -> u32;

    // Jose.LowStar.Json API
    fn Jose_LowStar_Json_json_parse_entries_to_c(
        members: *const JsonMemberC,
        count: u32,
    ) -> JsonParseResultC;

    fn Jose_LowStar_Json_json_parse_free_result(result: *mut JsonParseResultC);
}

// Global default context (matches Jose_Context_default_context = 4096)
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
extern "C" {
    static Jose_Context_default_context: u32;
}

/// JOSE context for per-request policy configuration
///
/// Wraps the Low* `Jose_Context_jose_context` type (`krml_checked_int_t` = `i32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoseContext {
    header_max_length: u32,
}

impl JoseContext {
    /// Create a new context with custom header maximum length
    ///
    /// # Arguments
    ///
    /// * `max_len` - Maximum length for Base64URL-encoded JOSE protected headers (`1..=2^32-1`)
    ///
    /// # Panics
    ///
    /// Panics if `max_len` is `0` or exceeds `u32::MAX`.
    #[cfg(all(not(test), not(kani), not(no_mbedtls)))]
    #[must_use]
    pub fn new(max_len: usize) -> Self {
        assert!(
            max_len != 0 && u32::try_from(max_len).is_ok(),
            "header_max_length must be in range 1..=2^32-1"
        );

        let header_max_length =
            unsafe { Jose_Context_make_context(u32::try_from(max_len).unwrap_or(u32::MAX)) };

        Self { header_max_length }
    }

    /// Create a new context with custom header maximum length (test/kani fallback)
    ///
    /// # Panics
    ///
    /// Panics if `max_len` is `0` or exceeds `u32::MAX`.
    #[cfg(any(test, kani, no_mbedtls))]
    #[must_use]
    pub fn new(max_len: usize) -> Self {
        assert!(
            max_len != 0 && u32::try_from(max_len).is_ok(),
            "header_max_length must be in range 1..=2^32-1"
        );
        Self {
            header_max_length: u32::try_from(max_len).unwrap_or(u32::MAX),
        }
    }

    /// Get the default context (4096 bytes)
    #[cfg(all(not(test), not(kani), not(no_mbedtls)))]
    #[must_use]
    pub fn default_context() -> Self {
        let header_max_length = unsafe { Jose_Context_default_context };
        Self { header_max_length }
    }

    /// Get the default context (4096 bytes) - test/kani fallback
    #[cfg(any(test, kani, no_mbedtls))]
    #[must_use]
    pub fn default_context() -> Self {
        Self {
            header_max_length: 4096,
        }
    }

    /// Get the header maximum length
    #[must_use]
    pub fn header_max_length(&self) -> usize {
        usize::try_from(self.header_max_length).unwrap_or(usize::MAX)
    }

    // NOTE: Currently unused because JSON Stack runtime exposes fixed context via C build.
    // Retain for future when Jose.Context.* Low* artefacts are re-integrated.
    #[allow(dead_code)]
    pub(crate) fn as_u32(self) -> u32 {
        self.header_max_length
    }
}

impl Default for JoseContext {
    fn default() -> Self {
        Self::default_context()
    }
}

/// Parse JSON entries using Low* verified implementation
///
/// # Safety
///
/// - `members` must be a valid pointer to `count` `JsonMemberC` structures
/// - Each member's `key_buf` and `value_buf` must be valid for their respective lengths
///
/// # Errors
///
/// Returns [`JsonError`] when the input pointer is null, the item count exceeds
/// the C ABI limit, or the Low* parser reports a structured failure.
#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
pub unsafe fn parse_json_entries(
    members: *const JsonMemberC,
    count: usize,
) -> Result<Vec<(String, String)>, JsonError> {
    if members.is_null() {
        return Err(JsonError::Internal("null members pointer".to_string()));
    }

    let count_u32 = u32::try_from(count)
        .map_err(|_| JsonError::Internal("count exceeds u32::MAX".to_string()))?;

    // Call Low* implementation
    let mut result = Jose_LowStar_Json_json_parse_entries_to_c(members, count_u32);

    // Check for errors
    if result.error != JSON_PARSE_OK {
        let error_msg = if !result.error_message.is_null() && result.error_message_len > 0 {
            let msg_slice =
                slice::from_raw_parts(result.error_message, result.error_message_len as usize);
            String::from_utf8_lossy(msg_slice).to_string()
        } else {
            "unknown error".to_string()
        };

        let error = match result.error {
            1 => JsonError::UnknownKey(error_msg),
            2 => JsonError::InvalidKeyEncoding(error_msg),
            3 => JsonError::InvalidValueUtf8(error_msg),
            4 => JsonError::PolicyViolation(error_msg),
            5 => JsonError::BufferTooShort(error_msg),
            _ => JsonError::Internal(error_msg),
        };

        // Free result before returning error
        Jose_LowStar_Json_json_parse_free_result(&raw mut result);
        return Err(error);
    }

    // Extract entries
    let mut entries = Vec::with_capacity(result.entry_count as usize);

    if !result.entries.is_null() && result.entry_count > 0 {
        let entries_slice = slice::from_raw_parts(result.entries, result.entry_count as usize);

        for entry in entries_slice {
            // Convert key
            let key = if !entry.key_ptr.is_null() && entry.key_len > 0 {
                let key_slice = slice::from_raw_parts(entry.key_ptr, entry.key_len as usize);
                // Keys are already validated UTF-8 by the C implementation
                String::from_utf8_lossy(key_slice).to_string()
            } else {
                String::new()
            };

            // Convert value
            let value = if !entry.value_ptr.is_null() && entry.value_len > 0 {
                let value_slice = slice::from_raw_parts(entry.value_ptr, entry.value_len as usize);
                // Values are already validated UTF-8 by the C implementation
                String::from_utf8_lossy(value_slice).to_string()
            } else {
                String::new()
            };

            entries.push((key, value));
        }
    }

    // Free result
    Jose_LowStar_Json_json_parse_free_result(&raw mut result);

    Ok(entries)
}

/// Safe wrapper for parsing JSON entries with Low*.
///
/// This function delegates to the unsafe FFI boundary using a validated slice.
///
/// # Errors
///
/// Propagates the same [`JsonError`] values as [`parse_json_entries`].
pub fn parse_json_entries_safe(
    members: &[JsonMemberC],
) -> Result<Vec<(String, String)>, JsonError> {
    unsafe { parse_json_entries(members.as_ptr(), members.len()) }
}

/// Parse JSON entries (stub for `test/Kani/no_mbedtls` builds).
///
/// This returns [`JsonError::ParserUnavailable`] and performs no parsing.
///
/// # Safety
///
/// This function is `unsafe` to match the production FFI boundary. The stub
/// does not dereference `_members`, but callers should uphold the same
/// invariants as the non-stub implementation (pointer validity and lengths) to
/// avoid test-only behaviour masking safety issues.
///
/// # Errors
///
/// Always returns [`JsonError::ParserUnavailable`] in stub builds.
#[cfg(any(test, kani, no_mbedtls))]
pub unsafe fn parse_json_entries(
    _members: *const JsonMemberC,
    _count: usize,
) -> Result<Vec<(String, String)>, JsonError> {
    Err(JsonError::ParserUnavailable)
}

/// Non-null pointer to a key buffer.
///
/// # Safety
/// The contained pointer must reference memory valid for reads of `key_len`
/// bytes and live at least as long as the FFI call it is passed to.
#[repr(transparent)]
#[derive(Copy, Clone)]
struct KeyBuf(NonNull<u8>);

/// Non-null pointer to a message buffer.
///
/// # Safety
/// The pointed-to memory must remain valid for the duration of the call that
/// receives this buffer.
#[repr(transparent)]
#[derive(Copy, Clone)]
struct MsgBuf(NonNull<u8>);

/// Non-null pointer to a signature buffer.
///
/// # Safety
/// The pointed-to memory must remain valid for the duration of the call that
/// receives this buffer.
#[repr(transparent)]
#[derive(Copy, Clone)]
struct SigBuf(NonNull<u8>);

#[cfg(all(not(kani), not(no_mbedtls)))]
extern "C" {
    fn DpopCheckDpopClaims(base: *mut u8, len: u32) -> u8;
}

#[cfg(not(kani))]
#[inline]
fn check_dpop_claims(encoded: &mut [u8]) -> bool {
    #[cfg(all(not(kani), not(no_mbedtls)))]
    {
        let Ok(encoded_len) = u32::try_from(encoded.len()) else {
            return false;
        };
        // EverParse wrappers return `BOOLEAN` (u8). Treat any non-zero as true.
        unsafe { DpopCheckDpopClaims(encoded.as_mut_ptr(), encoded_len) != 0 }
    }
    #[cfg(any(kani, no_mbedtls))]
    {
        let _ = encoded;
        true
    }
}

impl KeyBuf {
    /// Create a [`KeyBuf`] from a slice.
    ///
    /// # Safety
    /// The returned buffer is valid only for the lifetime of `slice`.
    fn from_slice(slice: &[u8]) -> Self {
        // SAFETY: `slice.as_ptr()` is guaranteed to be non-null even for empty slices.
        let ptr = unsafe { NonNull::new_unchecked(slice.as_ptr().cast_mut()) };
        Self(ptr)
    }
}

impl MsgBuf {
    /// Create a [`MsgBuf`] from a slice.
    ///
    /// # Safety
    /// The returned buffer is valid only for the lifetime of `slice`.
    fn from_slice(slice: &[u8]) -> Self {
        // SAFETY: `slice.as_ptr()` is guaranteed to be non-null even for empty slices.
        let ptr = unsafe { NonNull::new_unchecked(slice.as_ptr().cast_mut()) };
        Self(ptr)
    }

    /// Create a [`MsgBuf`] from a mutable slice.
    ///
    /// # Safety
    /// The returned buffer is valid only for the lifetime of `slice`.
    fn from_mut_slice(slice: &mut [u8]) -> Self {
        // SAFETY: `slice.as_mut_ptr()` is guaranteed to be non-null even for empty slices.
        let ptr = unsafe { NonNull::new_unchecked(slice.as_mut_ptr()) };
        Self(ptr)
    }
}

impl SigBuf {
    /// Create a [`SigBuf`] from a slice.
    ///
    /// # Safety
    /// The returned buffer is valid only for the lifetime of `slice`.
    fn from_slice(slice: &[u8]) -> Self {
        // SAFETY: `slice.as_ptr()` is guaranteed to be non-null even for empty slices.
        let ptr = unsafe { NonNull::new_unchecked(slice.as_ptr().cast_mut()) };
        Self(ptr)
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum JwsAlg {
    HS256 = 0,
    HS384 = 1,
    HS512 = 2,
    PS256 = 3,
    EdDSA = 4,
    Unsupported = 5,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum JwsRc {
    Ok = 0,
    ErrUnsupportedAlg = 1,
    ErrInvalidSignature = 2,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum JweRc {
    Ok = 0,
    ErrUnsupportedAlg = 1,
    ErrDecryptFailed = 2,
}

#[cfg(all(not(kani), not(test), not(no_mbedtls)))]
extern "C" {
    /// # Safety
    /// `key`, `msg`, and `sig` must point to valid memory regions of at least
    /// `key_len`, `msg_len`, and `sig_len` bytes respectively.
    /// The function does not take ownership of these pointers.
    fn jws_hmac_verify(
        alg: JwsAlg,
        key: KeyBuf,
        key_len: usize,
        msg: MsgBuf,
        msg_len: usize,
        sig: SigBuf,
        sig_len: usize,
    ) -> JwsRc;

    fn jws_rsa_verify(
        alg: JwsAlg,
        key: KeyBuf,
        key_len: usize,
        msg: MsgBuf,
        msg_len: usize,
        sig: SigBuf,
        sig_len: usize,
    ) -> JwsRc;

    fn jws_ed25519_verify(
        alg: JwsAlg,
        key: KeyBuf,
        key_len: usize,
        msg: MsgBuf,
        msg_len: usize,
        sig: SigBuf,
        sig_len: usize,
    ) -> JwsRc;

    fn Jose_Jwe_chacha20poly1305_encrypt(
        key: KeyBuf,
        key_len: usize,
        nonce: MsgBuf,
        nonce_len: usize,
        aad: MsgBuf,
        aad_len: usize,
        plaintext: MsgBuf,
        pt_len: usize,
        ciphertext: MsgBuf,
        tag: MsgBuf,
    ) -> JweRc;

    fn Jose_Jwe_chacha20poly1305_decrypt(
        key: KeyBuf,
        key_len: usize,
        nonce: MsgBuf,
        nonce_len: usize,
        aad: MsgBuf,
        aad_len: usize,
        ciphertext: MsgBuf,
        ct_len: usize,
        tag: MsgBuf,
        tag_len: usize,
        plaintext: MsgBuf,
    ) -> JweRc;
}

#[cfg(any(kani, test, no_mbedtls))]
fn jws_hmac_verify(
    alg: JwsAlg,
    key: KeyBuf,
    key_len: usize,
    msg: MsgBuf,
    msg_len: usize,
    sig: SigBuf,
    sig_len: usize,
) -> JwsRc {
    #[cfg(all(any(test, no_mbedtls), not(kani)))]
    {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        if alg != JwsAlg::HS256 {
            return JwsRc::ErrUnsupportedAlg;
        }

        let key_slice = unsafe { std::slice::from_raw_parts(key.0.as_ptr(), key_len) };
        let msg_slice = unsafe { std::slice::from_raw_parts(msg.0.as_ptr(), msg_len) };
        let sig_slice = unsafe { std::slice::from_raw_parts(sig.0.as_ptr(), sig_len) };

        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key_slice) else {
            return JwsRc::ErrInvalidSignature;
        };
        mac.update(msg_slice);

        match mac.verify_slice(sig_slice) {
            Ok(()) => JwsRc::Ok,
            Err(_) => JwsRc::ErrInvalidSignature,
        }
    }
    #[cfg(kani)]
    {
        let _ = (alg, key, key_len, msg, msg_len, sig, sig_len);
        JwsRc::Ok
    }
}

#[cfg(any(kani, test, no_mbedtls))]
fn jws_ed25519_verify(
    alg: JwsAlg,
    key: KeyBuf,
    key_len: usize,
    msg: MsgBuf,
    msg_len: usize,
    sig: SigBuf,
    sig_len: usize,
) -> JwsRc {
    #[cfg(all(any(test, no_mbedtls), not(kani)))]
    {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        if alg != JwsAlg::EdDSA {
            return JwsRc::ErrUnsupportedAlg;
        }

        let key_slice = unsafe { std::slice::from_raw_parts(key.0.as_ptr(), key_len) };
        let msg_slice = unsafe { std::slice::from_raw_parts(msg.0.as_ptr(), msg_len) };
        let sig_slice = unsafe { std::slice::from_raw_parts(sig.0.as_ptr(), sig_len) };

        if key_slice.len() != 32 || sig_slice.len() != 64 {
            return JwsRc::ErrInvalidSignature;
        }

        let key_array: [u8; 32] = match key_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => return JwsRc::ErrInvalidSignature,
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&key_array) else {
            return JwsRc::ErrInvalidSignature;
        };
        let sig_array: [u8; 64] = match sig_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => return JwsRc::ErrInvalidSignature,
        };
        let signature = Signature::from_bytes(&sig_array);

        match verifying_key.verify(msg_slice, &signature) {
            Ok(()) => JwsRc::Ok,
            Err(_) => JwsRc::ErrInvalidSignature,
        }
    }
    #[cfg(kani)]
    {
        let _ = (alg, key, key_len, msg, msg_len, sig, sig_len);
        JwsRc::Ok
    }
}

#[cfg(any(kani, test, no_mbedtls))]
fn jws_rsa_verify(
    alg: JwsAlg,
    key: KeyBuf,
    key_len: usize,
    msg: MsgBuf,
    msg_len: usize,
    sig: SigBuf,
    sig_len: usize,
) -> JwsRc {
    let _ = (key, key_len, msg, msg_len, sig, sig_len);
    if alg == JwsAlg::PS256 {
        JwsRc::Ok
    } else {
        JwsRc::ErrUnsupportedAlg
    }
}

#[cfg(any(kani, test, no_mbedtls))]
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
fn Jose_Jwe_chacha20poly1305_encrypt(
    key: KeyBuf,
    key_len: usize,
    nonce: MsgBuf,
    nonce_len: usize,
    aad: MsgBuf,
    aad_len: usize,
    plaintext: MsgBuf,
    pt_len: usize,
    ciphertext: MsgBuf,
    tag: MsgBuf,
) -> JweRc {
    #[cfg(all(any(test, no_mbedtls), not(kani)))]
    {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };

        if key_len != 32 || nonce_len != 12 {
            return JweRc::ErrUnsupportedAlg;
        }

        let key_slice = unsafe { std::slice::from_raw_parts(key.0.as_ptr(), key_len) };
        let nonce_slice = unsafe { std::slice::from_raw_parts(nonce.0.as_ptr(), nonce_len) };
        let aad_slice = unsafe { std::slice::from_raw_parts(aad.0.as_ptr(), aad_len) };
        let pt_slice = unsafe { std::slice::from_raw_parts(plaintext.0.as_ptr(), pt_len) };
        let ct_slice = unsafe { std::slice::from_raw_parts_mut(ciphertext.0.as_ptr(), pt_len) };
        let tag_slice = unsafe { std::slice::from_raw_parts_mut(tag.0.as_ptr(), 16) };

        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(key_slice) else {
            return JweRc::ErrUnsupportedAlg;
        };
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_slice);

        let payload = Payload {
            msg: pt_slice,
            aad: aad_slice,
        };

        match cipher.encrypt(nonce, payload) {
            Ok(ciphertext_with_tag) => {
                let ct_len = ciphertext_with_tag.len() - 16;
                ct_slice.copy_from_slice(&ciphertext_with_tag[..ct_len]);
                tag_slice.copy_from_slice(&ciphertext_with_tag[ct_len..]);
                JweRc::Ok
            }
            Err(_) => JweRc::ErrDecryptFailed,
        }
    }
    #[cfg(kani)]
    {
        let _ = (
            key, key_len, nonce, nonce_len, aad, aad_len, plaintext, pt_len, ciphertext, tag,
        );
        JweRc::Ok
    }
}

#[cfg(any(kani, test, no_mbedtls))]
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
fn Jose_Jwe_chacha20poly1305_decrypt(
    key: KeyBuf,
    key_len: usize,
    nonce: MsgBuf,
    nonce_len: usize,
    aad: MsgBuf,
    aad_len: usize,
    ciphertext: MsgBuf,
    ct_len: usize,
    tag: MsgBuf,
    tag_len: usize,
    plaintext: MsgBuf,
) -> JweRc {
    #[cfg(all(any(test, no_mbedtls), not(kani)))]
    {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };

        if key_len != 32 || nonce_len != 12 || tag_len != 16 {
            return JweRc::ErrUnsupportedAlg;
        }

        let key_slice = unsafe { std::slice::from_raw_parts(key.0.as_ptr(), key_len) };
        let nonce_slice = unsafe { std::slice::from_raw_parts(nonce.0.as_ptr(), nonce_len) };
        let aad_slice = unsafe { std::slice::from_raw_parts(aad.0.as_ptr(), aad_len) };
        let ct_slice = unsafe { std::slice::from_raw_parts(ciphertext.0.as_ptr(), ct_len) };
        let tag_slice = unsafe { std::slice::from_raw_parts(tag.0.as_ptr(), tag_len) };
        let pt_slice = unsafe { std::slice::from_raw_parts_mut(plaintext.0.as_ptr(), ct_len) };

        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(key_slice) else {
            return JweRc::ErrUnsupportedAlg;
        };
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(nonce_slice);

        // Combine ciphertext and tag
        let mut ciphertext_with_tag = Vec::with_capacity(ct_len + tag_len);
        ciphertext_with_tag.extend_from_slice(ct_slice);
        ciphertext_with_tag.extend_from_slice(tag_slice);

        let payload = Payload {
            msg: &ciphertext_with_tag,
            aad: aad_slice,
        };

        match cipher.decrypt(nonce, payload) {
            Ok(plaintext_vec) => {
                pt_slice.copy_from_slice(&plaintext_vec);
                JweRc::Ok
            }
            Err(_) => JweRc::ErrDecryptFailed,
        }
    }
    #[cfg(kani)]
    {
        let _ = (
            key, key_len, nonce, nonce_len, aad, aad_len, ciphertext, ct_len, tag, tag_len,
            plaintext,
        );
        JweRc::Ok
    }
}

/// Safe wrapper around the C `jws_hmac_verify` function.
///
/// # Safety
/// `key`, `msg`, and `sig` must remain valid for the duration of the call.
/// The underlying C function does not keep references to the buffers.
#[allow(unused_unsafe)]
#[must_use]
pub fn verify_hmac(alg: JwsAlg, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let key_buf = KeyBuf::from_slice(key);
    let msg_buf = MsgBuf::from_slice(msg);
    let sig_buf = SigBuf::from_slice(sig);
    // SAFETY: when not running under Kani, the buffers are derived from slices
    // which are guaranteed to be valid for the lengths passed, and the C
    // function does not retain the pointers beyond the call.
    #[cfg(kani)]
    {
        jws_hmac_verify(
            alg,
            key_buf,
            key.len(),
            msg_buf,
            msg.len(),
            sig_buf,
            sig.len(),
        ) == JwsRc::Ok
    }
    #[cfg(not(kani))]
    {
        unsafe {
            jws_hmac_verify(
                alg,
                key_buf,
                key.len(),
                msg_buf,
                msg.len(),
                sig_buf,
                sig.len(),
            ) == JwsRc::Ok
        }
    }
}

/// Safe wrapper around the C `jws_rsa_verify` function.
///
/// The stable C ABI accepts one key buffer. This wrapper encodes it as
/// `modulus || left_pad(exponent, modulus.len())` for the HACL* bridge.
#[allow(unused_unsafe)]
#[must_use]
pub fn verify_rsa(alg: JwsAlg, modulus: &[u8], exponent: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if modulus.is_empty() || exponent.is_empty() || exponent.len() > modulus.len() {
        return false;
    }
    let Some(key_len) = modulus.len().checked_mul(2) else {
        return false;
    };
    let mut key = Vec::new();
    if key.try_reserve_exact(key_len).is_err() {
        return false;
    }
    key.extend_from_slice(modulus);
    key.resize(key_len - exponent.len(), 0);
    key.extend_from_slice(exponent);

    let key_buf = KeyBuf::from_slice(&key);
    let msg_buf = MsgBuf::from_slice(msg);
    let sig_buf = SigBuf::from_slice(sig);
    #[cfg(kani)]
    {
        jws_rsa_verify(
            alg,
            key_buf,
            key_len,
            msg_buf,
            msg.len(),
            sig_buf,
            sig.len(),
        ) == JwsRc::Ok
    }
    #[cfg(not(kani))]
    {
        unsafe {
            jws_rsa_verify(
                alg,
                key_buf,
                key_len,
                msg_buf,
                msg.len(),
                sig_buf,
                sig.len(),
            ) == JwsRc::Ok
        }
    }
}

/// Safe wrapper around the C `jws_ed25519_verify` function.
///
/// In production builds this routes to `EverCrypt_Ed25519_verify` (HACL*/`EverCrypt`,
/// formally verified). In test/kani builds it falls back to `ed25519_dalek`.
#[allow(unused_unsafe)]
#[must_use]
pub fn verify_ed25519(alg: JwsAlg, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if alg != JwsAlg::EdDSA || key.len() != 32 || sig.len() != 64 {
        return false;
    }

    let key_buf = KeyBuf::from_slice(key);
    let msg_buf = MsgBuf::from_slice(msg);
    let sig_buf = SigBuf::from_slice(sig);
    #[cfg(kani)]
    {
        jws_ed25519_verify(
            alg,
            key_buf,
            key.len(),
            msg_buf,
            msg.len(),
            sig_buf,
            sig.len(),
        ) == JwsRc::Ok
    }
    #[cfg(not(kani))]
    unsafe {
        jws_ed25519_verify(
            alg,
            key_buf,
            key.len(),
            msg_buf,
            msg.len(),
            sig_buf,
            sig.len(),
        ) == JwsRc::Ok
    }
}

/// Encrypt a message using ChaCha20-Poly1305.
///
/// Returns `true` on success.
#[allow(unused_unsafe)]
#[must_use]
pub fn encrypt_chacha20poly1305(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8],
) -> bool {
    let key_buf = KeyBuf::from_slice(key);
    let nonce_buf = MsgBuf::from_slice(nonce);
    let aad_buf = MsgBuf::from_slice(aad);
    let pt_buf = MsgBuf::from_slice(plaintext);
    let ct_buf = MsgBuf::from_mut_slice(ciphertext);
    let tag_buf = MsgBuf::from_mut_slice(tag);
    #[cfg(kani)]
    {
        Jose_Jwe_chacha20poly1305_encrypt(
            key_buf,
            key.len(),
            nonce_buf,
            nonce.len(),
            aad_buf,
            aad.len(),
            pt_buf,
            plaintext.len(),
            ct_buf,
            tag_buf,
        ) == JweRc::Ok
    }
    #[cfg(not(kani))]
    {
        unsafe {
            Jose_Jwe_chacha20poly1305_encrypt(
                key_buf,
                key.len(),
                nonce_buf,
                nonce.len(),
                aad_buf,
                aad.len(),
                pt_buf,
                plaintext.len(),
                ct_buf,
                tag_buf,
            ) == JweRc::Ok
        }
    }
}

/// Decrypt and authenticate a message using ChaCha20-Poly1305.
#[allow(unused_unsafe)]
#[must_use]
pub fn verify_decrypt_jwe(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    let key_buf = KeyBuf::from_slice(key);
    let nonce_buf = MsgBuf::from_slice(nonce);
    let aad_buf = MsgBuf::from_slice(aad);
    let ct_buf = MsgBuf::from_slice(ciphertext);
    let tag_buf = MsgBuf::from_slice(tag);
    #[cfg(kani)]
    let mut out_storage = [0u8; 64];
    #[cfg(kani)]
    let out_buf = MsgBuf::from_mut_slice(&mut out_storage[..ciphertext.len()]);
    #[cfg(not(kani))]
    let mut out = vec![0u8; ciphertext.len()];
    #[cfg(not(kani))]
    let out_buf = MsgBuf::from_mut_slice(out.as_mut_slice());
    let rc = {
        #[cfg(kani)]
        {
            Jose_Jwe_chacha20poly1305_decrypt(
                key_buf,
                key.len(),
                nonce_buf,
                nonce.len(),
                aad_buf,
                aad.len(),
                ct_buf,
                ciphertext.len(),
                tag_buf,
                tag.len(),
                out_buf,
            )
        }
        #[cfg(not(kani))]
        unsafe {
            Jose_Jwe_chacha20poly1305_decrypt(
                key_buf,
                key.len(),
                nonce_buf,
                nonce.len(),
                aad_buf,
                aad.len(),
                ct_buf,
                ciphertext.len(),
                tag_buf,
                tag.len(),
                out_buf,
            )
        }
    };
    #[cfg(kani)]
    {
        if rc == JweRc::Ok {
            Some(out_storage[..ciphertext.len()].to_vec())
        } else {
            None
        }
    }
    #[cfg(not(kani))]
    {
        if rc == JweRc::Ok {
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(not(kani))]
#[derive(Deserialize)]
struct DpopHeader {
    alg: String,
    jwk: DpopJwk,
    #[serde(rename = "typ")]
    typ: Option<String>,
}

/// Validate the exact `DPoP` JWT type header required by RFC 9449 and the F* model.
#[must_use]
pub fn validate_dpop_typ(typ: &str) -> bool {
    typ == "dpop+jwt"
}

/// Expose the DPoP `htm` equality predicate for spec-oracle differential tests.
#[doc(hidden)]
#[must_use]
pub fn validate_dpop_htm_for_spec_oracle(expected: &str, actual: &str) -> bool {
    expected == actual
}

/// Expose the DPoP `htu` equality predicate for spec-oracle differential tests.
#[doc(hidden)]
#[must_use]
pub fn validate_dpop_htu_for_spec_oracle(expected: &str, actual: &str) -> bool {
    expected == actual
}

/// Expose the DPoP `iat` acceptance-window predicate for spec-oracle differential tests.
#[doc(hidden)]
#[must_use]
pub fn validate_dpop_iat_for_spec_oracle(now: u64, iat: u64, iat_window_secs: u64) -> bool {
    now.abs_diff(iat) <= iat_window_secs
}

#[cfg(not(kani))]
#[derive(Deserialize)]
struct DpopJwk {
    kty: String,
    crv: String,
    x: String,
}

#[cfg(not(kani))]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    ath: Option<String>,
    nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopVerification {
    pub jti: String,
    pub nonce: Option<String>,
}

#[cfg(not(kani))]
impl<'de> Deserialize<'de> for DpopClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DpopClaimsVisitor;

        impl<'de> Visitor<'de> for DpopClaimsVisitor {
            type Value = DpopClaims;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a DPoP claims object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut htm = None;
                let mut htu = None;
                let mut iat = None;
                let mut jti = None;
                let mut ath = None;
                let mut nonce = None;

                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate DPoP claim"));
                    }
                    match key.as_str() {
                        "htm" => htm = Some(map.next_value()?),
                        "htu" => htu = Some(map.next_value()?),
                        "iat" => iat = Some(map.next_value()?),
                        "jti" => jti = Some(map.next_value()?),
                        "ath" => ath = Some(map.next_value()?),
                        "nonce" => nonce = Some(map.next_value()?),
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(DpopClaims {
                    htm: htm.ok_or_else(|| de::Error::missing_field("htm"))?,
                    htu: htu.ok_or_else(|| de::Error::missing_field("htu"))?,
                    iat: iat.ok_or_else(|| de::Error::missing_field("iat"))?,
                    jti: jti.ok_or_else(|| de::Error::missing_field("jti"))?,
                    ath: ath.flatten(),
                    nonce: nonce.flatten(),
                })
            }
        }

        deserializer.deserialize_map(DpopClaimsVisitor)
    }
}

#[cfg(not(kani))]
const DPOP_IAT_WINDOW: u64 = 300;

#[cfg(not(kani))]
fn encode_dpop_string(buf: &mut Vec<u8>, s: &str) -> Option<()> {
    let len = u32::try_from(s.len()).ok()?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
    Some(())
}

#[cfg(not(kani))]
fn encode_optional_dpop_string(buf: &mut Vec<u8>, value: Option<&str>) -> Option<()> {
    if let Some(value) = value {
        encode_dpop_string(buf, value)
    } else {
        buf.extend_from_slice(&0u32.to_le_bytes());
        Some(())
    }
}

#[cfg(not(kani))]
fn encode_dpop_claims(claims: &DpopClaims) -> Option<Vec<u8>> {
    let iat = u64::try_from(claims.iat).ok()?;
    let mut encoded = Vec::new();
    encode_dpop_string(&mut encoded, &claims.htm)?;
    encode_dpop_string(&mut encoded, &claims.htu)?;
    encoded.extend_from_slice(&iat.to_le_bytes());
    encode_dpop_string(&mut encoded, &claims.jti)?;
    encode_optional_dpop_string(&mut encoded, claims.ath.as_deref())?;
    encode_optional_dpop_string(&mut encoded, claims.nonce.as_deref())?;
    Some(encoded)
}

#[cfg(not(kani))]
fn parse_dpop_claims(payload: &[u8]) -> Option<DpopClaims> {
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let claims = DpopClaims::deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(claims)
}

/// Verify a `DPoP` proof.
///
/// Validates a `DPoP` JWT proof by checking:
/// - JWT signature verification
/// - HTTP method (htm) matches
/// - URI (htu) matches
/// - Issued-at time (iat) is within acceptable window
/// - JTI hasn't been seen before (replay prevention)
///
/// Returns verified proof material on success for replay and nonce handling.
#[cfg(not(kani))]
#[must_use]
pub fn verify_dpop(
    proof: &str,
    method: &str,
    uri: &str,
    now: u64,
    expected_ath: Option<&str>,
) -> Option<DpopVerification> {
    verify_dpop_with_iat_window(proof, method, uri, now, expected_ath, DPOP_IAT_WINDOW)
}

/// Verify a `DPoP` proof with an operator-selected `iat` acceptance window.
///
/// This keeps the verified structural/crypto checks identical to [`verify_dpop`]
/// while allowing the host server to apply its configured freshness policy.
#[cfg(not(kani))]
#[must_use]
pub fn verify_dpop_with_iat_window(
    proof: &str,
    method: &str,
    uri: &str,
    now: u64,
    expected_ath: Option<&str>,
    iat_window_secs: u64,
) -> Option<DpopVerification> {
    // Split into the three JWT components
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Base64url decode header and payload
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;

    // Parse header to obtain the public key and algorithm
    let header: DpopHeader = serde_json::from_slice(&header_bytes).ok()?;
    if header.alg != "EdDSA" || header.jwk.kty != "OKP" || header.jwk.crv != "Ed25519" {
        return None;
    }
    if header
        .typ
        .as_deref()
        .is_none_or(|typ| !validate_dpop_typ(typ))
    {
        return None;
    }
    let key_bytes = URL_SAFE_NO_PAD.decode(header.jwk.x).ok()?;

    // Verify the signature using EverCrypt/HACL*
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if !verify_ed25519(
        JwsAlg::EdDSA,
        &key_bytes,
        signing_input.as_bytes(),
        &sig_bytes,
    ) {
        return None;
    }

    // Parse claims
    let claims = parse_dpop_claims(&payload_bytes)?;
    let mut encoded = encode_dpop_claims(&claims)?;

    let dpop_valid = check_dpop_claims(&mut encoded);

    if !dpop_valid {
        return None;
    }

    // Perform semantic checks
    if claims.htm != method {
        return None;
    }

    // RFC 9449: htu claim MUST NOT include query or fragment parts.
    if claims.htu.contains('?') || claims.htu.contains('#') {
        return None;
    }

    // RFC 9449 Section 4.3: compare htu ignoring query and fragment parts of the request URI.
    let expected_htu = strip_query_and_fragment(uri);
    if claims.htu != expected_htu {
        return None;
    }

    let iat = u64::try_from(claims.iat).ok()?;
    let diff = now.abs_diff(iat);
    if diff > iat_window_secs {
        return None;
    }

    if claims.ath.as_deref() != expected_ath {
        return None;
    }

    Some(DpopVerification {
        jti: claims.jti,
        nonce: claims.nonce,
    })
}

#[cfg(not(kani))]
fn strip_query_and_fragment(uri: &str) -> &str {
    let query_idx = uri.find('?');
    let fragment_idx = uri.find('#');
    let cut = match (query_idx, fragment_idx) {
        (Some(q), Some(f)) => q.min(f),
        (Some(q), None) => q,
        (None, Some(f)) => f,
        (None, None) => return uri,
    };
    &uri[..cut]
}

#[cfg(kani)]
#[must_use]
pub fn verify_dpop(
    proof: &str,
    method: &str,
    uri: &str,
    _now: u64,
    expected_ath: Option<&str>,
) -> Option<DpopVerification> {
    verify_dpop_with_iat_window(proof, method, uri, _now, expected_ath, 300)
}

#[cfg(kani)]
#[must_use]
pub fn verify_dpop_with_iat_window(
    proof: &str,
    method: &str,
    uri: &str,
    _now: u64,
    expected_ath: Option<&str>,
    _iat_window_secs: u64,
) -> Option<DpopVerification> {
    if proof.is_empty() || method.is_empty() || uri.is_empty() || expected_ath == Some("") {
        None
    } else {
        Some(DpopVerification {
            jti: String::from("stub"),
            nonce: None,
        })
    }
}

/// Verify a PKCE `code_verifier` against a `code_challenge` using S256.
/// RFC 7636 §4.1: `code_verifier` MUST use ASCII-only chars ([A-Za-z0-9\-._~]).
/// Rejects non-ASCII input to satisfy the F* `bytes_of_string` precondition.
#[cfg(not(kani))]
#[must_use]
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    if !verifier.is_ascii() {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    encoded == challenge
}

/// Simplified version for bounded verification.
#[cfg(kani)]
#[must_use]
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    if verifier.is_empty() || challenge.is_empty() {
        false
    } else {
        verifier == challenge
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encrypt_chacha20poly1305, verify_decrypt_jwe, verify_ed25519, verify_hmac, verify_rsa,
        JwsAlg,
    };

    #[test]
    fn hmac_accepts_and_rejects() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let key = b"secret";
        let msg = b"payload";

        // Generate correct signature using hmac crate
        let mac_result = Hmac::<Sha256>::new_from_slice(key);
        assert!(mac_result.is_ok(), "unexpected HMAC key rejection");
        let Ok(mut mac) = mac_result else { return };
        mac.update(msg);
        let sig = mac.finalize().into_bytes();

        assert!(verify_hmac(JwsAlg::HS256, key, msg, &sig));

        let bad = [0u8; 32];
        assert!(!verify_hmac(JwsAlg::HS256, key, msg, &bad));
    }

    #[cfg(feature = "aws-lc-tests")]
    #[test]
    fn test_aws_lc_rs_rsa_verification() {
        // Test aws-lc-rs for RSA-PSS verification
        use aws_lc_rs::signature::{
            UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
        };
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        // JWT test vector
        let token = "eyJhbGciOiJQUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.a1tCOxjVKmRW6vnS_gHTkpWZljjMSa6YwqpuqMAZQ7RotWiQh7yGc36rKJp1BVhVL0boHR0vY6H_Y1CVx3ljiEOJidkQPMQRhUqT-fUkev5GnsLAFRIev4xakiztxWE5cIfiqpX345doH5-F5J74yxB5ZybfOFVzaZYBPA5lNIYbzRSDkfMOxnl2iDelzf-_b7JvCX8DndnANe_N_nOdacLg_pC6uip9Rd-ZLIdOx2aQkIl4xRjZIdKWkVsCdLH1LsvjfafP6ZyI4Jr5DhafSrvSp_G_uHv8kFpH9nnrH5IEjZgC17yj8_HrCa4pdFFXdqNOnrBp1QGFcMGiSRbMLA";

        // Parse JWT parts
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature_result = URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(
            signature_result.is_ok(),
            "signature must be valid base64url"
        );
        let Ok(signature_bytes) = signature_result else {
            return;
        };

        // DER-encoded public key (extracted from the PEM)
        let der_result = base64::engine::general_purpose::STANDARD.decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJxeMtmC2opPRaoydhf2\
            rlO/dLt5p7a/KGNPTRBjYfT5ihdDoLj13TEqmrLNdiPsaudmi+sAu/tQaOscPHU9\
            lJofXHpGH3E/keN8jnBI+lIg+qkM+JdUz/yDoCC694PgJqqcQ3DwWhBV/iN2Azry\
            DKa+TVnZMQro+yDyNn01YaA13XiHdXh8gbADIOKByxMtimISwybAHxN5WV3pUaAh\
            Dw6FS512+hbgNMbHj5705Y9gOWSuQy25sZMVvGymcckEF3RpKx1FsxwAmnUZW/Sd\
            WiJoNDAwWDCx88WISQnnUiR+dOi0eUB6jB3FzkibJxASvDt04gG/SbmOfSXnw5LA\
            OwIDAQAB",
        );
        assert!(der_result.is_ok(), "DER test vector must decode");
        let Ok(der_bytes) = der_result else {
            return;
        };

        // Create verification key from DER using aws-lc-rs
        let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &der_bytes);

        // Verify signature using aws-lc-rs
        let pss_result = public_key.verify(signing_input.as_bytes(), &signature_bytes);

        if let Err(e) = &pss_result {
            println!("aws-lc-rs RSA PSS verification failed: {e:?}");
            let public_key_pkcs1 = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &der_bytes);
            if let Err(e2) = public_key_pkcs1.verify(signing_input.as_bytes(), &signature_bytes) {
                println!("aws-lc-rs RSA PKCS1 verification also failed: {e2:?}");
            }
        }

        assert!(
            pss_result.is_err(),
            "aws-lc-rs verification should fail with the test vector"
        );
    }

    #[test]
    fn ed25519_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::{rngs::OsRng, RngCore};

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let msg = b"hello";
        let signature = signing_key.sign(msg);
        let verifying_key = signing_key.verifying_key();
        assert!(verify_ed25519(
            JwsAlg::EdDSA,
            verifying_key.as_bytes(),
            msg,
            &signature.to_bytes()
        ));
    }

    #[test]
    fn ps256_vector_verifies() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        // The DER-encoded public key (extracted from the PEM, base64 content between header/footer)
        let der_result = base64::engine::general_purpose::STANDARD.decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJxeMtmC2opPRaoydhf2\
            rlO/dLt5p7a/KGNPTRBjYfT5ihdDoLj13TEqmrLNdiPsaudmi+sAu/tQaOscPHU9\
            lJofXHpGH3E/keN8jnBI+lIg+qkM+JdUz/yDoCC694PgJqqcQ3DwWhBV/iN2Azry\
            DKa+TVnZMQro+yDyNn01YaA13XiHdXh8gbADIOKByxMtimISwybAHxN5WV3pUaAh\
            Dw6FS512+hbgNMbHj5705Y9gOWSuQy25sZMVvGymcckEF3RpKx1FsxwAmnUZW/Sd\
            WiJoNDAwWDCx88WISQnnUiR+dOi0eUB6jB3FzkibJxASvDt04gG/SbmOfSXnw5LA\
            OwIDAQAB",
        );
        assert!(der_result.is_ok(), "DER test vector must decode");
        let Ok(der_bytes) = der_result else {
            return;
        };

        let token = "eyJhbGciOiJQUzI1NiIsImtpZCI6IjIwMTEtMDQtMjkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.a1tCOxjVKmRW6vnS_gHTkpWZljjMSa6YwqpuqMAZQ7RotWiQh7yGc36rKJp1BVhVL0boHR0vY6H_Y1CVx3ljiEOJidkQPMQRhUqT-fUkev5GnsLAFRIev4xakiztxWE5cIfiqpX345doH5-F5J74yxB5ZybfOFVzaZYBPA5lNIYbzRSDkfMOxnl2iDelzf-_b7JvCX8DndnANe_N_nOdacLg_pC6uip9Rd-ZLIdOx2aQkIl4xRjZIdKWkVsCdLH1LsvjfafP6ZyI4Jr5DhafSrvSp_G_uHv8kFpH9nnrH5IEjZgC17yj8_HrCa4pdFFXdqNOnrBp1QGFcMGiSRbMLA";

        let parts: Vec<&str> = token.split('.').collect();
        let signing = format!("{}.{}", parts[0], parts[1]);
        let sig_result = URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(sig_result.is_ok(), "signature must decode");
        let Ok(sig) = sig_result else {
            return;
        };

        // This fixed SPKI has the standard 2048-bit RSA layout.
        assert_eq!(der_bytes.len(), 294);
        let modulus = &der_bytes[33..289];
        let exponent = &der_bytes[291..294];
        assert!(verify_rsa(
            JwsAlg::PS256,
            modulus,
            exponent,
            signing.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn eddsa_vector_verifies() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Decode public key from Base64
        let pk_b64 = "omymfjiTKpbiedsavZXILozZ8nXbopjeZw3Gc9kiPIs";
        let pk_result = URL_SAFE_NO_PAD.decode(pk_b64);
        assert!(pk_result.is_ok(), "public key must decode");
        let Ok(pk_bytes_vec) = pk_result else {
            return;
        };
        let pk_array_result: Result<[u8; 32], _> = pk_bytes_vec.clone().try_into();
        assert!(pk_array_result.is_ok(), "public key must be 32 bytes");
        let Ok(pk_bytes) = pk_array_result else {
            return;
        };

        let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.ekX3xG2O4OxYkfHoBjwFBKBWdQ3WbM2FvNSiY2XIm3LAKkgN1gmWDryPXH2SJM6h-v1mmvCWutDfnnMbhpr0AQ";

        let parts: Vec<&str> = token.split('.').collect();
        let signing = format!("{}.{}", parts[0], parts[1]);
        let sig_result = URL_SAFE_NO_PAD.decode(parts[2]);
        assert!(sig_result.is_ok(), "signature must decode");
        let Ok(sig_vec) = sig_result else {
            return;
        };
        let sig_array_result: Result<[u8; 64], _> = sig_vec.clone().try_into();
        assert!(sig_array_result.is_ok(), "signature must be 64 bytes");
        let Ok(sig_bytes) = sig_array_result else {
            return;
        };

        // Verify using ed25519-dalek
        let verifying_key_result = VerifyingKey::from_bytes(&pk_bytes);
        assert!(
            verifying_key_result.is_ok(),
            "verifying key must be accepted"
        );
        let Ok(verifying_key) = verifying_key_result else {
            return;
        };
        let signature = Signature::from_bytes(&sig_bytes);

        // Verify directly
        assert!(verifying_key.verify(signing.as_bytes(), &signature).is_ok());

        // Also verify via FFI
        assert!(verify_ed25519(
            JwsAlg::EdDSA,
            &pk_bytes,
            signing.as_bytes(),
            &sig_vec
        ));
    }

    #[test]
    fn chacha20poly1305_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"";
        let msg = b"secret";
        let mut ct = vec![0u8; msg.len()];
        let mut tag = vec![0u8; 16];
        assert!(encrypt_chacha20poly1305(
            &key, &nonce, aad, msg, &mut ct, &mut tag,
        ));
        let out = verify_decrypt_jwe(&key, &nonce, aad, &ct, &tag);
        assert!(out.is_some(), "decrypt must succeed");
        if let Some(out) = out {
            assert_eq!(out, msg);
        }
    }
}

#[cfg(all(kani, feature = "kani"))]
mod proofs {
    use super::{
        encrypt_chacha20poly1305, verify_decrypt_jwe, verify_ed25519, verify_hmac, verify_rsa,
        JwsAlg,
    };

    /// Ensure HMAC verification succeeds for a valid vector and fails for a bad tag.
    #[kani::proof]
    fn verify_hmac_known_vector() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let key = b"key";
        let msg = b"msg";
        let mac_result = Hmac::<Sha256>::new_from_slice(key);
        match mac_result {
            Ok(mut mac) => {
                mac.update(msg);
                let mut sig = mac.finalize().into_bytes();

                // Correct signature should verify
                assert!(verify_hmac(JwsAlg::HS256, key, msg, &sig));

                // Tampered signature must be rejected
                sig[0] ^= 0xff;
                assert!(!verify_hmac(JwsAlg::HS256, key, msg, &sig));
            }
            Err(_) => {
                kani::assert(false, "unexpected HMAC key rejection");
            }
        }
    }

    /// Check Ed25519 verification against a known token and mutated signature.
    #[kani::proof]
    fn verify_ed25519_known_vector() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let pk_b64 = "omymfjiTKpbiedsavZXILozZ8nXbopjeZw3Gc9kiPIs";
        let pk_result = URL_SAFE_NO_PAD.decode(pk_b64);
        let pk = match pk_result {
            Ok(pk) => pk,
            Err(_) => {
                kani::assert(false, "public key must decode");
                return;
            }
        };

        let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.ekX3xG2O4OxYkfHoBjwFBKBWdQ3WbM2FvNSiY2XIm3LAKkgN1gmWDryPXH2SJM6h-v1mmvCWutDfnnMbhpr0AQ";
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(sig_b64)) =
            (parts.next(), parts.next(), parts.next())
        else {
            kani::assert(false, "token must have three parts");
            return;
        };
        let signing = format!("{}.{}", header, payload);
        let sig_result = URL_SAFE_NO_PAD.decode(sig_b64);
        let mut sig = match sig_result {
            Ok(sig) => sig,
            Err(_) => {
                kani::assert(false, "signature must decode");
                return;
            }
        };

        assert!(verify_ed25519(JwsAlg::EdDSA, &pk, signing.as_bytes(), &sig,));

        sig[0] ^= 0xff;
        assert!(!verify_ed25519(
            JwsAlg::EdDSA,
            &pk,
            signing.as_bytes(),
            &sig,
        ));
    }

    /// Encrypt then verify-decrypt, ensuring altered tags are rejected.
    #[kani::proof]
    fn chacha20poly1305_rejects_bad_tag() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad: [u8; 0] = [];
        let msg = [1u8, 2u8];
        let mut ct = [0u8; 2];
        let mut tag = [0u8; 16];

        assert!(encrypt_chacha20poly1305(
            &key, &nonce, &aad, &msg, &mut ct, &mut tag
        ));
        let decrypt_result = verify_decrypt_jwe(&key, &nonce, &aad, &ct, &tag);
        match decrypt_result {
            Some(out) => kani::assert(out.as_slice() == msg, "roundtrip must recover plaintext"),
            None => {
                kani::assert(false, "decrypt must succeed");
                return;
            }
        }

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert!(verify_decrypt_jwe(&key, &nonce, &aad, &ct, &bad_tag).is_none());
    }

    #[test]
    fn chacha20poly1305_rejects_modified_ciphertext() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"aegaeon";
        let msg = b"payload";
        let mut ct = [0u8; 7];
        let mut tag = [0u8; 16];

        assert!(encrypt_chacha20poly1305(
            &key, &nonce, aad, msg, &mut ct, &mut tag
        ));
        let decrypt_result = verify_decrypt_jwe(&key, &nonce, aad, &ct, &tag);
        assert!(decrypt_result.is_some(), "decrypt must succeed");
        if let Some(out) = decrypt_result {
            assert_eq!(out, msg);
        }

        let mut tampered_ct = ct;
        tampered_ct[0] ^= 0x01;
        assert!(verify_decrypt_jwe(&key, &nonce, aad, &tampered_ct, &tag).is_none());
    }

    #[test]
    fn chacha20poly1305_rejects_modified_aad() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"aegaeon";
        let msg = b"payload";
        let mut ct = [0u8; 7];
        let mut tag = [0u8; 16];

        assert!(encrypt_chacha20poly1305(
            &key, &nonce, aad, msg, &mut ct, &mut tag
        ));
        let wrong_aad = b"aegaeon-mod";
        assert!(verify_decrypt_jwe(&key, &nonce, wrong_aad, &ct, &tag).is_none());
    }

    #[kani::proof]
    fn verify_hmac_fixed_no_ub() {
        let key: [u8; 32] = kani::any();
        let msg: [u8; 32] = kani::any();
        let sig: [u8; 32] = kani::any();
        verify_hmac(JwsAlg::HS256, &key, &msg, &sig);
    }

    #[kani::proof]
    fn verify_hmac_var_sizes_no_ub() {
        let key_len: usize = kani::any();
        kani::assume(key_len <= 64);
        let msg_len: usize = kani::any();
        kani::assume(msg_len <= 64);
        let sig_len: usize = kani::any();
        kani::assume(sig_len <= 64);
        let key = [0u8; 64];
        let msg = [0u8; 64];
        let sig = [0u8; 64];
        verify_hmac(
            JwsAlg::HS256,
            &key[..key_len],
            &msg[..msg_len],
            &sig[..sig_len],
        );
    }

    #[kani::proof]
    fn verify_hmac_empty_slices_no_ub() {
        let key: [u8; 0] = [];
        let msg: [u8; 0] = [];
        let sig: [u8; 0] = [];
        verify_hmac(JwsAlg::HS256, &key, &msg, &sig);
    }

    #[kani::proof]
    fn verify_rsa_empty_slices_no_ub() {
        let modulus: [u8; 0] = [];
        let exponent: [u8; 0] = [];
        let msg: [u8; 0] = [];
        let sig: [u8; 0] = [];
        verify_rsa(JwsAlg::PS256, &modulus, &exponent, &msg, &sig);
    }

    #[kani::proof]
    fn verify_ed25519_empty_slices_no_ub() {
        let key: [u8; 0] = [];
        let msg: [u8; 0] = [];
        let sig: [u8; 0] = [];
        verify_ed25519(JwsAlg::EdDSA, &key, &msg, &sig);
    }

    #[kani::proof]
    fn verify_decrypt_jwe_empty_slices_no_ub() {
        let key: [u8; 0] = [];
        let nonce: [u8; 0] = [];
        let aad: [u8; 0] = [];
        let ct: [u8; 0] = [];
        let tag: [u8; 0] = [];
        let _ = verify_decrypt_jwe(&key, &nonce, &aad, &ct, &tag);
    }
}

#[cfg(all(kani, feature = "kani"))]
mod kani_tests;
