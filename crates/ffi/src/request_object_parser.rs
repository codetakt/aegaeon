//! EverParse-backed validators for Request Object (JAR) canonical payloads.
//!
//! This module validates the *canonical binary encoding* derived from an
//! already-verified Request Object JWT. It does not parse raw JWT JSON. The
//! server can optionally enable this as defense-in-depth via environment gates.

use std::convert::TryFrom;

/// Errors that can occur when invoking the EverParse-generated validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestObjectParseError {
    /// Input buffer length does not fit in `u32` expected by the C ABI.
    BufferTooLarge,
    /// The payload failed `EverParse` schema validation.
    InvalidPayload,
    /// The native parser is not available in this build (e.g. tests, Kani, or
    /// no mbedtls support compiled in). Callers should fall back to Rust-only
    /// logic in this case.
    ParserUnavailable,
}

type ParseResult = Result<(), RequestObjectParseError>;

/// Validate a canonical `RequestObjectClaims` payload (see `RequestObjectSchema.3d`).
///
/// # Errors
///
/// Returns [`RequestObjectParseError`] when the input exceeds the C ABI size
/// limit, the native parser rejects the payload, or the native parser is
/// unavailable in this build.
pub fn check_request_object_claims(bytes: &[u8]) -> ParseResult {
    let len = u32::try_from(bytes.len()).map_err(|_| RequestObjectParseError::BufferTooLarge)?;

    #[cfg(all(not(test), not(kani), not(no_mbedtls)))]
    unsafe {
        let ptr = bytes.as_ptr().cast_mut();
        let ok = RequestObjectSchemaCheckRequestObjectClaimsEntry(ptr, len);
        if ok {
            Ok(())
        } else {
            Err(RequestObjectParseError::InvalidPayload)
        }
    }

    #[cfg(any(test, kani, no_mbedtls))]
    {
        let _ = (len, bytes);
        Err(RequestObjectParseError::ParserUnavailable)
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
extern "C" {
    fn RequestObjectSchemaCheckRequestObjectClaimsEntry(base: *mut u8, len: u32) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_unavailable_in_tests() {
        let payload = [0u8; 4];
        assert_eq!(
            check_request_object_claims(&payload),
            Err(RequestObjectParseError::ParserUnavailable)
        );
    }

    #[test]
    fn buffer_too_large() {
        let huge = vec![0u8; (u32::MAX as usize) + 1];
        assert_eq!(
            check_request_object_claims(&huge),
            Err(RequestObjectParseError::BufferTooLarge)
        );
    }
}
