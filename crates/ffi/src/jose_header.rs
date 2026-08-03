//! Low*/EverParse-backed validators for JOSE header micro-language entries.

use std::convert::TryFrom;

/// Errors that can occur when invoking the EverParse-generated validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoseHeaderEntryError {
    /// Input buffer length does not fit in `u32` expected by the C ABI.
    BufferTooLarge,
    /// The payload is truncated relative to the `EverParse` entry framing.
    Truncated,
    /// The payload failed `EverParse` schema validation.
    InvalidPayload,
    /// The native parser is not available in this build (e.g. tests, Kani, or
    /// no mbedtls support compiled in). Callers should fall back to Rust-only
    /// logic in this case.
    ParserUnavailable,
}

type ParseResult = Result<(), JoseHeaderEntryError>;

/// Validate a binary `jose_header_entry` buffer (see `fstar/lowparse/JoseHeader.3d`).
///
/// Note: this validates only the length-prefixed TLV *entry structure*:
/// `[key_len][key bytes][value_len][value bytes]`.
/// ASCII key policy, UTF-8 decoding, allow-listing, and whole-stream trailing
/// byte checks remain enforced in the handwritten TLV parser. The runtime path
/// goes through the extracted `Jose.HeaderParser.Runtime` bridge so the native
/// Rust/FFI entry validator exercises the same Low*/C surface that is compiled
/// into the JOSE extraction pipeline.
///
/// # Errors
///
/// Returns [`JoseHeaderEntryError`] when the input exceeds the C ABI size
/// limit, the native parser rejects the payload, or the native parser is
/// unavailable in this build.
pub fn check_jose_header_entry(bytes: &[u8]) -> ParseResult {
    let len = u32::try_from(bytes.len()).map_err(|_| JoseHeaderEntryError::BufferTooLarge)?;

    #[cfg(all(not(test), not(kani), not(no_mbedtls)))]
    unsafe {
        let ptr = bytes.as_ptr().cast_mut();
        match map_validation_status(Jose_HeaderParser_Runtime_validate_entry_buffer(ptr, len)) {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    #[cfg(any(test, kani, no_mbedtls))]
    {
        let _ = (len, bytes);
        Err(JoseHeaderEntryError::ParserUnavailable)
    }
}

#[cfg(any(test, all(not(kani), not(no_mbedtls))))]
const ENTRY_VALIDATOR_OK: u8 = 0;
#[cfg(any(test, all(not(kani), not(no_mbedtls))))]
const ENTRY_VALIDATOR_TRUNCATED: u8 = 1;
#[cfg(test)]
const ENTRY_VALIDATOR_FAILED: u8 = 2;

#[cfg(any(test, all(not(kani), not(no_mbedtls))))]
fn map_validation_status(status: u8) -> Option<JoseHeaderEntryError> {
    match status {
        ENTRY_VALIDATOR_OK => None,
        ENTRY_VALIDATOR_TRUNCATED => Some(JoseHeaderEntryError::Truncated),
        _ => Some(JoseHeaderEntryError::InvalidPayload),
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
extern "C" {
    fn Jose_HeaderParser_Runtime_validate_entry_buffer(base: *mut u8, len: u32) -> u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_status_maps_success_to_none() {
        assert_eq!(map_validation_status(ENTRY_VALIDATOR_OK), None);
    }

    #[test]
    fn validation_status_maps_truncated_to_truncated() {
        assert_eq!(
            map_validation_status(ENTRY_VALIDATOR_TRUNCATED),
            Some(JoseHeaderEntryError::Truncated)
        );
    }

    #[test]
    fn validation_status_maps_failed_to_invalid_payload() {
        assert_eq!(
            map_validation_status(ENTRY_VALIDATOR_FAILED),
            Some(JoseHeaderEntryError::InvalidPayload)
        );
    }

    #[test]
    fn validation_status_maps_unknown_values_to_invalid_payload() {
        assert_eq!(
            map_validation_status(255),
            Some(JoseHeaderEntryError::InvalidPayload)
        );
    }

    #[test]
    fn parser_unavailable_in_tests() {
        let payload = [0u8; 4];
        assert_eq!(
            check_jose_header_entry(&payload),
            Err(JoseHeaderEntryError::ParserUnavailable)
        );
    }

    #[test]
    fn buffer_too_large() {
        let huge = vec![0u8; (u32::MAX as usize) + 1];
        assert_eq!(
            check_jose_header_entry(&huge),
            Err(JoseHeaderEntryError::BufferTooLarge)
        );
    }
}
