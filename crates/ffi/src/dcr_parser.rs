//! EverParse-backed validators for DCR payloads.

use std::convert::TryFrom;

/// Errors that can occur when invoking the EverParse-generated validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcrParseError {
    /// Input buffer length does not fit in `u32` expected by the C ABI.
    BufferTooLarge,
    /// The payload failed `EverParse` schema validation.
    InvalidPayload,
    /// The native parser is not available in this build (e.g. tests, Kani, or
    /// no mbedtls support compiled in). Callers should fall back to Rust-only
    /// logic in this case.
    ParserUnavailable,
}

type ParseResult = Result<(), DcrParseError>;

/// Validate a registration request payload.
///
/// # Errors
///
/// Returns [`DcrParseError`] when the input exceeds the C ABI length bound, the
/// `EverParse` validator rejects the payload, or the native parser is not
/// available in this build.
pub fn check_registration_request(bytes: &[u8]) -> ParseResult {
    run_parser(ParserKind::RegistrationRequest, bytes)
}

/// Validate a registration response payload.
///
/// # Errors
///
/// Returns [`DcrParseError`] under the same conditions as
/// [`check_registration_request`].
pub fn check_registration_response(bytes: &[u8]) -> ParseResult {
    run_parser(ParserKind::RegistrationResponse, bytes)
}

/// Validate an update request payload.
///
/// # Errors
///
/// Returns [`DcrParseError`] under the same conditions as
/// [`check_registration_request`].
pub fn check_update_request(bytes: &[u8]) -> ParseResult {
    run_parser(ParserKind::UpdateRequest, bytes)
}

/// Validate an error response payload.
///
/// # Errors
///
/// Returns [`DcrParseError`] under the same conditions as
/// [`check_registration_request`].
pub fn check_error_response(bytes: &[u8]) -> ParseResult {
    run_parser(ParserKind::ErrorResponse, bytes)
}

#[derive(Clone, Copy)]
enum ParserKind {
    RegistrationRequest,
    RegistrationResponse,
    UpdateRequest,
    ErrorResponse,
}

fn run_parser(kind: ParserKind, bytes: &[u8]) -> ParseResult {
    let len = u32::try_from(bytes.len()).map_err(|_| DcrParseError::BufferTooLarge)?;

    #[cfg(all(not(test), not(kani), not(no_mbedtls)))]
    unsafe {
        let ptr = bytes.as_ptr().cast_mut();
        let ok = match kind {
            ParserKind::RegistrationRequest => DcrCheckRegistrationRequest(ptr, len),
            ParserKind::RegistrationResponse => DcrCheckRegistrationResponse(ptr, len),
            ParserKind::UpdateRequest => DcrCheckUpdateRequest(ptr, len),
            ParserKind::ErrorResponse => DcrCheckErrorResponse(ptr, len),
        };
        if ok {
            Ok(())
        } else {
            Err(DcrParseError::InvalidPayload)
        }
    }

    #[cfg(any(test, kani, no_mbedtls))]
    {
        let _ = (kind, len, bytes);
        Err(DcrParseError::ParserUnavailable)
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls)))]
extern "C" {
    fn DcrCheckRegistrationRequest(base: *mut u8, len: u32) -> bool;
    fn DcrCheckRegistrationResponse(base: *mut u8, len: u32) -> bool;
    fn DcrCheckUpdateRequest(base: *mut u8, len: u32) -> bool;
    fn DcrCheckErrorResponse(base: *mut u8, len: u32) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_unavailable_in_tests() {
        let payload = [0u8; 4];
        assert_eq!(
            check_registration_request(&payload),
            Err(DcrParseError::ParserUnavailable)
        );
        assert_eq!(
            check_registration_response(&payload),
            Err(DcrParseError::ParserUnavailable)
        );
        assert_eq!(
            check_update_request(&payload),
            Err(DcrParseError::ParserUnavailable)
        );
        assert_eq!(
            check_error_response(&payload),
            Err(DcrParseError::ParserUnavailable)
        );
    }

    #[test]
    fn buffer_too_large() {
        let huge = vec![0u8; (u32::MAX as usize) + 1];
        assert_eq!(
            check_registration_request(&huge),
            Err(DcrParseError::BufferTooLarge)
        );
    }
}
