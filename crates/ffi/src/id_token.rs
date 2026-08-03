//! `EverParse`-backed validators for ID Token and `UserInfo` payloads.

use std::convert::TryFrom;

#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
use std::ffi::{c_char, CString};

#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
use std::slice;

/// Errors produced by the EverParse-generated ID Token parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdTokenParserError {
    /// The supplied buffer length exceeds the `u32` range expected by the C ABI.
    BufferTooLarge,
    /// The payload failed schema validation.
    InvalidPayload,
    /// The native parser is unavailable in this build (tests, Kani, or missing mbedtls).
    ParserUnavailable,
}

/// Errors raised by the Low* hash computation helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcHashError {
    /// The input buffer length exceeded the `u32` range expected by the Low* ABI.
    InputTooLarge,
    /// The algorithm string contains an interior null byte (`CString` conversion failure).
    InvalidAlgorithm,
    /// The Low* runtime is not available under this build configuration (tests, Kani, or missing mbedtls).
    Unavailable,
    /// The Low* helper reported a computation failure.
    ComputationFailed,
    /// The Low* helper returned a null digest pointer.
    NullDigest,
}

type ParseResult = Result<(), IdTokenParserError>;

/// Returns `true` when `b` is part of the base64url alphabet (RFC 7515 §2).
#[cfg(any(test, all(kani, feature = "kani"), feature = "everparse_idtoken"))]
fn is_base64url_char(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

/// Maximum per-segment size (header/payload/signature) accepted for canonical
/// JWT buffers. This keeps `EverParse` / downstream verification bounded even if
/// an RP feeds us an unusually large compact serialization.
#[cfg(any(test, all(kani, feature = "kani"), feature = "everparse_idtoken"))]
const MAX_JWT_SEGMENT_BYTES: usize = 4096;

#[cfg(any(test, all(kani, feature = "kani"), feature = "everparse_idtoken"))]
fn encode_len_prefixed_segment(
    out: &mut Vec<u8>,
    segment: &[u8],
) -> Result<(), IdTokenParserError> {
    let len = u32::try_from(segment.len()).map_err(|_| IdTokenParserError::BufferTooLarge)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(segment);
    Ok(())
}

/// Canonicalize a JWS Compact serialization into a length-prefixed buffer.
///
/// Invariants on success:
/// - Exactly three segments (header, payload, signature).
/// - Each segment is non-empty and contains base64url characters only.
/// - The returned buffer is `len||segment` concatenated three times, which is
///   the format consumed by the EverParse-generated `IdTokenSchema` parsers.
/// - This is the defining contract for `ParserKind::IdTokenJwt`: the F*/Low*
///   proofs assume that every ID Token coming from Rust obeys these structural
///   guards before any semantic verification takes place.
#[cfg(any(test, all(kani, feature = "kani"), feature = "everparse_idtoken"))]
fn split_compact_jwt_segments(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut first_dot = None;
    let mut second_dot = None;
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'.' {
            if first_dot.is_none() {
                first_dot = Some(index);
            } else if second_dot.is_none() {
                second_dot = Some(index);
            } else {
                return None;
            }
        }
        index += 1;
    }

    let first_dot = first_dot?;
    let second_dot = second_dot?;
    Some((
        &bytes[..first_dot],
        &bytes[first_dot + 1..second_dot],
        &bytes[second_dot + 1..],
    ))
}

#[cfg(any(test, all(kani, feature = "kani"), feature = "everparse_idtoken"))]
fn segment_is_valid_base64url(segment: &[u8]) -> bool {
    let mut index = 0;
    while index < segment.len() {
        if !is_base64url_char(segment[index]) {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(any(test, all(kani, feature = "kani"), feature = "everparse_idtoken"))]
fn build_canonical_jwt_buffer(bytes: &[u8]) -> Result<Vec<u8>, IdTokenParserError> {
    let (header, payload, signature) =
        split_compact_jwt_segments(bytes).ok_or(IdTokenParserError::InvalidPayload)?;

    for segment in [header, payload, signature] {
        if segment.is_empty()
            || segment.len() > MAX_JWT_SEGMENT_BYTES
            || !segment_is_valid_base64url(segment)
        {
            return Err(IdTokenParserError::InvalidPayload);
        }
    }

    let total_len =
        header.len() + payload.len() + signature.len() + (3 * std::mem::size_of::<u32>());
    let mut canonical = Vec::with_capacity(total_len);
    encode_len_prefixed_segment(&mut canonical, header)?;
    encode_len_prefixed_segment(&mut canonical, payload)?;
    encode_len_prefixed_segment(&mut canonical, signature)?;
    Ok(canonical)
}

/// Validate a binary `IDTokenClaims` payload (see `IdTokenSchema.3d`).
///
/// # Errors
///
/// Returns [`IdTokenParserError`] when the payload exceeds the C ABI size
/// limit, fails parser validation, or the native parser is unavailable.
pub fn check_id_token_claims(bytes: &[u8]) -> ParseResult {
    run_parser(ParserKind::IdTokenClaims, bytes)
}

/// Validate a binary `UserinfoResponse` payload.
///
/// # Errors
///
/// Returns [`IdTokenParserError`] under the same conditions as
/// [`check_id_token_claims`].
pub fn check_userinfo_response(bytes: &[u8]) -> ParseResult {
    run_parser(ParserKind::UserinfoResponse, bytes)
}

/// Validate a serialized `IDTokenJWT` payload (header + claims + signature framing).
///
/// # Errors
///
/// Returns [`IdTokenParserError`] under the same conditions as
/// [`check_id_token_claims`].
pub fn check_id_token_jwt(bytes: &[u8]) -> ParseResult {
    run_parser(ParserKind::IdTokenJwt, bytes)
}

#[derive(Clone, Copy)]
enum ParserKind {
    IdTokenClaims,
    UserinfoResponse,
    IdTokenJwt,
}

fn run_parser(kind: ParserKind, bytes: &[u8]) -> ParseResult {
    match kind {
        ParserKind::IdTokenJwt => run_jwt_parser(bytes),
        _ => run_native_parser(kind, bytes),
    }
}

fn run_jwt_parser(bytes: &[u8]) -> ParseResult {
    #[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "everparse_idtoken"))]
    {
        let mut canonical = build_canonical_jwt_buffer(bytes)?;
        let len = u32::try_from(canonical.len()).map_err(|_| IdTokenParserError::BufferTooLarge)?;
        let ok = unsafe { IdTokenSchemaCheckIdTokenJwtEntry(canonical.as_mut_ptr(), len) };
        if ok {
            Ok(())
        } else {
            Err(IdTokenParserError::InvalidPayload)
        }
    }

    #[cfg(not(all(not(test), not(kani), not(no_mbedtls), feature = "everparse_idtoken")))]
    {
        let _ = bytes;
        Err(IdTokenParserError::ParserUnavailable)
    }
}

fn run_native_parser(kind: ParserKind, bytes: &[u8]) -> ParseResult {
    let len = u32::try_from(bytes.len()).map_err(|_| IdTokenParserError::BufferTooLarge)?;

    #[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "everparse_idtoken"))]
    unsafe {
        let ptr = bytes.as_ptr().cast_mut();
        let ok = match kind {
            ParserKind::IdTokenClaims => IdTokenSchemaCheckIdTokenClaimsEntry(ptr, len),
            ParserKind::UserinfoResponse => IdTokenSchemaCheckUserinfoResponseEntry(ptr, len),
            ParserKind::IdTokenJwt => unreachable!("JWT parser uses the canonical buffer pathway"),
        };
        if ok {
            Ok(())
        } else {
            Err(IdTokenParserError::InvalidPayload)
        }
    }

    #[cfg(not(all(not(test), not(kani), not(no_mbedtls), feature = "everparse_idtoken")))]
    {
        let _ = (kind, len, bytes);
        Err(IdTokenParserError::ParserUnavailable)
    }
}

#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "everparse_idtoken"))]
extern "C" {
    fn IdTokenSchemaCheckIdTokenClaimsEntry(base: *mut u8, len: u32) -> bool;
    fn IdTokenSchemaCheckUserinfoResponseEntry(base: *mut u8, len: u32) -> bool;
    fn IdTokenSchemaCheckIdTokenJwtEntry(base: *mut u8, len: u32) -> bool;
}

#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
extern "C" {
    fn HashComputation_Low_compute_oidc_hash_bytes(
        alg: *const c_char,
        input: FStarBytesBytes,
    ) -> HashComputationLowHashResult;
    fn HashComputation_Low_free_bytes(bytes: FStarBytesBytes);
}

#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct HashComputationLowHashResult {
    status: u32,
    digest: FStarBytesBytes,
}

#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct FStarBytesBytes {
    length: u32,
    data: *const c_char,
}

#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
const HASH_STATUS_OK: u32 = 0;
#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
const HASH_STATUS_INVALID_ALGORITHM: u32 = 1;

/// Compute the OIDC hash bytes using the Low* helper when available.
///
/// # Errors
///
/// Returns an error when the helper is unavailable (tests/Kani/missing
/// mbedtls) or if the FFI bridge encounters malformed inputs.
#[cfg(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash"))]
pub fn compute_oidc_hash_bytes(alg: &str, input: &[u8]) -> Result<Vec<u8>, OidcHashError> {
    let length = u32::try_from(input.len()).map_err(|_| OidcHashError::InputTooLarge)?;
    let alg_c = CString::new(alg).map_err(|_| OidcHashError::InvalidAlgorithm)?;

    let input_bytes = FStarBytesBytes {
        length,
        data: input.as_ptr().cast::<c_char>(),
    };

    let result =
        unsafe { HashComputation_Low_compute_oidc_hash_bytes(alg_c.as_ptr(), input_bytes) };

    match result.status {
        HASH_STATUS_OK => {}
        HASH_STATUS_INVALID_ALGORITHM => {
            unsafe { HashComputation_Low_free_bytes(result.digest) };
            return Err(OidcHashError::InvalidAlgorithm);
        }
        _ => {
            unsafe { HashComputation_Low_free_bytes(result.digest) };
            return Err(OidcHashError::ComputationFailed);
        }
    }

    if result.digest.data.is_null() {
        unsafe { HashComputation_Low_free_bytes(result.digest) };
        return Err(OidcHashError::NullDigest);
    }

    let digest_slice = unsafe {
        slice::from_raw_parts(
            result.digest.data.cast::<u8>(),
            result.digest.length as usize,
        )
    };
    if digest_slice.is_empty() || digest_is_zero(digest_slice) {
        unsafe { HashComputation_Low_free_bytes(result.digest) };
        return Err(OidcHashError::ComputationFailed);
    }
    let output = digest_slice.to_vec();
    unsafe { HashComputation_Low_free_bytes(result.digest) };
    Ok(output)
}

#[cfg(not(all(not(test), not(kani), not(no_mbedtls), feature = "lowstar_hash")))]
/// Compute the OIDC hash bytes using the Low* helper when available.
///
/// # Errors
///
/// Always returns [`OidcHashError::Unavailable`] in configurations where the
/// Low* helper is not compiled in.
pub fn compute_oidc_hash_bytes(_alg: &str, _input: &[u8]) -> Result<Vec<u8>, OidcHashError> {
    Err(OidcHashError::Unavailable)
}

#[inline]
#[cfg(any(test, feature = "lowstar_hash"))]
fn digest_is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[cfg(all(kani, feature = "kani"))]
mod kani_verification {
    use super::*;

    #[kani::proof]
    #[kani::unwind(24)]
    fn oidc_id_token_jwt_canonicalisation_no_panic() {
        let choice: u8 = kani::any();
        kani::assume(choice < 6);

        let input: &[u8] = match choice {
            0 => b"AAA.BBB.CCC",
            1 => b"AA.BB",
            2 => b"AA.BB.",
            3 => b".AA.BB",
            4 => b"A=A.BB.CC",
            _ => b"AA-.BB_.CC0",
        };

        kani::assume(input.len() <= 11);

        let result = build_canonical_jwt_buffer(input);

        match choice {
            0 | 5 => {
                let canonical = match result {
                    Ok(canonical) => canonical,
                    Err(err) => {
                        let _ = err;
                        kani::assert(false, "unexpected canonicalisation error");
                        return;
                    }
                };

                // Two '.' separators are removed when splitting into segments.
                kani::assert(
                    canonical.len() == (3 * std::mem::size_of::<u32>()) + (input.len() - 2),
                    "canonical length mismatch",
                );

                // Length prefixes match the extracted segments.
                let header_len =
                    u32::from_le_bytes([canonical[0], canonical[1], canonical[2], canonical[3]])
                        as usize;
                let header_end = 4 + header_len;
                let payload_len = u32::from_le_bytes([
                    canonical[header_end],
                    canonical[header_end + 1],
                    canonical[header_end + 2],
                    canonical[header_end + 3],
                ]) as usize;
                let payload_end = header_end + 4 + payload_len;
                let signature_len = u32::from_le_bytes([
                    canonical[payload_end],
                    canonical[payload_end + 1],
                    canonical[payload_end + 2],
                    canonical[payload_end + 3],
                ]) as usize;

                kani::assert(header_len > 0, "header length must be non-zero");
                kani::assert(payload_len > 0, "payload length must be non-zero");
                kani::assert(signature_len > 0, "signature length must be non-zero");
                kani::assert(
                    payload_end + 4 + signature_len == canonical.len(),
                    "prefixes must cover entire buffer",
                );
            }
            _ => {
                kani::assert(
                    matches!(result, Err(IdTokenParserError::InvalidPayload)),
                    "invalid input should be rejected",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_zero_detection() {
        assert!(digest_is_zero(&[]));
        assert!(digest_is_zero(&[0, 0, 0]));
        assert!(!digest_is_zero(&[1, 0, 0]));
        assert!(!digest_is_zero(&[0, 0, 2]));
    }

    #[test]
    fn parser_unavailable_in_tests() {
        let payload = [0u8; 4];
        assert_eq!(
            check_id_token_claims(&payload),
            Err(IdTokenParserError::ParserUnavailable)
        );
        assert_eq!(
            check_userinfo_response(&payload),
            Err(IdTokenParserError::ParserUnavailable)
        );
        assert_eq!(
            check_id_token_jwt(&payload),
            Err(IdTokenParserError::ParserUnavailable)
        );
    }

    #[test]
    fn buffer_too_large() {
        let huge = vec![0u8; (u32::MAX as usize) + 1];
        assert_eq!(
            check_id_token_claims(&huge),
            Err(IdTokenParserError::BufferTooLarge)
        );
    }

    #[test]
    fn jwt_canonical_builder_happy_path() {
        let input = b"AAA.BBB.CCC";
        let result = build_canonical_jwt_buffer(input);
        assert!(
            result.is_ok(),
            "unexpected canonical buffer error: {result:?}"
        );
        if let Ok(canonical) = result {
            // len fields + payloads
            assert_eq!(canonical.len(), (3 * 4) + 9);
        }
    }

    #[test]
    fn jwt_canonical_builder_rejects_invalid_segments() {
        assert!(build_canonical_jwt_buffer(b"AA.BB").is_err());
        assert!(build_canonical_jwt_buffer(b"AA.BB.").is_err());
        assert!(build_canonical_jwt_buffer(b".AA.BB").is_err());
        assert!(build_canonical_jwt_buffer(b"A=A.BB.CC").is_err());
    }
}
