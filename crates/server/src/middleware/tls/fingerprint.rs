use crate::util;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::HeaderMap;

/// Normalize values from `x-forwarded-client-cert` headers into `SHA256:<HEX>` form.
#[must_use]
pub fn normalize_forwarded_client_cert(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Some proxies emit `Hash=<alg>:<fingerprint>;Cert="<pem...>"`.
    let mut candidate = None;
    for part in trimmed.split(';') {
        let part_trim = part.trim();
        if let Some(rest) = part_trim.strip_prefix("Hash=") {
            candidate = Some(rest.trim_matches('"'));
            break;
        } else if let Some(rest) = part_trim.strip_prefix("hash=") {
            candidate = Some(rest.trim_matches('"'));
            break;
        }
    }

    let candidate = candidate.unwrap_or(trimmed);
    canonicalize_sha256_fingerprint(candidate)
}

/// Extract normalized SHA256 fingerprint directly from the request headers.
pub fn extract_mtls_fingerprint(headers: &HeaderMap) -> Option<String> {
    strict_forwarded_client_cert(headers).ok().flatten()
}

pub(super) fn strict_forwarded_client_cert(
    headers: &HeaderMap,
) -> Result<Option<String>, util::SingleHeaderError> {
    match util::single_header_str(headers, "x-forwarded-client-cert")? {
        Some(value) => normalize_forwarded_client_cert(value)
            .map(Some)
            .ok_or(util::SingleHeaderError::InvalidValue),
        None => Ok(None),
    }
}

/// Convert a normalized `SHA256:<HEX>` mTLS fingerprint into the RFC 8705 / RFC 7800
/// confirmation value (`x5t#S256`) as base64url(SHA-256(cert_der)).
#[must_use]
pub fn mtls_fingerprint_to_x5t_s256(fingerprint: &str) -> Option<String> {
    let normalized = normalize_forwarded_client_cert(fingerprint)?;
    let hex = normalized.strip_prefix("SHA256:")?;
    let bytes = decode_hex(hex)?;
    if bytes.len() != 32 {
        return None;
    }
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

fn canonicalize_sha256_fingerprint(input: &str) -> Option<String> {
    let value = input.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }

    let upper_no_ws: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if upper_no_ws.contains("BEGINCERTIFICATE") || upper_no_ws.contains("ENDCERTIFICATE") {
        return None;
    }

    let rest = if let Some(idx) = value.find(':') {
        let (head, tail) = value.split_at(idx);
        if head.eq_ignore_ascii_case("sha256") {
            &tail[1..]
        } else {
            value
        }
    } else {
        value
    };

    let hex: String = rest
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some(format!("SHA256:{hex}"))
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = decode_hex_nibble(bytes[idx])?;
        let lo = decode_hex_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Some(out)
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_forwarded_hash_entry() {
        let bytes: Vec<u8> = (0u8..32).collect();
        let hex_with_colons = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let header = format!(r#"Hash=sha256:{hex_with_colons};Cert="dummy""#);
        assert_eq!(
            normalize_forwarded_client_cert(&header),
            Some(format!(
                "SHA256:{}",
                bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
            ))
        );
    }

    #[test]
    fn normalize_forwarded_prefixed_value() {
        let hex = (0u8..32).map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            normalize_forwarded_client_cert(&format!("sha256:{hex}")),
            Some(format!("SHA256:{}", hex.to_ascii_uppercase()))
        );
    }

    #[test]
    fn normalize_forwarded_colon_hex() {
        let bytes: Vec<u8> = (0u8..32).collect();
        let hex_with_colons = bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            normalize_forwarded_client_cert(&hex_with_colons),
            Some(format!(
                "SHA256:{}",
                bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
            ))
        );
    }

    #[test]
    fn normalize_forwarded_rejects_pem() {
        assert_eq!(
            normalize_forwarded_client_cert("-----BEGIN CERTIFICATE-----"),
            None
        );
    }

    #[test]
    fn normalize_forwarded_rejects_short_digest() {
        assert_eq!(normalize_forwarded_client_cert("AA:BB:CC"), None);
        assert_eq!(normalize_forwarded_client_cert("sha256:abcdef"), None);
    }

    #[test]
    fn normalize_forwarded_rejects_non_hex_digest() {
        assert_eq!(
            normalize_forwarded_client_cert(
                "sha256:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1EZZ"
            ),
            None
        );
    }

    #[test]
    fn mtls_fingerprint_to_x5t_s256_converts_hex_to_base64url() -> Result<(), String> {
        let bytes: Vec<u8> = (0u8..32).collect();
        let hex_with_colons = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let header = format!("Hash=sha256:{hex_with_colons};Cert=\"dummy\"");

        let x5t = mtls_fingerprint_to_x5t_s256(&header)
            .ok_or_else(|| "valid test fixture should convert to x5t#S256".to_string())?;
        let expected = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(x5t, expected);
        Ok(())
    }
}
