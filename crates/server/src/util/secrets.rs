/// Constant-time byte-slice comparison to prevent timing side-channel attacks.
///
/// Returns `true` iff `a` and `b` have equal length and identical contents.
/// The comparison always processes both slices in full (no early exit on mismatch).
///
/// **Note:** The function does leak the *length* of the inputs (returns `false`
/// immediately when lengths differ). This is acceptable for OAuth client secrets
/// and PKCE challenges where the attacker cannot exploit length information.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[must_use]
pub fn secret_log_fingerprint(value: &str) -> String {
    aegaeon_crypto::hash::sha256_hex(value.as_bytes())
        .chars()
        .take(16)
        .collect()
}
