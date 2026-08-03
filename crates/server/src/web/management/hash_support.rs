pub(super) fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    aegaeon_crypto::hash::sha256_digest(bytes)
}

pub(super) fn sha256_hex(data: &[u8]) -> String {
    aegaeon_crypto::hash::sha256_hex(data)
}
