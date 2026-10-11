use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub(crate) fn canonical_base64url_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    // Full chunks contain whole base64 quanta; the strict final decode also checks
    // unused trailing bits. Callers bound the enclosing token or response; this
    // check never allocates a decoded copy.
    let mut decoded = [0_u8; 768];
    segment
        .as_bytes()
        .chunks(1024)
        .all(|chunk| URL_SAFE_NO_PAD.decode_slice(chunk, &mut decoded).is_ok())
}
