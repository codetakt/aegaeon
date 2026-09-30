//! Length checks used by the real AEAD dispatch, before constructing raw buffers.
//!
//! Every `usize` is classified, including lengths the native u32 ABI cannot
//! represent. Rejection is an ordinary API result, not a caller precondition.

#[inline]
pub(crate) fn encrypt(
    key_len: usize,
    nonce_len: usize,
    aad_len: usize,
    plaintext_len: usize,
    ciphertext_capacity: usize,
    tag_capacity: usize,
    dispatch: impl FnOnce() -> bool,
) -> bool {
    if key_len != 32
        || nonce_len != 12
        || aad_len > u32::MAX as usize
        || plaintext_len > u32::MAX as usize
        || ciphertext_capacity < plaintext_len
        || tag_capacity < 16
    {
        return false;
    }
    dispatch()
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_native_length_limit_and_preserves_backend_result() {
        for backend_result in [false, true] {
            let mut dispatched = false;
            assert_eq!(
                super::encrypt(
                    32,
                    12,
                    u32::MAX as usize,
                    u32::MAX as usize,
                    u32::MAX as usize,
                    16,
                    || {
                        dispatched = true;
                        backend_result
                    },
                ),
                backend_result,
            );
            assert!(dispatched);
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_unrepresentable_lengths_without_dispatch() {
        // Check conversion boundaries without allocating multi-gigabyte slices.
        for len in [u32::MAX as usize + 1, usize::MAX] {
            for (aad_len, plaintext_len) in [(len, 0), (0, len), (len, len)] {
                assert!(!super::encrypt(
                    32,
                    12,
                    aad_len,
                    plaintext_len,
                    usize::MAX,
                    16,
                    || panic!("unsupported lengths reached the backend"),
                ));
            }
        }
    }
}
