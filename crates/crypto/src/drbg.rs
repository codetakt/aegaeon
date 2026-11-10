//! HMAC-SHA256 DRBG per NIST SP 800-90A Section 10.1.2.
//!
//! This Rust implementation mirrors the verified F* specification in
//! `fstar/crypto/Drbg.HmacSha256.fst`. The F* module verifies the construction
//! (output length, counter monotonicity, determinism). This module provides the
//! runtime implementation using the `hmac` and `sha2` crates.
//!
//! Restricted profile (matching F* spec):
//! - No nonce or `personalization_string` (seed = full `seed_material`).
//! - No `additional_input` (always empty in `generate`).
//! - Per-request instantiation (no state carried across requests).

use crate::mac::HmacSha256Key;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// SP 800-90A constants for HMAC-SHA256.
const OUTLEN: usize = 32;
const RESEED_LIMIT: u64 = 1 << 48;
pub const MAX_BYTES_PER_REQUEST: usize = 65536; // 2^19 bits = 2^16 bytes

/// DRBG state per SP 800-90A Section 10.1.2.
pub struct DrbgState {
    key: [u8; OUTLEN],
    v: [u8; OUTLEN],
    reseed_counter: u64,
}

impl Zeroize for DrbgState {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
        // The request counter is public metadata, not secret material.
    }
}

impl Drop for DrbgState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DrbgState {}

impl DrbgState {
    /// `HMAC_DRBG` Update per SP 800-90A Section 10.1.2.2.
    fn update(&mut self, provided_data: &[u8]) {
        // Step 1: K = HMAC(K, V || 0x00 || provided_data)
        let mac = HmacSha256Key::new(&self.key);
        let mut input = Zeroizing::new(Vec::with_capacity(OUTLEN + 1 + provided_data.len()));
        input.extend_from_slice(&self.v);
        input.push(0x00);
        input.extend_from_slice(provided_data);
        let new_key = mac.sign_guarded(&input);
        self.key.copy_from_slice(&new_key);

        // Step 2: V = HMAC(K_new, V)
        let mac = HmacSha256Key::new(&self.key);
        let new_v = mac.sign_guarded(&self.v);
        self.v.copy_from_slice(&new_v);

        // Steps 3-5: If provided_data is not empty, additional round with 0x01
        if !provided_data.is_empty() {
            let mac = HmacSha256Key::new(&self.key);
            let mut input = Zeroizing::new(Vec::with_capacity(OUTLEN + 1 + provided_data.len()));
            input.extend_from_slice(&self.v);
            input.push(0x01);
            input.extend_from_slice(provided_data);
            let new_key = mac.sign_guarded(&input);
            self.key.copy_from_slice(&new_key);

            let mac = HmacSha256Key::new(&self.key);
            let new_v = mac.sign_guarded(&self.v);
            self.v.copy_from_slice(&new_v);
        }
    }

    /// Instantiate: create DRBG state from 32-byte entropy seed.
    /// SP 800-90A Section 10.1.2.3.
    #[must_use]
    pub fn instantiate(seed: &[u8; 32]) -> Self {
        let mut state = DrbgState {
            key: [0x00; OUTLEN],
            v: [0x01; OUTLEN],
            reseed_counter: 0,
        };
        state.update(seed);
        state.reseed_counter = 1;
        state
    }

    /// Generate: produce `n` bytes of pseudorandom output.
    /// SP 800-90A Section 10.1.2.5.
    ///
    /// # Panics
    /// Panics if `n == 0`, `n > MAX_BYTES_PER_REQUEST`, or reseed limit exceeded.
    pub fn generate(&mut self, n: usize) -> Vec<u8> {
        let mut output = self.generate_guarded(n);
        // Preserve the public ownership-transfer API without another copy.
        std::mem::take(&mut *output)
    }

    fn generate_guarded(&mut self, n: usize) -> Zeroizing<Vec<u8>> {
        assert!(
            n > 0 && n <= MAX_BYTES_PER_REQUEST,
            "invalid request length"
        );
        assert!(self.reseed_counter <= RESEED_LIMIT, "reseed limit exceeded");

        let blocks_needed = n.div_ceil(OUTLEN);
        // Bounds above make the rounded capacity finite and prevent later
        // reallocation of the secret-bearing output buffer.
        let mut temp = Zeroizing::new(Vec::with_capacity(blocks_needed * OUTLEN));

        for _ in 0..blocks_needed {
            let mac = HmacSha256Key::new(&self.key);
            let new_v = mac.sign_guarded(&self.v);
            self.v.copy_from_slice(&new_v);
            temp.extend_from_slice(&self.v);
        }

        temp[n..].zeroize();
        temp.truncate(n);

        // Post-generation update with empty additional_input
        self.update(&[]);
        self.reseed_counter += 1;

        temp
    }

    /// Reseed: re-key state with fresh entropy.
    /// SP 800-90A Section 10.1.2.4.
    pub fn reseed(&mut self, entropy: &[u8; 32]) {
        self.update(entropy);
        self.reseed_counter = 1;
    }
}

/// Generate `n` random bytes using HMAC-SHA256 DRBG with OS entropy.
///
/// This is the primary entry point for the verified crypto profile.
/// Combines `getrandom` (entropy source) with the verified DRBG construction.
///
/// # Panics
///
/// Panics if the operating system RNG fails unexpectedly.
#[allow(clippy::expect_used)]
#[must_use]
pub fn drbg_random_bytes(n: usize) -> Vec<u8> {
    let mut output = drbg_random_bytes_guarded(n);
    std::mem::take(&mut *output)
}

#[allow(clippy::expect_used)]
pub(crate) fn drbg_random_bytes_guarded(n: usize) -> Zeroizing<Vec<u8>> {
    assert!(
        n > 0 && n <= MAX_BYTES_PER_REQUEST,
        "invalid request length"
    );
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).expect("system RNG failed");
    let mut state = DrbgState::instantiate(&seed);
    state.generate_guarded(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn guarded_partial_block_and_reseed_preserve_reference_sequence() {
        // Fixed, nonsecret seed. Values were independently derived using the
        // SP 800-90A restricted construction and Python's HMAC-SHA256 provider.
        let seed = std::array::from_fn(|index| index as u8);
        let mut state = DrbgState::instantiate(&seed);
        assert_eq!(
            hex(&state.generate_guarded(33)),
            "3226437dd9f98b17591aad731383303213439f64d029a5764e84e36256ddeb79e2"
        );
        assert_eq!(
            hex(&state.key),
            "3bdad94cbe8c360fa838d9447160999fc8bd9f83cc38a3e1f6a0e101868dade1"
        );
        assert_eq!(
            hex(&state.v),
            "3a801daf63121d24582d7e67773282a2a24de141e21b4cbd74b33d2b97cb3594"
        );
        assert_eq!(
            hex(&state.generate(32)),
            "8bec53ca34d241938d1dc9ae54c03b1fa39c05ed269fe1cfc3f16409513a308d"
        );
        assert_eq!(state.reseed_counter, 3);
        state.reseed(&[0xa5; 32]);
        assert_eq!(state.reseed_counter, 1);
        assert_eq!(
            hex(&state.generate_guarded(64)),
            concat!(
                "8d319dfabed726ca71e6781d26d843166206a3be8de619a3be4a722933eae75c5",
                "0c69c0b1d860c4b553df51c318c31672d55829cf7fd7b8e317cc930b2bff054"
            )
        );
        assert_eq!(state.reseed_counter, 2);
    }

    #[test]
    fn state_erasure_clears_secrets_and_preserves_public_counter() {
        fn requires_zeroizing_drop<T: ZeroizeOnDrop>() {}
        requires_zeroizing_drop::<DrbgState>();
        let mut state = DrbgState::instantiate(&[0x42; 32]);
        let _output = state.generate_guarded(32);
        assert_ne!(state.key, [0; OUTLEN]);
        assert_ne!(state.v, [0; OUTLEN]);
        let counter = state.reseed_counter;
        state.zeroize();
        assert_eq!(state.key, [0; OUTLEN]);
        assert_eq!(state.v, [0; OUTLEN]);
        assert_eq!(state.reseed_counter, counter);
        // Drop delegates to this same erase operation; this is not a claim
        // about copies in the provider, registers, or released memory.
    }

    #[test]
    fn invalid_guarded_request_preserves_live_state() {
        for length in [0, MAX_BYTES_PER_REQUEST + 1] {
            let mut state = DrbgState::instantiate(&[0x42; 32]);
            let before = (state.key, state.v, state.reseed_counter);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state.generate_guarded(length)
            }));
            assert!(result.is_err());
            assert_eq!((state.key, state.v, state.reseed_counter), before);
        }
    }

    #[test]
    fn instantiate_sets_counter() {
        let seed = [0x42u8; 32];
        let state = DrbgState::instantiate(&seed);
        assert_eq!(state.reseed_counter, 1);
    }

    #[test]
    fn generate_output_length() {
        let seed = [0x42u8; 32];
        let mut state = DrbgState::instantiate(&seed);
        for len in [1, 16, 32, 64, 100, 256] {
            let output = state.generate(len);
            assert_eq!(output.len(), len);
        }
    }

    #[test]
    fn generate_increments_counter() {
        let seed = [0x42u8; 32];
        let mut state = DrbgState::instantiate(&seed);
        assert_eq!(state.reseed_counter, 1);
        let _ = state.generate(32);
        assert_eq!(state.reseed_counter, 2);
        let _ = state.generate(32);
        assert_eq!(state.reseed_counter, 3);
    }

    #[test]
    fn deterministic_same_seed() {
        let seed = [0xABu8; 32];
        let mut state1 = DrbgState::instantiate(&seed);
        let mut state2 = DrbgState::instantiate(&seed);
        assert_eq!(state1.generate(64), state2.generate(64));
    }

    #[test]
    fn different_seeds_different_output() {
        let seed1 = [0xAAu8; 32];
        let seed2 = [0xBBu8; 32];
        let mut state1 = DrbgState::instantiate(&seed1);
        let mut state2 = DrbgState::instantiate(&seed2);
        assert_ne!(state1.generate(32), state2.generate(32));
    }

    #[test]
    fn reseed_resets_counter() {
        let seed = [0x42u8; 32];
        let mut state = DrbgState::instantiate(&seed);
        let _ = state.generate(32);
        assert_eq!(state.reseed_counter, 2);
        let new_entropy = [0x99u8; 32];
        state.reseed(&new_entropy);
        assert_eq!(state.reseed_counter, 1);
    }

    #[test]
    fn drbg_random_bytes_length() {
        let output = drbg_random_bytes(32);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn drbg_random_bytes_not_all_zero() {
        let output = drbg_random_bytes(32);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    #[should_panic(expected = "invalid request length")]
    fn generate_rejects_zero_length() {
        let seed = [0x42u8; 32];
        let mut state = DrbgState::instantiate(&seed);
        let _ = state.generate(0);
    }

    #[test]
    #[should_panic(expected = "invalid request length")]
    fn generate_rejects_too_large() {
        let seed = [0x42u8; 32];
        let mut state = DrbgState::instantiate(&seed);
        let _ = state.generate(MAX_BYTES_PER_REQUEST + 1);
    }
}
