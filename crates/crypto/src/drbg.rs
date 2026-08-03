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

impl DrbgState {
    /// `HMAC_DRBG` Update per SP 800-90A Section 10.1.2.2.
    fn update(&mut self, provided_data: &[u8]) {
        // Step 1: K = HMAC(K, V || 0x00 || provided_data)
        let mac = HmacSha256Key::new(&self.key);
        let mut input = Vec::with_capacity(OUTLEN + 1 + provided_data.len());
        input.extend_from_slice(&self.v);
        input.push(0x00);
        input.extend_from_slice(provided_data);
        let new_key = mac.sign(&input);
        self.key.copy_from_slice(&new_key);

        // Step 2: V = HMAC(K_new, V)
        let mac = HmacSha256Key::new(&self.key);
        let new_v = mac.sign(&self.v);
        self.v.copy_from_slice(&new_v);

        // Steps 3-5: If provided_data is not empty, additional round with 0x01
        if !provided_data.is_empty() {
            let mac = HmacSha256Key::new(&self.key);
            let mut input = Vec::with_capacity(OUTLEN + 1 + provided_data.len());
            input.extend_from_slice(&self.v);
            input.push(0x01);
            input.extend_from_slice(provided_data);
            let new_key = mac.sign(&input);
            self.key.copy_from_slice(&new_key);

            let mac = HmacSha256Key::new(&self.key);
            let new_v = mac.sign(&self.v);
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
        assert!(
            n > 0 && n <= MAX_BYTES_PER_REQUEST,
            "invalid request length"
        );
        assert!(self.reseed_counter <= RESEED_LIMIT, "reseed limit exceeded");

        let blocks_needed = n.div_ceil(OUTLEN);
        let mut temp = Vec::with_capacity(blocks_needed * OUTLEN);

        for _ in 0..blocks_needed {
            let mac = HmacSha256Key::new(&self.key);
            let new_v = mac.sign(&self.v);
            self.v.copy_from_slice(&new_v);
            temp.extend_from_slice(&self.v);
        }

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
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("system RNG failed");
    let mut state = DrbgState::instantiate(&seed);
    let output = state.generate(n);
    // Zeroize seed (defense in depth)
    seed.fill(0);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

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
