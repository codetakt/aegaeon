// `ring` and `aws-lc-rs` currently pin different `untrusted` major versions.
// This crate intentionally hosts both until the upstream dependency graph converges.
#![allow(clippy::multiple_crate_versions)]

//! Unified crypto abstraction layer for Aegaeon.
//!
//! All crypto library calls (`sha2`, `ring`, `aws-lc-rs`, `p256`, `hmac`, `getrandom`)
//! are centralized here. Production crates depend on `aegaeon-crypto` instead of
//! using these libraries directly.

pub mod drbg;
pub mod error;
pub mod hash;
pub mod jwe;
pub mod mac;
pub mod rand;
pub mod signature;
pub mod signing;
pub mod tls;

pub use error::CryptoError;
