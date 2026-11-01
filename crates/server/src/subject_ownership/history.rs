//! Shared strict history syntax and independently reproducible inventory hashing.

pub mod artifacts;
pub mod cli;
mod digest;
pub mod model;
mod pre_migration;
pub(crate) mod preflight;
mod strict_json;
mod validation;

pub use digest::{content_id, frame, sha256_hex, HashChain};
pub use strict_json::{parse_strict, HistoryInputError};

pub use validation::{parse_inventory, parse_manifest, validate_union};
