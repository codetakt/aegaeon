//! TLS crypto-provider initialization.
//!
//! Keep rustls provider selection in the crypto abstraction crate so production
//! crates do not call AWS-LC / ring provider APIs directly.

use std::sync::Once;

static RUSTLS_CRYPTO_PROVIDER: Once = Once::new();

/// Install the process-wide rustls crypto provider used by TLS clients.
pub fn install_rustls_crypto_provider() {
    RUSTLS_CRYPTO_PROVIDER.call_once(|| {
        let _already_installed = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
