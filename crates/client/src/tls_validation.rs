use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

/// The workspace links rustls with both the `ring` (this crate) and `aws_lc_rs`
/// (`aegaeon-crypto`) provider features, so the process-level default provider is
/// ambiguous; every config builder here must pin the provider explicitly.
fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
use thiserror::Error;
use webpki_roots::TLS_SERVER_ROOTS;

/// Provides hardened TLS configuration for OAuth/OIDC clients.
#[derive(Clone)]
pub struct TlsValidator {
    root_store: RootCertStore,
}

#[derive(Debug, Error)]
pub enum TlsValidationError {
    #[error("failed to parse certificate: {0}")]
    CertificateParse(String),
    #[error("failed to load PEM material")]
    PemLoad,
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    #[error("handshake failure: {0}")]
    Handshake(String),
}

impl TlsValidator {
    /// Constructs a validator seeded with the Mozilla root store.
    ///
    /// # Errors
    ///
    /// Returns an error if future validator initialization adds fallible root-store setup steps.
    pub fn strict() -> Result<Self, TlsValidationError> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self { root_store })
    }

    /// Appends an additional root certificate in PEM format (PEM without surrounding whitespace).
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied PEM cannot be decoded or does not contain a valid root
    /// certificate.
    pub fn add_root_pem(mut self, pem: &str) -> Result<Self, TlsValidationError> {
        let mut reader = std::io::Cursor::new(pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TlsValidationError::PemLoad)?;
        if certs.is_empty() {
            return Err(TlsValidationError::PemLoad);
        }
        for cert in certs {
            self.root_store
                .add(cert)
                .map_err(|_| TlsValidationError::CertificateParse("invalid root".into()))?;
        }
        Ok(self)
    }

    /// Returns a rustls `ClientConfig` with the configured root store.
    ///
    /// # Errors
    ///
    /// Returns an error if the crypto provider cannot supply the safe default protocol versions.
    pub fn into_client_config(self) -> Result<ClientConfig, TlsValidationError> {
        Ok(ClientConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsValidationError::CertificateParse(format!("protocol versions: {e}")))?
            .with_root_certificates(self.root_store)
            .with_no_client_auth())
    }

    /// Establishes an in-memory TLS handshake against a provided server configuration.
    /// Intended for testing that the validator rejects bad certificates.
    ///
    /// # Errors
    ///
    /// Returns an error when the server name is invalid or the TLS handshake cannot be completed
    /// successfully.
    pub fn verify_handshake(
        &self,
        server_name: &str,
        server_config: rustls::ServerConfig,
    ) -> Result<(), TlsValidationError> {
        let config = ClientConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsValidationError::CertificateParse(format!("protocol versions: {e}")))?
            .with_root_certificates(self.root_store.clone())
            .with_no_client_auth();

        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| TlsValidationError::InvalidDnsName(server_name.to_string()))?;
        let mut client_conn = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|e| TlsValidationError::Handshake(format!("client connection failed: {e}")))?;
        let mut server_conn = rustls::ServerConnection::new(Arc::new(server_config))
            .map_err(|e| TlsValidationError::Handshake(format!("server connection failed: {e}")))?;
        drive_tls(&mut client_conn, &mut server_conn)?;
        Ok(())
    }
}

fn drive_tls(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Result<(), TlsValidationError> {
    use std::io::{Cursor, Read};

    let mut client_buffer = Vec::new();
    let mut server_buffer = Vec::new();

    loop {
        while client.wants_write() {
            client
                .write_tls(&mut client_buffer)
                .map_err(|e| TlsValidationError::Handshake(format!("client write failed: {e}")))?;
        }
        if !client_buffer.is_empty() {
            let mut reader = Cursor::new(client_buffer.clone());
            server
                .read_tls(&mut reader)
                .map_err(|e| TlsValidationError::Handshake(format!("server read failed: {e}")))?;
            client_buffer.clear();
            server.process_new_packets().map_err(|e| {
                TlsValidationError::Handshake(format!("server process failed: {e}"))
            })?;
        }

        while server.wants_write() {
            server
                .write_tls(&mut server_buffer)
                .map_err(|e| TlsValidationError::Handshake(format!("server write failed: {e}")))?;
        }
        if !server_buffer.is_empty() {
            let mut reader = Cursor::new(server_buffer.clone());
            client
                .read_tls(&mut reader)
                .map_err(|e| TlsValidationError::Handshake(format!("client read failed: {e}")))?;
            server_buffer.clear();
            client.process_new_packets().map_err(|e| {
                TlsValidationError::Handshake(format!("client process failed: {e}"))
            })?;
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }

        if !client.wants_write()
            && !server.wants_write()
            && client_buffer.is_empty()
            && server_buffer.is_empty()
        {
            return Err(TlsValidationError::Handshake(
                "TLS handshake stalled".to_string(),
            ));
        }
    }

    let mut sink = [0u8; 128];
    let _ = client.reader().read(&mut sink);
    let _ = server.reader().read(&mut sink);

    Ok(())
}

/// Helper used by tests to create a `rustls::ServerConfig` from PEM material.
///
/// # Errors
///
/// Returns an error when the provided certificate chain or private key cannot be used to build a
/// server configuration.
pub fn server_config_from_der(
    certs: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
) -> Result<rustls::ServerConfig, TlsValidationError> {
    let key = PrivatePkcs8KeyDer::from(key_der);
    let private = PrivateKeyDer::from(key);
    rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsValidationError::CertificateParse(format!("protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, private)
        .map_err(|e| TlsValidationError::CertificateParse(format!("server config error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Certificate, CertificateParams, DistinguishedName, IsCa, KeyUsagePurpose};
    use rustls::pki_types::CertificateDer;

    fn ca_certificate() -> Result<Certificate, rcgen::Error> {
        let mut params = CertificateParams::new(vec!["aegaeon.test".into()]);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name = DistinguishedName::new();
        Certificate::from_params(params)
    }

    fn server_certificate(
        ca: &Certificate,
        dns_name: &str,
    ) -> Result<(Certificate, Vec<u8>), rcgen::Error> {
        let mut params = CertificateParams::new(vec![dns_name.into()]);
        params.distinguished_name = DistinguishedName::new();
        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der_with_signer(ca)?;
        Ok((cert, cert_der))
    }

    fn convert_der(bytes: Vec<u8>) -> CertificateDer<'static> {
        CertificateDer::from(bytes)
    }

    #[test]
    fn handshake_succeeds_with_trusted_ca() -> Result<(), Box<dyn std::error::Error>> {
        let ca = ca_certificate()?;
        let (server_cert, server_der) = server_certificate(&ca, "api.aegaeon.test")?;
        let validator = TlsValidator::strict()?.add_root_pem(&ca.serialize_pem()?)?;
        let server_cfg = server_config_from_der(
            vec![convert_der(server_der)],
            server_cert.serialize_private_key_der(),
        )?;

        validator.verify_handshake("api.aegaeon.test", server_cfg)?;
        Ok(())
    }

    #[test]
    fn handshake_fails_for_wrong_host() -> Result<(), Box<dyn std::error::Error>> {
        let ca = ca_certificate()?;
        let (server_cert, server_der) = server_certificate(&ca, "auth.aegaeon.test")?;
        let validator = TlsValidator::strict()?.add_root_pem(&ca.serialize_pem()?)?;
        let server_cfg = server_config_from_der(
            vec![convert_der(server_der)],
            server_cert.serialize_private_key_der(),
        )?;

        let err = match validator.verify_handshake("api.aegaeon.test", server_cfg) {
            Ok(()) => return Err(std::io::Error::other("host mismatch should fail").into()),
            Err(err) => err,
        };
        assert!(matches!(err, TlsValidationError::Handshake(_)));
        Ok(())
    }

    #[test]
    fn handshake_fails_for_untrusted_ca() -> Result<(), Box<dyn std::error::Error>> {
        let ca = ca_certificate()?;
        let (server_cert, server_der) = server_certificate(&ca, "api.aegaeon.test")?;
        let validator = TlsValidator::strict()?;
        let server_cfg = server_config_from_der(
            vec![convert_der(server_der)],
            server_cert.serialize_private_key_der(),
        )?;

        let err = match validator.verify_handshake("api.aegaeon.test", server_cfg) {
            Ok(()) => return Err(std::io::Error::other("untrusted CA should fail").into()),
            Err(err) => err,
        };
        assert!(matches!(err, TlsValidationError::Handshake(_)));
        Ok(())
    }
}
