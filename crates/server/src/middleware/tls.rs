use crate::config::TransportSecurityConfig;
use crate::util;
use http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{info, warn};

mod fingerprint;
mod forwarded;

use fingerprint::strict_forwarded_client_cert;
pub use fingerprint::{
    extract_mtls_fingerprint, mtls_fingerprint_to_x5t_s256, normalize_forwarded_client_cert,
};
use forwarded::{extract_proto, rate_limit_subject, sanitize_header_value};

#[derive(Clone)]
pub struct TransportSecurity {
    cfg: Arc<TransportSecurityConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportRejectionKind {
    MissingRemoteAddr,
    UntrustedProxy,
    MissingForwardedHeader,
    MalformedForwardedHeader,
    InsecureProto,
    MtlsClientCertMissing,
}

#[derive(Debug)]
pub struct TransportRejection {
    pub kind: TransportRejectionKind,
}

impl TransportSecurity {
    #[must_use]
    pub fn new(cfg: TransportSecurityConfig) -> Self {
        Self { cfg: Arc::new(cfg) }
    }

    #[must_use]
    pub fn config(&self) -> Arc<TransportSecurityConfig> {
        self.cfg.clone()
    }

    /// # Errors
    ///
    /// Returns a [`TransportRejectionKind`] when proxy provenance, forwarded
    /// header validation, TLS indication, or required mTLS metadata checks fail.
    pub fn enforce(
        &self,
        remote: Option<SocketAddr>,
        headers: &HeaderMap,
    ) -> Result<(), TransportRejectionKind> {
        enforce(&self.cfg, remote, headers)
    }

    /// Return the rate-limit subject for a request after applying the transport boundary.
    ///
    /// When TLS-proxy enforcement is active and a standard `Forwarded` header is present, the
    /// nearest trusted proxy hop's `for=` value is used. Without `Forwarded`, callers fall back to
    /// the direct remote address so deployments that only assert `X-Forwarded-Proto` keep explicit
    /// proxy-level throttling rather than trusting non-standard client-IP headers.
    pub fn rate_limit_subject(
        &self,
        remote: Option<SocketAddr>,
        headers: &HeaderMap,
    ) -> Result<String, TransportRejectionKind> {
        rate_limit_subject(&self.cfg, remote, headers)
    }
}

fn enforce(
    cfg: &TransportSecurityConfig,
    remote: Option<SocketAddr>,
    headers: &HeaderMap,
) -> Result<(), TransportRejectionKind> {
    if !cfg.require_tls_proxy {
        return Ok(());
    }

    let remote_addr = remote.ok_or(TransportRejectionKind::MissingRemoteAddr)?;
    let remote_ip = remote_addr.ip();

    if !is_trusted_proxy(&cfg.trusted_proxies, &remote_ip) {
        warn!(
            target = "aegaeon.transport",
            %remote_ip,
            "rejecting request from untrusted proxy"
        );
        return Err(TransportRejectionKind::UntrustedProxy);
    }

    let proto = extract_proto(cfg, headers)?;
    if proto != "https" {
        warn!(
            target = "aegaeon.transport",
            %remote_ip,
            proto = proto.as_str(),
            "rejecting insecure proto"
        );
        return Err(TransportRejectionKind::InsecureProto);
    }

    if cfg.require_proxy_mtls {
        match strict_forwarded_client_cert(headers) {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                warn!(
                    target = "aegaeon.transport",
                    %remote_ip,
                    "rejecting request missing or invalid mTLS client certificate header"
                );
                return Err(TransportRejectionKind::MtlsClientCertMissing);
            }
        }
    }

    if cfg.log_forwarded_values {
        if let Some(value) = util::single_header_str(headers, "forwarded").ok().flatten() {
            info!(
                target = "aegaeon.transport",
                %remote_ip,
                forwarded = sanitize_header_value(value).as_str(),
                "accepted forwarded header"
            );
        } else if let Some(value) = util::single_header_str(headers, "x-forwarded-proto")
            .ok()
            .flatten()
        {
            info!(
                target = "aegaeon.transport",
                %remote_ip,
                proto = sanitize_header_value(value).as_str(),
                "accepted x-forwarded-proto header"
            );
        }
    }

    Ok(())
}

fn is_trusted_proxy(trusted: &[IpNet], remote: &IpAddr) -> bool {
    trusted.iter().any(|net| net.contains(remote))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportSecurityConfig;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn trusted_proxy_match() {
        let cfg = TransportSecurityConfig {
            trusted_proxies: vec![IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            require_tls_proxy: true,
            max_proxy_hops: 1,
            require_proxy_mtls: false,
            log_forwarded_values: false,
        };
        let headers = HeaderMap::new();
        assert!(enforce(&cfg, Some(([127, 0, 0, 1], 1234).into()), &headers).is_err());
    }
}
