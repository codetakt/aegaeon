use crate::middleware::tls::normalize_forwarded_client_cert;
use crate::middleware::DpopBinding;

pub(super) struct ResourceSenderContext<'a> {
    pub(super) binding_jkt: Option<&'a str>,
    normalized_mtls: Option<String>,
    pub(super) mode_hint: String,
}

impl<'a> ResourceSenderContext<'a> {
    pub(super) fn from_request(
        binding: Option<&'a DpopBinding>,
        mtls_fingerprint: Option<&str>,
    ) -> Self {
        let binding_jkt = binding.map(|b| b.jkt.as_str());
        let normalized_mtls = mtls_fingerprint.and_then(normalize_forwarded_client_cert);
        let mode_hint = if binding_jkt.is_some() {
            "dpop"
        } else if normalized_mtls.is_some() {
            "mtls"
        } else {
            "bearer"
        }
        .to_string();

        Self {
            binding_jkt,
            normalized_mtls,
            mode_hint,
        }
    }

    pub(super) fn mtls_ref(&self) -> Option<&str> {
        self.normalized_mtls.as_deref()
    }
}
