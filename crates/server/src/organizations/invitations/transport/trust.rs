//! Independent per-origin trust. No endpoint or authorization is granted here.
use crate::organizations::store_observation::transport::certificate;
use reqwest::{Certificate, ClientBuilder};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    origin: String,
    root_cert: PathBuf,
}

#[derive(Clone, Default)]
pub(crate) struct Trust(BTreeMap<String, Vec<Certificate>>);

impl Trust {
    pub(crate) fn validate(inputs: &[Input]) -> Result<(), ()> {
        if inputs.len() > 8 {
            return Err(());
        }
        let mut origins = std::collections::BTreeSet::new();
        for input in inputs {
            let url = url::Url::parse(&input.origin).map_err(|_| ())?;
            if input.origin.len() > 2_048
                || url.scheme() != "https"
                || url.port_or_known_default() != Some(443)
                || !matches!(url.host(), Some(url::Host::Domain(h)) if h.contains('.') && !h.ends_with('.'))
                || url.origin().ascii_serialization() != input.origin
                || !input.root_cert.is_absolute()
                || input.root_cert.as_os_str().len() > 4_096
                || !origins.insert(&input.origin)
            {
                return Err(());
            }
        }
        Ok(())
    }

    pub(crate) fn load(inputs: &[Input]) -> Result<Self, ()> {
        Self::validate(inputs)?;
        let mut roots = BTreeMap::new();
        for input in inputs {
            let bytes = certificate(&input.root_cert).map_err(|_| ())?;
            if bytes.len() > 65_536 {
                return Err(());
            }
            let blocks = pem::parse_many(&bytes).map_err(|_| ())?;
            if blocks.is_empty() || blocks.iter().any(|block| block.tag() != "CERTIFICATE") {
                return Err(());
            }
            let mut store = rustls::RootCertStore::empty();
            let mut certs = Vec::new();
            for block in blocks {
                // Validate the DER before admission, not just the PEM envelope.
                store
                    .add(block.contents().to_vec().into())
                    .map_err(|_| ())?;
                certs.push(Certificate::from_der(block.contents()).map_err(|_| ())?);
            }
            roots.insert(input.origin.clone(), certs);
        }
        Ok(Self(roots))
    }

    pub(crate) fn configure(
        &self,
        builder: ClientBuilder,
        endpoint: &str,
    ) -> Result<ClientBuilder, ()> {
        let url = url::Url::parse(endpoint).map_err(|_| ())?;
        Ok(match self.0.get(&url.origin().ascii_serialization()) {
            Some(roots) => roots
                .iter()
                .fold(builder.tls_built_in_root_certs(false), |b, root| {
                    b.add_root_certificate(root.clone())
                }),
            None => builder,
        })
    }
}

#[cfg(test)]
mod tests;
