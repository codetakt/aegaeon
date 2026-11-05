//! Independently supplied deployment selection, never a database activation flag.
//! Parsing creates configuration only; live catalog/store admission still decides.
use super::super::{connector::Endpoint, Error, Result, Selection};
use super::{
    connector::Connector,
    dispatch::{valid_selection, Dispatcher, Environment},
    DeploymentId,
};
use crate::organizations::invitations::transport::trust::{Input, Trust};
use serde::Deserialize;
use std::{collections::BTreeSet, path::PathBuf};
use uuid::Uuid;

pub const MAX_CONFIGURATION_BYTES: usize = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    deployment_id: Uuid,
    selection: Selection,
    control: Transport,
    primary: Transport,
    token: Transport,
    environments: Vec<Child>,
    #[serde(default)]
    delivery_trust: Vec<Input>,
}

// Intentionally not Debug/Serialize: endpoint credentials never enter receipts/logs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transport {
    url: String,
    root_cert: PathBuf,
}

impl Transport {
    fn endpoint(&self) -> Endpoint<'_> {
        Endpoint {
            url: &self.url,
            root_cert: &self.root_cert,
        }
    }
    fn bounded(&self) -> bool {
        !self.url.is_empty()
            && self.url.len() <= 16_384
            && self.root_cert.is_absolute()
            && self.root_cert.as_os_str().len() <= 4_096
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Child {
    id: Uuid,
    issuer: String,
    selection: Selection,
}

/// Validated metadata; it cannot be used as an execution permit.
pub struct Configuration {
    document: Document,
}

mod cutover;

impl Configuration {
    /// Read one bounded regular file. FIFO/device inputs cannot block bootstrap.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = crate::organizations::store_observation::transport::certificate(path)
            .map_err(|_| Error::Refused)?;
        Self::parse(&bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIGURATION_BYTES {
            return Err(Error::Refused);
        }
        let document: Document = serde_json::from_slice(bytes).map_err(|_| Error::Refused)?;
        Trust::validate(&document.delivery_trust).map_err(|_| Error::Refused)?;
        if document.version != 1
            || document.deployment_id.is_nil()
            || !valid_selection(&document.selection)
            || document.environments.len() > 1_024
            || ![&document.control, &document.primary, &document.token]
                .iter()
                .all(|t| t.bounded())
        {
            return Err(Error::Refused);
        }
        let mut ids = BTreeSet::new();
        let mut issuers = BTreeSet::new();
        for child in &document.environments {
            let issuer = url::Url::parse(&child.issuer).map_err(|_| Error::Refused)?;
            if child.id.is_nil()
                || child.issuer.len() > 16_384
                || issuer.scheme() != "https"
                || issuer.host_str().is_none()
                || !issuer.username().is_empty()
                || issuer.password().is_some()
                || issuer.query().is_some()
                || issuer.fragment().is_some()
                || !valid_selection(&child.selection)
                || (child.selection.primary, child.selection.token_store)
                    != (document.selection.primary, document.selection.token_store)
                || !ids.insert(child.id)
                || !issuers.insert(issuer.to_string())
            {
                return Err(Error::Refused);
            }
        }
        Ok(Self { document })
    }

    /// Match the independently selected startup stores/issuer before network I/O.
    /// Byte equality deliberately refuses ambiguous alternate endpoint encodings.
    pub fn check_runtime(
        &self,
        environment: Uuid,
        issuer: &str,
        primary: &str,
        token: &str,
    ) -> Result<()> {
        if self.document.primary.url != primary
            || self.document.token.url != token
            || !self
                .document
                .environments
                .iter()
                .any(|child| child.id == environment && child.issuer == issuer)
        {
            return Err(Error::Refused);
        }
        Ok(())
    }

    /// Resolve the independent issuer-host selector before querying restored data.
    /// Multiple paths on the same host remain ambiguous and are refused.
    pub(crate) fn startup_environment(&self, issuer_host: &str) -> Result<(Uuid, String)> {
        let matches = self
            .document
            .environments
            .iter()
            .filter(|child| {
                url::Url::parse(&child.issuer).is_ok_and(|url| {
                    &url[url::Position::BeforeHost..url::Position::AfterPort] == issuer_host
                })
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [child] => Ok((child.id, child.issuer.clone())),
            _ => Err(Error::Refused),
        }
    }

    /// Freeze verified-TLS endpoints and trust roots. Still no network or activation.
    #[cfg(test)]
    pub(crate) fn delivery_trust(&self) -> Result<Trust> {
        Trust::load(&self.document.delivery_trust).map_err(|_| Error::Refused)
    }

    /// Freeze verified-TLS endpoints and trust roots. Still no network or activation.
    pub fn dispatcher(self) -> Result<Dispatcher> {
        let d = self.document;
        let connector = Connector::new(
            d.control.endpoint(),
            d.primary.endpoint(),
            d.token.endpoint(),
        )?;
        Dispatcher::new(
            connector,
            DeploymentId::new(d.deployment_id)?,
            d.selection,
            d.environments
                .into_iter()
                .map(|child| Environment {
                    id: child.id,
                    issuer: child.issuer,
                    selection: child.selection,
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests;
