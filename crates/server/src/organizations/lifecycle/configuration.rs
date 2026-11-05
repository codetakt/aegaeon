//! Protected lifecycle input: selected DB, generation and fixed issuer registry.
use super::{Limits, Runtime, Selection};
use crate::organizations::{
    invitations::transport::trust::{Input, Trust},
    store_observation::transport,
    witness::Error,
};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    deployment_id: Uuid,
    generation: Uuid,
    primary: Primary,
    environments: Vec<Environment>,
    admission: Admission,
    #[serde(default)]
    delivery_trust: Vec<Input>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Primary {
    url: String,
    root_cert: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    id: Uuid,
    issuer: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    ordinary: u32,
    revocation: u32,
    snapshot: u32,
}

// Deliberately no Debug/Serialize: this includes endpoint credentials.
pub struct Configuration {
    document: Document,
}
impl Configuration {
    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&transport::certificate(path).map_err(|_| Error::Refused)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 1_048_576 {
            return Err(Error::Refused);
        }
        let document: Document = serde_json::from_slice(bytes).map_err(|_| Error::Refused)?;
        Selection::new(document.deployment_id, document.generation)?;
        if document.version != 2
            || document.primary.url.is_empty()
            || document.primary.url.len() > 16_384
            || !document.primary.root_cert.is_absolute()
            || document.primary.root_cert.as_os_str().len() > 4096
            || document.environments.is_empty()
            || document.environments.len() > 1024
            || !(1..=4096).contains(&document.admission.ordinary)
            || !(1..=64).contains(&document.admission.revocation)
            || !(1..=4).contains(&document.admission.snapshot)
        {
            return Err(Error::Refused);
        }
        Trust::validate(&document.delivery_trust).map_err(|_| Error::Refused)?;
        let mut ids = std::collections::BTreeSet::new();
        let mut issuers = std::collections::BTreeSet::new();
        for e in &document.environments {
            let url = url::Url::parse(&e.issuer).map_err(|_| Error::Refused)?;
            if e.id.is_nil()
                || e.issuer.len() > 16384
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !ids.insert(e.id)
                || !issuers.insert(url.to_string())
            {
                return Err(Error::Refused);
            }
        }
        Ok(Self { document })
    }
    pub fn selection(&self) -> Selection {
        Selection {
            deployment: self.document.deployment_id,
            generation: self.document.generation,
        }
    }
    pub(crate) fn startup_environment(&self, host: &str, primary: &str) -> Result<(Uuid, String)> {
        if primary != self.document.primary.url {
            return Err(Error::Refused);
        }
        let mut found = self.document.environments.iter().filter(|e| {
            url::Url::parse(&e.issuer)
                .is_ok_and(|url| &url[url::Position::BeforeHost..url::Position::AfterPort] == host)
        });
        let e = found.next().ok_or(Error::Refused)?;
        if found.next().is_some() {
            return Err(Error::Refused);
        }
        Ok((e.id, e.issuer.clone()))
    }
    pub(crate) fn delivery_trust(&self) -> Result<Trust> {
        Trust::load(&self.document.delivery_trust).map_err(|_| Error::Refused)
    }
    pub async fn connect(
        self,
        pool: PgPoolOptions,
        management_url: Option<&str>,
    ) -> Result<Arc<Runtime>> {
        let d = self.document;
        let ca = transport::certificate(&d.primary.root_cert).map_err(|_| Error::Refused)?;
        let management = management_url
            .map(|url| transport::postgres_options(url, &d.primary.root_cert, ca.clone()))
            .transpose()
            .map_err(|_| Error::Refused)?;
        let endpoint = transport::postgres_options(&d.primary.url, &d.primary.root_cert, ca)
            .map_err(|_| Error::Refused)?;
        Runtime::checked_with_management(
            Selection::new(d.deployment_id, d.generation)?,
            pool,
            endpoint,
            d.environments
                .into_iter()
                .map(|e| (e.id, e.issuer))
                .collect(),
            Limits {
                ordinary: d.admission.ordinary,
                revocation: d.admission.revocation,
                snapshot: d.admission.snapshot,
            },
            management,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> serde_json::Value {
        serde_json::json!({"version":2,"deployment_id":Uuid::new_v4(),"generation":Uuid::new_v4(),
            "primary":{"url":"postgresql://runtime:private@db.example/aegaeon?sslmode=verify-full","root_cert":"/protected/ca.pem"},
            "environments":[{"id":Uuid::new_v4(),"issuer":"https://issuer.example/"}],
            "admission":{"ordinary":2048,"revocation":16,"snapshot":1}})
    }
    #[test]
    fn lifecycle_configuration_requires_selected_current_database_only() {
        let doc = document();
        let parsed = Configuration::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(parsed
            .startup_environment("issuer.example", doc["primary"]["url"].as_str().unwrap())
            .is_ok());
        assert!(parsed
            .startup_environment("issuer.example", "postgresql://other")
            .is_err());
        assert!(parsed
            .startup_environment("foreign.example", doc["primary"]["url"].as_str().unwrap())
            .is_err());
        for field in ["control", "token", "selection"] {
            let mut bad = doc.clone();
            bad[field] = serde_json::json!({});
            assert!(Configuration::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
    #[test]
    fn lifecycle_configuration_refuses_ambiguous_unbounded_or_legacy_input() {
        let doc = document();
        for path in ["ordinary", "revocation", "snapshot"] {
            let mut bad = doc.clone();
            bad["admission"][path] = serde_json::json!(0);
            assert!(Configuration::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut bad = doc.clone();
        bad["version"] = serde_json::json!(1);
        assert!(Configuration::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = doc.clone();
        bad["environments"][0]["issuer"] = serde_json::json!("http://issuer.example/");
        assert!(Configuration::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = doc.clone();
        bad["environments"] = serde_json::json!([doc["environments"][0], doc["environments"][0]]);
        assert!(Configuration::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        assert!(Configuration::parse(&vec![b' '; 1_048_577]).is_err());
    }
}
