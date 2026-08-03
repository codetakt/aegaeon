mod http;
mod transport;
mod types;
mod url_policy;

pub use http::HttpFederationFetcher;
pub use types::{
    FederationFetchFuture, FederationFetcher, FetchedEntityConfiguration,
    FetchedSubordinateStatement,
};
pub use url_policy::{
    entity_configuration_url, normalize_federation_outbound_allowed_domains,
    subordinate_statement_url, validate_entity_url,
};

#[cfg(test)]
pub(in crate::federation) use transport::ensure_fetch_status_success;
#[cfg(test)]
pub(in crate::federation) use url_policy::host_matches_allowlist;
