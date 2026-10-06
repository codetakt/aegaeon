use super::super::{EntityStatement, FederationError, JwkSet};
use std::future::Future;
use std::pin::Pin;

pub type FederationFetchFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, FederationError>> + Send + 'a>>;

/// Trait for fetching and verifying federation metadata.
///
/// Implementations handle HTTP transport and JWS signature verification.
/// Trust-chain resolution requires compact JWS from both `*_with_jws` methods
/// and independently verifies the complete path using superior-endorsed keys.
/// Parsed statements are discovery inputs only; they do not authorize metadata.
pub trait FederationFetcher: Send + Sync {
    /// Fetch and verify a self-signed Entity Configuration from
    /// `{entity_id}/.well-known/openid-federation`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when transport, parsing, or signature verification fails.
    fn fetch_entity_configuration<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, EntityStatement>;

    /// Fetch and verify a self-signed Entity Configuration, retaining the raw JWS when the
    /// implementation has access to it.
    ///
    /// The default preserves source compatibility for decoded-only implementations.
    /// Such implementations cannot resolve trust chains: resolution explicitly fails
    /// when a compact JWS is missing. Override both JWS methods to support resolution.
    fn fetch_entity_configuration_with_jws<'a>(
        &'a self,
        entity_id: &'a str,
    ) -> FederationFetchFuture<'a, FetchedEntityConfiguration> {
        Box::pin(async move {
            self.fetch_entity_configuration(entity_id)
                .await
                .map(FetchedEntityConfiguration::without_jws)
        })
    }

    /// Fetch and verify a Subordinate Statement from the authority's
    /// fetch endpoint. The subordinate statement is verified against the
    /// authority's JWKS (`issuer_jwks`).
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when transport, parsing, or signature verification fails.
    fn fetch_subordinate_statement<'a>(
        &'a self,
        authority_entity_id: &'a str,
        authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, EntityStatement>;

    /// Fetch and verify a Subordinate Statement, retaining the raw JWS when available.
    fn fetch_subordinate_statement_with_jws<'a>(
        &'a self,
        authority_entity_id: &'a str,
        authority_config: &'a EntityStatement,
        subordinate_entity_id: &'a str,
        issuer_jwks: &'a JwkSet,
    ) -> FederationFetchFuture<'a, FetchedSubordinateStatement> {
        Box::pin(async move {
            self.fetch_subordinate_statement(
                authority_entity_id,
                authority_config,
                subordinate_entity_id,
                issuer_jwks,
            )
            .await
            .map(FetchedSubordinateStatement::without_jws)
        })
    }
}

/// Verified entity configuration plus optional raw JWS representation.
pub struct FetchedEntityConfiguration {
    pub statement: EntityStatement,
    pub entity_configuration_jws: Option<String>,
}

impl FetchedEntityConfiguration {
    #[must_use]
    pub fn without_jws(statement: EntityStatement) -> Self {
        Self {
            statement,
            entity_configuration_jws: None,
        }
    }

    #[must_use]
    pub fn with_jws(statement: EntityStatement, entity_configuration_jws: String) -> Self {
        Self {
            statement,
            entity_configuration_jws: Some(entity_configuration_jws),
        }
    }
}

/// Verified subordinate statement plus optional raw JWS representation.
pub struct FetchedSubordinateStatement {
    pub statement: EntityStatement,
    pub subordinate_statement_jws: Option<String>,
}

impl FetchedSubordinateStatement {
    #[must_use]
    pub fn without_jws(statement: EntityStatement) -> Self {
        Self {
            statement,
            subordinate_statement_jws: None,
        }
    }

    #[must_use]
    pub fn with_jws(statement: EntityStatement, subordinate_statement_jws: String) -> Self {
        Self {
            statement,
            subordinate_statement_jws: Some(subordinate_statement_jws),
        }
    }
}
