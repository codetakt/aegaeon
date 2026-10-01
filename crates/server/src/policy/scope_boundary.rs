//! Save-time ceilings. Callers serialize writes using the environment row lock.
use std::collections::BTreeMap;

use serde::Serialize;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::{client_credentials::ClientCredentialsPolicy, token_exchange::TokenExchangePolicy};

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScopeViolation {
    pub rule: String,
    pub client_id: String,
    pub target_audience: String,
    pub scope: String,
    pub reason: &'static str,
}

impl std::fmt::Display for ScopeViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: client {:?}, target {:?}, scope {:?}: {}",
            self.rule, self.client_id, self.target_audience, self.scope, self.reason
        )
    }
}

/// Check every rule, including scopes that are not defaults. Lookup is deliberately
/// supplied by the caller: a process-local registry is not save-time authority.
pub(crate) fn violations<'a>(
    exchange: &TokenExchangePolicy,
    credentials: &ClientCredentialsPolicy,
    mut lookup: impl FnMut(&str) -> Option<&'a [String]>,
    only_client: Option<&str>,
) -> Vec<ScopeViolation> {
    let mut result = Vec::new();
    let mut check = |rule: String, client: &str, target: &str, scopes: Vec<&str>| {
        if only_client.is_some_and(|id| id != client) {
            return;
        }
        let allowed = lookup(client);
        for scope in scopes {
            if !allowed.is_some_and(|allowed| allowed.iter().any(|value| value == scope)) {
                result.push(ScopeViolation {
                    rule: rule.clone(),
                    client_id: client.into(),
                    target_audience: target.into(),
                    scope: scope.into(),
                    reason: if allowed.is_some() {
                        "scope is outside client allowedScopes"
                    } else {
                        "client is not an active configuration member"
                    },
                });
            }
        }
    };
    for (index, rule) in exchange.rules.iter().enumerate() {
        check(
            format!("tokenExchange.rules[{index}]"),
            &rule.client_id,
            &rule.target_audience,
            rule.scopes
                .iter()
                .map(|scope| scope.target_scope.as_str())
                .collect(),
        );
    }
    for (index, rule) in credentials.rules.iter().enumerate() {
        check(
            format!("clientCredentials.rules[{index}]"),
            &rule.client_id,
            &rule.target_audience,
            rule.scopes.iter().map(String::as_str).collect(),
        );
    }
    result
}

/// The active memberships will be carried into the candidate configuration.
/// Include expired ACTIVE rows as well: expiry does not permit an invalid scope
/// ceiling to be saved, nor does this check restore runtime eligibility.
pub(crate) async fn policy_violations(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    active_version: Uuid,
    exchange: &TokenExchangePolicy,
    credentials: &ClientCredentialsPolicy,
) -> Result<Vec<ScopeViolation>, sqlx::Error> {
    let rows: Vec<(String, Vec<String>)> = sqlx::query_as(
        "SELECT client_identifier, allowed_scopes FROM aegaeon.clients
         WHERE environment_id=$1 AND configuration_version_id=$2 AND status='ACTIVE'",
    )
    .bind(environment)
    .bind(active_version)
    .fetch_all(&mut **tx)
    .await?;
    let clients: BTreeMap<_, _> = rows.into_iter().collect();
    Ok(violations(
        exchange,
        credentials,
        |id| clients.get(id).map(Vec::as_slice),
        None,
    ))
}

/// Used after DCR's environment lock, before any client/secret/token rotation.
pub(crate) async fn client_violations(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    client: &str,
    scopes: &[String],
) -> Result<Vec<ScopeViolation>, sqlx::Error> {
    let policy: sqlx::types::Json<crate::management::types::PolicyDocument> = sqlx::query_scalar(
        "SELECT v.configuration_document->'policy' FROM aegaeon.environments e
         JOIN aegaeon.configuration_versions v
           ON v.environment_id=e.id AND v.id=e.active_configuration_version_id
         WHERE e.id=$1",
    )
    .bind(environment)
    .fetch_one(&mut **tx)
    .await?;
    Ok(violations(
        &policy.token_exchange,
        &policy.client_credentials,
        |_| Some(scopes),
        Some(client),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_scope_is_checked_without_case_folding_or_default_filtering() {
        let exchange: TokenExchangePolicy = serde_json::from_value(serde_json::json!({
            "version":1,"targets":[],"rules":[{"clientId":"caller","sourceAudience":"source",
            "targetAudience":"target","scopes":[{"targetScope":"Read","sourceScopes":["read"]},
            {"targetScope":"write","sourceScopes":["write"]}],"defaultScopes":[]}]
        }))
        .unwrap();
        let credentials: ClientCredentialsPolicy = serde_json::from_value(serde_json::json!({
            "version":1,"resourceServers":[],"rules":[{"clientId":"other","targetAudience":"target",
            "scopes":["read"],"defaultScopes":[],"defaultTarget":false}]
        }))
        .unwrap();
        let allowed = vec!["read".to_owned()];
        let all = violations(
            &exchange,
            &credentials,
            |id| (id == "caller").then_some(allowed.as_slice()),
            None,
        );
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].scope, "Read");
        assert_eq!(all[1].scope, "write");
        assert_eq!(all[2].client_id, "other");
        assert_eq!(
            all[2].reason,
            "client is not an active configuration member"
        );
        let own = violations(&exchange, &credentials, |_| Some(&allowed), Some("caller"));
        assert_eq!(own, all[..2]);
        let expanded = vec!["Read".to_owned(), "write".to_owned()];
        assert!(
            violations(&exchange, &credentials, |_| Some(&expanded), Some("caller")).is_empty()
        );
    }
}
