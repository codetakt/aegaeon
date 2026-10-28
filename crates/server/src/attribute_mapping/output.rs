//! OIDC adapter: validated recipient context and a single database observation.
use std::collections::{BTreeMap, BTreeSet};

use aegaeon_attribute_mapping::{
    Attribute, AttributeKey, AttributeValue, MappingError, MappingOutput, Recipient, Subject,
    Surface,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{
    configuration::standard_schema, load_attribute_sources, AttributeSourceRecord,
    AttributeStoreError, MappingConfiguration,
};

/// Adapter result serialized for the trusted authorization-code store.
/// Decoded JSON is not a source authentication mechanism or an authority grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcMappingSnapshot {
    issuer: String,
    oidc_subject: String,
    scopes: BTreeSet<String>,
    output: MappingOutput,
}

fn scope_for_claim(name: &str) -> Option<&'static str> {
    match name {
        "email" | "email_verified" => Some("email"),
        "phone_number" | "phone_number_verified" => Some("phone"),
        "address" => Some("address"),
        name if standard_schema(name).is_some() => Some("profile"),
        _ => None,
    }
}

impl OidcMappingSnapshot {
    /// Recheck the recipient, subject, scope and freshness at actual issuance.
    pub(crate) fn claims_for(
        &self,
        issuer: &str,
        subject: &str,
        client: &str,
        surface: &Surface,
        scopes: &BTreeSet<String>,
        now: i64,
    ) -> Result<BTreeMap<String, Value>, MappingError> {
        if self.issuer != issuer
            || self.oidc_subject != subject
            || self.output.recipient.client_id != client
            || self.output.recipient.surface != *surface
            || self.scopes != *scopes
        {
            return Err(MappingError::RecipientMismatch);
        }
        aegaeon_attribute_mapping::validate_encoded_size(
            self,
            aegaeon_attribute_mapping::MAX_OUTPUT_BYTES,
        )?;
        let reserved =
            BTreeSet::from([crate::application_authorization::inorii::CLAIM_NAME.to_string()]);
        for (name, claim) in &self.output.claims {
            if aegaeon_attribute_mapping::is_protocol_owned_claim(name, &reserved) {
                return Err(MappingError::ReservedClaim);
            }
            for source in &claim.sources {
                if source.provenance.observed_at > now {
                    return Err(MappingError::InvalidTime);
                }
                if source.provenance.expires_at.is_some_and(|end| end <= now) {
                    return Err(MappingError::Expired);
                }
            }
        }
        Ok(self
            .output
            .claims
            .iter()
            .map(|(name, claim)| (name.clone(), claim.value.clone()))
            .collect())
    }
}

pub(super) struct EvaluationContext<'a> {
    pub(super) revision: Uuid,
    pub(super) subject: Subject,
    pub(super) recipient: Recipient,
    pub(super) scopes: BTreeSet<String>,
    pub(super) issuer: &'a str,
    pub(super) oidc_subject: &'a str,
    pub(super) now: i64,
}

fn input_attributes(
    configuration: &MappingConfiguration,
    sources: &[AttributeSourceRecord],
    subject: &Subject,
    inputs: &BTreeSet<AttributeKey>,
    revision: Uuid,
    now: i64,
) -> Result<Vec<Attribute>, MappingError> {
    let mut attributes = Vec::new();
    for declaration in &configuration.sources {
        let record = sources
            .iter()
            .find(|record| record.namespace == declaration.namespace);
        if record.is_some_and(|record| record.provenance.kind != declaration.kind) {
            return Err(MappingError::InputDenied);
        }
        // The database observation establishes absence, not a provider assertion.
        // It remains transient and is never backfilled into a stored source row.
        let provenance = record.map_or_else(
            || aegaeon_attribute_mapping::Provenance {
                kind: aegaeon_attribute_mapping::SourceKind::Transient,
                authority: "storage:absence".into(),
                source_revision: revision.to_string(),
                observed_at: now,
                expires_at: None,
            },
            |record| record.provenance.clone(),
        );
        for field in &declaration.attributes {
            let key = AttributeKey {
                source: declaration.namespace.clone(),
                name: field.name.clone(),
            };
            if !inputs.contains(&key) {
                continue;
            }
            attributes.push(Attribute {
                key,
                owner: subject.clone(),
                value: record
                    .and_then(|record| record.values.get(&field.name))
                    .map_or(AttributeValue::Missing, |value| {
                        AttributeValue::Present(value.clone())
                    }),
                provenance: provenance.clone(),
                recipients: field
                    .recipients
                    .iter()
                    .map(|target| Recipient {
                        environment_id: subject.environment_id.clone(),
                        client_id: target.client_id.clone(),
                        surface: target.surface.clone(),
                    })
                    .collect(),
            });
        }
    }
    Ok(attributes)
}

pub(super) fn evaluate_snapshot(
    configuration: &MappingConfiguration,
    sources: &[AttributeSourceRecord],
    context: EvaluationContext<'_>,
) -> Result<OidcMappingSnapshot, MappingError> {
    let EvaluationContext {
        revision,
        subject,
        recipient,
        scopes,
        issuer,
        oidc_subject,
        now,
    } = context;
    configuration.validate()?;
    let definition = configuration.policies.iter().find(|policy| {
        policy.recipient.client_id == recipient.client_id
            && policy.recipient.surface == recipient.surface
    });
    // Once enabled, absence of a recipient policy releases no profile data.
    // Never fall back to the legacy output path for an unconfigured recipient.
    let mut output = MappingOutput {
        subject: subject.clone(),
        recipient: recipient.clone(),
        policy_revision: revision.to_string(),
        claims: BTreeMap::new(),
    };
    if let Some(definition) = definition {
        if definition.required_scopes.is_subset(&scopes) {
            let (mut policy, mut contract) =
                definition.bind(&subject.environment_id, &revision.to_string())?;
            policy
                .outputs
                .retain(|name, _| scope_for_claim(name).is_none_or(|scope| scopes.contains(scope)));
            policy
                .released_outputs
                .retain(|name| policy.outputs.contains_key(name));
            contract
                .fields
                .retain(|name, _| policy.outputs.contains_key(name));
            let attributes = input_attributes(
                configuration,
                sources,
                &subject,
                &policy.inputs,
                revision,
                now,
            )?;
            output = aegaeon_attribute_mapping::evaluate(
                &subject,
                &recipient,
                now,
                &attributes,
                &policy,
                &contract,
            )?;
            for (flag, value) in [
                ("email_verified", "email"),
                ("phone_number_verified", "phone_number"),
            ] {
                if output
                    .claims
                    .get(flag)
                    .is_some_and(|claim| claim.value == Value::Bool(true))
                    && !output.claims.contains_key(value)
                {
                    return Err(MappingError::OutputContract);
                }
            }
            if output
                .claims
                .get("updated_at")
                .is_some_and(|claim| claim.value.as_i64().is_none_or(|time| time < 0))
            {
                return Err(MappingError::OutputContract);
            }
        }
    }
    Ok(OidcMappingSnapshot {
        issuer: issuer.to_string(),
        oidc_subject: oidc_subject.to_string(),
        scopes,
        output,
    })
}

/// The caller has already authenticated the protocol recipient and subject.
/// Configuration, immutable owner and source rows are read in one RR snapshot.
/// `expected_revision` binds authorization to the configuration used for its
/// earlier client/profile observation. UserInfo selects the current snapshot.
pub(crate) async fn load_oidc_mapping(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
    client: &str,
    surface: Surface,
    scopes: BTreeSet<String>,
    expected_revision: Option<&crate::runtime_configuration::RuntimeAuthorityRevision>,
) -> Result<Option<OidcMappingSnapshot>, AttributeStoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query("SELECT environment_id, configuration_version_id, configuration_document, pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(configuration_document::text,pg_catalog.getdatabaseencoding())), 'hex') AS document_fingerprint, floor(extract(epoch FROM statement_timestamp()))::bigint AS observed_now FROM aegaeon.active_runtime_environments WHERE issuer_url = $1 LIMIT 2")
        .bind(issuer).fetch_all(&mut *tx).await?;
    let [row] = rows.as_slice() else {
        if rows.is_empty() && expected_revision.is_none() {
            tx.commit().await?;
            return Ok(None);
        }
        return Err(AttributeStoreError::InvalidData);
    };
    let revision: Uuid = row.try_get("configuration_version_id")?;
    let fingerprint: String = row.try_get("document_fingerprint")?;
    if expected_revision.is_some_and(|expected| {
        expected.active_configuration_version_id() != revision
            || expected.active_configuration_document_fingerprint() != fingerprint
    }) {
        return Err(AttributeStoreError::InvalidData);
    }
    let document: Value = row.try_get("configuration_document")?;
    let Some(mapping) = document.get("attributeMapping") else {
        tx.commit().await?;
        return Ok(None);
    };
    let configuration: MappingConfiguration =
        serde_json::from_value(mapping.clone()).map_err(|_| AttributeStoreError::InvalidData)?;
    configuration.validate()?;
    let environment: Uuid = row.try_get("environment_id")?;
    let user: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2 AND status='ACTIVE'")
        .bind(environment).bind(subject).fetch_optional(&mut *tx).await?;
    let user = user.ok_or(AttributeStoreError::OwnerNotFound)?;
    let sources = load_attribute_sources(&mut *tx, environment, user).await?;
    let snapshot = evaluate_snapshot(
        &configuration,
        &sources,
        EvaluationContext {
            revision,
            subject: Subject {
                environment_id: environment.to_string(),
                user_id: user.to_string(),
            },
            recipient: Recipient {
                environment_id: environment.to_string(),
                client_id: client.to_string(),
                surface,
            },
            scopes,
            issuer,
            oidc_subject: subject,
            now: row.try_get("observed_now")?,
        },
    )?;
    tx.commit().await?;
    Ok(Some(snapshot))
}
