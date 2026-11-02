use aegaeon_attribute_mapping::{
    AttributeKey, Expression, FieldSchema, MappingError, MappingPolicy, OutputContract, Recipient,
    SourceKind, Surface, ValueSchema, MAX_COLLECTION_ITEMS,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MappingConfiguration {
    pub schema_version: u32,
    pub sources: Vec<SourceDefinition>,
    pub policies: Vec<PolicyDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceDefinition {
    /// `local`, or `connection:<immutable connection UUID>`.
    pub namespace: String,
    pub kind: SourceKind,
    pub attributes: Vec<AttributeDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttributeDefinition {
    pub name: String,
    pub recipients: Vec<RecipientSelector>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecipientSelector {
    pub client_id: String,
    pub surface: Surface,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyDefinition {
    pub recipient: RecipientSelector,
    pub inputs: BTreeSet<AttributeKey>,
    pub outputs: BTreeMap<String, Expression>,
    pub released_outputs: BTreeSet<String>,
    /// Additional claim schemas; standard OIDC claim schemas cannot be replaced.
    pub custom_schema: BTreeMap<String, FieldSchema>,
    pub required_scopes: BTreeSet<String>,
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn field(schema: ValueSchema) -> FieldSchema {
    FieldSchema {
        required: false,
        schema,
    }
}

pub(super) fn standard_schema(name: &str) -> Option<ValueSchema> {
    match name {
        "name" | "given_name" | "family_name" | "middle_name" | "nickname"
        | "preferred_username" | "profile" | "picture" | "website" | "email" | "gender"
        | "birthdate" | "zoneinfo" | "locale" | "phone_number" => Some(ValueSchema::String),
        "email_verified" | "phone_number_verified" => Some(ValueSchema::Boolean),
        "updated_at" => Some(ValueSchema::Integer),
        "address" => Some(ValueSchema::Object {
            properties: [
                "formatted",
                "street_address",
                "locality",
                "region",
                "postal_code",
                "country",
            ]
            .into_iter()
            .map(|name| {
                (
                    name.to_string(),
                    FieldSchema {
                        required: false,
                        schema: ValueSchema::String,
                    },
                )
            })
            .collect(),
        }),
        _ => None,
    }
}

impl PolicyDefinition {
    /// Produce a policy bound to the actual environment and configuration revision.
    /// These identifiers are supplied by the runtime loader, not the document.
    ///
    /// # Errors
    /// Rejects unsupported surfaces, replaced standard schemas and invalid mappings.
    pub fn bind(
        &self,
        environment: &str,
        revision: &str,
    ) -> Result<(MappingPolicy, OutputContract), MappingError> {
        if !matches!(self.recipient.surface, Surface::IdToken | Surface::Userinfo) {
            return Err(MappingError::OutputContract);
        }
        if self.required_scopes.len() > MAX_COLLECTION_ITEMS {
            return Err(MappingError::ResourceLimit);
        }
        if self
            .required_scopes
            .iter()
            .any(|scope| !crate::oauth_scope::is_scope_token(scope))
        {
            return Err(MappingError::Identifier);
        }
        for (flag, value) in [
            ("email_verified", "email"),
            ("phone_number_verified", "phone_number"),
        ] {
            if let Some(expression) = self.outputs.get(flag) {
                match expression {
                    Expression::Literal {
                        value: serde_json::Value::Bool(false),
                    } => {}
                    Expression::Read { attribute, path }
                        if attribute.name == flag
                            && path.is_empty()
                            && attribute.source.starts_with("connection:") =>
                    {
                        match self.outputs.get(value) {
                            Some(Expression::Read {
                                attribute: paired,
                                path,
                            }) if paired.name == value
                                && paired.source == attribute.source
                                && path.is_empty() => {}
                            _ => return Err(MappingError::OutputContract),
                        }
                    }
                    _ => return Err(MappingError::OutputContract),
                }
            }
        }
        let mut fields = self.custom_schema.clone();
        if fields.keys().any(|name| standard_schema(name).is_some()) {
            return Err(MappingError::OutputContract);
        }
        for name in self.outputs.keys() {
            if let Some(schema) = standard_schema(name) {
                fields.insert(name.clone(), field(schema));
            }
        }
        let policy = MappingPolicy {
            schema_version: 1,
            revision: revision.to_string(),
            recipient: Recipient {
                environment_id: environment.to_string(),
                client_id: self.recipient.client_id.clone(),
                surface: self.recipient.surface.clone(),
            },
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            released_outputs: self.released_outputs.clone(),
        };
        let contract = OutputContract {
            fields,
            additional_reserved_names: BTreeSet::from([
                crate::application_authorization::inorii::CLAIM_NAME.to_string(),
            ]),
        };
        policy.validate(&contract)?;
        Ok((policy, contract))
    }
}

impl MappingConfiguration {
    /// Validate the complete configuration at both management admission and load.
    ///
    /// # Errors
    /// Returns an error for ambiguous selectors, invalid source declarations,
    /// undeclared inputs, resource limits, or invalid policy/output contracts.
    pub fn validate(&self) -> Result<(), MappingError> {
        aegaeon_attribute_mapping::validate_encoded_size(self, 262_144)?;
        if self.schema_version != 1 {
            return Err(MappingError::SchemaVersion);
        }
        if self.sources.len() > MAX_COLLECTION_ITEMS || self.policies.len() > MAX_COLLECTION_ITEMS {
            return Err(MappingError::ResourceLimit);
        }
        let mut declared = BTreeSet::new();
        let mut source_names = BTreeSet::new();
        let mut total_attributes = 0;
        for source in &self.sources {
            if !source_names.insert(&source.namespace) {
                return Err(MappingError::DuplicateAttribute);
            }
            match source.kind {
                SourceKind::Local if source.namespace == "local" => {}
                SourceKind::External
                    if source
                        .namespace
                        .strip_prefix("connection:")
                        .is_some_and(|id| {
                            uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id)
                        }) => {}
                _ => return Err(MappingError::Identifier),
            }
            total_attributes += source.attributes.len();
            if total_attributes > MAX_COLLECTION_ITEMS {
                return Err(MappingError::ResourceLimit);
            }
            for attribute in &source.attributes {
                if !valid_identifier(&attribute.name) {
                    return Err(MappingError::Identifier);
                }
                if !declared.insert(AttributeKey {
                    source: source.namespace.clone(),
                    name: attribute.name.clone(),
                }) {
                    return Err(MappingError::DuplicateAttribute);
                }
                if attribute.recipients.len() > MAX_COLLECTION_ITEMS {
                    return Err(MappingError::ResourceLimit);
                }
                let mut recipients = BTreeSet::new();
                for recipient in &attribute.recipients {
                    if !valid_identifier(&recipient.client_id)
                        || !matches!(recipient.surface, Surface::IdToken | Surface::Userinfo)
                        || !recipients.insert(recipient)
                    {
                        return Err(MappingError::RecipientMismatch);
                    }
                }
            }
        }
        let mut selectors = BTreeSet::new();
        for policy in &self.policies {
            if !selectors.insert(&policy.recipient) {
                return Err(MappingError::RecipientMismatch);
            }
            if !policy.inputs.is_subset(&declared) {
                return Err(MappingError::UnknownAttribute);
            }
            // Admission validates shape only. Effective identities/revision are
            // bound by the runtime adapter from its authenticated context.
            policy.bind("admission-context", "admission-revision")?;
        }
        Ok(())
    }
}
