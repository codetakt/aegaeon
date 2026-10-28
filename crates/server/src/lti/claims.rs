//! LTI's predefined mapping policy and its adapter-owned output contract.
use aegaeon_attribute_mapping::{
    Attribute, AttributeKey, AttributeValue, Expression, FieldSchema, MappingOutput, MappingPolicy,
    OutputContract, Provenance, Recipient, SourceKind, Subject, Surface, ValueSchema,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::{model::*, LtiError};
use crate::attribute_mapping::{profile::ProfileMapping, AttributeSourceRecord};

pub fn claim(name: &str) -> String {
    format!("{CLAIM_PREFIX}{name}")
}

fn key(name: &str) -> AttributeKey {
    AttributeKey {
        source: "lti:context".into(),
        name: name.into(),
    }
}

fn field(required: bool, schema: ValueSchema) -> FieldSchema {
    FieldSchema { required, schema }
}

fn object(properties: &[(&str, bool, ValueSchema)]) -> ValueSchema {
    ValueSchema::Object {
        properties: properties
            .iter()
            .map(|(name, required, schema)| ((*name).into(), field(*required, schema.clone())))
            .collect(),
    }
}

fn strings() -> ValueSchema {
    ValueSchema::Array {
        items: Box::new(ValueSchema::String),
    }
}

fn preset(recipient: Recipient, revision: String) -> (MappingPolicy, OutputContract) {
    let mut policy = ProfileMapping::empty_policy(recipient, revision);
    let mut contract = OutputContract {
        fields: BTreeMap::new(),
        additional_reserved_names: [
            "message_type",
            "version",
            "deployment_id",
            "target_link_uri",
        ]
        .iter()
        .map(|name| claim(name))
        .collect(),
    };
    // Each required LTI attribute is read through the common engine, including
    // its provenance and disclosure checks. Protocol identifiers remain separate.
    for (name, schema) in [
        ("roles", strings()),
        (
            "resource_link",
            object(&[
                ("id", true, ValueSchema::String),
                ("title", false, ValueSchema::String),
                ("description", false, ValueSchema::String),
            ]),
        ),
        (
            "context",
            object(&[
                ("id", true, ValueSchema::String),
                ("label", false, ValueSchema::String),
                ("title", false, ValueSchema::String),
                ("type", false, strings()),
            ]),
        ),
    ] {
        policy.inputs.insert(key(name));
        policy.outputs.insert(
            claim(name),
            Expression::Read {
                attribute: key(name),
                path: vec![],
            },
        );
        policy.released_outputs.insert(claim(name));
        contract.fields.insert(claim(name), field(true, schema));
    }
    (policy, contract)
}

/// Validate extension names and schemas before storage. A policy cannot invent
/// verified identity facts or inject other LTI/Advantage capabilities.
pub(super) fn validate_mapping(mapping: &ProfileMapping) -> Result<(), LtiError> {
    if mapping
        .inputs
        .iter()
        .chain(&mapping.source_grants)
        .any(|key| key.source != "local")
    {
        return Err(LtiError::Invalid);
    }
    for (name, rule) in &mapping.outputs {
        let valid = match name.as_str() {
            "name" | "given_name" | "family_name" | "middle_name" | "nickname"
            | "preferred_username" | "profile" | "picture" | "website" | "email" | "locale"
            | "zoneinfo" | "phone_number" => rule.schema == ValueSchema::String,
            name if name == claim("custom") => matches!(&rule.schema,
                ValueSchema::Object { properties } if properties.values().all(|field| field.schema == ValueSchema::String)),
            name => {
                super::validation::https(name)
                    && !name.starts_with("https://purl.imsglobal.org/")
                    && !name.starts_with("http://purl.imsglobal.org/")
            }
        };
        if !valid {
            return Err(LtiError::Invalid);
        }
    }
    let recipient = Recipient {
        environment_id: "validation".into(),
        client_id: "validation".into(),
        surface: Surface::Profile(PROFILE.into()),
    };
    let (mut policy, mut contract) = preset(recipient, "validation".into());
    mapping.extend(&mut policy, &mut contract)?;
    Ok(())
}

pub struct ClaimContext<'a> {
    pub environment_id: &'a str,
    pub user_id: &'a str,
    pub client_id: &'a str,
    pub revision: &'a str,
    pub producer: &'a str,
    pub observed_at: i64,
    pub expires_at: i64,
    pub now: i64,
}

/// Map authenticated placement facts and admitted stored local attributes.
///
/// # Errors
/// Rejects invalid roles, expired or misbound inputs, and prohibited disclosure.
pub fn evaluate(
    config: &ToolConfiguration,
    deployment: &Deployment,
    link: &ResourceLink,
    roles: &BTreeSet<String>,
    local: &[AttributeSourceRecord],
    context: &ClaimContext<'_>,
) -> Result<MappingOutput, LtiError> {
    if !super::validation::roles(roles)
        || !roles.is_subset(&deployment.allowed_roles)
        || !deployment.producers.contains(context.producer)
        || !deployment.resource_links.iter().any(|entry| entry == link)
        || !config.deployments.iter().any(|entry| entry == deployment)
    {
        return Err(LtiError::Denied);
    }
    config.placement(&deployment.id, &link.id)?;
    validate_mapping(&config.mapping)?;
    let owner = Subject {
        environment_id: context.environment_id.into(),
        user_id: context.user_id.into(),
    };
    let recipient = Recipient {
        environment_id: context.environment_id.into(),
        client_id: context.client_id.into(),
        surface: Surface::Profile(PROFILE.into()),
    };
    let (mut policy, mut contract) = preset(recipient.clone(), context.revision.into());
    config.mapping.extend(&mut policy, &mut contract)?;
    let provenance = Provenance {
        kind: SourceKind::Transient,
        authority: context.producer.into(),
        source_revision: context.revision.into(),
        observed_at: context.observed_at,
        expires_at: Some(context.expires_at),
    };
    let mut attributes: Vec<Attribute> = placement_values(link, roles)
        .into_iter()
        .map(|(name, value)| Attribute {
            key: key(name),
            owner: owner.clone(),
            value: AttributeValue::Present(value),
            provenance: provenance.clone(),
            recipients: BTreeSet::from([recipient.clone()]),
        })
        .collect();
    let source = local.iter().find(|record| record.namespace == "local");
    if source.is_some_and(|record| record.provenance.kind != SourceKind::Local)
        || local
            .iter()
            .filter(|record| record.namespace == "local")
            .count()
            > 1
    {
        return Err(LtiError::Denied);
    }
    for key in &config.mapping.inputs {
        let provenance = source.map_or_else(
            || Provenance {
                kind: SourceKind::Transient,
                authority: "storage:absence".into(),
                source_revision: context.revision.into(),
                observed_at: context.now,
                expires_at: Some(context.expires_at),
            },
            |source| source.provenance.clone(),
        );
        attributes.push(Attribute {
            key: key.clone(),
            owner: owner.clone(),
            value: source
                .and_then(|source| source.values.get(&key.name))
                .map_or(AttributeValue::Missing, |value| {
                    AttributeValue::Present(value.clone())
                }),
            provenance,
            recipients: if config.mapping.source_grants.contains(key) {
                BTreeSet::from([recipient.clone()])
            } else {
                BTreeSet::new()
            },
        });
    }
    Ok(aegaeon_attribute_mapping::evaluate(
        &owner,
        &recipient,
        context.now,
        &attributes,
        &policy,
        &contract,
    )?)
}

/// Compose protocol-owned LTI claims after the preset has passed its contract.
/// The caller must bind the output to the admitted subject and recipient before signing.
#[must_use]
pub fn message_claims(
    output: MappingOutput,
    deployment: &Deployment,
    link: &ResourceLink,
) -> BTreeMap<String, Value> {
    let mut values: BTreeMap<String, Value> = output
        .claims
        .into_iter()
        .map(|(name, mapped)| (name, mapped.value))
        .collect();
    values.insert(claim("message_type"), json!("LtiResourceLinkRequest"));
    values.insert(claim("version"), json!("1.3.0"));
    values.insert(claim("deployment_id"), json!(deployment.id));
    values.insert(claim("target_link_uri"), json!(link.target_link_uri));
    values
}

fn placement_values(link: &ResourceLink, roles: &BTreeSet<String>) -> [(&'static str, Value); 3] {
    let mut resource = json!({"id":link.id});
    let mut course = json!({"id":link.context.id});
    for (object, name, value) in [
        (&mut resource, "title", &link.title),
        (&mut course, "title", &link.context.title),
    ] {
        if let Some(value) = value {
            object[name] = json!(value);
        }
    }
    if let Some(value) = &link.description {
        resource["description"] = json!(value);
    }
    if let Some(value) = &link.context.label {
        course["label"] = json!(value);
    }
    if !link.context.types.is_empty() {
        course["type"] = json!(link.context.types);
    }
    [
        ("roles", json!(roles)),
        ("resource_link", resource),
        ("context", course),
    ]
}
