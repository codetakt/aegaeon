use super::*;
use aegaeon_attribute_mapping::{
    MappingError, Provenance, Recipient, SourceKind, Subject, Surface,
};
use serde_json::json;
use std::collections::BTreeSet;
use uuid::Uuid;

pub(crate) fn configuration(surface: Surface) -> anyhow::Result<MappingConfiguration> {
    Ok(serde_json::from_value(json!({
        "schemaVersion":1,
        "sources":[{"namespace":"local","kind":"local","attributes":[
            {"name":"department","recipients":[{"clientId":"test_client","surface":surface}]},
            {"name":"name","recipients":[{"clientId":"test_client","surface":surface}]}
        ]}],
        "policies":[{"recipient":{"clientId":"test_client","surface":surface},
            "inputs":[{"source":"local","name":"department"},{"source":"local","name":"name"}],
            "outputs":{
                "organization":{"op":"object","fields":{"department":{"op":"read","attribute":{"source":"local","name":"department"},"path":[]}}},
                "name":{"op":"read","attribute":{"source":"local","name":"name"},"path":[]}
            },
            "releasedOutputs":["organization","name"],
            "customSchema":{"organization":{"required":true,"schema":{"type":"object","properties":{"department":{"required":true,"schema":{"type":"string"}}}}}},
            "requiredScopes":["openid","profile"]
        }]
    }))?)
}

fn source() -> AttributeSourceRecord {
    AttributeSourceRecord {
        namespace: "local".into(),
        revision: 1,
        provenance: Provenance {
            kind: SourceKind::Local,
            authority: "management:test".into(),
            source_revision: "1".into(),
            observed_at: 100,
            expires_at: Some(200),
        },
        values: json!({"department":"Engineering","name":"Example User"}),
    }
}

pub(crate) fn snapshot(surface: Surface, issuer: &str) -> anyhow::Result<OidcMappingSnapshot> {
    let mut source = source();
    source.provenance.expires_at = None;
    Ok(output::evaluate_snapshot(
        &configuration(surface.clone())?,
        &[source],
        output::EvaluationContext {
            revision: Uuid::from_u128(1),
            subject: Subject {
                environment_id: "environment".into(),
                user_id: "immutable-owner".into(),
            },
            recipient: Recipient {
                environment_id: "environment".into(),
                client_id: "test_client".into(),
                surface,
            },
            scopes: scopes(),
            issuer,
            oidc_subject: "user123",
            now: 150,
        },
    )?)
}

fn scopes() -> BTreeSet<String> {
    BTreeSet::from(["openid".into(), "profile".into()])
}

#[test]
fn attribute_mapping_oidc_admission_rejects_verified_flag_fabrication_and_owned_claims(
) -> anyhow::Result<()> {
    for name in [
        "email_verified",
        "phone_number_verified",
        "sub",
        "acr",
        "_claim_names",
        "_claim_sources",
    ] {
        let mut configuration = configuration(Surface::IdToken)?;
        let policy = &mut configuration.policies[0];
        policy.outputs.insert(
            name.into(),
            aegaeon_attribute_mapping::Expression::Literal { value: json!(true) },
        );
        policy.released_outputs.insert(name.into());
        assert!(configuration.validate().is_err(), "{name}");
    }
    let mut configuration = configuration(Surface::Userinfo)?;
    configuration.sources.push(configuration.sources[0].clone());
    assert_eq!(
        configuration.validate(),
        Err(MappingError::DuplicateAttribute)
    );
    Ok(())
}

#[test]
fn attribute_mapping_oidc_snapshot_binds_context_and_survives_trusted_store_roundtrip(
) -> anyhow::Result<()> {
    let mapped = snapshot(Surface::IdToken, "https://issuer.example")?;
    let mapped: OidcMappingSnapshot = serde_json::from_value(serde_json::to_value(mapped)?)?;
    let claims = mapped.claims_for(
        "https://issuer.example",
        "user123",
        "test_client",
        &Surface::IdToken,
        &scopes(),
        160,
    )?;
    assert_eq!(claims["organization"], json!({"department":"Engineering"}));
    for (issuer, subject, client, surface, scopes) in [
        (
            "https://other.example",
            "user123",
            "test_client",
            Surface::IdToken,
            scopes(),
        ),
        (
            "https://issuer.example",
            "other",
            "test_client",
            Surface::IdToken,
            scopes(),
        ),
        (
            "https://issuer.example",
            "user123",
            "other",
            Surface::IdToken,
            scopes(),
        ),
        (
            "https://issuer.example",
            "user123",
            "test_client",
            Surface::Userinfo,
            scopes(),
        ),
        (
            "https://issuer.example",
            "user123",
            "test_client",
            Surface::IdToken,
            BTreeSet::from(["openid".into()]),
        ),
    ] {
        assert!(mapped
            .claims_for(issuer, subject, client, &surface, &scopes, 160)
            .is_err());
    }
    let mut forged = serde_json::to_value(mapped)?;
    forged["output"]["claims"]["sub"] = json!({"value":"forged","sources":[]});
    let forged: OidcMappingSnapshot = serde_json::from_value(forged)?;
    assert_eq!(
        forged.claims_for(
            "https://issuer.example",
            "user123",
            "test_client",
            &Surface::IdToken,
            &scopes(),
            160
        ),
        Err(MappingError::ReservedClaim)
    );
    Ok(())
}

#[test]
fn attribute_mapping_oidc_scope_recipient_and_missing_standard_claims() -> anyhow::Result<()> {
    let configuration = configuration(Surface::Userinfo)?;
    for (client, granted, expected) in [
        ("test_client", scopes(), true),
        ("unconfigured", scopes(), false),
        ("test_client", BTreeSet::from(["openid".into()]), false),
    ] {
        let mut source = source();
        // Standard claims are voluntary; absence does not turn into null or error.
        source
            .values
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("object"))?
            .remove("name");
        let mapped = output::evaluate_snapshot(
            &configuration,
            &[source],
            output::EvaluationContext {
                revision: Uuid::from_u128(1),
                subject: Subject {
                    environment_id: "environment".into(),
                    user_id: "owner".into(),
                },
                recipient: Recipient {
                    environment_id: "environment".into(),
                    client_id: client.into(),
                    surface: Surface::Userinfo,
                },
                scopes: granted.clone(),
                issuer: "https://issuer.example",
                oidc_subject: "user123",
                now: 150,
            },
        )?;
        let claims = mapped.claims_for(
            "https://issuer.example",
            "user123",
            client,
            &Surface::Userinfo,
            &granted,
            150,
        )?;
        assert_eq!(claims.contains_key("organization"), expected);
        assert!(!claims.contains_key("name"));
        if expected {
            assert_eq!(
                mapped.claims_for(
                    "https://issuer.example",
                    "user123",
                    client,
                    &Surface::Userinfo,
                    &granted,
                    200
                ),
                Err(MappingError::Expired)
            );
        }
    }
    Ok(())
}

#[test]
fn attribute_mapping_verification_preserves_source_value_pair() -> anyhow::Result<()> {
    let namespace = format!("connection:{}", Uuid::from_u128(1));
    let recipient = json!({"clientId":"rp","surface":{"kind":"userinfo"}});
    let read =
        |name: &str| json!({"op":"read","attribute":{"source":namespace,"name":name},"path":[]});
    let configuration: MappingConfiguration = serde_json::from_value(json!({
        "schemaVersion":1,"sources":[{"namespace":namespace,"kind":"external","attributes":[
            {"name":"email","recipients":[recipient]}, {"name":"email_verified","recipients":[recipient]}
        ]}],"policies":[{"recipient":recipient,"inputs":[{"source":namespace,"name":"email"},{"source":namespace,"name":"email_verified"}],
            "outputs":{"email":read("email"),"email_verified":read("email_verified")},"releasedOutputs":["email","email_verified"],"customSchema":{},"requiredScopes":["openid","email"]}]
    }))?;
    let mut source = AttributeSourceRecord {
        namespace,
        revision: 1,
        provenance: Provenance {
            kind: SourceKind::External,
            authority: "https://provider.example".into(),
            source_revision: "1".into(),
            observed_at: 100,
            expires_at: Some(200),
        },
        values: json!({"email":"Example@example.com","email_verified":true}),
    };
    let context = || output::EvaluationContext {
        revision: Uuid::from_u128(2),
        subject: Subject {
            environment_id: "environment".into(),
            user_id: "owner".into(),
        },
        recipient: Recipient {
            environment_id: "environment".into(),
            client_id: "rp".into(),
            surface: Surface::Userinfo,
        },
        scopes: BTreeSet::from(["openid".into(), "email".into()]),
        issuer: "https://issuer.example",
        oidc_subject: "subject",
        now: 150,
    };
    let mapped = output::evaluate_snapshot(&configuration, &[source.clone()], context())?;
    let claims = mapped.claims_for(
        "https://issuer.example",
        "subject",
        "rp",
        &Surface::Userinfo,
        &context().scopes,
        150,
    )?;
    assert_eq!(claims["email"], "Example@example.com");
    assert_eq!(claims["email_verified"], true);
    let mut changed = configuration.clone();
    changed.policies[0].outputs.insert(
        "email".into(),
        aegaeon_attribute_mapping::Expression::Literal {
            value: json!("other@example.com"),
        },
    );
    assert_eq!(changed.validate(), Err(MappingError::OutputContract));
    source.values = json!({"email_verified":true});
    assert!(matches!(
        output::evaluate_snapshot(&configuration, &[source], context()),
        Err(MappingError::OutputContract)
    ));
    Ok(())
}

#[test]
fn attribute_mapping_known_absence_omits_voluntary_claims_without_inventing_values(
) -> anyhow::Result<()> {
    let mut configuration = configuration(Surface::Userinfo)?;
    let policy = &mut configuration.policies[0];
    policy.outputs.remove("organization");
    policy.released_outputs.remove("organization");
    policy.custom_schema.clear();
    let context = || output::EvaluationContext {
        revision: Uuid::from_u128(1),
        subject: Subject {
            environment_id: "environment".into(),
            user_id: "owner".into(),
        },
        recipient: Recipient {
            environment_id: "environment".into(),
            client_id: "test_client".into(),
            surface: Surface::Userinfo,
        },
        scopes: scopes(),
        issuer: "https://issuer.example",
        oidc_subject: "subject",
        now: 150,
    };
    let mapped = output::evaluate_snapshot(&configuration, &[], context())?;
    assert!(mapped
        .claims_for(
            "https://issuer.example",
            "subject",
            "test_client",
            &Surface::Userinfo,
            &scopes(),
            150
        )?
        .is_empty());
    let original = configuration.policies[0].outputs["name"].clone();
    configuration.policies[0].outputs.insert(
        "name".into(),
        aegaeon_attribute_mapping::Expression::Coalesce {
            choices: vec![
                original,
                aegaeon_attribute_mapping::Expression::Literal {
                    value: json!("Fallback"),
                },
            ],
        },
    );
    let mapped = output::evaluate_snapshot(&configuration, &[], context())?;
    assert_eq!(
        mapped.claims_for(
            "https://issuer.example",
            "subject",
            "test_client",
            &Surface::Userinfo,
            &scopes(),
            150
        )?["name"],
        "Fallback"
    );
    let encoded = serde_json::to_value(mapped)?;
    assert_eq!(
        encoded["output"]["claims"]["name"]["sources"][0]["provenance"]["kind"],
        "transient"
    );
    assert_eq!(
        encoded["output"]["claims"]["name"]["sources"][0]["provenance"]["authority"],
        "storage:absence"
    );
    Ok(())
}
