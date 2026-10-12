use super::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn owner() -> Subject {
    Subject {
        environment_id: "environment-a".into(),
        user_id: "local-user-id".into(),
    }
}

fn recipient() -> Recipient {
    Recipient {
        environment_id: "environment-a".into(),
        client_id: "rp-a".into(),
        surface: Surface::IdToken,
    }
}

fn key(name: &str) -> AttributeKey {
    AttributeKey {
        source: "connection-a".into(),
        name: name.into(),
    }
}

fn attribute(name: &str, value: Value) -> Attribute {
    Attribute {
        key: key(name),
        owner: owner(),
        value: AttributeValue::Present(value),
        provenance: Provenance {
            kind: SourceKind::External,
            authority: "https://issuer.example".into(),
            source_revision: "source-7".into(),
            observed_at: 100,
            expires_at: Some(200),
        },
        recipients: BTreeSet::from([recipient()]),
    }
}

fn read(name: &str) -> Expression {
    Expression::Read {
        attribute: key(name),
        path: vec![],
    }
}

fn literal(value: Value) -> Expression {
    Expression::Literal { value }
}

fn field(schema: ValueSchema) -> FieldSchema {
    FieldSchema {
        required: true,
        schema,
    }
}

fn setup(expr: Expression, schema: ValueSchema) -> (MappingPolicy, OutputContract) {
    (
        MappingPolicy {
            schema_version: 1,
            revision: "policy-3".into(),
            recipient: recipient(),
            inputs: BTreeSet::from([key("name"), key("groups"), key("private")]),
            outputs: BTreeMap::from([("result".into(), expr)]),
            released_outputs: BTreeSet::from(["result".into()]),
        },
        OutputContract {
            fields: BTreeMap::from([("result".into(), field(schema))]),
            additional_reserved_names: BTreeSet::new(),
        },
    )
}

fn run(
    attrs: &[Attribute],
    policy: &MappingPolicy,
    contract: &OutputContract,
) -> Result<MappingOutput, MappingError> {
    evaluate(&owner(), &recipient(), 150, attrs, policy, contract)
}

#[test]
fn structured_output_keeps_source_provenance_and_policy_revision() {
    let expr = Expression::Object {
        fields: BTreeMap::from([
            (
                "display".into(),
                Expression::LowerAscii {
                    input: Box::new(read("name")),
                },
            ),
            (
                "memberships".into(),
                Expression::Map {
                    input: Box::new(read("groups")),
                    item: Box::new(Expression::Object {
                        fields: BTreeMap::from([(
                            "role".into(),
                            Expression::Item {
                                path: vec![PathStep::Key("label".into())],
                            },
                        )]),
                    }),
                },
            ),
        ]),
    };
    let schema = ValueSchema::Object {
        properties: BTreeMap::from([
            ("display".into(), field(ValueSchema::String)),
            (
                "memberships".into(),
                field(ValueSchema::Array {
                    items: Box::new(ValueSchema::Object {
                        properties: BTreeMap::from([("role".into(), field(ValueSchema::String))]),
                    }),
                }),
            ),
        ]),
    };
    let (policy, contract) = setup(expr, schema);
    let attrs = vec![
        attribute("name", json!(" Ada ")),
        attribute("groups", json!([{"label":"teacher"},{"label":"editor"}])),
    ];
    let output = run(&attrs, &policy, &contract).unwrap();
    assert_eq!(
        output.claims["result"].value,
        json!({"display":" ada ","memberships":[{"role":"teacher"},{"role":"editor"}]})
    );
    assert_eq!(output.policy_revision, "policy-3");
    assert_eq!(output.claims["result"].sources.len(), 2);
    assert_eq!(
        output.claims["result"].sources[0].provenance,
        attrs[1].provenance
    );
}

#[test]
fn internal_attributes_can_use_the_same_engine() {
    let mut attr = attribute("name", json!("Operations"));
    attr.key.source = "local".into();
    attr.provenance.kind = SourceKind::Local;
    attr.provenance.authority = "profile-manager".into();
    let (mut policy, contract) = setup(
        Expression::Read {
            attribute: attr.key.clone(),
            path: vec![],
        },
        ValueSchema::String,
    );
    policy.inputs.insert(attr.key.clone());
    let output = run(&[attr], &policy, &contract).unwrap();
    assert_eq!(
        output.claims["result"].sources[0].provenance.kind,
        SourceKind::Local
    );
}

#[test]
fn recipient_environment_client_and_surface_are_exact() {
    let (policy, contract) = setup(read("name"), ValueSchema::String);
    let attrs = [attribute("name", json!("Ada"))];
    for target in [
        Recipient {
            environment_id: "environment-b".into(),
            ..recipient()
        },
        Recipient {
            client_id: "rp-b".into(),
            ..recipient()
        },
        Recipient {
            surface: Surface::Userinfo,
            ..recipient()
        },
    ] {
        assert_eq!(
            evaluate(&owner(), &target, 150, &attrs, &policy, &contract),
            Err(MappingError::RecipientMismatch)
        );
    }
}

#[test]
fn cross_user_and_cross_environment_inputs_are_rejected() {
    let (policy, contract) = setup(read("name"), ValueSchema::String);
    for subject in [
        Subject {
            user_id: "other-user".into(),
            ..owner()
        },
        Subject {
            environment_id: "other-env".into(),
            ..owner()
        },
    ] {
        let mut attr = attribute("name", json!("Ada"));
        attr.owner = subject;
        attr.recipients.clear();
        assert_eq!(
            run(&[attr], &policy, &contract),
            Err(MappingError::SubjectMismatch)
        );
    }
}

#[test]
fn transformation_permission_and_both_release_permissions_are_independent() {
    let (policy, contract) = setup(read("name"), ValueSchema::String);
    let attr = attribute("name", json!("Ada"));
    let mut no_input = policy.clone();
    no_input.inputs.clear();
    assert_eq!(
        run(std::slice::from_ref(&attr), &no_input, &contract),
        Err(MappingError::InputDenied)
    );
    let mut no_output = policy.clone();
    no_output.released_outputs.clear();
    assert_eq!(
        run(std::slice::from_ref(&attr), &no_output, &contract),
        Err(MappingError::OutputDenied)
    );
    let mut no_source = attr;
    no_source.recipients.clear();
    assert_eq!(
        run(&[no_source], &policy, &contract),
        Err(MappingError::DisclosureDenied)
    );
}

#[test]
fn renaming_and_derivation_cannot_release_a_restricted_source() {
    let (policy, contract) = setup(
        Expression::Concat {
            parts: vec![literal(json!("team:")), read("private")],
            separator: "".into(),
        },
        ValueSchema::String,
    );
    let mut attr = attribute("private", json!("restricted"));
    attr.recipients.clear();
    assert_eq!(
        run(&[attr], &policy, &contract),
        Err(MappingError::DisclosureDenied)
    );
}

#[test]
fn unused_coalesce_branch_cannot_leak_presence_or_drop_restrictions() {
    let (policy, contract) = setup(
        Expression::Coalesce {
            choices: vec![literal(json!("public")), read("private")],
        },
        ValueSchema::String,
    );
    let mut attr = attribute("private", json!("restricted"));
    attr.recipients.clear();
    for value in [
        AttributeValue::Present(json!("restricted")),
        AttributeValue::Missing,
    ] {
        attr.value = value;
        assert_eq!(
            run(&[attr.clone()], &policy, &contract),
            Err(MappingError::DisclosureDenied)
        );
    }
}

#[test]
fn empty_array_does_not_bypass_map_body_authorization() {
    let (policy, contract) = setup(
        Expression::Map {
            input: Box::new(read("groups")),
            item: Box::new(read("private")),
        },
        ValueSchema::Array {
            items: Box::new(ValueSchema::String),
        },
    );
    let mut restricted = attribute("private", json!("secret"));
    restricted.recipients.clear();
    assert_eq!(
        run(
            &[attribute("groups", json!([])), restricted],
            &policy,
            &contract
        ),
        Err(MappingError::DisclosureDenied)
    );
}

#[test]
fn missing_and_null_are_distinct_in_storage_and_coalesce() {
    let (policy, contract) = setup(
        Expression::Coalesce {
            choices: vec![read("name"), literal(Value::Null)],
        },
        ValueSchema::Null,
    );
    for value in [
        AttributeValue::Missing,
        AttributeValue::Present(Value::Null),
    ] {
        let mut attr = attribute("name", Value::Null);
        attr.value = value;
        let restored: Attribute =
            serde_json::from_str(&serde_json::to_string(&attr).unwrap()).unwrap();
        assert_eq!(restored, attr);
        assert_eq!(
            run(&[restored], &policy, &contract).unwrap().claims["result"].value,
            Value::Null
        );
    }
    let (policy, contract) = setup(
        Expression::Coalesce {
            choices: vec![read("name"), literal(json!("fallback"))],
        },
        ValueSchema::String,
    );
    assert_eq!(
        run(&[attribute("name", Value::Null)], &policy, &contract),
        Err(MappingError::OutputContract)
    );
}

#[test]
fn absent_optional_object_field_is_omitted_but_array_position_is_not_shifted() {
    let mut attr = attribute("name", Value::Null);
    attr.value = AttributeValue::Missing;
    let (policy, contract) = setup(
        Expression::Object {
            fields: BTreeMap::from([("optional".into(), read("name"))]),
        },
        ValueSchema::Object {
            properties: BTreeMap::from([(
                "optional".into(),
                FieldSchema {
                    required: false,
                    schema: ValueSchema::String,
                },
            )]),
        },
    );
    assert_eq!(
        run(&[attr.clone()], &policy, &contract).unwrap().claims["result"].value,
        json!({})
    );
    let (policy, contract) = setup(
        Expression::Array {
            items: vec![read("name"), literal(json!("second"))],
        },
        ValueSchema::Array {
            items: Box::new(ValueSchema::String),
        },
    );
    assert_eq!(
        run(&[attr], &policy, &contract),
        Err(MappingError::MissingRequired)
    );
}

#[test]
fn unknown_source_is_not_treated_as_a_known_missing_attribute() {
    let (policy, contract) = setup(
        Expression::Coalesce {
            choices: vec![read("name"), literal(json!("default"))],
        },
        ValueSchema::String,
    );
    assert_eq!(
        run(&[], &policy, &contract),
        Err(MappingError::UnknownAttribute)
    );
}

#[test]
fn freshness_uses_injected_time_with_exclusive_expiry() {
    let (policy, contract) = setup(read("name"), ValueSchema::String);
    let attrs = [attribute("name", json!("Ada"))];
    assert!(evaluate(&owner(), &recipient(), 100, &attrs, &policy, &contract).is_ok());
    assert!(evaluate(&owner(), &recipient(), 199, &attrs, &policy, &contract).is_ok());
    assert_eq!(
        evaluate(&owner(), &recipient(), 200, &attrs, &policy, &contract),
        Err(MappingError::Expired)
    );
    assert_eq!(
        evaluate(&owner(), &recipient(), 99, &attrs, &policy, &contract),
        Err(MappingError::InvalidTime)
    );
}

#[test]
fn snapshot_replacement_does_not_mutate_an_in_flight_policy() {
    let (old, contract) = setup(read("name"), ValueSchema::String);
    let mut successor = old.clone();
    successor.revision = "policy-4".into();
    successor.released_outputs.clear();
    let attrs = [attribute("name", json!("Ada"))];
    assert_eq!(
        run(&attrs, &successor, &contract),
        Err(MappingError::OutputDenied)
    );
    assert_eq!(
        run(&attrs, &old, &contract).unwrap().policy_revision,
        "policy-3"
    );
}

#[test]
fn protocol_owned_claims_and_adapter_reserved_names_are_rejected() {
    for name in [
        "sub",
        "iss",
        "aud",
        "nonce",
        "exp",
        "auth_time",
        "amr",
        "cnf",
        "SUB",
        "deployment",
    ] {
        let (mut policy, mut contract) = setup(literal(json!("injected")), ValueSchema::String);
        policy.outputs = BTreeMap::from([(name.into(), literal(json!("injected")))]);
        policy.released_outputs = BTreeSet::from([name.into()]);
        contract.fields = BTreeMap::from([(name.into(), field(ValueSchema::String))]);
        contract
            .additional_reserved_names
            .insert("deployment".into());
        assert_eq!(
            run(&[], &policy, &contract),
            Err(MappingError::ReservedClaim)
        );
    }
}

#[test]
fn same_attribute_name_in_different_sources_does_not_overwrite() {
    let a = attribute("name", json!("a"));
    let mut b = attribute("name", json!("b"));
    b.key.source = "connection-b".into();
    let (policy, contract) = setup(read("name"), ValueSchema::String);
    assert_eq!(
        run(&[a.clone(), b], &policy, &contract).unwrap().claims["result"].value,
        json!("a")
    );
    assert_eq!(
        run(&[a.clone(), a], &policy, &contract),
        Err(MappingError::DuplicateAttribute)
    );
}

#[test]
fn exact_path_preserves_keys_and_rejects_wrong_container_types() {
    let (policy, contract) = setup(
        Expression::Read {
            attribute: key("name"),
            path: vec![PathStep::Key(" /~ ".into()), PathStep::Index(0)],
        },
        ValueSchema::String,
    );
    assert_eq!(
        run(
            &[attribute("name", json!({" /~ ":["selected"]}))],
            &policy,
            &contract
        )
        .unwrap()
        .claims["result"]
            .value,
        json!("selected")
    );
    assert_eq!(
        run(
            &[attribute("name", json!({" /~ ":{"0":"wrong"}}))],
            &policy,
            &contract
        ),
        Err(MappingError::TypeMismatch)
    );
}

#[test]
fn schema_rejects_unknown_properties_and_wrong_nested_types() {
    let schema = ValueSchema::Object {
        properties: BTreeMap::from([("count".into(), field(ValueSchema::Integer))]),
    };
    for value in [
        json!({"count":1,"extra":true}),
        json!({"count":"1"}),
        json!({"count":1.5}),
    ] {
        let (policy, contract) = setup(literal(value), schema.clone());
        assert_eq!(
            run(&[], &policy, &contract),
            Err(MappingError::OutputContract)
        );
    }
}

#[test]
fn unknown_policy_fields_and_versions_fail_closed() {
    let (policy, contract) = setup(literal(json!("ok")), ValueSchema::String);
    let mut encoded = serde_json::to_value(&policy).unwrap();
    encoded["unexpected"] = json!(true);
    assert!(serde_json::from_value::<MappingPolicy>(encoded).is_err());
    let mut future = policy;
    future.schema_version = 2;
    assert_eq!(
        run(&[], &future, &contract),
        Err(MappingError::SchemaVersion)
    );
}

#[test]
fn errors_do_not_contain_input_values() {
    let (policy, contract) = setup(
        Expression::LowerAscii {
            input: Box::new(read("private")),
        },
        ValueSchema::String,
    );
    let error = run(
        &[attribute("private", json!({"secret":"never-log-this"}))],
        &policy,
        &contract,
    )
    .unwrap_err();
    assert!(!format!("{error:?}: {error}").contains("never-log-this"));
}

#[test]
fn array_item_scope_is_explicit() {
    let (policy, contract) = setup(Expression::Item { path: vec![] }, ValueSchema::String);
    assert_eq!(run(&[], &policy, &contract), Err(MappingError::ItemScope));
}

#[test]
fn expression_depth_and_literal_size_are_bounded() {
    let mut expr = literal(json!("small"));
    for _ in 0..MAX_EXPRESSION_DEPTH + 1 {
        expr = Expression::LowerAscii {
            input: Box::new(expr),
        };
    }
    let (policy, contract) = setup(expr, ValueSchema::String);
    assert_eq!(
        run(&[], &policy, &contract),
        Err(MappingError::ResourceLimit)
    );
    let (policy, contract) = setup(
        literal(json!("x".repeat(MAX_OUTPUT_BYTES))),
        ValueSchema::String,
    );
    assert_eq!(
        run(&[], &policy, &contract),
        Err(MappingError::ResourceLimit)
    );
}

#[test]
fn aggregate_input_size_is_bounded_before_values_are_copied() {
    let (policy, contract) = setup(read("name"), ValueSchema::String);
    let attrs = [
        attribute("name", json!("small")),
        attribute("unused", json!("x".repeat(MAX_INPUT_BYTES))),
    ];
    assert_eq!(
        run(&attrs, &policy, &contract),
        Err(MappingError::ResourceLimit)
    );
}

#[test]
fn nested_maps_stop_at_step_budget_without_external_side_effects() {
    let array = literal(json!(vec![0; 200]));
    let expr = Expression::Map {
        input: Box::new(array.clone()),
        item: Box::new(Expression::Map {
            input: Box::new(array),
            item: Box::new(literal(Value::Null)),
        }),
    };
    let (policy, contract) = setup(
        expr,
        ValueSchema::Array {
            items: Box::new(ValueSchema::Array {
                items: Box::new(ValueSchema::Null),
            }),
        },
    );
    assert_eq!(
        run(&[], &policy, &contract),
        Err(MappingError::ResourceLimit)
    );
}

#[test]
fn policy_and_complete_output_round_trip_without_losing_evidence() {
    let (policy, contract) = setup(read("name"), ValueSchema::String);
    let restored: MappingPolicy =
        serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
    assert_eq!(restored, policy);
    let output = run(&[attribute("name", json!("Ada"))], &restored, &contract).unwrap();
    let restored: MappingOutput =
        serde_json::from_slice(&serde_json::to_vec(&output).unwrap()).unwrap();
    assert_eq!(restored, output);
}

#[test]
fn nested_selector_and_value_encodings_reject_unknown_fields() {
    assert!(
        serde_json::from_value::<Surface>(json!({"kind":"userinfo","unexpected":true})).is_err()
    );
    assert!(serde_json::from_value::<PathStep>(
        json!({"kind":"key","value":"email","unexpected":true})
    )
    .is_err());
    assert!(
        serde_json::from_value::<AttributeValue>(json!({"state":"missing","unexpected":true}))
            .is_err()
    );
}
