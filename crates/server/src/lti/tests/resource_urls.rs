use super::*;
use aegaeon_attribute_mapping::MappingOutput;

fn mapped_resource(name: &str, value: &str) -> Result<MappingOutput, LtiError> {
    let mut config = configuration();
    config.mapping.outputs.insert(
        name.into(),
        ProfileRule {
            expression: Expression::Literal {
                value: json!(value),
            },
            schema: ValueSchema::String,
            required: true,
        },
    );
    config.mapping.released_outputs.insert(name.into());
    validate_configuration(&config)?;
    let (deployment, link) = config.placement("deployment-1", "resource-1")?;
    evaluate(&config, deployment, link, &BTreeSet::new(), &[], &context())
}

#[test]
fn mapped_resource_urls_require_https_before_message_composition() {
    for name in ["profile", "picture", "website"] {
        for value in [
            "http://platform.example/user/1",
            "data:image/svg+xml,<svg/>",
            "javascript:alert(1)",
            "//platform.example/user/1",
            "https:platform.example/user/1",
            "https:///platform.example/user/1",
            "https://user:password@platform.example/user/1",
            "https://platform.example/\\attacker.example",
            "https://platform.example/user/\n1",
            "https://platform.example/user/ 1",
            "",
        ] {
            assert!(mapped_resource(name, value).is_err(), "{name}: {value:?}");
        }
    }
}

#[test]
fn mapped_https_resources_preserve_query_unicode_and_fragments() {
    for name in ["profile", "picture", "website"] {
        for value in [
            "https://platform.example/user/1",
            "HTTPS://platform.example/user/1?size=large#portrait",
            "https://platform.example/利用者/%E6%97%A5#profile",
        ] {
            let output = mapped_resource(name, value).expect("HTTPS resource");
            assert_eq!(output.claims[name].value, value);
        }
    }
    // A role identifies vocabulary; it is not a dereferenced content resource.
    let marker = "http://purl.imsglobal.org/vocab/lti/system/person#TestUser";
    let mut config = configuration();
    config.deployments[0].allowed_roles.insert(marker.into());
    let (deployment, link) = config.placement("deployment-1", "resource-1").unwrap();
    let output = evaluate(
        &config,
        deployment,
        link,
        &deployment.allowed_roles,
        &[],
        &context(),
    )
    .expect("preview user retains a real role");
    assert!(output.claims[&claim("roles")]
        .value
        .as_array()
        .unwrap()
        .contains(&json!(marker)));
    assert!(evaluate(
        &config,
        deployment,
        link,
        &BTreeSet::from([marker.into()]),
        &[],
        &context()
    )
    .is_err());
}
