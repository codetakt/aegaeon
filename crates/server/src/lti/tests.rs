use super::{claims::*, model::*, request::*, *};
use crate::attribute_mapping::profile::ProfileRule;
use aegaeon_attribute_mapping::{AttributeKey, Expression, ValueSchema};
use serde_json::json;
use std::collections::BTreeSet;

pub(super) fn configuration() -> ToolConfiguration {
    serde_json::from_value(json!({
        "schemaVersion":1,"name":"Example Tool","status":"active",
        "initiateLoginUri":"https://tool.example/login?tenant=example",
        "redirectUris":["https://tool.example/launch"],
        "deployments":[{"id":"deployment-1","status":"active","producers":["context-producer"],
            "allowedRoles":["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
            "resourceLinks":[{"id":"resource-1","status":"active", "targetLinkUri":"https://tool.example/resource/1",
                "context":{"id":"context-1","types":["http://purl.imsglobal.org/vocab/lis/v2/course#CourseSection"]}}]}]
    })).expect("valid fixture")
}

#[test]
fn secure_defaults_are_explicitly_relaxable_without_widening_profile() {
    let mut config = configuration();
    assert!(config.security.require_consent);
    assert!(config.security.require_dpop);
    assert!(config.security.staged_activation);
    config.security = SecurityPolicy {
        require_consent: false,
        require_dpop: false,
        staged_activation: false,
    };
    assert!(validate_configuration(&config).is_ok());
    config
        .redirect_uris
        .insert("http://tool.example/launch".into());
    assert!(validate_configuration(&config).is_err());
}

#[test]
fn registration_rejects_ambiguous_destinations_and_identity_moves() {
    let original = configuration();
    assert!(validate_configuration(&original).is_ok());
    for uri in [
        "https://tool.example/login?%69ss=other",
        "https://user@tool.example/login",
        "https://tool.example/login#x",
        "https://tool.example/\\other",
    ] {
        let mut next = original.clone();
        next.initiate_login_uri = uri.into();
        assert!(validate_configuration(&next).is_err(), "{uri}");
    }
    let mut next = original.clone();
    next.deployments[0].resource_links[0].context.id = "another-context".into();
    assert!(validate_transition(&original, &next).is_err());
    next = original.clone();
    next.deployments.clear();
    assert!(validate_transition(&original, &next).is_err());
    let mut retired = original.clone();
    retired.status = Lifecycle::Retired;
    assert!(validate_transition(&retired, &original).is_err());
}

#[test]
fn form_preserves_opaque_values_and_refuses_decoding_ambiguity() {
    assert_eq!(
        form("state=%20a%2Bb+%26%3D&nonce=%E6%97%A5").expect("valid")["state"],
        " a+b &="
    );
    for raw in ["nonce=a&%6eonce=b", "x=%", "x=%FF", "x=%G0", "=x"] {
        assert!(form(raw).is_err(), "{raw}");
    }
    let base = "client_id=tool&redirect_uri=https%3A%2F%2Ftool.example%2Flaunch&login_hint=hint&lti_message_hint=message&nonce=+opaque+&state=%2B&scope=openid&response_type=id_token&response_mode=form_post&prompt=none";
    for value in ["", "%00", "%0A", "%0D", "%7F", "%E6%97%A5"] {
        assert!(
            AuthorizationRequest::parse(&base.replace("state=%2B", &format!("state={value}")))
                .is_err()
        );
    }
    let request = AuthorizationRequest::parse(base).expect("request");
    assert!(request.validate().is_ok());
    assert_eq!(request.nonce, " opaque ");
    assert_eq!(request.state.as_deref(), Some("+"));
    for (from, to) in [
        ("form_post", "FORM_POST"),
        ("id_token", "code"),
        ("openid", "openid+email"),
        ("prompt=none", "prompt=login"),
    ] {
        assert!(AuthorizationRequest::parse(&base.replace(from, to))
            .expect("parse")
            .validate()
            .is_err());
    }
}

fn context() -> ClaimContext<'static> {
    ClaimContext {
        environment_id: "env",
        user_id: "owner",
        client_id: "tool",
        revision: "revision-1",
        producer: "context-producer",
        observed_at: 100,
        expires_at: 200,
        now: 101,
    }
}

#[test]
fn preset_emits_required_message_claims_without_implicit_personal_attributes() {
    let config = configuration();
    let (deployment, link) = config
        .placement("deployment-1", "resource-1")
        .expect("placement");
    let output = evaluate(
        &config,
        deployment,
        link,
        &deployment.allowed_roles,
        &[],
        &context(),
    )
    .expect("output");
    assert_eq!(output.claims[&claim("roles")].sources.len(), 1);
    let claims = message_claims(output, deployment, link);
    assert_eq!(claims[&claim("message_type")], "LtiResourceLinkRequest");
    assert_eq!(claims[&claim("version")], "1.3.0");
    assert_eq!(claims[&claim("target_link_uri")], link.target_link_uri);
    assert_eq!(claims[&claim("resource_link")]["id"], link.id);
    assert!(!claims.contains_key("email"));
    assert!(!claims.contains_key("sub"));
}

#[test]
fn preset_refuses_role_escalation_expiry_and_wrong_producer() {
    let config = configuration();
    let (deployment, link) = config
        .placement("deployment-1", "resource-1")
        .expect("placement");
    assert!(evaluate(
        &config,
        deployment,
        link,
        &BTreeSet::from(["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor".into()]),
        &[],
        &context()
    )
    .is_err());
    let mut ctx = context();
    ctx.now = 200;
    assert!(evaluate(
        &config,
        deployment,
        link,
        &deployment.allowed_roles,
        &[],
        &ctx
    )
    .is_err());
    ctx = context();
    ctx.producer = "other-producer";
    assert!(evaluate(
        &config,
        deployment,
        link,
        &deployment.allowed_roles,
        &[],
        &ctx
    )
    .is_err());
    assert!(evaluate(&config, deployment, link, &BTreeSet::new(), &[], &context()).is_ok());
}

#[test]
fn custom_policy_cannot_replace_protocol_or_preset_authority() {
    for name in [
        "sub",
        "iss",
        "email_verified",
        "https://purl.imsglobal.org/spec/lti/claim/roles",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
        "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint",
    ] {
        let mut config = configuration();
        config.mapping.outputs.insert(
            name.into(),
            ProfileRule {
                expression: Expression::Literal {
                    value: json!("attacker"),
                },
                schema: ValueSchema::String,
                required: false,
            },
        );
        config.mapping.released_outputs.insert(name.into());
        assert!(validate_configuration(&config).is_err(), "{name}");
    }
}

#[test]
fn local_missing_input_still_requires_independent_disclosure_permission() {
    let mut config = configuration();
    let key = AttributeKey {
        source: "local".into(),
        name: "nickname".into(),
    };
    config.mapping.inputs.insert(key.clone());
    config.mapping.outputs.insert(
        "nickname".into(),
        ProfileRule {
            expression: Expression::Coalesce {
                choices: vec![
                    Expression::Read {
                        attribute: key.clone(),
                        path: vec![],
                    },
                    Expression::Literal {
                        value: json!("anonymous"),
                    },
                ],
            },
            schema: ValueSchema::String,
            required: false,
        },
    );
    config.mapping.released_outputs.insert("nickname".into());
    let (deployment, link) = config
        .placement("deployment-1", "resource-1")
        .expect("placement");
    assert!(evaluate(&config, deployment, link, &BTreeSet::new(), &[], &context()).is_err());
    config.mapping.source_grants.insert(key);
    let (deployment, link) = config
        .placement("deployment-1", "resource-1")
        .expect("placement");
    let output =
        evaluate(&config, deployment, link, &BTreeSet::new(), &[], &context()).expect("permitted");
    assert_eq!(output.claims["nickname"].value, "anonymous");
}
