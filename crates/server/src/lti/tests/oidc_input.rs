use super::*;

const REQUEST: &str = "client_id=tool&redirect_uri=https%3A%2F%2Ftool.example%2Flaunch&login_hint=hint&lti_message_hint=message&nonce=n&scope=openid&response_type=id_token&response_mode=form_post&prompt=none";

#[test]
fn unsupported_oidc_objects_retain_the_required_protocol_error() {
    for (suffix, code) in [
        ("request=opaque", "request_not_supported"),
        (
            "request_uri=https%3A%2F%2Frequest.example%2Fobject",
            "request_uri_not_supported",
        ),
        ("registration=%7B%7D", "registration_not_supported"),
        (
            "request=opaque&request_uri=https%3A%2F%2Frequest.example",
            "invalid_request",
        ),
    ] {
        let request = AuthorizationRequest::parse(&format!("{REQUEST}&{suffix}"))
            .expect("parse before redirect admission");
        assert_eq!(request.validate(), Err(code));
        let stored = serde_json::to_value(&request).expect("store");
        assert_eq!(
            serde_json::from_value::<AuthorizationRequest>(stored)
                .expect("load")
                .validate(),
            Err(code)
        );
    }
}

#[test]
fn optional_claim_preferences_cannot_change_the_lti_profile() {
    for suffix in [
        "request=&request_uri=&registration=&id_token_hint=&state=",
        "display=touch&ui_locales=ja&claims_locales=ja&acr_values=urn%3Aexample%3Aunknown",
        "claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%7D%7D",
    ] {
        let request = AuthorizationRequest::parse(&format!("{REQUEST}&{suffix}")).expect("request");
        assert!(request.validate().is_ok());
        assert!(request.state.is_none());
        assert!(request.id_token_hint.is_none());
    }
    let request =
        AuthorizationRequest::parse(&format!("{REQUEST}&id_token_hint=original.jwt.bytes"))
            .expect("hint");
    assert_eq!(request.id_token_hint.as_deref(), Some("original.jwt.bytes"));
    let stored = serde_json::to_value(&request).expect("store");
    assert_eq!(
        serde_json::from_value::<AuthorizationRequest>(stored)
            .expect("load")
            .id_token_hint,
        request.id_token_hint
    );
    let old = serde_json::to_value(AuthorizationRequest::parse(REQUEST).expect("old request"))
        .expect("old store");
    assert!(old.get("id_token_hint").is_none() && old.get("unsupported").is_none());
    assert!(serde_json::from_value::<AuthorizationRequest>(old)
        .expect("compatible")
        .validate()
        .is_ok());
}
