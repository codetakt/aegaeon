use super::*;

const REQUEST: &str = "client_id=tool&redirect_uri=https%3A%2F%2Ftool.example%2Flaunch&login_hint=hint&lti_message_hint=message&nonce=n&scope=openid&response_type=id_token&response_mode=form_post&prompt=none";

#[test]
fn authentication_age_is_bounded_and_rechecked_without_inventing_acr() {
    for suffix in ["", "&max_age=", "&acr_values=urn%3Aexample%3Aunsupported"] {
        let request = AuthorizationRequest::parse(&format!("{REQUEST}{suffix}")).unwrap();
        assert!(request.validate().is_ok());
        assert!(request.authentication_is_current(100, 1_000));
        assert!(!request.authentication_is_current(101, 100));
        assert!(!request.authentication_is_current(0, -1));
    }
    let request = AuthorizationRequest::parse(&format!("{REQUEST}&max_age=60")).unwrap();
    assert!(request.validate().is_ok());
    assert!(request.authentication_is_current(100, 160));
    assert!(!request.authentication_is_current(100, 161));
    let retained: AuthorizationRequest =
        serde_json::from_value(serde_json::to_value(&request).unwrap()).unwrap();
    assert!(!retained.authentication_is_current(100, 161));
    let zero = AuthorizationRequest::parse(&format!("{REQUEST}&max_age=0")).unwrap();
    assert!(zero.validate().is_ok());
    assert!(!zero.authentication_is_current(100, 100));
    let old = serde_json::to_value(AuthorizationRequest::parse(REQUEST).unwrap()).unwrap();
    assert!(
        old.get("max_age").is_none(),
        "preserve older retained request equality"
    );
    let mut old = old.as_object().unwrap().clone();
    old.remove("max_age");
    assert!(serde_json::from_value::<AuthorizationRequest>(old.into())
        .unwrap()
        .authentication_is_current(100, 1_000));
}

#[test]
fn authentication_age_refuses_malformed_overflow_and_duplicate_values() {
    for value in [
        "-1",
        "+1",
        "1.0",
        "1e2",
        "%EF%BC%91",
        "18446744073709551616",
    ] {
        let request = AuthorizationRequest::parse(&format!("{REQUEST}&max_age={value}")).unwrap();
        assert_eq!(request.validate(), Err("invalid_request"), "{value}");
        assert!(!request.authentication_is_current(100, 100));
    }
    assert!(AuthorizationRequest::parse(&format!("{REQUEST}&max_age=1&%6dax_age=2")).is_err());
    let largest =
        AuthorizationRequest::parse(&format!("{REQUEST}&max_age=18446744073709551615")).unwrap();
    assert!(largest.validate().is_ok());
    assert!(largest.authentication_is_current(0, i64::MAX));
}
