use super::*;

fn header(payload: &[u8]) -> String {
    format!(
        "bAsIc {}",
        base64::engine::general_purpose::STANDARD.encode(payload)
    )
}

#[test]
fn oauth_basic_decodes_each_component_once_after_raw_colon_split() {
    for (payload, id, secret) in [
        (
            "client%3Aid:secret%3Avalue:tail",
            "client:id",
            "secret:value:tail",
        ),
        ("client+id:secret+value", "client id", "secret value"),
        (
            "a%2Bb%25%26%3D%C3%A9:s%2B%25%26%3D%E9%9B%AA",
            "a+b%&=é",
            "s+%&=雪",
        ),
        ("%252B:%2525", "%2B", "%25"),
        (
            "generated_ID-1:secret_ID-2",
            "generated_ID-1",
            "secret_ID-2",
        ),
        ("a&b=c:s&x=y", "a&b=c", "s&x=y"),
    ] {
        assert_eq!(
            ClientRegistry::decode_basic_auth_credentials(&header(payload.as_bytes())),
            Some((id.into(), secret.into()))
        );
    }
}

#[test]
fn oauth_basic_rejects_invalid_encodings() {
    for payload in [
        b"missing-colon".as_slice(),
        b"%:secret",
        b"id:%2",
        b"%GG:secret",
        b"id:%x0",
        b"id:%FF",
        b"%C3%28:secret",
        b"id:\xff",
    ] {
        assert!(ClientRegistry::decode_basic_auth_credentials(&header(payload)).is_none());
    }
    for value in [
        "Basic %%%",
        "Basic",
        "Bearer aWQ6c2VjcmV0",
        "Basic aWQ6c2VjcmV0=",
    ] {
        assert!(ClientRegistry::decode_basic_auth_credentials(value).is_none());
    }
}

#[test]
fn oauth_basic_authenticates_logical_credentials_without_raw_fallback() -> TestResult {
    let registry = ClientRegistry::new_process_local_for_tests();
    for (id, secret, wire) in [
        (
            "client: +%&=é",
            "secret: +%&=雪",
            "client%3A+%2B%25%26%3D%C3%A9:secret%3A+%2B%25%26%3D%E9%9B%AA",
        ),
        (
            "literal+client",
            "literal+secret",
            "literal%2Bclient:literal%2Bsecret",
        ),
        (
            "once%2Bclient",
            "once%25secret",
            "once%252Bclient:once%2525secret",
        ),
        ("plain_ID-1", "secret_ID-2", "plain_ID-1:secret_ID-2"),
    ] {
        let mut client = registration_client(id, None);
        client.token_endpoint_auth_method = "client_secret_basic".into();
        client.client_secret = Some(secret.into());
        assert!(registry.register(client));
        assert_eq!(
            registry
                .try_validate_basic_auth(&header(wire.as_bytes()))
                .map_err(|e| e.to_string())?,
            Some((id.into(), secret.into()))
        );
    }
    for raw in [
        "literal+client:literal+secret",
        "once%2Bclient:once%25secret",
        "literal%2Bclient:literal+secret",
        "once%252Bclient:once%25secret",
        "plain_ID-1:wrong",
    ] {
        assert!(registry
            .try_validate_basic_auth(&header(raw.as_bytes()))
            .map_err(|e| e.to_string())?
            .is_none());
    }
    let mut client = registration_client("post-client", None);
    client.token_endpoint_auth_method = "client_secret_post".into();
    client.client_secret = Some("secret".into());
    assert!(registry.register(client));
    assert!(registry
        .try_validate_basic_auth(&header(b"post-client:secret"))
        .map_err(|e| e.to_string())?
        .is_none());
    Ok(())
}
