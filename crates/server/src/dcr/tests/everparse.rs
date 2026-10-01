use super::super::everparse::{
    encode_dcr_registration_request, finalize_dcr_everparse_self_check,
    should_run_dcr_everparse_self_check,
};
use super::*;
use crate::policy::DEVICE_CODE_GRANT_TYPE;
use ffi::dcr_parser::DcrParseError;

// Decode the prefix using its declared redirect length, including nonempty fixtures.
fn encoded_fields(meta: &ClientRegistration) -> Result<(u8, u32, u8, u32), String> {
    use std::io::{Cursor, Read, Seek, SeekFrom};
    fn word(cursor: &mut Cursor<Vec<u8>>) -> Result<u32, String> {
        let mut bytes = [0; 4];
        cursor.read_exact(&mut bytes).map_err(|e| e.to_string())?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn byte(cursor: &mut Cursor<Vec<u8>>) -> Result<u8, String> {
        let mut bytes = [0];
        cursor.read_exact(&mut bytes).map_err(|e| e.to_string())?;
        Ok(bytes[0])
    }
    let mut cursor = Cursor::new(encode_dcr_registration_request(meta).map_err(|e| e.to_string())?);
    assert_eq!(word(&mut cursor)?, 1);
    let redirect_length = word(&mut cursor)?;
    cursor
        .seek(SeekFrom::Current(i64::from(redirect_length)))
        .map_err(|e| e.to_string())?;
    Ok((
        byte(&mut cursor)?,
        word(&mut cursor)?,
        byte(&mut cursor)?,
        word(&mut cursor)?,
    ))
}

#[test]
fn dcr_everparse_grant_masks_preserve_existing_and_device_bits() -> DcrTestResult {
    let grants = [
        ("authorization_code", 0x1),
        ("refresh_token", 0x2),
        ("client_credentials", 0x4),
        (JWT_BEARER_GRANT_TYPE, 0x8),
        (TOKEN_EXCHANGE_GRANT_TYPE, 0x10),
        (DEVICE_CODE_GRANT_TYPE, 0x20),
    ];
    for redirects in [
        vec![],
        vec![
            "https://client.example/callback".into(),
            "https://client.example/second".into(),
        ],
    ] {
        let mut meta = ClientRegistration {
            redirect_uris: Some(redirects),
            ..Default::default()
        };
        for (grant, bit) in grants {
            meta.grant_types = Some(vec![grant.into()]);
            assert_eq!(encoded_fields(&meta)?.2, 1);
            assert_eq!(encoded_fields(&meta)?.3, bit);
            meta.grant_types = Some(vec![
                grant.into(),
                DEVICE_CODE_GRANT_TYPE.into(),
                grant.into(),
            ]);
            assert_eq!(encoded_fields(&meta)?.3, bit | 0x20);
        }
        meta.grant_types = Some(grants.iter().map(|(grant, _)| (*grant).into()).collect());
        assert_eq!(encoded_fields(&meta)?.3, 0x3f);
    }
    Ok(())
}

#[test]
fn dcr_everparse_code_default_preserves_presence_and_auth_tags() -> DcrTestResult {
    let mut meta = ClientRegistration::default();
    assert_eq!(encoded_fields(&meta)?, (0, 1, 0, 1));
    meta.grant_types = Some(vec![]);
    for (method, tag) in [
        ("none", 0),
        ("client_secret_basic", 1),
        ("client_secret_post", 2),
        ("private_key_jwt", 3),
        ("tls_client_auth", 4),
        ("self_signed_tls_client_auth", 5),
    ] {
        meta.token_endpoint_auth_method = Some(method.into());
        assert_eq!(encoded_fields(&meta)?, (1, tag, 1, 0));
    }
    Ok(())
}

#[test]
fn dcr_everparse_rejects_unknown_and_misspelled_device_grants() -> DcrTestResult {
    for grant in [
        "unknown",
        "urn:ietf:params:oauth:grant-type:DEVICE_CODE",
        "urn:ietf:params:oauth:grant-type:device_code ",
    ] {
        let meta = ClientRegistration {
            grant_types: Some(vec![grant.into()]),
            ..Default::default()
        };
        assert!(matches!(
            encode_dcr_registration_request(&meta),
            Err(DcrEverparseSelfCheckError::Encode(_))
        ));
    }
    Ok(())
}

#[test]
fn dcr_everparse_native_device_self_check_and_truncation_control() -> DcrTestResult {
    for grants in [
        vec![DEVICE_CODE_GRANT_TYPE.into()],
        vec!["authorization_code".into(), DEVICE_CODE_GRANT_TYPE.into()],
    ] {
        let meta = ClientRegistration {
            redirect_uris: Some(vec!["https://client.example/callback".into()]),
            grant_types: Some(grants),
            ..Default::default()
        };
        // This intentionally requires the actual native supplier; ParserUnavailable is failure.
        must_ok!(
            everparse_self_check_registration_with_runtime(&meta, true),
            "native device self-check"
        );
        let encoded = must_ok!(encode_dcr_registration_request(&meta), "device encoding");
        assert_eq!(
            ffi::dcr_parser::check_registration_request(&encoded[..encoded.len() - 1]),
            Err(DcrParseError::InvalidPayload)
        );
    }
    Ok(())
}

#[test]
fn required_dcr_self_check_preserves_parser_failures() -> DcrTestResult {
    for (parser, expected) in [
        (
            DcrParseError::ParserUnavailable,
            DcrEverparseSelfCheckError::ParserUnavailable,
        ),
        (
            DcrParseError::InvalidPayload,
            DcrEverparseSelfCheckError::InvalidPayload,
        ),
    ] {
        assert_eq!(
            finalize_dcr_everparse_self_check(true, Err(parser)),
            Err(expected)
        );
    }
    Ok(())
}

#[cfg(not(feature = "verified-claim"))]
#[test]
fn compat_profile_allows_dcr_self_check_bypass_when_disabled() -> DcrTestResult {
    let meta = ClientRegistration {
        grant_types: Some(vec!["unknown".into()]),
        ..Default::default()
    };
    must_ok!(
        everparse_self_check_registration_with_runtime(&meta, false),
        "disabled check bypasses encoding"
    );
    assert!(!should_run_dcr_everparse_self_check(false));
    assert!(should_run_dcr_everparse_self_check(true));
    assert_eq!(
        finalize_dcr_everparse_self_check(false, Err(DcrParseError::ParserUnavailable)),
        Ok(())
    );
    Ok(())
}

#[cfg(feature = "verified-claim")]
#[test]
fn verified_claim_profile_requires_dcr_self_check_without_env_gate() -> DcrTestResult {
    assert!(should_run_dcr_everparse_self_check(false));
    let meta = ClientRegistration {
        grant_types: Some(vec!["unknown".into()]),
        ..Default::default()
    };
    assert!(matches!(
        everparse_self_check_registration_with_runtime(&meta, false),
        Err(DcrEverparseSelfCheckError::Encode(_))
    ));

    let err = must_err!(
        finalize_dcr_everparse_self_check(true, Err(DcrParseError::ParserUnavailable)),
        "strict profile must fail closed when DCR parser is unavailable",
    );

    assert_eq!(err, DcrEverparseSelfCheckError::ParserUnavailable);
    Ok(())
}
