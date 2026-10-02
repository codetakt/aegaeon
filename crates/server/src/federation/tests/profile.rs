fn payload(configuration: bool) -> Value {
    let statement = if configuration {
        sample_entity_config("https://subject.example", 1_700_000_000)
    } else {
        sample_subordinate_statement(
            "https://issuer.example",
            "https://subject.example",
            1_700_000_000,
        )
    };
    must_ok(serde_json::to_value(statement))
}

fn signed(value: &Value) -> String {
    let key = sample_signing_key();
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    super::purpose::sign_with_header(
        key,
        &json!({"alg":"ES256", "typ":"entity-statement+jwt", "kid":jwk["kid"]}),
        value,
    )
}

fn reject(value: &Value) {
    let jwt = signed(value);
    assert_federation_signature_only(&jwt, sample_signing_key());
    assert!(verify_entity_statement(&jwt, &sample_jwks()).is_err());
    if value["iss"] == value["sub"] {
        assert!(verify_entity_configuration(&jwt).is_err());
    }
}

fn accept(value: &Value) -> EntityStatement {
    let jwt = signed(value);
    let statement = must_ok(verify_entity_statement(&jwt, &sample_jwks()));
    let expected: EntityStatement = must_ok(serde_json::from_value(value.clone()));
    assert_eq!(
        must_ok(serde_json::to_value(&statement)),
        must_ok(serde_json::to_value(expected))
    );
    if value["iss"] == value["sub"] {
        must_ok(verify_entity_configuration(&jwt));
    }
    statement
}

#[test]
fn signed_profile_rejects_wrong_kind_presence_even_null() {
    let _guard = raw_json_env_guard();
    for (configuration, fields) in [
        (
            false,
            vec![
                "authority_hints",
                "trust_anchor_hints",
                "trust_marks",
                "trust_mark_issuers",
                "trust_mark_owners",
            ],
        ),
        (
            true,
            vec![
                "constraints",
                "metadata_policy",
                "metadata_policy_crit",
                "source_endpoint",
            ],
        ),
    ] {
        for field in fields {
            for value in [Value::Null, json!({}), json!([]), json!("extension")] {
                let mut claims = payload(configuration);
                claims[field] = value;
                reject(&claims);
            }
        }
    }
}

#[test]
fn signed_profile_checks_every_optional_claim_shape() {
    let _guard = raw_json_env_guard();
    for (configuration, fields) in [
        (
            true,
            vec![
                "authority_hints",
                "trust_anchor_hints",
                "trust_marks",
                "trust_mark_issuers",
                "trust_mark_owners",
                "metadata",
            ],
        ),
        (
            false,
            vec![
                "constraints",
                "metadata_policy",
                "source_endpoint",
                "metadata",
            ],
        ),
    ] {
        for field in fields {
            for value in [Value::Null, json!(17), json!(true)] {
                let mut claims = payload(configuration);
                claims[field] = value;
                reject(&claims);
            }
        }
    }
    for field in ["authority_hints", "trust_anchor_hints"] {
        for value in [
            json!([]),
            json!({}),
            json!([null]),
            json!([1]),
            json!(["not-an-identifier"]),
        ] {
            let mut claims = payload(true);
            claims[field] = value;
            reject(&claims);
        }
    }
    for field in ["constraints", "metadata_policy"] {
        let mut claims = payload(false);
        claims[field] = json!([]);
        reject(&claims);
    }
    for value in [
        json!([]),
        json!({"mark":null}),
        json!({"mark":{}}),
        json!({"mark":["bad"]}),
    ] {
        let mut claims = payload(true);
        claims["trust_mark_issuers"] = value;
        reject(&claims);
    }
    for owner in [
        Value::Null,
        json!({}),
        json!({"sub":"bad","jwks":sample_jwks_value()}),
        json!({"sub":"https://owner.example"}),
        json!({"sub":"https://owner.example","jwks":null}),
    ] {
        let mut claims = payload(true);
        claims["trust_mark_owners"] = json!({"mark":owner});
        reject(&claims);
    }
}

#[test]
fn signed_profile_valid_optional_fields_and_extensions_preserve_typed_values() {
    let _guard = raw_json_env_guard();
    let mut config = payload(true);
    config["authority_hints"] = json!(["https://unused.example", "https://unused.example"]);
    config["trust_anchor_hints"] = json!(["https://[::1]"]);
    config["trust_marks"] = json!([]);
    config["trust_mark_issuers"] = json!({"non-url-type":[], "another":["https://localhost"]});
    config["trust_mark_owners"] = json!({"non-url-type":{"sub":"https://owner.example", "jwks":sample_jwks_value(), "extension":null}});
    config["unknown_extension"] = json!({"allowed":null});
    config["aud"] = Value::Null;
    config["trust_anchor"] = Value::Null;
    accept(&config);
    let mut subordinate = payload(false);
    subordinate["constraints"] =
        json!({"max_path_length":1,"allowed_leaf_entity_types":["openid_provider"]});
    subordinate["metadata_policy"] =
        json!({"openid_provider":{"optional_parameter":{"value":null}}});
    subordinate["source_endpoint"] = json!("https://127.0.0.1:8443/fetch?tenant=a");
    accept(&subordinate);
}

#[test]
fn signed_profile_identifier_syntax_is_distinct_from_retrieval_safety() {
    let _guard = raw_json_env_guard();
    for id in [
        "https://pathless.example",
        "HTTPS://EXAMPLE.COM",
        "https://localhost",
        "https://[::1]:8443/path",
    ] {
        let mut claims = payload(true);
        claims["iss"] = json!(id);
        claims["sub"] = json!(id);
        claims["authority_hints"] = json!(["https://127.0.0.1"]);
        assert_eq!(accept(&claims).iss, id);
    }
    for id in [
        "",
        "http://example.com",
        "https:example.com",
        "https:///example.com",
        "https://@example.com",
        "https://user@example.com",
        "https://example.com?",
        "https://example.com#",
        " https://example.com",
        "https://example.com/space here",
        "https://example.com/\n",
        "https://example.com\\path",
    ] {
        for field in ["iss", "sub", "authority_hints", "trust_anchor_hints"] {
            let mut claims = payload(true);
            if field.ends_with("hints") {
                claims[field] = json!([id]);
            } else {
                claims["iss"] = json!(id);
                claims["sub"] = json!(id);
            }
            reject(&claims);
        }
    }
}

#[test]
fn signed_profile_metadata_null_check_is_one_parameter_deep() {
    let _guard = raw_json_env_guard();
    for configuration in [true, false] {
        for metadata in [
            Value::Null,
            json!([]),
            json!({"type":null}),
            json!({"type":[]}),
            json!({"type":"scalar"}),
            json!({"type":{"parameter":null}}),
        ] {
            let mut claims = payload(configuration);
            claims["metadata"] = metadata;
            reject(&claims);
        }
        let mut claims = payload(configuration);
        claims["metadata"] =
            json!({"empty":{}, "extension":{"nested":{"allowed_null":null}, "array":[null]}});
        accept(&claims);
    }
}

#[test]
fn signed_profile_checks_every_original_jwk_kid_before_material_selection() {
    let _guard = raw_json_env_guard();
    for configuration in [true, false] {
        let mut missing = payload(configuration);
        must_some(missing.as_object_mut()).remove("jwks");
        reject(&missing);
        for jwks in [
            Value::Null,
            json!([]),
            json!({}),
            json!({"keys":null}),
            json!({"keys":[]}),
            json!({"keys":[null]}),
        ] {
            let mut claims = payload(configuration);
            claims["jwks"] = jwks;
            reject(&claims);
        }
        for kid in [
            None,
            Some(Value::Null),
            Some(json!(12)),
            Some(sample_jwks_value()["keys"][0]["kid"].clone()),
        ] {
            let mut unused = sample_jwks_value()["keys"][0].clone();
            unused["use"] = json!("enc");
            match kid {
                Some(kid) => unused["kid"] = kid,
                None => {
                    must_some(unused.as_object_mut()).remove("kid");
                }
            }
            let mut claims = payload(configuration);
            must_some(claims["jwks"]["keys"].as_array_mut()).push(unused);
            reject(&claims);
        }
        let mut claims = payload(configuration);
        let mut unused = sample_jwks_value()["keys"][0].clone();
        unused["use"] = json!("enc");
        unused["kid"] = json!("unused");
        must_some(claims["jwks"]["keys"].as_array_mut()).push(unused);
        accept(&claims);
        claims["jwks"]["keys"][0]["use"] = json!("enc");
        reject(&claims);
    }
}

fn trust_mark(payload: &Value) -> String {
    let key = InMemoryKeyManager::new();
    let jwk = must_some(FederationKeyManager::federation_public_jwk(&key));
    super::purpose::sign_with_header(
        &key,
        &json!({"alg":"ES256","typ":"trust-mark+jwt","kid":jwk["kid"]}),
        payload,
    )
}

#[test]
fn signed_profile_checks_trust_mark_envelope_and_raw_type_without_accreditation() {
    let _guard = raw_json_env_guard();
    let mark_claims = json!({"iss":"https://untrusted-issuer.example", "sub":"https://subject.example", "iat":1_700_000_000,"trust_mark_type":"non-url-type"});
    let mark = trust_mark(&mark_claims);
    let mut claims = payload(true);
    claims["trust_marks"] =
        json!([{"trust_mark_type":"non-url-type","trust_mark":mark,"extension":null}]);
    accept(&claims);
    for envelope in [
        Value::Null,
        json!({}),
        json!({"id":"non-url-type","trust_mark":mark}),
        json!({"trust_mark_type":null,"trust_mark":mark}),
        json!({"trust_mark_type":"different","trust_mark":mark}),
        json!({"trust_mark_type":"non-url-type","trust_mark":null}),
        json!({"trust_mark_type":"non-url-type","trust_mark":"malformed"}),
    ] {
        claims["trust_marks"] = json!([envelope]);
        reject(&claims);
    }
    let mut alias = mark_claims.clone();
    must_some(alias.as_object_mut()).remove("trust_mark_type");
    alias["id"] = json!("non-url-type");
    for jwt in [
        trust_mark(&alias),
        format!("{}.", must_some(mark.rsplit_once('.')).0),
    ] {
        claims["trust_marks"] = json!([{"trust_mark_type":"non-url-type","trust_mark":jwt}]);
        reject(&claims);
    }
}

#[test]
fn signed_profile_refuses_all_present_unsupported_critical_claims() {
    let _guard = raw_json_env_guard();
    for configuration in [false, true] {
        for field in ["crit", "metadata_policy_crit"] {
            for value in [
                Value::Null,
                json!([]),
                json!({}),
                json!(["extension"]),
                json!(["iss"]),
                json!(["absent"]),
                json!(["extension", "extension"]),
            ] {
                let mut claims = payload(configuration);
                claims["extension"] = json!({});
                claims[field] = value;
                reject(&claims);
            }
        }
    }
}

#[test]
fn signed_profile_discovery_endpoints_are_typed_and_configuration_only() {
    let _guard = raw_json_env_guard();
    for field in [
        "federation_fetch_endpoint",
        "federation_list_endpoint",
        "federation_resolve_endpoint",
        "federation_trust_mark_status_endpoint",
        "federation_trust_mark_list_endpoint",
        "federation_trust_mark_endpoint",
        "federation_historical_keys_endpoint",
    ] {
        for configuration in [true, false] {
            let mut claims = payload(configuration);
            claims["metadata"] =
                json!({"federation_entity":{field:"https://localhost:8443/service?tenant=a"}});
            if !configuration
                && matches!(
                    field,
                    "federation_fetch_endpoint" | "federation_list_endpoint"
                )
            {
                reject(&claims);
            } else {
                accept(&claims);
            }
            for value in [
                Value::Null,
                json!(false),
                json!("https://@example.com"),
                json!("https://example.com#fragment"),
                json!("https://example.com/ space"),
                json!("https://example.com\\path"),
                json!("http://example.com"),
            ] {
                claims["metadata"]["federation_entity"][field] = value;
                reject(&claims);
            }
        }
    }
    for value in [
        Value::Null,
        json!(false),
        json!("https://@example.com"),
        json!("https://example.com#fragment"),
        json!("https://example.com\\path"),
    ] {
        let mut claims = payload(false);
        claims["source_endpoint"] = value;
        reject(&claims);
    }
}

#[test]
fn signed_profile_preserves_unverified_parser_and_checks_raw_duplicate_extensions() {
    let _guard = raw_json_env_guard();
    let mut claims = payload(true);
    claims["metadata_policy"] = json!({});
    must_ok(parse_entity_statement_unverified(&signed(&claims)));
    reject(&claims);
    let base = must_ok(serde_json::to_string(&payload(true)));
    let raw = format!(
        "{},\"extension\":{{\"x\":1,\"x\":2}}}}",
        must_some(base.strip_suffix('}'))
    );
    let key = sample_signing_key();
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    let header =
        encode_json_value(&json!({"alg":"ES256","typ":"entity-statement+jwt","kid":jwk["kid"]}));
    let input = format!("{}.{}", header, URL_SAFE_NO_PAD.encode(raw.as_bytes()));
    let jwt = format!(
        "{}.{}",
        input,
        URL_SAFE_NO_PAD.encode(must_ok(FederationKeyManager::sign_federation(
            key,
            input.as_bytes()
        )))
    );
    must_ok(parse_entity_statement_unverified(&jwt));
    assert_federation_signature_only(&jwt, key);
    assert!(verify_entity_statement(&jwt, &sample_jwks()).is_err());
}

#[test]
fn signed_profile_header_bans_do_not_depend_on_generic_unknown_header_rejection() {
    let _guard = raw_json_env_guard();
    for field in ["trust_chain", "peer_trust_chain"] {
        for value in [
            Value::Null,
            json!([]),
            json!("unknown"),
            json!(["compact.jwt.value"]),
        ] {
            let jwk = must_some(FederationKeyManager::federation_public_jwk(
                sample_signing_key(),
            ));
            let mut header = json!({"alg":"ES256","typ":"entity-statement+jwt","kid":jwk["kid"]});
            header[field] = value;
            let bytes = must_ok(serde_json::to_vec(&header));
            assert!(
                must_err(headers::validate_entity_statement_header_bytes(&bytes))
                    .to_string()
                    .contains("must not contain trust chain headers")
            );
            let jwt =
                super::purpose::sign_with_header(sample_signing_key(), &header, &payload(true));
            assert_federation_signature_only(&jwt, sample_signing_key());
            assert!(verify_entity_statement(&jwt, &sample_jwks()).is_err());
        }
    }
    must_ok(headers::validate_entity_statement_header_bytes(
        br#"{"ordinary_extension":null}"#,
    ));
}

#[test]
fn signed_constraint_shapes_and_entity_types_roundtrip() {
    let _guard = raw_json_env_guard();
    let mut claims = payload(false);
    for allowed in [json!([]), json!(["Custom", "custom", "Custom"])] {
        claims["constraints"] = json!({"allowed_entity_types": allowed, "unknown_extension": null});
        let jwt = signed(&claims);
        let parsed = must_ok(parse_entity_statement_unverified(&jwt));
        let verified = accept(&claims);
        for statement in [parsed, verified] {
            let roundtrip = must_ok(serde_json::to_value(statement));
            assert_eq!(roundtrip["constraints"]["allowed_entity_types"], allowed);
        }
    }
    for field in [
        "allowed_entity_types",
        "allowed_leaf_entity_types",
        "max_path_length",
    ] {
        for value in [Value::Null, json!(true), json!({}), json!("wrong")] {
            claims["constraints"] = json!({field:value});
            reject(&claims);
        }
    }
    for value in [
        json!([1]),
        json!(["custom", null]),
        json!(["federation_entity"]),
    ] {
        claims["constraints"] = json!({"allowed_entity_types":value});
        reject(&claims);
    }
    claims["constraints"] = json!({"allowed_leaf_entity_types":[1]});
    reject(&claims);
    claims["constraints"] =
        json!({"max_path_length":0,"allowed_entity_types":[],"allowed_leaf_entity_types":[]});
    accept(&claims);
}

#[test]
fn signed_critical_policy_admission_preserves_supported_names_without_occurrence() {
    let _guard = raw_json_env_guard();
    for names in [json!(["intersect"]), json!(["intersect", "intersect"])] {
        let mut claims = payload(false);
        claims["metadata_policy_crit"] = names.clone();
        for statement in [
            accept(&claims),
            must_ok(parse_entity_statement_unverified(&signed(&claims))),
        ] {
            must_ok(validate_entity_statement(&statement, 1_700_000_000));
            let serialized = must_ok(serde_json::to_value(&statement));
            assert_eq!(serialized["metadata_policy_crit"], names);
            let roundtrip: EntityStatement = must_ok(serde_json::from_value(serialized));
            assert_eq!(
                roundtrip.metadata_policy_crit,
                statement.metadata_policy_crit
            );
        }
        claims["iss"] = claims["sub"].clone();
        reject(&claims);
        let typed: EntityStatement = must_ok(serde_json::from_value(claims));
        assert!(validate_entity_statement(&typed, 1_700_000_000).is_err());
    }
    for value in [
        Value::Null,
        json!([]),
        json!({}),
        json!("intersect"),
        json!(true),
        json!([1]),
        json!(["intersect", null]),
        json!([""]),
        json!(["Intersect"]),
        json!(["INTERSECT"]),
        json!(["custom"]),
        json!(["value"]),
        json!(["add"]),
        json!(["default"]),
        json!(["one_of"]),
        json!(["subset_of"]),
        json!(["superset_of"]),
        json!(["essential"]),
    ] {
        let mut claims = payload(false);
        claims["metadata_policy_crit"] = value;
        reject(&claims);
        if let Ok(typed) = serde_json::from_value::<EntityStatement>(claims.clone()) {
            // Direct serde cannot distinguish null from omission; only test
            // representable presence here. Raw admission above rejects null.
            if typed.metadata_policy_crit.is_some() {
                assert!(validate_entity_statement(&typed, 1_700_000_000).is_err());
            }
        }
    }
    assert!(accept(&payload(false)).metadata_policy_crit.is_none());
}

#[test]
fn signed_critical_policy_duplicate_json_member_is_rejected() {
    let _guard = raw_json_env_guard();
    let base = must_ok(serde_json::to_string(&payload(false)));
    let raw = format!(
        "{},\"metadata_policy_crit\":[\"intersect\"],\"metadata_policy_crit\":[\"intersect\"]}}",
        must_some(base.strip_suffix('}'))
    );
    let key = sample_signing_key();
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    let header =
        encode_json_value(&json!({"alg":"ES256","typ":"entity-statement+jwt","kid":jwk["kid"]}));
    let input = format!("{}.{}", header, URL_SAFE_NO_PAD.encode(raw.as_bytes()));
    let jwt = format!(
        "{}.{}",
        input,
        URL_SAFE_NO_PAD.encode(must_ok(FederationKeyManager::sign_federation(
            key,
            input.as_bytes()
        )))
    );
    assert_federation_signature_only(&jwt, key);
    assert!(verify_entity_statement(&jwt, &sample_jwks()).is_err());
}

#[test]
fn supported_metadata_critical_name_does_not_enable_payload_or_header_extensions() {
    let _guard = raw_json_env_guard();
    let mut claims = payload(false);
    claims["metadata_policy_crit"] = json!(["intersect"]);
    claims["crit"] = json!(["intersect"]);
    claims["intersect"] = json!({});
    reject(&claims);
    must_some(claims.as_object_mut()).remove("crit");
    let key = sample_signing_key();
    let jwk = must_some(FederationKeyManager::federation_public_jwk(key));
    let header = json!({"alg":"ES256","typ":"entity-statement+jwt","kid":jwk["kid"],"crit":["intersect"],"intersect":true});
    let jwt = super::purpose::sign_with_header(key, &header, &claims);
    assert_federation_signature_only(&jwt, key);
    assert!(verify_entity_statement(&jwt, &sample_jwks()).is_err());
}
