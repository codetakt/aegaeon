use super::*;

pub(super) fn plain() -> Vec<(&'static str, Value)> {
    let mut cases = Vec::new();
    for redirects in [
        json!(7),
        json!([7]),
        json!([]),
        json!(["private-sentinel"]),
        json!(["https://client.example/callback#fragment"]),
        json!(["ftp://client.example/callback"]),
        json!(["https://user@client.example/callback"]),
    ] {
        let mut value = metadata();
        value["redirect_uris"] = redirects;
        cases.push(("invalid_redirect_uri", value));
    }
    for (field, invalid) in [
        ("post_logout_redirect_uris", json!(["private-sentinel"])),
        ("post_logout_redirect_uris", json!([7])),
        ("jwks", json!(7)),
        ("backchannel_logout_uri", json!("private-sentinel")),
        ("scope", json!("bad\\é")),
    ] {
        let mut value = metadata();
        value[field] = invalid;
        cases.push(("invalid_client_metadata", value));
    }
    cases
}

pub(super) fn claims() -> Value {
    json!({"iss":"https://ssa.example", "exp":4102444800_u64,
        "redirect_uris":["https://client.example/callback"]})
}

fn sign(claims: &Value) -> TestResult<String> {
    Ok(jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa2048-private.pk8.pem"
        )))?,
    )?)
}

pub(super) fn with_statement(claims: Value) -> TestResult<Value> {
    let mut value = metadata();
    value["software_statement"] = json!(sign(&claims)?);
    Ok(value)
}

pub(super) fn statements() -> TestResult<Vec<(&'static str, Value)>> {
    let mut cases = Vec::new();
    for (field, value) in [
        ("iss", json!("https://other.example")),
        ("exp", json!(1)),
        ("redirect_uris", json!([7])),
        ("software_statement", json!("nested-private-sentinel")),
    ] {
        let mut statement = claims();
        statement[field] = value;
        cases.push(("invalid_software_statement", with_statement(statement)?));
    }
    let signed = sign(&claims())?;
    let mut corrupted = signed.into_bytes();
    let index = corrupted
        .iter()
        .rposition(|byte| *byte == b'.')
        .ok_or_else(|| io::Error::other("missing JWT signature"))?
        + 1;
    corrupted[index] = if corrupted[index] == b'A' { b'B' } else { b'A' };
    let unsupported = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims(),
        &jsonwebtoken::EncodingKey::from_secret(b"synthetic-signing-secret"),
    )?;
    for statement in [
        "private-sentinel".into(),
        "bm90LWpzb24.e30.c2ln".into(),
        String::from_utf8(corrupted)?,
        unsupported,
    ] {
        let mut value = metadata();
        value["software_statement"] = json!(statement);
        cases.push(("invalid_software_statement", value));
    }
    let mut bad_redirect = claims();
    bad_redirect["redirect_uris"] = json!(["private-sentinel"]);
    let mut value = with_statement(bad_redirect)?;
    value["redirect_uris"] = json!(["private-sentinel"]);
    cases.push(("invalid_redirect_uri", value));
    let mut conflict = claims();
    conflict["scope"] = json!("different");
    cases.push(("invalid_client_metadata", with_statement(conflict)?));
    Ok(cases)
}
