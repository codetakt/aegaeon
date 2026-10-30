use super::*;

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL"]
fn redis_bound_code_envelope_requires_version_and_explicit_expectation() -> StoreTestResult {
    let url = redis_url()?;
    let f = BoundFixture::new(&url, None)?;
    let mut conn = connect(&url)?;
    let original = get(&mut conn, &f.code_key)?.ok_or("code")?;
    for mutation in ["missing-version", "v2", "missing-key", "bad-key"] {
        let mut value: serde_json::Value =
            serde_json::from_str(&original).map_err(|e| e.to_string())?;
        match mutation {
            "missing-version" => {
                value
                    .as_object_mut()
                    .ok_or("record")?
                    .remove("storage_version");
            }
            "v2" => value["storage_version"] = serde_json::json!(2),
            "missing-key" => {
                value.as_object_mut().ok_or("record")?.remove("dpop_jkt");
            }
            _ => value["dpop_jkt"] = serde_json::json!("bad"),
        }
        let changed = value.to_string();
        set(&mut conn, &f.code_key, &changed)?;
        assert!(
            f.issuer.code_store.try_get_code(&f.code).is_err(),
            "{mutation}"
        );
        assert!(
            !matches!(f.exchange(&f.key), Ok(TokenResponse::Success { .. })),
            "{mutation}"
        );
        assert_eq!(
            get(&mut conn, &f.code_key)?.as_deref(),
            Some(changed.as_str())
        );
        f.assert_counts(0)?;
    }
    set(&mut conn, &f.code_key, &original)?;
    success(f.exchange(&f.key)?)?;
    f.assert_counts(1)?;
    let f = BoundFixture::new(&url, None)?;
    let mut value: serde_json::Value =
        serde_json::from_str(&get(&mut conn, &f.code_key)?.ok_or("code")?)
            .map_err(|e| e.to_string())?;
    value["dpop_jkt"] = serde_json::Value::Null;
    set(&mut conn, &f.code_key, &value.to_string())?;
    assert!(f
        .issuer
        .code_store
        .try_get_code(&f.code)?
        .ok_or("unbound")?
        .dpop_jkt
        .is_none());
    assert!(matches!(
        f.issuer.exchange_code_for_tokens(request(&f.code), None)?,
        TokenResponse::Success { .. }
    ));
    Ok(())
}

#[test]
#[ignore = "requires isolated AEGAEON_TEST_REDIS_URL"]
fn redis_bound_code_v3_isolated_from_reconstructed_v2_reader_writer() -> StoreTestResult {
    let url = redis_url()?;
    let f = BoundFixture::new(&url, None)?;
    let mut conn = connect(&url)?;
    let original = get(&mut conn, &f.code_key)?.ok_or("code")?;
    // This is a reconstruction of the preserved v2 key builder, not an old
    // process or a rolling-upgrade claim. Production rollout requires draining.
    let mut hash = aegaeon_crypto::hash::Sha256Hasher::new();
    hash.update(b"aegaeon:authcode:v2");
    hash.update(&(f.code.len() as u64).to_be_bytes());
    hash.update(f.code.as_bytes());
    let prefix = f
        .code_key
        .rsplit_once(":code:")
        .ok_or("prefix")?
        .0
        .replace(":authcode:v3", ":authcode:v2");
    let old_key = format!("{prefix}:code:{}", URL_SAFE_NO_PAD.encode(hash.finalize()));
    assert_eq!(
        get(&mut conn, &old_key)?,
        None,
        "v2 reader cannot find newly bound authority"
    );
    let mut old: serde_json::Value = serde_json::from_str(&original).map_err(|e| e.to_string())?;
    old.as_object_mut()
        .ok_or("object")?
        .remove("storage_version");
    old.as_object_mut().ok_or("object")?.remove("dpop_jkt");
    let old = old.to_string();
    redis::cmd("SET")
        .arg(&old_key)
        .arg(&old)
        .arg("EX")
        .arg(300)
        .query::<()>(&mut conn)
        .map_err(|e| e.to_string())?;
    redis::cmd("DEL")
        .arg(&f.code_key)
        .query::<()>(&mut conn)
        .map_err(|e| e.to_string())?;
    assert!(f.issuer.code_store.try_get_code(&f.code)?.is_none());
    assert!(invalid_code(f.exchange(&f.key)));
    f.assert_counts(0)?;
    assert_eq!(get(&mut conn, &old_key)?.as_deref(), Some(old.as_str()));
    let ttl: i64 = redis::cmd("TTL")
        .arg(&old_key)
        .query(&mut conn)
        .map_err(|e| e.to_string())?;
    assert!(ttl > 0 && ttl <= 300);
    set(&mut conn, &f.code_key, &original)?;
    success(f.exchange(&f.key)?)?;
    assert_eq!(get(&mut conn, &old_key)?.as_deref(), Some(old.as_str()));
    redis::cmd("DEL")
        .arg(&old_key)
        .query::<()>(&mut conn)
        .map_err(|e| e.to_string())?;
    Ok(())
}
