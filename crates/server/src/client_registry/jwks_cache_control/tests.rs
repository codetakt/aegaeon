use super::*;
use std::time::UNIX_EPOCH;

const DATE_1994: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
const UTC_1994: i128 = 784_111_777_000_000_000;
fn headers(fields: &[(&str, &[u8])]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (name, value) in fields {
        h.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value).unwrap(),
        );
    }
    h
}
fn metadata(fields: &[(&str, &[u8])]) -> CacheMetadata {
    CacheMetadata::from_headers(
        &headers(fields),
        DateContext::from_system_time(UNIX_EPOCH + Duration::from_secs(784_111_777)),
    )
}
fn timing() -> ResponseTiming {
    let now = Instant::now();
    ResponseTiming {
        request: now,
        receipt: now,
        receipt_utc: Some(UTC_1994),
    }
}
fn seconds(n: u64) -> Option<u128> {
    Some(u128::from(n) * 1_000_000_000)
}

#[test]
fn combined_octet_grammar_quotes_extensions_and_normal_lifetime() {
    for fields in [
        vec![("Cache-Control", b"public, mAx-aGe=120".as_slice())],
        vec![
            (
                "Cache-Control",
                b"x=\"no-store, max-age=0, \\\"x\\\\z\x80\"".as_slice(),
            ),
            ("Cache-Control", b",, mAx-aGe=\"120\",,".as_slice()),
        ],
        vec![
            ("Cache-Control", b"x=\"one".as_slice()),
            ("Cache-Control", b"two\",max-age=120".as_slice()),
        ],
    ] {
        let m = metadata(&fields);
        let time = timing();
        let f = m.freshness(time, 300);
        assert!(m.permits_retention());
        assert_eq!(f.lifetime, seconds(120));
        assert!(f.reusable(time.receipt + Duration::from_secs(119)));
        assert!(!f.reusable(time.receipt + Duration::from_secs(120)));
    }
}

#[test]
fn malformed_duplicate_and_known_argument_shapes_do_not_grant_default() {
    for input in [
        b"max-age".as_slice(),
        b"max-age=",
        b"max-age=-1",
        b"max-age=+1",
        b"max-age=1.5",
        b"max-age=\" 1\"",
        b"max-age=\"\xff\"",
        b"max-age=\"1",
        b"max-age=1,max-age=1",
        b"no-store=x",
        b"no-transform=1",
        b"no-transform=\"1\"",
        b"must-understand=x",
        b"no-cache=\"bad:name\"",
        b"private=\"bad/name\"",
        b"no-cache=\"bad name\"",
        b"private=\"\\\"bad\"",
        b"max-age =1",
    ] {
        let m = metadata(&[("Cache-Control", input)]);
        assert!(!m.permits_retention(), "{input:?}");
        assert!(
            !m.freshness(timing(), 300).reusable(Instant::now()),
            "{input:?}"
        );
    }
    let m = metadata(&[
        ("Cache-Control", b"max-age=1"),
        ("Cache-Control", b"MAX-AGE=1"),
    ]);
    assert!(!m.permits_retention());
}

#[test]
fn finite_numeric_boundaries_saturate_before_cap_and_scan_suffix() {
    for (wire, expected) in [
        ("0", 0),
        ("1", 1),
        ("86400", 86400),
        ("86401", 86400),
        ("2147483648", 86400),
        ("18446744073709551615", 86400),
        ("18446744073709551616", 86400),
    ] {
        let value = format!("max-age={wire}");
        assert_eq!(
            metadata(&[("Cache-Control", value.as_bytes())])
                .freshness(timing(), 300)
                .lifetime,
            seconds(expected)
        );
    }
    let long = "9".repeat(8193);
    assert_eq!(delta_seconds(long.as_bytes()), Some(u64::MAX));
    assert_eq!(delta_seconds(format!("{long}x").as_bytes()), None);
    let m = metadata(&[
        ("Cache-Control", b"max-age=86400"),
        ("Age", long.as_bytes()),
    ]);
    let f = m.freshness(timing(), 300);
    assert!(!f.reusable(Instant::now()));
    assert_eq!(
        saturated_age(Duration::MAX.as_nanos(), 1),
        Duration::MAX.as_nanos()
    );
    // These finite vectors complement the source loop argument; 8193 is not a domain cap.
}

#[test]
fn restrictions_qualified_fields_and_application_precedence() {
    for input in [
        b"no-store,max-age=60".as_slice(),
        b"public,no-store",
        b"no-store,must-understand",
        b"private",
        b"private=ETag",
        b"private=\"\"",
    ] {
        assert!(!metadata(&[("Cache-Control", input)]).permits_retention());
    }
    for input in [
        b"no-cache,max-age=60".as_slice(),
        b"no-cache=\"ETag, Last-Modified\",max-age=60",
        b"no-cache=ETag,max-age=60",
        b"no-cache=\",,\",max-age=60",
        b"no-cache=\"E\\Tag\",no-cache,max-age=60",
    ] {
        let m = metadata(&[("Cache-Control", input)]);
        assert!(m.permits_retention());
        let f = m.freshness(timing(), 300);
        assert!(f.no_cache);
        assert!(!f.reusable(Instant::now()));
    }
    for input in [
        b"s-maxage=120,max-age=60".as_slice(),
        b"s-maxage=60,max-age=120",
        b"max-age=60,must-revalidate,proxy-revalidate,must-understand,no-transform",
    ] {
        let m = metadata(&[("Cache-Control", input)]);
        assert!(m.permits_retention());
        assert_eq!(m.freshness(timing(), 300).lifetime, seconds(60));
    }
}

#[test]
fn corrected_age_includes_final_response_and_residence_delay() {
    let mut time = timing();
    time.request = time.receipt - Duration::from_secs(2);
    time.receipt_utc = Some(UTC_1994 + 10_000_000_000);
    let m = metadata(&[
        ("Cache-Control", b"max-age=20"),
        ("Date", DATE_1994.as_bytes()),
        ("Age", b"5"),
    ]);
    let f = m.freshness(time, 300);
    assert_eq!(f.initial_age, seconds(10));
    assert_eq!(
        f.current_age(time.receipt + Duration::from_secs(3)),
        seconds(13)
    );
    assert_eq!(
        f.remaining(time.receipt + Duration::from_secs(3)),
        Some(Duration::from_secs(7))
    );
    time.receipt_utc = Some(UTC_1994);
    let f = m.freshness(time, 300);
    assert_eq!(f.initial_age, seconds(7));
    assert!(!f.reusable(time.receipt + Duration::from_secs(13)));
}

#[test]
fn age_uses_first_member_of_first_line_without_valid_value_search() {
    for (age, expected) in [
        (b"5, 99".as_slice(), Some(5)),
        (b"bad, 0", None),
        (b",0", None),
        (b" 5\t", Some(5)),
    ] {
        let m = metadata(&[("Age", age), ("Age", b"0")]);
        let f = m.freshness(timing(), 300);
        assert_eq!(f.initial_age, expected.and_then(seconds));
    }
    assert_eq!(
        metadata(&[]).freshness(timing(), 300).initial_age,
        seconds(0)
    );
}

#[test]
fn dates_expires_precedence_and_invalid_explicit_values() {
    for (expires, expected) in [
        ("Sun, 06 Nov 1994 08:50:37 GMT", 60),
        (DATE_1994, 0),
        ("Sun, 06 Nov 1994 08:48:37 GMT", 0),
        ("0", 0),
    ] {
        let m = metadata(&[("Expires", expires.as_bytes())]);
        assert_eq!(m.freshness(timing(), 300).lifetime, seconds(expected));
    }
    let m = metadata(&[("Date", b"bad")]);
    assert!(m.freshness(timing(), 300).initial_age.is_none());
    let m = metadata(&[
        ("Date", DATE_1994.as_bytes()),
        ("Date", DATE_1994.as_bytes()),
    ]);
    assert!(m.freshness(timing(), 300).initial_age.is_none());
    let m = metadata(&[
        ("Expires", DATE_1994.as_bytes()),
        ("Expires", DATE_1994.as_bytes()),
    ]);
    assert!(m.freshness(timing(), 300).lifetime.is_none());
    for explicit in [b"max-age=60".as_slice(), b"s-maxage=60"] {
        let m = metadata(&[
            ("Cache-Control", explicit),
            ("Expires", b"0"),
            ("Expires", b"Sun, 06 Nov 1994 08:49:60 GMT"),
        ]);
        assert_eq!(m.freshness(timing(), 300).lifetime, seconds(60));
    }
}

#[test]
fn exact_default_and_explicit_nanosecond_boundaries() {
    for m in [
        metadata(&[]),
        metadata(&[("Cache-Control", b"max-age=300")]),
    ] {
        let time = timing();
        let f = m.freshness(time, 300);
        assert!(f.reusable(time.receipt + Duration::from_nanos(299_999_999_999)));
        for n in [300_000_000_000, 300_000_000_001, 300_999_999_999] {
            assert!(!f.reusable(time.receipt + Duration::from_nanos(n)));
        }
    }
}

#[test]
fn unavailable_clock_and_valid_leap_second_do_not_grant_heuristic() {
    let mut time = timing();
    time.request = time.receipt + Duration::from_nanos(1);
    assert!(metadata(&[]).freshness(time, 300).initial_age.is_none());
    time = timing();
    let f = metadata(&[]).freshness(time, 300);
    assert!(f
        .current_age(time.receipt - Duration::from_nanos(1))
        .is_none());
    let unavailable =
        DateContext::from_system_time(UNIX_EPOCH + Duration::from_secs(253_402_300_800));
    let m = CacheMetadata::from_headers(
        &headers(&[("Date", b"Sunday, 06-Nov-94 08:49:37 GMT")]),
        unavailable,
    );
    assert!(matches!(m.date, Metadata::ClockOutOfRange));
    time.receipt_utc = None;
    assert!(metadata(&[]).freshness(time, 300).initial_age.is_none());
    let m = metadata(&[("Date", b"Sun, 06 Nov 1994 08:49:60 GMT")]);
    assert!(matches!(m.date, Metadata::Valid(_)));
    assert!(m.freshness(timing(), 300).initial_age.is_none());
    let m = metadata(&[("Expires", b"Sun, 06 Nov 1994 08:49:60 GMT")]);
    assert!(matches!(m.expires, Metadata::Valid(_)));
    assert!(m.freshness(timing(), 300).lifetime.is_none());
}

#[test]
fn response_304_group_inheritance_replacement_and_absolute_expiration() {
    let context = DateContext::from_system_time(UNIX_EPOCH + Duration::from_secs(784_111_777));
    let old = metadata(&[("Cache-Control", b"max-age=300"), ("Age", b"290")]);
    let inherited = old.freshen(&HeaderMap::new(), context);
    let f = inherited.freshness(timing(), 300);
    assert_eq!(f.lifetime, seconds(300));
    assert_eq!(f.initial_age, seconds(0));
    let old = metadata(&[
        ("Cache-Control", b"max-age=300"),
        ("Expires", b"Sun, 06 Nov 1994 08:50:37 GMT"),
    ]);
    let replacement = old.freshen(
        &headers(&[
            ("Cache-Control", b"public"),
            ("Date", b"Sun, 06 Nov 1994 08:50:07 GMT"),
        ]),
        context,
    );
    let mut time = timing();
    time.receipt_utc = Some(UTC_1994 + 30_000_000_000);
    assert_eq!(replacement.freshness(time, 300).lifetime, seconds(30));
    assert_eq!(
        metadata(&[])
            .freshen(&HeaderMap::new(), context)
            .freshness(timing(), 300)
            .lifetime,
        seconds(300)
    );
}

#[test]
fn response_304_restrictions_and_vary_empty_nonempty_invalid_mixtures() {
    let context = DateContext::capture();
    let old = metadata(&[("Cache-Control", b"max-age=300")]);
    for fields in [
        vec![("Cache-Control", b"no-store".as_slice())],
        vec![("Cache-Control", b"private".as_slice())],
        vec![("Vary", b"Accept-Encoding".as_slice())],
        vec![("Vary", b"\"x\"".as_slice())],
    ] {
        assert!(!old.freshen(&headers(&fields), context).permits_retention());
    }
    for fields in [
        vec![("Vary", b" ,\t,".as_slice()), ("Vary", b"".as_slice())],
        vec![],
    ] {
        assert!(metadata(&fields).permits_retention());
    }
    for member in [
        b"Accept-Encoding".as_slice(),
        b"*",
        b"x, *",
        b"x:y",
        b"\"x\"",
        b"\xff",
    ] {
        assert!(!metadata(&[("Vary", b",,"), ("Vary", member), ("Vary", b"")]).permits_retention());
    }
}
