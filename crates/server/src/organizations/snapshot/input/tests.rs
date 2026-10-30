use super::*;
use crate::subject_ownership::history::sha256_hex;
use serde_json::json;
use std::io::Cursor;

#[test]
fn independent_python_framing_fixture_agrees_with_native_consumer() {
    // Fixed bytes produced by scripts/tests/test_organization_snapshot.py; its
    // SHA framing is independent of the native HashChain used by the exporter.
    let bytes = include_bytes!("fixtures/independent-v1.jsonl");
    let expected = Scope {
        environment_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
        domain_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
    };
    let mut input = Input::new(Cursor::new(bytes), expected, &sha256_hex(bytes)).unwrap();
    let row = input.next_row().unwrap().unwrap();
    assert_eq!(row.data["external_id"], "School/É");
    assert_eq!(row.data["revision"].as_i64(), Some(i64::MAX));
    assert!(input.next_row().unwrap().is_none());
    assert_eq!(input.finish().unwrap().bytes, bytes.len() as u64);
}

fn scope() -> Scope {
    Scope {
        environment_id: Uuid::from_u128(1),
        domain_id: Uuid::from_u128(2),
    }
}

fn fixture(rows: &[(&str, &str, &str)]) -> Vec<u8> {
    let header = super::super::Header {
        record: "header",
        version: 1,
        snapshot_id: Uuid::from_u128(3),
        scope: scope(),
        captured_at: "2026-10-30T00:00:00.000000Z".into(),
        credential_transfer: false,
    };
    let mut bytes = super::super::line(&header).unwrap();
    let mut chains: Vec<_> = SECTIONS.iter().map(|s| section_digest(s.name)).collect();
    for (section, key, data) in rows {
        let index = SECTIONS.iter().position(|s| s.name == *section).unwrap();
        chains[index].push(key, data.as_bytes()).unwrap();
        bytes.extend(
            format!(
                "{{\"record\":\"row\",\"section\":{},\"key\":{},\"data\":{data}}}\n",
                json!(section),
                json!(key)
            )
            .as_bytes(),
        );
    }
    let sections: Vec<_> = SECTIONS
        .iter()
        .zip(chains)
        .map(|(s, chain)| {
            let (count, digest) = chain.finish();
            super::super::SectionDigest {
                section: s.name,
                count,
                sha256: hex_digest(&digest),
            }
        })
        .collect();
    let manifest = super::super::Manifest {
        record: "manifest",
        version: 1,
        snapshot_id: header.snapshot_id,
        scope: scope(),
        sections: &sections,
        content_bytes: bytes.len() as u64,
    };
    bytes.extend(super::super::line(&manifest).unwrap());
    bytes
}

fn consume(bytes: &[u8]) -> Result<IntegrityReceipt> {
    let mut input = Input::new(Cursor::new(bytes), scope(), &sha256_hex(bytes))?;
    while input.next_row()?.is_some() {}
    input.finish()
}

#[test]
fn exact_bytes_unicode_and_signed_bigint_survive_native_input() {
    let data = "{\"external_id\": \"School/É/学校\", \"small\": -9223372036854775808, \"large\": 9223372036854775807}";
    let bytes = fixture(&[
        ("organizations", "School", data),
        ("organizations", "school", "{}"),
        ("organizations", "É", "{}"),
        ("organizations", "学校", "{}"),
    ]);
    let mut input = Input::new(Cursor::new(&bytes), scope(), &sha256_hex(&bytes)).unwrap();
    let row = input.next_row().unwrap().unwrap();
    assert_eq!(row.exact_data, data);
    assert_eq!(row.data["small"].as_i64(), Some(i64::MIN));
    assert_eq!(row.data["large"].as_i64(), Some(i64::MAX));
    for key in ["school", "É", "学校"] {
        assert_eq!(input.next_row().unwrap().unwrap().key, key);
    }
    assert!(input.next_row().unwrap().is_none());
    assert!(input.next_row().unwrap().is_none());
    let receipt = input.finish().unwrap();
    assert!(!receipt.import_authorized);
    assert_eq!(receipt.sections.len(), 20);
    assert_eq!(receipt.sections[5].count, 4);
    assert_eq!(receipt.bytes, bytes.len() as u64);
    assert_eq!(receipt.sha256, sha256_hex(&bytes));
    let unsigned = fixture(&[("audit", "id", r#"{"value":18446744073709551615}"#)]);
    let mut input = Input::new(Cursor::new(&unsigned), scope(), &sha256_hex(&unsigned)).unwrap();
    assert_eq!(
        input.next_row().unwrap().unwrap().data["value"].as_u64(),
        Some(u64::MAX)
    );
    assert!(input.next_row().unwrap().is_none());
    assert!(!input.finish().unwrap().import_authorized);
}

#[test]
fn truncation_trailing_and_expected_hash_refuse_complete_receipt() {
    let bytes = fixture(&[("organizations", "id", "{}")]);
    for end in [
        0,
        1,
        bytes.iter().position(|b| *b == b'\n').unwrap() + 1,
        bytes.len() - 1,
    ] {
        assert!(consume(&bytes[..end]).is_err());
    }
    for suffix in [b"\n".as_slice(), b"{}\n", b"\0"] {
        assert!(consume(&[bytes.as_slice(), suffix].concat()).is_err());
    }
    let mut input = Input::new(Cursor::new(&bytes), scope(), &"a".repeat(64)).unwrap();
    assert!(input.next_row().unwrap().is_some());
    assert_eq!(
        input.next_row().unwrap_err().reason,
        "expected whole-file digest mismatch"
    );
    assert!(input.next_row().is_err());
    assert!(input.finish().is_err());
    assert!(
        Input::new(Cursor::new(&bytes), scope(), &sha256_hex(&bytes))
            .unwrap()
            .finish()
            .is_err()
    );
}

#[test]
fn lexical_ambiguity_and_unknown_envelopes_refused_even_with_matching_hashes() {
    for data in [
        r#"{"a":1,"\u0061":2}"#,
        r#"{"nested":{"k":1,"k":2}}"#,
        r#"{"a":1.0}"#,
        r#"{"a":1e0}"#,
        r#"{"a":-0}"#,
        r#"{"a":18446744073709551616}"#,
        r#"{"a":-9223372036854775809}"#,
        r#"{"a":"\u0000"}"#,
        r#"{"\u0000":1}"#,
        "[]",
    ] {
        assert!(
            consume(&fixture(&[("organizations", "id", data)])).is_err(),
            "{data}"
        );
    }
    let original = String::from_utf8(fixture(&[("organizations", "id", "{}")])).unwrap();
    for (from, to) in [
        (
            "\"record\":\"row\"",
            "\"record\":\"row\",\"record\":\"row\"",
        ),
        ("\"key\":\"id\"", "\"key\":\"id\",\"unknown\":null"),
        (
            "\"credentialTransfer\":false",
            "\"credentialTransfer\":true",
        ),
        ("\"version\":1", "\"version\":true"),
        ("\"version\":1", "\"version\":2"),
    ] {
        assert!(consume(original.replacen(from, to, 1).as_bytes()).is_err());
    }
}

#[test]
fn altered_manifest_or_json_equal_reserialization_refused() {
    let original =
        String::from_utf8(fixture(&[("organizations", "id", "{\"a\":1,\"b\":2}")])).unwrap();
    for (from, to) in [
        ("{\"a\":1,\"b\":2}", "{\"b\":2,\"a\":1}"),
        ("\"count\":1", "\"count\":2"),
        ("\"count\":1", "\"count\":true"),
        ("\"record\":\"manifest\"", "\"record\":\"header\""),
    ] {
        assert!(consume(original.replacen(from, to, 1).as_bytes()).is_err());
    }
    let mut lines: Vec<Value> = original
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    lines.last_mut().unwrap()["sections"]
        .as_array_mut()
        .unwrap()
        .pop();
    let bytes: Vec<u8> = lines
        .iter()
        .flat_map(|v| super::super::line(v).unwrap())
        .collect();
    assert!(consume(&bytes).is_err());
}

#[test]
fn scope_identifiers_and_section_key_order_are_not_normalized() {
    let bytes = fixture(&[]);
    assert!(Input::new(
        Cursor::new(&bytes),
        Scope {
            domain_id: Uuid::from_u128(4),
            ..scope()
        },
        &sha256_hex(&bytes)
    )
    .is_err());
    assert!(Input::new(
        Cursor::new(&bytes),
        Scope {
            domain_id: Uuid::nil(),
            ..scope()
        },
        &sha256_hex(&bytes)
    )
    .is_err());
    for data in [
        r#"{"domain_id":"00000000-0000-0000-0000-000000000004"}"#,
        r#"{"environment_id":"00000000000000000000000000000001"}"#,
    ] {
        assert!(consume(&fixture(&[("organizations", "id", data)])).is_err());
    }
    for rows in [
        vec![("roles", "a", "{}"), ("domain", "b", "{}")],
        vec![
            ("organizations", "same", "{}"),
            ("organizations", "same", "{}"),
        ],
        vec![
            ("organizations", "school", "{}"),
            ("organizations", "School", "{}"),
        ],
    ] {
        assert!(consume(&fixture(&rows)).is_err());
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(consume(
        text.replacen(
            "00000000-0000-0000-0000-000000000003",
            "00000000000000000000000000000003",
            1
        )
        .as_bytes()
    )
    .is_err());
}

#[test]
fn bounds_are_enforced_before_unbounded_line_or_parser_allocation() {
    let at_limit = format!("{{\"v\":\"{}\"}}", "x".repeat(MAX_ROW_BYTES - 8));
    assert_eq!(at_limit.len(), MAX_ROW_BYTES);
    assert!(consume(&fixture(&[(
        "organizations",
        &"x".repeat(MAX_KEY_BYTES),
        &at_limit
    )]))
    .is_ok());
    let too_large = format!("{{\"v\":\"{}\"}}", "x".repeat(MAX_ROW_BYTES - 7));
    assert!(consume(&fixture(&[("organizations", "id", &too_large)])).is_err());
    assert!(consume(&fixture(&[(
        "organizations",
        &"x".repeat(MAX_KEY_BYTES + 1),
        "{}"
    )]))
    .is_err());
    let deep = format!("{{\"v\":{}0{}}}", "[".repeat(33), "]".repeat(33));
    assert!(consume(&fixture(&[("organizations", "id", &deep)])).is_err());
    let mut cursor = Cursor::new(vec![b'x'; MAX_LINE_BYTES * 2]);
    assert!(Input::new(&mut cursor, scope(), &"a".repeat(64)).is_err());
    assert_eq!(cursor.position(), MAX_LINE_BYTES as u64 + 1);
    let bytes = fixture(&[]);
    let mut input = Input::new(Cursor::new(&bytes), scope(), &sha256_hex(&bytes)).unwrap();
    input.bytes = MAX_TRANSFER_BYTES;
    assert_eq!(input.next_row().unwrap_err().reason, "transfer byte limit");
    assert!(input.finish().is_err());
}

#[test]
fn io_failure_after_staging_poisoned_and_no_complete_receipt() {
    struct Fault {
        inner: Cursor<Vec<u8>>,
        remaining: usize,
    }
    impl Read for Fault {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::other("injected read failure"));
            }
            let length = out.len().min(self.remaining);
            let count = self.inner.read(&mut out[..length])?;
            self.remaining -= count;
            Ok(count)
        }
    }
    let bytes = fixture(&[("organizations", "id", "{}")]);
    let remaining = bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(1)
        .unwrap()
        .0
        + 1;
    let source = std::io::BufReader::with_capacity(
        32,
        Fault {
            inner: Cursor::new(bytes.clone()),
            remaining,
        },
    );
    let mut input = Input::new(source, scope(), &sha256_hex(&bytes)).unwrap();
    assert!(input.next_row().unwrap().is_some());
    assert_eq!(input.next_row().unwrap_err().reason, "input read failed");
    assert_eq!(input.next_row().unwrap_err().reason, "input already failed");
    assert!(input.finish().is_err());
}
