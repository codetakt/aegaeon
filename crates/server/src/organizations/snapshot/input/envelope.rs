use crate::organizations::Scope;
use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Header {
    record: String,
    version: u32,
    pub snapshot_id: Uuid,
    pub scope: Scope,
    captured_at: String,
    credential_transfer: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Row<'a> {
    pub record: String,
    pub section: String,
    pub key: String,
    #[serde(borrow)]
    pub data: &'a RawValue,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Digest {
    pub section: String,
    pub count: u64,
    pub sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Manifest {
    record: String,
    version: u32,
    snapshot_id: Uuid,
    scope: Scope,
    sections: Vec<Digest>,
    content_bytes: u64,
}

pub(super) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn canonical(value: &Value, snapshot: Uuid, scope: Scope) -> bool {
    !snapshot.is_nil()
        && value["snapshotId"].as_str() == Some(snapshot.to_string().as_str())
        && value["scope"] == serde_json::json!(scope)
}

pub(super) fn header(value: &Value, scope: Scope) -> Result<Header, &'static str> {
    let result: Header = Header::deserialize(value).map_err(|_| "header envelope")?;
    if result.record != "header"
        || result.version != 2
        || result.credential_transfer
        || result.scope != scope
        || !canonical(value, result.snapshot_id, scope)
        || result.captured_at.len() > 40
        || OffsetDateTime::parse(&result.captured_at, &Rfc3339).is_err()
    {
        return Err("header version, scope or capture time");
    }
    Ok(result)
}

pub(super) fn manifest(
    value: &Value,
    header: &Header,
    bytes: u64,
    sections: &[Digest],
) -> Result<(), &'static str> {
    let result: Manifest = Manifest::deserialize(value).map_err(|_| "manifest envelope")?;
    if result.record != "manifest"
        || result.version != 2
        || result.snapshot_id != header.snapshot_id
        || result.scope != header.scope
        || result.content_bytes != bytes
        || result.sections != sections
        || !canonical(value, result.snapshot_id, header.scope)
    {
        return Err("terminal manifest mismatch");
    }
    Ok(())
}
