//! Private profile encoding; not a new OAuth/OIDC identifier or JSON standard.
use super::*;
use crate::organizations::witness::creation::{Input, Kind};
use aegaeon_crypto::hash::sha256_digest;
use serde_json::{json, Value};
const MAX_BYTES: usize = 1024 * 1024;

fn text(out: &mut Vec<u8>, value: &str) -> Result<(), ()> {
    if value.len() > MAX_BYTES || value.contains('\0') {
        return Err(());
    }
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value.as_bytes());
    Ok(())
}
fn shape(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), ()> {
    *nodes += 1;
    if depth > 32 || *nodes > 4096 {
        return Err(());
    }
    match value {
        Value::Array(values) => {
            for value in values {
                shape(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                shape(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
struct Bounded(Vec<u8>);
impl std::io::Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("upstream creation payload too large"));
        }
        self.0.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn selector(callback: &Callback<'_>) -> Result<[u8; 32], Response> {
    let request = callback.request;
    let c = request.context;
    let fail = || denied(callback.state);
    let mut selector = b"aegaeon-creation-upstream-selector-v1\0".to_vec();
    selector.extend(c.environment_id.as_bytes());
    text(&mut selector, &request.issuer).map_err(|()| fail())?;
    text(&mut selector, &callback.exchange.upstream_sub_hash).map_err(|()| fail())?;
    Ok(sha256_digest(&selector))
}

pub(super) fn input(callback: &Callback<'_>) -> Result<Input, Response> {
    let request = callback.request;
    let token = &callback.exchange.id_token;
    let c = request.context;
    let fail = || denied(callback.state);
    let selector = selector(callback)?;
    let mut actor = b"aegaeon-creation-upstream-actor-v1\0".to_vec();
    for id in [
        c.team_id,
        c.tenant_id,
        c.environment_id,
        c.configuration_version_id,
        c.connection_id,
    ] {
        if id.is_nil() {
            return Err(fail());
        }
        actor.extend(id.as_bytes());
    }
    for value in [
        &request.issuer,
        &request.client_id,
        &request.client_auth_method,
    ] {
        text(&mut actor, value).map_err(|()| fail())?;
    }
    let email = token
        .claims
        .additional_claims
        .get("email")
        .and_then(Value::as_str);
    if email.is_some_and(|s| s.len() > MAX_BYTES || s.contains('\0')) {
        return Err(fail());
    }
    let policy = request.jit_provisioning_policy.as_ref().ok_or_else(fail)?;
    let projection =
        crate::upstream::project_upstream_attribute_mappings(&request.attribute_mappings, token)
            .map_err(|_| fail())?;
    let mut payload = json!({"email":email,"verified":token.claims.additional_claims.get("email_verified").and_then(Value::as_bool).unwrap_or(false),"status":policy.initial_status.as_db_value(),
        "profile":{"emailPresent":projection.email.is_some(),"email":projection.email,
        "verified":projection.email_verified,"namePresent":projection.display_name.is_some(),"name":projection.display_name,
        "custom":projection.custom_claims,"managed":projection.managed_custom_claim_keys}});
    shape(&payload, 0, &mut 0).map_err(|()| fail())?;
    payload.sort_all_objects();
    let mut encoded = Bounded(b"aegaeon-creation-upstream-v1\0".to_vec());
    serde_json::to_writer(&mut encoded, &payload).map_err(|_| fail())?;
    Input::new(
        Kind::Upstream,
        selector,
        sha256_digest(&actor),
        sha256_digest(&encoded.0),
        None,
    )
    .map_err(|_| fail())
}
