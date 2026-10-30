//! Version-one closed disclosure shapes. No input chooses SQL/table/field names.
use super::super::input::PendingRow;
use serde_json::Value;
use uuid::Uuid;

mod semantics;

const CONTRACTS: &[(&str, &str)] = &[
    ("domain", "id:uuid environment_id:uuid name:text is_default:bool enabled:bool revision:positive invitation_delivery:?object support_policy:?object support_policy_revision:positive"),
    ("targets", "environment_id:uuid domain_id:uuid audience:text management:bool introspection_clients:array"),
    ("roles", "environment_id:uuid domain_id:uuid role_key:text version:positive privileges:array manages_members:bool assignable_roles:array"),
    ("client_bindings", "id:uuid environment_id:uuid domain_id:uuid client_registration_id:uuid client_identifier:text active:bool revision:positive targets:array created_at:text"),
    ("operators", "id:uuid environment_id:uuid domain_id:uuid administrator_id:uuid active:bool revision:positive capabilities:array created_at:text"),
    ("organizations", "id:uuid environment_id:uuid domain_id:uuid external_id:text state:text revision:positive grant_generation:positive created_at:text"),
    ("memberships", "environment_id:uuid domain_id:uuid organization_id:uuid end_user_id:uuid incarnation:uuid state:text revision:positive grant_generation:positive roles:array"),
    ("invitations", "id:uuid environment_id:uuid domain_id:uuid organization_id:uuid revision:positive state:text recipient:text authority:object issued_at:nonnegative expires_at:positive delivery_revision:nonnegative delivered_at:?nonnegative accepted_challenge_id:?uuid result:?object delivery_outcome:text"),
    ("challenges", "id:uuid environment_id:uuid domain_id:uuid invitation_id:uuid invitation_delivery_revision:positive recipient_binding:object request_key:text issued_at:nonnegative expires_at:positive delivery_revision:nonnegative delivered_at:?nonnegative delivery_outcome:text"),
    ("identity_requests", "id:uuid environment_id:uuid domain_id:uuid invitation_id:uuid invitation_delivery_revision:positive policy_revision:positive purpose:text request_key:text request_digest:hex target_user_id:?uuid target_identity_revision:?positive issued_at:nonnegative expires_at:positive state:text result:?object delivery_revision:nonnegative delivered_at:?nonnegative delivery_outcome:text"),
    ("administrative_grants", "id:uuid environment_id:uuid domain_id:uuid organization_id:uuid user_id:uuid client_registration_id:uuid root_id:text authority:object revision:positive active:bool issued_at:positive expires_at:positive creation_key:text request_digest:hex revocation_key:?text revocation_digest:?hex"),
    ("audit", "id:uuid environment_id:uuid domain_id:uuid organization_id:?uuid actor_id:uuid actor_kind:text client_id:text client_registration_id:?uuid request_id:text reason:text event_type:text data:object created_at:text"),
    ("receipts", "environment_id:uuid domain_id:uuid actor_id:uuid actor_kind:text client_id:text client_registration_id:receipt_registration operation:text idempotency_key:text request_digest:hex result:object created_at:text"),
    ("outbox", "event_id:uuid attempts:nonnegative delivered_at:?text"),
    ("owners", "owner_id:uuid environment_id:uuid recorded_at:text"),
    ("subject_history", "environment_id:uuid subject:text owner_id:uuid recorded_at:text"),
    ("identities", "id:uuid environment_id:uuid subject:text status:text created_at:text updated_at:text organization_identity_revision:positive organization_reauthentication_after:nonnegative"),
    ("namespace", "environment_id:uuid issuer_host:text origin:text contract_version:positive recorded_at:text"),
    ("environment_dependency", "id:uuid issuer_host:text issuer_url:text status:text active_configuration_version_id:?uuid organization_identity_policy:?object organization_identity_policy_revision:positive"),
    ("client_dependencies", "id:uuid environment_id:uuid configuration_version_id:uuid client_identifier:text client_type:text status:text deleted_at:?text allowed_grant_types:array allowed_scopes:array dpop_bound_access_tokens:bool token_endpoint_authentication_method:text"),
];

pub(super) fn validate(row: &PendingRow) -> Result<(), &'static str> {
    let (_, contract) = CONTRACTS
        .iter()
        .find(|(name, _)| *name == row.section)
        .ok_or("unknown source section")?;
    let object = row.data.as_object().ok_or("source row object")?;
    let mut count = 0usize;
    for descriptor in contract.split_whitespace() {
        let (name, kind) = descriptor
            .split_once(':')
            .ok_or("invalid compiled row contract")?;
        let value = object.get(name).ok_or("missing source column")?;
        if !matches_kind(value, kind) {
            return Err("source column type or range");
        }
        count += 1;
    }
    if count != object.len() {
        return Err("unknown source column or credential material");
    }
    if row.section == "receipts" {
        let registration = object["client_registration_id"]
            .as_str()
            .ok_or("receipt registration")?;
        let nil = registration == "00000000-0000-0000-0000-000000000000";
        match object["actor_kind"].as_str() {
            Some("operator") if nil => (),
            Some("member") if !nil => (),
            _ => return Err("receipt actor registration binding"),
        }
    }
    semantics::validate(row).map_err(|_| "source row semantics")
}

fn matches_kind(value: &Value, kind: &str) -> bool {
    let kind = match kind.strip_prefix('?') {
        Some(_) if value.is_null() => return true,
        Some(kind) => kind,
        None => kind,
    };
    match kind {
        "uuid" => value.as_str().is_some_and(|s| {
            Uuid::parse_str(s).is_ok_and(|id| !id.is_nil() && id.to_string() == s)
        }),
        "receipt_registration" => value
            .as_str()
            .is_some_and(|s| Uuid::parse_str(s).is_ok_and(|id| id.to_string() == s)),
        "hex" => value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }),
        "text" => value.as_str().is_some_and(|s| !s.is_empty()),
        "bool" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "positive" => value.as_i64().is_some_and(|n| n > 0),
        "nonnegative" => value.as_i64().is_some_and(|n| n >= 0),
        _ => false,
    }
}
