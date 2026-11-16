//! Compare only the affected user consent and token authority.
use super::*;
use std::collections::BTreeSet;

pub(super) struct Projection {
    consents: serde_json::Map<String, Value>,
    codes: serde_json::Map<String, Value>,
    tokens: Value,
}

pub(super) async fn projection(
    f: &Fixture,
    state: &AppState,
    witness: &CallerFixture,
) -> TestResult<Projection> {
    let consents: Value = sqlx::query_scalar("SELECT COALESCE(jsonb_object_agg(id::text,jsonb_build_object('uri',authorize_uri,'decision',decision,'snapshot',request_snapshot,'token_sha256',token_sha256)), '{}'::jsonb) FROM aegaeon.authorization_consents WHERE environment_id=$1 AND subject=$2")
        .bind(state.environment_id).bind(format!("organization-user-{}", f.users[1]))
        .fetch_one(&f.pool).await?;
    let codes = state.tokens.issuer.code_store.clone();
    let tokens = state.tokens.store.clone();
    let (codes, tokens) = scoped(witness, async {
        let result = crate::organizations::request_work::async_store::blocking(move || {
            let codes = codes.try_snapshot()?;
            let tokens = tokens.try_snapshot()?;
            Ok::<_, String>((json!(codes.codes), json!({
                "access":tokens.access_tokens,"refresh":tokens.refresh_tokens,
                "grants":tokens.refresh_grants,"bearer":tokens.bearer_meta,
                "revoked":tokens.revoked_tokens.into_iter().collect::<BTreeSet<_>>(),"version":tokens.version
            })))
        }).await?;
        result.map_err(Into::into)
    }).await?;
    Ok(Projection {
        consents: consents
            .as_object()
            .ok_or("consent projection shape")?
            .clone(),
        codes: codes.as_object().ok_or("code projection shape")?.clone(),
        tokens,
    })
}

pub(super) fn same_projection(a: &Projection, b: &Projection) -> TestResult {
    if a.consents != b.consents || a.codes != b.codes || a.tokens != b.tokens {
        return Err("authorization projection changed unexpectedly".into());
    }
    Ok(())
}

pub(super) fn evaluate(
    before: &Projection,
    after: &Projection,
    boundary: &str,
    target: Option<&str>,
    state: &AppState,
    f: &Fixture,
) -> TestResult {
    if before.tokens != after.tokens {
        return Err("cancel minted or changed an access/refresh grant".into());
    }
    let old_ids: BTreeSet<_> = before.consents.keys().collect();
    let new_rows: Vec<_> = after
        .consents
        .iter()
        .filter(|(id, _)| !old_ids.contains(id))
        .collect();
    for (id, row) in &before.consents {
        let mut expected = row.clone();
        if target == Some(id.as_str()) {
            expected["decision"] = json!(if boundary == "selection" {
                "deny"
            } else {
                "approve"
            });
        }
        if after.consents.get(id) != Some(&expected) {
            return Err("existing consent disposition differs".into());
        }
    }
    let old_codes: BTreeSet<_> = before.codes.keys().collect();
    for (id, value) in &before.codes {
        if after.codes.get(id) != Some(value) {
            return Err("existing code changed".into());
        }
    }
    let new_codes: Vec<_> = after
        .codes
        .iter()
        .filter(|(id, _)| !old_codes.contains(id))
        .collect();
    match boundary {
        "picker" => {
            if new_rows.len() != 1
                || new_rows[0].1["decision"] != Value::Null
                || !new_codes.is_empty()
            {
                return Err("cancelled picker did not leave exactly one pending picker".into());
            }
            if new_rows[0].1["uri"] != json!("/authorize/organization-selection") {
                return Err("picker row kind differs".into());
            }
            let entries = new_rows[0].1["snapshot"]["page"]["organizations"]
                .as_array()
                .ok_or("picker page organizations")?;
            if entries.len() != 1 || entries[0]["identifier"] != IDENTIFIER {
                return Err("picker selection authority differs".into());
            }
        }
        "selection" => {
            if new_rows.len() != 1
                || new_rows[0].1["decision"] != Value::Null
                || new_rows[0].1["uri"] != "/authorize"
                || !new_codes.is_empty()
            {
                return Err("cancelled selection disposition differs".into());
            }
            let consent: crate::organizations::consent::Consent =
                serde_json::from_value(new_rows[0].1["snapshot"]["organization"].clone())?;
            if consent.scope != f.organization.scope
                || consent.user_id != f.users[1]
                || consent.client_id != OWNER
                || consent.memberships.len() != 1
            {
                return Err("selected approval authority differs".into());
            }
            let member = consent
                .memberships
                .get(&f.organization.id)
                .ok_or("selected membership missing")?;
            if member.privileges != [PRIVILEGE.to_owned()].into_iter().collect() {
                return Err("selected privileges differ".into());
            }
            let original = &before.consents[target.ok_or("selection target")?]["snapshot"]["page"]
                ["organizations"];
            let [entry] = original
                .as_array()
                .ok_or("original picker entries")?
                .as_slice()
            else {
                return Err("original picker count differs".into());
            };
            if entry["identifier"] != IDENTIFIER
                || serde_json::to_value(member)? != entry["authority"]
            {
                return Err("selection enlarged original picker authority".into());
            }
        }
        "approval" => {
            if !new_rows.is_empty() || new_codes.len() != 1 {
                return Err("cancelled approval must issue exactly one code".into());
            }
            let row = &before.consents[target.ok_or("approval target")?];
            let record = new_codes[0].1;
            if record["client_id"] != OWNER
                || record["user_id"] != format!("organization-user-{}", f.users[1])
                || record["authorization_details"]
                    != json!([row["snapshot"]["organization"]["request"].clone()])
                || record["used"] != false
                || record["redirect_uri"] != "https://example.test/cb"
            {
                return Err("issued code authority/binding differs".into());
            }
        }
        _ => return Err("unknown cancellation boundary".into()),
    }
    if state.runtime_restart.is_requested() {
        return Err("unexpected runtime closure after confirmed drain".into());
    }
    eprintln!(
        "discovery-cancellation {}",
        json!({"phase":"disposition","boundary":boundary,
        "new_consents":new_rows.len(),"new_codes":new_codes.len(),"token_projection_unchanged":true})
    );
    Ok(())
}
