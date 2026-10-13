use super::*;
use std::collections::{BTreeMap, BTreeSet};
fn valid(value: Option<&str>) -> bool {
    value.is_some_and(|s| {
        !s.is_empty() && s.len() <= 255 && s.bytes().all(|b| b.is_ascii() && b != 0)
    })
}
fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
fn fact(
    origin: &str,
    key: &str,
    hash: &str,
    env: &str,
    owner: &str,
    subject: Option<&str>,
) -> Value {
    let is_valid = valid(subject);
    let flag = if is_valid { "true" } else { "false" };
    json!({"fact_id":content_id("aegaeon-subject-fact-v1",&[("origin",Some(origin)),("row_key",Some(key)),("sha256",Some(hash)),("uuid",Some(env)),("uuid",Some(owner)),("text",subject),("boolean",Some(flag))]),"origin":origin,"row_key":key,"row_sha256":hash,"environment_id":env,"owner_id":owner,"subject":subject,"valid":is_valid})
}
#[allow(clippy::too_many_arguments)]
fn finding(
    class: &str,
    origin: &str,
    key: &str,
    hash: &str,
    env: Option<&str>,
    owners: &[String],
    subjects: &[String],
    facts: &[String],
) -> Value {
    json!({"finding_id":content_id("aegaeon-subject-finding-v1",&[("class",Some(class)),("origin",Some(origin)),("row_key",Some(key)),("sha256",Some(hash))]),"class":class,"origin":origin,"row_key":key,"row_sha256":hash,"environment_id":env,"observed_owner_ids":owners,"observed_subjects":subjects,"preserved_fact_ids":facts})
}
fn strings(value: Option<&str>) -> Vec<String> {
    value.into_iter().map(str::to_owned).collect()
}
fn outside<'a>(class: &'a str, env: Option<&str>, target: &str) -> &'a str {
    if env.is_some_and(|e| e != target) {
        "outside_target"
    } else {
        class
    }
}

pub(super) fn classify(
    collection: &str,
    key: &str,
    text: &str,
    value: &Value,
    target: &str,
    environments: &HashSet<String>,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let hash = sha256_hex(&frame(text.as_bytes()));
    let env = value["environment_id"].as_str();
    let facts = Vec::new();
    let mut findings = Vec::new();
    if collection == "end_users" {
        return classify_current_user(key, &hash, value, target);
    }
    let event = value["event_type"]
        .as_str()
        .ok_or_else(|| refuse("audit event type is missing"))?;
    let target_owner = value["target_id"].as_str();
    let data_owner = value["data"]["userId"].as_str();
    let mut owners = strings(target_owner);
    if data_owner != target_owner {
        owners.extend(strings(data_owner));
    }
    let known = env.is_some_and(|e| environments.contains(e));
    let recognized = value["category"] == "CONTROL_PLANE"
        && value["outcome"] == "SUCCESS"
        && value["target_type"] == "END_USER"
        && known
        && target_owner.is_some_and(canonical_uuid)
        && data_owner == target_owner
        && matches!(
            event,
            "management.user.created.v1"
                | "management.user.invited.v1"
                | "management.user.imported.v1"
                | "management.user.updated.v1"
                | "management.user.deleted.v1"
                | "management.user.restored.v1"
                | "management.user.suspended.v1"
                | "management.user.reactivated.v1"
        );
    if recognized {
        return Ok(classify_recognized(
            key, &hash, value, target, event, &owners,
        ));
    }
    let provisioning = event == "upstream.user.provision.authorized.v1";
    if provisioning {
        owners.clear();
    }
    let mut observed = BTreeMap::from([
        ("data.subject", value["data"]["subject"].as_str()),
        (
            "data.previous.subject",
            value["data"]["previous"]["subject"].as_str(),
        ),
        (
            "data.current.subject",
            value["data"]["current"]["subject"].as_str(),
        ),
    ]);
    if provisioning {
        observed.insert("actor_id", value["actor_id"].as_str());
        observed.insert("target_id", target_owner);
    }
    let mut subjects = Vec::new();
    for (location, subject) in observed {
        if let Some(subject) = subject {
            if !subjects.iter().any(|s| s == subject) {
                subjects.push(subject.to_owned());
            }
            if !valid(Some(subject)) {
                findings.push(finding(
                    outside("invalid_history", env, target),
                    event,
                    &format!("{key}:{location}"),
                    &hash,
                    env,
                    &owners,
                    &strings(Some(subject)),
                    &[],
                ));
            }
        }
    }
    let class = if !known {
        "unscoped_event"
    } else if !subjects.is_empty() && (provisioning || event.starts_with("management.user.")) {
        "unknown_owner"
    } else if !owners.is_empty() || event.starts_with("management.user.") {
        "malformed_event"
    } else {
        "unknown_event"
    };
    findings.push(finding(
        outside(class, env, target),
        event,
        key,
        &hash,
        env,
        &owners,
        &subjects,
        &[],
    ));
    Ok((facts, findings))
}

fn classify_current_user(
    key: &str,
    hash: &str,
    value: &Value,
    target: &str,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let env = value["environment_id"].as_str();
    let mut facts = Vec::new();
    let mut findings = Vec::new();
    let env = env.ok_or_else(|| refuse("current user environment is missing"))?;
    let owner = value["id"]
        .as_str()
        .ok_or_else(|| refuse("current user owner is missing"))?;
    let subject = value["subject"].as_str();
    let f = fact("current_user", key, hash, env, owner, subject);
    if !valid(subject) {
        findings.push(finding(
            outside("invalid_history", Some(env), target),
            "current_user",
            key,
            hash,
            Some(env),
            &strings(Some(owner)),
            &strings(subject),
            &strings(f["fact_id"].as_str()),
        ));
    }
    facts.push(f);
    Ok((facts, findings))
}

fn classify_recognized(
    key: &str,
    hash: &str,
    value: &Value,
    target: &str,
    event: &str,
    owners: &[String],
) -> (Vec<Value>, Vec<Value>) {
    let env = value["environment_id"].as_str();
    let target_owner = value["target_id"].as_str();
    let mut facts = Vec::new();
    let mut findings = Vec::new();
    let fields: &[&str] = if matches!(
        event,
        "management.user.created.v1" | "management.user.invited.v1" | "management.user.imported.v1"
    ) {
        &["subject"]
    } else {
        &["previous", "current"]
    };
    let mut ids = Vec::new();
    let mut malformed = false;
    for field in fields {
        let (origin, subject) = match *field {
            "subject" => (
                "management_create_subject",
                value["data"]["subject"].as_str(),
            ),
            "previous" => (
                "management_previous_subject",
                value["data"]["previous"]["subject"].as_str(),
            ),
            _ => (
                "management_current_subject",
                value["data"]["current"]["subject"].as_str(),
            ),
        };
        let location = format!("{key}:{field}");
        let f = fact(
            origin,
            &location,
            hash,
            env.expect("known environment"),
            target_owner.expect("recognized owner"),
            subject,
        );
        let id = f["fact_id"].as_str().expect("fact ID").to_owned();
        ids.push(id.clone());
        match subject {
            None => malformed = true,
            Some(s) if !valid(Some(s)) => findings.push(finding(
                outside("invalid_history", env, target),
                event,
                &location,
                hash,
                env,
                owners,
                &strings(Some(s)),
                &[id],
            )),
            _ => (),
        }
        facts.push(f);
    }
    if malformed {
        findings.push(finding(
            outside("malformed_event", env, target),
            event,
            &format!("{key}:malformed"),
            hash,
            env,
            owners,
            &[],
            &ids,
        ));
    }
    (facts, findings)
}

pub(super) fn conflicts(facts: &[Value], findings: &mut Vec<Value>) {
    let mut owners: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut subjects: BTreeMap<(&str, &str), BTreeSet<&str>> = BTreeMap::new();
    for f in facts {
        let env = f["environment_id"].as_str().expect("fact environment");
        let owner = f["owner_id"].as_str().expect("fact owner");
        owners.entry(owner).or_default().insert(env);
        if f["valid"] == true {
            subjects
                .entry((env, f["subject"].as_str().expect("valid subject")))
                .or_default()
                .insert(owner);
        }
    }
    for f in facts {
        let env = f["environment_id"].as_str().expect("fact environment");
        let owner = f["owner_id"].as_str().expect("fact owner");
        let subject = f["subject"].as_str();
        if owners[owner].len() > 1
            || subject.is_some_and(|s| subjects.get(&(env, s)).is_some_and(|o| o.len() > 1))
        {
            findings.push(finding(
                "ownership_conflict",
                f["origin"].as_str().expect("fact origin"),
                f["row_key"].as_str().expect("fact key"),
                f["row_sha256"].as_str().expect("fact hash"),
                Some(env),
                &strings(Some(owner)),
                &strings(subject),
                &strings(f["fact_id"].as_str()),
            ));
        }
    }
}
