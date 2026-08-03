pub(crate) fn redact_json_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            let keys_to_redact: Vec<String> = map
                .keys()
                .filter(|key| is_sensitive_audit_key(key))
                .cloned()
                .collect();
            keys_to_redact.into_iter().for_each(|key| {
                map.insert(key, serde_json::Value::String("[REDACTED]".to_string()));
            });
            map.values_mut().for_each(redact_json_value);
        }
        serde_json::Value::Array(values) => {
            values.iter_mut().for_each(redact_json_value);
        }
        _ => {}
    }
}

pub(crate) fn redacted_audit_data(mut data: serde_json::Value) -> serde_json::Value {
    redact_json_value(&mut data);
    data
}

fn canonical_sensitive_key(key: &str) -> String {
    key.chars()
        .filter(|ch| *ch != '_' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_sensitive_audit_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let canonical = canonical_sensitive_key(key);
    lower.starts_with("client_secret")
        || lower.starts_with("password")
        || lower.starts_with("secret")
        || lower.ends_with("_encrypted")
        || canonical.ends_with("encrypted")
        || matches!(
            canonical.as_str(),
            "accesstoken"
                | "activationtoken"
                | "actortoken"
                | "actortokentype"
                | "apikey"
                | "apikeyvalue"
                | "assertion"
                | "authorizationcode"
                | "bootstraptoken"
                | "clientassertion"
                | "clientassertiontype"
                | "clientsecret"
                | "clientsecretvalue"
                | "code"
                | "codeverifier"
                | "csrftoken"
                | "devicecode"
                | "idtoken"
                | "idtokenhint"
                | "keyhandle"
                | "onetimepassword"
                | "otp"
                | "password"
                | "passwordconfirmation"
                | "passwordhash"
                | "privatekey"
                | "privatekeypem"
                | "rawtoken"
                | "recoverytoken"
                | "redeemurl"
                | "refreshtoken"
                | "registrationaccesstoken"
                | "request"
                | "secret"
                | "secretkey"
                | "subjecttoken"
                | "token"
                | "totp"
                | "usercode"
        )
}

#[cfg(test)]
mod tests {
    use super::redacted_audit_data;
    use serde_json::json;

    #[test]
    fn redacts_nested_sensitive_audit_keys() {
        let data = redacted_audit_data(json!({
            "clientSecret": "plain",
            "nested": {
                "private-key-pem": "pem",
                "public": "kept"
            },
            "tokens": [{"refreshToken": "raw"}]
        }));

        assert_eq!(data["clientSecret"], "[REDACTED]");
        assert_eq!(data["nested"]["private-key-pem"], "[REDACTED]");
        assert_eq!(data["nested"]["public"], "kept");
        assert_eq!(data["tokens"][0]["refreshToken"], "[REDACTED]");
    }
}
