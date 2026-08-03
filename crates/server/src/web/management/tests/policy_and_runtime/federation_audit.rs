
#[test]
fn federation_logout_audit_snapshot_defaults_to_unmanaged() {
    let snapshot = federation_logout_audit_snapshot(&serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": "auth.example.com",
        "issuerUrl": "https://auth.example.com",
    }));

    assert_eq!(snapshot, serde_json::json!({ "managed": false }));
}

#[test]
fn federation_logout_audit_snapshot_normalizes_policy_fields() {
    let snapshot = federation_logout_audit_snapshot(&serde_json::json!({
        "federation": {
            "upstreamIssuer": "https://issuer.example",
            "clientId": "upstream-client",
            "redirectUri": "https://auth.example.com/oauth/upstream/test/callback",
            "logout": {
                "backChannel": true,
                "sessionHintClaim": "sid",
                "recoveryPolicy": "disable_connection"
            }
        }
    }));

    assert_eq!(
        snapshot,
        serde_json::json!({
            "managed": true,
            "backChannel": true,
            "sessionHintClaim": "sid",
            "recoveryPolicy": "disable_connection",
        })
    );
}

#[test]
fn federation_logout_audit_snapshot_defaults_recovery_policy() {
    let snapshot = federation_logout_audit_snapshot(&serde_json::json!({
        "federation": {
            "upstreamIssuer": "https://issuer.example",
            "clientId": "upstream-client",
            "redirectUri": "https://auth.example.com/oauth/upstream/test/callback",
            "logout": {
                "backChannel": false,
                "sessionHintClaim": "sid"
            }
        }
    }));

    assert_eq!(
        snapshot,
        serde_json::json!({
            "managed": true,
            "backChannel": false,
            "sessionHintClaim": "sid",
            "recoveryPolicy": "force_prompt_login",
        })
    );
}

#[test]
fn federation_attribute_mapping_audit_snapshot_defaults_to_empty_array() {
    let snapshot = federation_attribute_mapping_audit_snapshot(&serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": "auth.example.com",
        "issuerUrl": "https://auth.example.com",
    }));

    assert_eq!(snapshot, serde_json::json!([]));
}

#[test]
fn federation_attribute_mapping_audit_snapshot_normalizes_rows() {
    let snapshot = federation_attribute_mapping_audit_snapshot(&serde_json::json!({
        "federation": {
            "attributeMapping": [
                {
                    "from": " email ",
                    "to": " profile.email ",
                    "rule": " lower "
                },
                {
                    "from": "groups",
                    "to": "roles"
                },
                {
                    "from": "   ",
                    "to": "ignored"
                },
                {
                    "from": "ignored",
                    "to": ""
                }
            ]
        }
    }));

    assert_eq!(
        snapshot,
        serde_json::json!([
            {
                "from": "email",
                "to": "profile.email",
                "rule": "lower",
            },
            {
                "from": "groups",
                "to": "roles",
            }
        ])
    );
}

#[test]
fn federation_claim_release_audit_snapshot_defaults_to_unmanaged() {
    let snapshot = federation_claim_release_audit_snapshot(&serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": "auth.example.com",
        "issuerUrl": "https://auth.example.com",
    }));

    assert_eq!(
        snapshot,
        serde_json::json!({
            "managed": false,
            "claims": [],
        })
    );
}

#[test]
fn federation_claim_release_audit_snapshot_normalizes_managed_claims() {
    let snapshot = federation_claim_release_audit_snapshot(&serde_json::json!({
        "federation": {
            "attributeMapping": [
                { "from": "groups", "to": "roles", "rule": "mapGroups" },
                { "from": "department", "to": "organization" }
            ],
            "claimRelease": [
                { "claim": "organization", "surfaces": ["userinfo", "id_token"] },
                { "claim": "roles", "surfaces": ["userinfo"] }
            ]
        }
    }));

    assert_eq!(
        snapshot,
        serde_json::json!({
            "managed": true,
            "claims": [
                {
                    "claim": "organization",
                    "surfaces": ["id_token", "userinfo"],
                },
                {
                    "claim": "roles",
                    "surfaces": ["userinfo"],
                }
            ],
        })
    );
}

#[test]
fn federation_claim_release_audit_snapshot_defaults_managed_claims_to_blocked() {
    let snapshot = federation_claim_release_audit_snapshot(&serde_json::json!({
        "federation": {
            "attributeMapping": [
                { "from": "groups", "to": "roles", "rule": "mapGroups" }
            ]
        }
    }));

    assert_eq!(
        snapshot,
        serde_json::json!({
            "managed": true,
            "claims": [
                {
                    "claim": "roles",
                    "surfaces": [],
                }
            ],
        })
    );
}

#[test]
fn federation_logout_audit_severity_warns_for_frontchannel_policy() {
    let severity = federation_logout_audit_severity(&serde_json::json!({
        "managed": true,
        "backChannel": false,
        "sessionHintClaim": "sid",
        "recoveryPolicy": "force_prompt_login",
    }));

    assert_eq!(severity, "WARN");
}
