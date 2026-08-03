use crate::upstream::{parse_upstream_attribute_mappings, parse_upstream_claim_release_policy};

pub(in crate::web::management) fn federation_claim_release_audit_snapshot(
    configuration_document: &serde_json::Value,
) -> serde_json::Value {
    let federation = configuration_document.get("federation");
    let Ok(attribute_mappings) = parse_upstream_attribute_mappings(federation) else {
        return serde_json::json!({
            "managed": false,
            "claims": [],
        });
    };

    match parse_upstream_claim_release_policy(federation, &attribute_mappings)
        .ok()
        .flatten()
    {
        Some(policy) => {
            let claims = policy
                .managed_custom_claims
                .iter()
                .map(|claim| {
                    let mut surfaces = Vec::new();
                    if policy
                        .id_token_custom_claims
                        .iter()
                        .any(|candidate| candidate == claim)
                    {
                        surfaces.push("id_token");
                    }
                    if policy
                        .userinfo_custom_claims
                        .iter()
                        .any(|candidate| candidate == claim)
                    {
                        surfaces.push("userinfo");
                    }
                    serde_json::json!({
                        "claim": claim,
                        "surfaces": surfaces,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "managed": true,
                "claims": claims,
            })
        }
        None => serde_json::json!({
            "managed": false,
            "claims": [],
        }),
    }
}
