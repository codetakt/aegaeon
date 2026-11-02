use super::*;
use aegaeon_attribute_mapping::MAX_OUTPUT_BYTES;

fn evaluate(surface: Surface, padding: usize) -> anyhow::Result<OidcMappingSnapshot> {
    let mut input = source();
    input.values["department"] = json!("x".repeat(padding));
    Ok(output::evaluate_snapshot(
        &configuration(surface.clone())?,
        &[input],
        output::EvaluationContext {
            revision: Uuid::from_u128(1),
            subject: Subject {
                environment_id: "environment".into(),
                user_id: "immutable-owner".into(),
            },
            recipient: Recipient {
                environment_id: "environment".into(),
                client_id: "test_client".into(),
                surface,
            },
            scopes: scopes(),
            issuer: "https://issuer.example",
            oidc_subject: "user123",
            now: 150,
        },
    )?)
}

fn full_snapshot_limit(surface: Surface) -> anyhow::Result<()> {
    let empty_size = serde_json::to_vec(&evaluate(surface.clone(), 0)?)?.len();
    let padding = MAX_OUTPUT_BYTES - empty_size;
    let exact = evaluate(surface.clone(), padding)?;
    assert_eq!(serde_json::to_vec(&exact)?.len(), MAX_OUTPUT_BYTES);
    // The engine output still fits even when one more byte would exceed the
    // enclosing authorization snapshot. Admission and redemption must agree.
    let output = serde_json::to_value(&exact)?["output"].clone();
    assert!(serde_json::to_vec(&output)?.len() + 1 < MAX_OUTPUT_BYTES);
    let claims = exact.claims_for(
        "https://issuer.example",
        "user123",
        "test_client",
        &surface,
        &scopes(),
        160,
    )?;
    assert_eq!(
        claims["organization"]["department"],
        json!("x".repeat(padding))
    );
    let Err(error) = evaluate(surface, padding + 1) else {
        anyhow::bail!("oversized snapshot must not be issued");
    };
    assert_eq!(
        error.downcast_ref::<MappingError>(),
        Some(&MappingError::ResourceLimit)
    );
    Ok(())
}

#[test]
fn attribute_mapping_id_token_snapshot_size_is_checked_before_code_issuance() -> anyhow::Result<()>
{
    full_snapshot_limit(Surface::IdToken)
}

#[test]
fn attribute_mapping_userinfo_snapshot_size_matches_output_admission() -> anyhow::Result<()> {
    full_snapshot_limit(Surface::Userinfo)
}
