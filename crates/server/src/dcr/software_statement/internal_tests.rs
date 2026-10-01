use super::*;
use crate::management::types::PolicyDocument;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn software_statement_internal_clock_and_key_failures_remain_internal() -> TestResult {
    let policy = PolicyDocument {
        ssa_jwt_pem: Some(include_str!("../../../tests/fixtures/rsa2048-public.pem").into()),
        ..PolicyDocument::default()
    };
    let config = super::super::DcrValidationConfig::try_from_policy(
        &policy, false, false, false, false, 8192,
    )?;
    let statement = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &serde_json::json!({"iss":"https://issuer.example", "exp":4102444800_u64}),
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../tests/fixtures/rsa2048-private.pk8.pem"
        ))?,
    )?;
    for clock in [Err(()), Ok(u64::MAX)] {
        assert!(matches!(
            verify_software_statement_registered_claims(
                &statement,
                config.software_statement(),
                || clock
            ),
            Err(SoftwareStatementVerificationError::Internal(_))
        ));
    }
    // This defensive branch is normally excluded by the policy constructor.
    let mut invalid = config.software_statement().clone();
    invalid.public_key_pem = Some("invalid configured key".into());
    assert!(matches!(
        verify_software_statement_registered_claims(&statement, &invalid, || Ok(1)),
        Err(SoftwareStatementVerificationError::Internal(_))
    ));
    Ok(())
}
