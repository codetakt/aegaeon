use super::*;

fn request_object_claims_with_exp(exp: Option<u64>) -> RequestObjectClaims {
    RequestObjectClaims {
        iss: None,
        aud: None,
        exp,
        nbf: None,
        client_id: None,
        redirect_uri: None,
        response_type: None,
        scope: None,
        state: None,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        response_mode: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        jti: None,
        extra: None,
    }
}

#[test]
fn request_object_jti_retention_rejects_expired_claims() -> Result<(), String> {
    let store = RequestObjectJtiStore::new_process_local_for_tests(Duration::from_secs(600));
    let claims = request_object_claims_with_exp(Some(now_epoch_secs()?.saturating_sub(1)));
    let err = request_object_jti_retention(&store, &claims, 60)
        .err()
        .ok_or_else(|| "expired Request Object must fail closed".to_string())?;

    assert_eq!(err.error, "invalid_request");
    assert_eq!(
        err.error_description,
        "Request Object exp must be in the future"
    );
    Ok(())
}

#[test]
fn request_object_jti_retention_rejects_exp_outside_replay_window() -> Result<(), String> {
    let store = RequestObjectJtiStore::new_process_local_for_tests(Duration::from_secs(10));
    let claims = request_object_claims_with_exp(Some(now_epoch_secs()? + 60));
    let err = request_object_jti_retention(&store, &claims, 60)
        .err()
        .ok_or_else(|| "overlong Request Object lifetime must fail closed".to_string())?;

    assert_eq!(err.error, "invalid_request");
    assert_eq!(
        err.error_description,
        "Request Object exp exceeds jti replay window"
    );
    Ok(())
}
