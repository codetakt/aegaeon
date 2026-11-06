use super::*;

/// The successful HTTP mint is the control; corrupt only the output presented
/// to the real atomic Redis commit. None of these candidate credentials is delivered.
pub(super) async fn refuses_changed_output(
    state: &AppState,
    source: &str,
    token: &str,
) -> TestResult {
    let subject = state
        .tokens
        .store
        .try_get_bearer_meta(source)?
        .ok_or("subject")?;
    let access = state
        .tokens
        .store
        .try_verify_access_token(token)?
        .ok_or("selected access")?;
    let meta = state
        .tokens
        .store
        .try_get_bearer_meta(token)?
        .ok_or("selected metadata")?;
    for field in [
        "auth_time",
        "acr",
        "privileges",
        "horizon",
        "client_binding",
        "details",
    ] {
        let mut access = access.clone();
        let mut output = meta.clone();
        access.token = format!("undelivered-negative-{}", uuid::Uuid::new_v4());
        output.token_id = access.token.clone();
        let selected = output
            .selected_organization
            .as_mut()
            .ok_or("selected authority")?;
        match field {
            "auth_time" => output.auth_time_epoch_secs = Some(1),
            "acr" => output.acr = Some("invented".into()),
            "privileges" => {
                selected
                    .decision
                    .privileges
                    .insert("documents.write".into());
                output.authorization_details = Some(selected.decision.authorization_details());
            }
            "horizon" => selected.parent_expires_at += 86400,
            "client_binding" => selected.client_binding_id = uuid::Uuid::new_v4(),
            _ => output.authorization_details = Some(json!([{"type":"payment"}])),
        }
        let id = access.token.clone();
        assert!(
            matches!(
                state
                    .tokens
                    .store
                    .store_exchanged_access_async(access, output, subject.clone())
                    .await,
                Err(crate::authcode::store::ExchangeCommitError::Rejected(_))
            ),
            "store failed to refuse {field}"
        );
        assert!(
            state.tokens.store.try_get_bearer_meta(&id)?.is_none(),
            "partial metadata publication: {field}"
        );
        assert!(
            state.tokens.store.try_verify_access_token(&id)?.is_none(),
            "partial token publication: {field}"
        );
    }
    Ok(())
}
