//! Explicit proof/message replacement under the selected runtime and credential.
use super::{organization_authority, AppState};
use crate::organizations::{
    invitations::{self, durable, transport},
    request_work::async_store,
    Scope,
};
use uuid::Uuid;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NotificationReissueRequest {
    pub domain_id: Uuid,
    pub invitation_id: Uuid,
    pub challenge_id: Option<Uuid>,
    pub identity_request_id: Option<Uuid>,
    pub expected_delivery_revision: i64,
    pub operation_id: Uuid,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationReissueResult {
    pub message_id: Uuid,
    pub delivery_revision: i64,
    pub expires_at: i64,
}

impl AppState {
    pub(crate) async fn reissue_notification(
        &self,
        input: &NotificationReissueRequest,
        credential: &transport::Credential,
    ) -> Result<NotificationReissueResult, ()> {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            execute(self, input, credential),
        )
        .await
        .map_err(|_| ())?
    }
}

async fn execute(
    state: &AppState,
    input: &NotificationReissueRequest,
    credential: &transport::Credential,
) -> Result<NotificationReissueResult, ()> {
    state.require_subject_namespace().map_err(|_| ())?;
    let owner = async_store::current_epoch_owner(state.environment_id).map_err(|_| ())?;
    let expected = organization_authority::projection(state).map_err(|_| ())?;
    let mut connection = owner.connection(&state.db_pool).await.map_err(|_| ())?;
    let scope = Scope {
        environment_id: state.environment_id,
        domain_id: input.domain_id,
    };
    let runtime = invitations::delegated::Runtime {
        store: &state.tokens.store,
        admission: &owner,
        issuer: &state.issuer,
    };
    let now = || {
        crate::util::now_unix_epoch_secs()
            .ok()
            .and_then(|v| i64::try_from(v).ok())
            .ok_or(())
    };
    let mut tx = connection.begin().await.map_err(|_| ())?;
    let result = durable::reissue(
        &mut tx,
        &durable::Reissue {
            scope,
            invitation: input.invitation_id,
            challenge: input.challenge_id,
            identity_request: input.identity_request_id,
            expected_delivery_revision: input.expected_delivery_revision,
            operation: input.operation_id,
        },
        &credential.digest(),
        now()?,
        Some(&runtime),
    )
    .await
    .map_err(|_| ())?;
    organization_authority::recheck_projection(state, &mut tx, &expected)
        .await
        .map_err(|_| ())?;
    invitations::recheck(&mut tx, scope, input.invitation_id, now()?, &runtime)
        .await
        .map_err(|_| ())?;
    owner.admit_commit().map_err(|_| ())?;
    // Unknown completion is reconciled by repeating the same operation ID and
    // exact input; it never creates another proof or extends the deadline.
    tx.commit().await.map_err(|_| ())?;
    connection.release().await;
    Ok(NotificationReissueResult {
        message_id: result.message_id,
        delivery_revision: result.delivery_revision,
        expires_at: result.expires_at,
    })
}
