use super::*;
use crate::organizations::request_work::Admission;

pub(crate) struct Completion<'a> {
    pub request_id: &'a str,
    pub scope: Scope,
    pub invitation: Uuid,
    pub request: Uuid,
    pub proof: &'a str,
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CompletionResult {
    pub user_id: Uuid,
    pub subject: String,
    pub credential_id: Uuid,
    pub identity_revision: i64,
}

pub(crate) async fn complete(
    tx: &mut Transaction<'_, Postgres>,
    input: &Completion<'_>,
    password: String,
    admission: &Admission,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<CompletionResult, RepositoryError> {
    crate::local_credentials::validate_password(&password).map_err(|_| AuthorityError::Invalid)?;
    let pending = pending(
        tx,
        input.scope,
        input.invitation,
        input.request,
        input.now,
        runtime,
    )
    .await?;
    require(matches_secret(
        input.scope,
        pending.id,
        pending.revision,
        pending.purpose.capability(),
        pending.hash.as_deref(),
        input.proof,
    ))?;
    let replay = if let Some(result) = &pending.result {
        Some(
            credential(
                tx,
                input.scope,
                &pending,
                result.user_id,
                result.identity_revision,
                Some(result.credential_id),
            )
            .await?,
        )
    } else {
        if pending.purpose == Purpose::PasswordRecovery {
            let (id, revision) = pending.target.ok_or(AuthorityError::Forbidden)?;
            credential(tx, input.scope, &pending, id, revision, None).await?;
        }
        None
    };
    let password_hash = password_work(password, replay, admission).await?;
    if let Some(result) = pending.result {
        return Ok(result);
    }
    let user = match pending.purpose {
        Purpose::Registration => register(tx, input.scope, &pending.invitation.recipient).await?,
        Purpose::PasswordRecovery => pending.target.ok_or(AuthorityError::Forbidden)?.0,
    };
    let credential_id: Uuid = sqlx::query_scalar("INSERT INTO aegaeon.end_user_password_credentials(end_user_id,password_hash,status) VALUES ($1,$2,'ACTIVE') ON CONFLICT(end_user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,status='ACTIVE',revoked_by_administrator_id=NULL,last_used_at=NULL,updated_at=now() RETURNING id")
        .bind(user).bind(password_hash.ok_or(AuthorityError::Forbidden)?).fetch_one(&mut **tx).await?;
    sqlx::query("UPDATE aegaeon.end_user_recovery_tokens SET revoked_at=now() WHERE end_user_id=$1 AND redeemed_at IS NULL AND revoked_at IS NULL")
        .bind(user).execute(&mut **tx).await?;
    let row = sqlx::query(
        "SELECT subject,organization_identity_revision FROM aegaeon.end_users WHERE id=$1",
    )
    .bind(user)
    .fetch_one(&mut **tx)
    .await?;
    let result = CompletionResult {
        user_id: user,
        subject: row.try_get("subject")?,
        credential_id,
        identity_revision: row.try_get("organization_identity_revision")?,
    };
    require((1..i64::MAX).contains(&result.identity_revision))?;
    sqlx::query(
        "UPDATE aegaeon.organization_identity_requests SET state='completed',result=$2 WHERE id=$1",
    )
    .bind(input.request)
    .bind(serde_json::to_value(&result)?)
    .execute(&mut **tx)
    .await?;
    let actor = audit::executor(
        &pending.invitation,
        input.request_id,
        "invitation identity completion",
        &serde_json::json!({"kind":"recipient_identity_proof","objectId":input.request,"deliveryRevision":pending.revision,"userId":user,"identityRevision":result.identity_revision}),
    )?;
    repo::event(tx,&pending.org,&actor,"organization.identity_completed",
        serde_json::json!({"request_id":input.request,"invitation_id":input.invitation,"purpose":pending.purpose,
            "user_id":user,"before_identity_revision":pending.target.map(|v|v.1),"identity_revision":result.identity_revision,
            "before":{"state":"pending","identityRevision":pending.target.map(|v|v.1)},"after":{"state":"completed","identityRevision":result.identity_revision}})).await?;
    Ok(result)
}

async fn password_work(
    password: String,
    existing: Option<String>,
    admission: &Admission,
) -> Result<Option<String>, RepositoryError> {
    admission
        .blocking(move || {
            // The owned permit survives response timeout and task cancellation.
            if let Some(hash) = existing {
                // This replay verifier was generated here, with fixed Argon2 costs.
                // Refuse an altered PHC cost before allocating attacker-sized work.
                require(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$") && hash.len() <= 128)?;
                if !crate::local_credentials::verify_password(&password, &hash) {
                    return Err(AuthorityError::Conflict.into());
                }
                Ok(None)
            } else {
                crate::local_credentials::hash_password(&password)
                    .map(Some)
                    .map_err(|_| {
                        sqlx::Error::Protocol("identity password supplier unavailable".into())
                            .into()
                    })
            }
        })
        .await
        .map_err(|_| sqlx::Error::Protocol("identity password worker unavailable".into()))?
}

async fn register(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    address: &str,
) -> Result<Uuid, RepositoryError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM aegaeon.end_users WHERE environment_id=$1 AND email=lower($2))")
        .bind(scope.environment_id).bind(address).fetch_one(&mut **tx).await?;
    if exists {
        return Err(AuthorityError::Conflict.into());
    }
    let id = Uuid::new_v4();
    let email = address.to_ascii_lowercase();
    sqlx::query("INSERT INTO aegaeon.end_users(id,environment_id,subject,email,status) VALUES ($1,$2,$3,$4,'ACTIVE')")
        .bind(id).bind(scope.environment_id).bind(id.to_string()).bind(&email).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO aegaeon.end_user_profiles(end_user_id,email_verified,verified_delivery_address) VALUES ($1,$2,$3)")
        .bind(id).bind(email == address).bind(address).execute(&mut **tx).await?;
    Ok(id)
}

async fn credential(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    pending: &Pending,
    id: Uuid,
    revision: i64,
    expected_credential: Option<Uuid>,
) -> Result<String, RepositoryError> {
    let row = sqlx::query("SELECT u.email,u.organization_identity_revision AS revision,p.email_verified,p.verified_delivery_address FROM aegaeon.end_users u LEFT JOIN aegaeon.end_user_profiles p ON p.end_user_id=u.id WHERE u.environment_id=$1 AND u.id=$2 AND u.status='ACTIVE' FOR UPDATE OF u")
        .bind(scope.environment_id).bind(id).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    require(
        (1..i64::MAX).contains(&revision)
            && row.try_get::<i64, _>("revision")? == revision
            && verified_address(&row, &pending.invitation.recipient)?,
    )?;
    let row = sqlx::query("SELECT id,password_hash FROM aegaeon.end_user_password_credentials WHERE end_user_id=$1 AND status='ACTIVE' FOR UPDATE")
        .bind(id).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    require(expected_credential.is_none_or(|expected| row.get::<Uuid, _>("id") == expected))?;
    Ok(row.try_get("password_hash")?)
}

pub(crate) async fn recheck(
    tx: &mut Transaction<'_, Postgres>,
    input: &Completion<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<(), RepositoryError> {
    let pending = pending(
        tx,
        input.scope,
        input.invitation,
        input.request,
        input.now,
        runtime,
    )
    .await?;
    let result = pending.result.as_ref().ok_or(AuthorityError::Forbidden)?;
    credential(
        tx,
        input.scope,
        &pending,
        result.user_id,
        result.identity_revision,
        Some(result.credential_id),
    )
    .await?;
    Ok(())
}
