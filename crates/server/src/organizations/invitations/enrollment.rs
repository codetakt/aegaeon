//! Invitation-bound identity creation and password recovery. No session or
//! membership is created here; the caller owns authenticated delivery and CSRF.
use super::*;
use crate::organizations::operators::mutations::identity_policy;

mod completion;
pub(crate) mod delivery;
pub(crate) use completion::recheck as recheck_completion;
pub(crate) use completion::{complete, Completion, CompletionResult};

pub(crate) const MAX_REQUESTS_PER_ENVIRONMENT: i64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Purpose {
    Registration,
    PasswordRecovery,
}
impl Purpose {
    fn capability(self) -> cap::Purpose {
        match self {
            Self::Registration => cap::Purpose::IdentityRegistration,
            Self::PasswordRecovery => cap::Purpose::IdentityRecovery,
        }
    }
    fn key(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::PasswordRecovery => "password_recovery",
        }
    }
}

pub(crate) struct Request<'a> {
    pub request_id: &'a str,
    pub scope: Scope,
    pub invitation: Uuid,
    pub capability: &'a str,
    pub purpose: Purpose,
    pub login_identifier: Option<&'a str>,
    pub key: &'a str,
    pub now: i64,
}

struct Pending {
    id: Uuid,
    invitation: Stored,
    org: Organization,
    purpose: Purpose,
    target: Option<(Uuid, i64)>,
    expires: i64,
    result: Option<CompletionResult>,
    revision: i64,
    delivered_at: Option<i64>,
    outcome: String,
    hash: Option<Vec<u8>>,
}

async fn lock(tx: &mut Transaction<'_, Postgres>, scope: Scope) -> Result<(), RepositoryError> {
    scope.validate()?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('organization.identity-policy:' || $1::text,0))")
        .bind(scope.environment_id.to_string()).execute(&mut **tx).await?;
    Ok(())
}

async fn policy(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    purpose: Purpose,
) -> Result<i64, RepositoryError> {
    let configuration = identity_policy::read_locked(tx, scope.environment_id).await?;
    let policy = configuration.policy.ok_or(AuthorityError::Forbidden)?;
    require(
        configuration.revision < i64::MAX
            && match purpose {
                Purpose::Registration => policy.registration,
                Purpose::PasswordRecovery => policy.password_recovery,
            },
    )?;
    Ok(configuration.revision)
}

pub(crate) async fn request(
    tx: &mut Transaction<'_, Postgres>,
    input: &Request<'_>,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Uuid, RepositoryError> {
    request_key(input.key)?;
    validate_identifier(input)?;
    lock(tx, input.scope).await?;
    let stored = load(tx, input.scope, input.invitation).await?;
    let org = current_with_runtime(tx, input.scope, &stored, input.now, runtime).await?;
    require(
        stored.invitation.state == State::Pending
            && matches_secret(
                input.scope,
                input.invitation,
                stored.delivery_revision,
                cap::Purpose::Invitation,
                stored.hash.as_deref(),
                input.capability,
            ),
    )?;
    let policy_revision = policy(tx, input.scope, input.purpose).await?;
    // A request without a configured delivery supplier would create unusable authority.
    require(
        operators::mutations::delivery::read_locked(tx, input.scope)
            .await?
            .channel
            .is_some(),
    )?;
    let digest = aegaeon_crypto::hash::sha256_digest(&serde_json::to_vec(&serde_json::json!({
        "purpose":input.purpose,"identifier":input.login_identifier,
        "invitation_revision":stored.delivery_revision,"policy_revision":policy_revision,
    }))?);
    let old = sqlx::query("SELECT id,request_digest,expires_at FROM aegaeon.organization_identity_requests WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND request_key=$4")
        .bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation).bind(input.key).fetch_optional(&mut **tx).await?;
    if let Some(old) = old {
        if old.try_get::<Vec<u8>, _>("request_digest")? != digest {
            return Err(AuthorityError::Conflict.into());
        }
        require(input.now < old.try_get::<i64, _>("expires_at")?)?;
        return Ok(old.try_get("id")?);
    }
    capacity(tx, input.scope, input.invitation).await?;
    let target = match (input.purpose, input.login_identifier) {
        (Purpose::PasswordRecovery, Some(identifier)) => {
            find_target(tx, input.scope, identifier, &stored.recipient).await?
        }
        _ => None,
    };
    let id = Uuid::new_v4();
    let expires = input
        .now
        .checked_add(cap::IDENTITY_PROOF_SECONDS)
        .ok_or(AuthorityError::Exhausted)?
        .min(stored.invitation.expires_at);
    sqlx::query("INSERT INTO aegaeon.organization_identity_requests(id,environment_id,domain_id,invitation_id,invitation_delivery_revision,policy_revision,purpose,request_key,request_digest,target_user_id,target_identity_revision,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(id).bind(input.scope.environment_id).bind(input.scope.domain_id).bind(input.invitation)
        .bind(stored.delivery_revision).bind(policy_revision).bind(input.purpose.key()).bind(input.key).bind(digest.as_slice())
        .bind(target.map(|v|v.0)).bind(target.map(|v|v.1)).bind(input.now).bind(expires).execute(&mut **tx).await?;
    let actor = audit::executor(
        &stored,
        input.request_id,
        "invitation identity request",
        &serde_json::json!({"kind":"invitation_capability","objectId":input.invitation,"deliveryRevision":stored.delivery_revision,"policyRevision":policy_revision}),
    )?;
    repo::event(tx,&org,&actor,"organization.identity_requested",
        serde_json::json!({"invitation_id":input.invitation,"request_id":id,"purpose":input.purpose,"policy_revision":policy_revision,"before":null,"after":{"state":"pending","deliveryRevision":0}})).await?;
    Ok(id)
}

fn validate_identifier(input: &Request<'_>) -> Result<(), AuthorityError> {
    match input.purpose {
        Purpose::Registration => require(input.login_identifier.is_none()),
        Purpose::PasswordRecovery => require(input.login_identifier.is_some_and(|v| {
            !v.is_empty() && v.len() <= 255 && v.trim() == v && !v.chars().any(char::is_control)
        })),
    }
}

async fn capacity(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
) -> Result<(), RepositoryError> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_identity_requests WHERE environment_id=$1 LIMIT $2) bounded")
        .bind(scope.environment_id).bind(MAX_REQUESTS_PER_ENVIRONMENT).fetch_one(&mut **tx).await?;
    let per_invitation: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_identity_requests WHERE invitation_id=$1 LIMIT 5) bounded")
        .bind(invitation).fetch_one(&mut **tx).await?;
    if count >= MAX_REQUESTS_PER_ENVIRONMENT || per_invitation >= 5 {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}

async fn find_target(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    identifier: &str,
    address: &str,
) -> Result<Option<(Uuid, i64)>, RepositoryError> {
    // Match ordinary password login before considering mailbox ownership, so
    // ambiguity is refused instead of choosing whichever account has a proof.
    let rows = sqlx::query("SELECT u.id,u.organization_identity_revision AS revision,u.email,p.email_verified,p.verified_delivery_address FROM aegaeon.end_users u JOIN aegaeon.end_user_password_credentials c ON c.end_user_id=u.id AND c.status='ACTIVE' LEFT JOIN aegaeon.end_user_profiles p ON p.end_user_id=u.id WHERE u.environment_id=$1 AND u.status='ACTIVE' AND (($3 AND u.email=lower($2)) OR (NOT $3 AND u.subject=$2 COLLATE \"C\")) ORDER BY u.id LIMIT 2 FOR SHARE OF u,c")
        .bind(scope.environment_id).bind(identifier).bind(identifier.contains('@')).fetch_all(&mut **tx).await?;
    if rows.len() != 1 {
        return Ok(None);
    }
    let row = &rows[0];
    let revision: i64 = row.try_get("revision")?;
    Ok(
        (verified_address(row, address)? && (1..i64::MAX).contains(&revision))
            .then(|| (row.get("id"), revision)),
    )
}

fn verified_address(row: &sqlx::postgres::PgRow, address: &str) -> Result<bool, sqlx::Error> {
    let exact: Option<String> = row.try_get("verified_delivery_address")?;
    Ok(exact.as_deref() == Some(address)
        || (exact.is_none()
            && row.try_get::<Option<bool>, _>("email_verified")? == Some(true)
            && row.try_get::<Option<String>, _>("email")?.as_deref() == Some(address)))
}

async fn pending(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    id: Uuid,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Pending, RepositoryError> {
    lock(tx, scope).await?;
    let stored = load(tx, scope, invitation).await?;
    let org = current_with_runtime(tx, scope, &stored, now, runtime).await?;
    require(stored.invitation.state == State::Pending)?;
    let row = sqlx::query("SELECT * FROM aegaeon.organization_identity_requests WHERE environment_id=$1 AND domain_id=$2 AND invitation_id=$3 AND id=$4 FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(invitation).bind(id).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let purpose: Purpose =
        serde_json::from_value(serde_json::json!(row.try_get::<String, _>("purpose")?))?;
    let expires = row.try_get("expires_at")?;
    require(
        policy(tx, scope, purpose).await? == row.try_get::<i64, _>("policy_revision")?
            && stored.delivery_revision == row.try_get::<i64, _>("invitation_delivery_revision")?
            && cap::is_live(
                purpose.capability(),
                row.try_get("issued_at")?,
                expires,
                now,
            ),
    )?;
    let result: Option<CompletionResult> = row
        .try_get::<Option<serde_json::Value>, _>("result")?
        .map(serde_json::from_value)
        .transpose()?;
    require((row.try_get::<String, _>("state")? == "completed") == result.is_some())?;
    Ok(Pending {
        id,
        invitation: stored,
        org,
        purpose,
        expires,
        result,
        target: row
            .try_get::<Option<Uuid>, _>("target_user_id")?
            .zip(row.try_get("target_identity_revision")?),
        revision: row.try_get("delivery_revision")?,
        delivered_at: row.try_get("delivered_at")?,
        outcome: row.try_get("delivery_outcome")?,
        hash: row.try_get("capability_hash")?,
    })
}
