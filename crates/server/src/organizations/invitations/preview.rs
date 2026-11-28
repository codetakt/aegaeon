//! Recipient preview and the validator retained with a conditional acceptance.
use super::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct Preview {
    issuer: String,
    #[cfg_attr(feature="openapi",schema(value_type=String,format="uuid"))]
    organization_id: Uuid,
    organization_name: String,
    roles: Vec<OfferedRole>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct OfferedRole {
    key: String,
    label: String,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub(super) enum Receipt {
    Conditional {
        membership: Membership,
        validator: String,
    },
    Legacy(Membership),
}

impl Receipt {
    pub(super) fn membership(&self) -> &Membership {
        match self {
            Self::Conditional { membership, .. } | Self::Legacy(membership) => membership,
        }
    }
    pub(super) fn validator(&self) -> Option<&str> {
        match self {
            Self::Conditional { validator, .. } => Some(validator),
            Self::Legacy(_) => None,
        }
    }
    pub(super) fn valid(&self) -> bool {
        self.validator().is_none_or(|tag| {
            tag.len() == 66
                && tag.starts_with('"')
                && tag.ends_with('"')
                && tag.as_bytes()[1..65]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Storage(#[from] RepositoryError),
    #[error("a specific strong validator is required")]
    InvalidTag,
    #[error("missing required acceptance precondition")]
    MissingTag,
}

pub(crate) enum Condition {
    Missing,
    Invalid,
    Tag(Vec<u8>),
}

impl Condition {
    pub(super) fn tag(&self, required: bool) -> Result<Option<&[u8]>, Error> {
        match self {
            Self::Missing if required => Err(Error::MissingTag),
            Self::Missing => Ok(None),
            Self::Invalid => Err(Error::InvalidTag),
            Self::Tag(tag) => Ok(Some(tag)),
        }
    }
}

pub(super) struct Metadata {
    name: String,
    revision: i64,
    roles: Vec<RoleMetadata>,
}

#[derive(Serialize)]
struct RoleMetadata {
    key: String,
    label: String,
    authority_version: i64,
    display_revision: i64,
}

pub(super) async fn details(
    tx: &mut Transaction<'_, Postgres>,
    org: &Organization,
    versions: &BTreeMap<String, i64>,
) -> Result<Option<Metadata>, RepositoryError> {
    let row=sqlx::query("SELECT display_name,display_revision FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
        .bind(org.scope.environment_id).bind(org.scope.domain_id).bind(org.id).fetch_one(&mut **tx).await?;
    let Some(name) = row.try_get::<Option<String>, _>("display_name")? else {
        return Ok(None);
    };
    let validate = crate::organizations::operators::mutations::display::valid_text;
    require(validate(&name))?;
    let offered = versions.keys().cloned().collect::<Vec<_>>();
    let rows=sqlx::query("SELECT role_key,display_label,version,display_revision FROM aegaeon.organization_role_definitions WHERE environment_id=$1 AND domain_id=$2 AND role_key=ANY($3) ORDER BY role_key COLLATE \"C\" FOR SHARE")
        .bind(org.scope.environment_id).bind(org.scope.domain_id).bind(&offered).fetch_all(&mut **tx).await?;
    if rows.len() != offered.len() {
        return Err(AuthorityError::Forbidden.into());
    }
    let mut roles = Vec::with_capacity(rows.len());
    for row in rows {
        let key: String = row.try_get("role_key")?;
        let version: i64 = row.try_get("version")?;
        if versions.get(&key) != Some(&version) {
            return Err(AuthorityError::Forbidden.into());
        }
        let Some(label) = row.try_get::<Option<String>, _>("display_label")? else {
            return Ok(None);
        };
        require(validate(&label))?;
        roles.push(RoleMetadata {
            key,
            label,
            authority_version: version,
            display_revision: row.try_get("display_revision")?,
        });
    }
    Ok(Some(Metadata {
        name,
        revision: row.try_get("display_revision")?,
        roles,
    }))
}

pub(super) async fn check_hosted_display(
    tx: &mut Transaction<'_, Postgres>,
    org: &Organization,
    authority: &Authority,
) -> Result<(), RepositoryError> {
    if let Some(client) = authority.hosted_client_registration_id {
        require(!client.is_nil())?;
        if details(tx, org, &authority.role_versions).await?.is_none() {
            return Err(AuthorityError::DisplayUnavailable.into());
        }
    }
    Ok(())
}

pub(super) async fn validated(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    org: &Organization,
    stored: &Stored,
    challenge_revision: i64,
) -> Result<(Preview, String), Error> {
    let Metadata {
        name,
        revision,
        roles,
    } = details(tx, org, &stored.authority.role_versions)
        .await?
        .ok_or_else(|| RepositoryError::from(AuthorityError::DisplayUnavailable))?;
    // Compact JSON arrays fix field order and string boundaries. Role keys use
    // the same bytewise order as the role catalog. Never encode raw proofs.
    let basis = serde_json::json!([
        "aegaeon-invitation-preview-v1",
        input.recipient.binding.issuer,
        input.scope.environment_id,
        input.scope.domain_id,
        org.id,
        stored.invitation.id,
        stored.invitation.revision,
        stored.delivery_revision,
        input.recipient,
        input.challenge_id,
        challenge_revision,
        org.revision,
        org.grant_generation,
        name,
        revision,
        roles
    ]);
    let bytes = serde_json::to_vec(&basis).map_err(RepositoryError::from)?;
    let tag = format!("\"{}\"", aegaeon_crypto::hash::sha256_hex(&bytes));
    Ok((
        Preview {
            issuer: input.recipient.binding.issuer.clone(),
            organization_id: org.id,
            organization_name: name,
            roles: roles
                .into_iter()
                .map(|r| OfferedRole {
                    key: r.key,
                    label: r.label,
                })
                .collect(),
        },
        tag,
    ))
}

pub(crate) async fn preview(
    tx: &mut Transaction<'_, Postgres>,
    input: &Acceptance<'_>,
    runtime: &delegated::Runtime<'_>,
) -> Result<(Preview, String, i64), Error> {
    let checked = acceptance::verified(tx, input, Some(runtime)).await?;
    if checked.stored.invitation.state != State::Pending {
        return Err(RepositoryError::from(AuthorityError::Forbidden).into());
    }
    let (view, tag) = validated(
        tx,
        input,
        &checked.org,
        &checked.stored,
        checked.challenge_revision,
    )
    .await?;
    Ok((view, tag, checked.expires_at))
}
