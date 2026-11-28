//! Human-managed invitation display metadata. Domain authority and receipt locks
//! serialize label patches with role configuration and invitation operations.
use super::*;
use icu_properties::{
    props::{BidiControl, DefaultIgnorableCodePoint},
    CodePointSetData,
};
use std::collections::BTreeMap;

pub(crate) type Labels = BTreeMap<String, String>;
pub(crate) type Patch = BTreeMap<String, Option<String>>;

#[derive(Clone, Copy)]
pub(crate) enum Target {
    Organization(Uuid),
    Roles,
}

impl Target {
    fn capability(self) -> Capability {
        match self {
            Self::Organization(_) => Capability::Provision,
            Self::Roles => Capability::Configure,
        }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::Organization(_) => "domain.organization.display",
            Self::Roles => "domain.roles.display",
        }
    }
    pub(crate) fn tag_prefix(self) -> &'static str {
        match self {
            Self::Organization(_) => "organization-display",
            Self::Roles => "role-display",
        }
    }
    pub(crate) fn id(self, scope: Scope) -> Uuid {
        match self {
            Self::Organization(id) => id,
            Self::Roles => scope.domain_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct OrganizationDisplay {
    #[cfg_attr(feature="openapi",schema(value_type=String,format="uuid"))]
    pub id: Uuid,
    pub revision: i64,
    pub display_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub(crate) struct RoleDisplay {
    #[cfg_attr(feature="openapi",schema(value_type=String,format="uuid"))]
    pub id: Uuid,
    pub revision: i64,
    #[cfg_attr(feature="openapi",schema(value_type=BTreeMap<String,String>))]
    pub labels: Labels,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Display {
    Roles(RoleDisplay),
    Organization(OrganizationDisplay),
}
impl Display {
    pub(crate) fn revision(&self) -> i64 {
        match self {
            Self::Roles(v) => v.revision,
            Self::Organization(v) => v.revision,
        }
    }
}

#[derive(Serialize)]
pub(crate) enum Change {
    Name(Uuid, Option<String>),
    Labels(Patch),
}

impl Change {
    pub(crate) fn target(&self) -> Target {
        match self {
            Self::Name(id, _) => Target::Organization(*id),
            Self::Labels(_) => Target::Roles,
        }
    }
}

pub(in crate::organizations) fn valid_text(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.trim() == value
        && unicode_normalization::is_nfc(value)
        && value.chars().all(|c| {
            !c.is_control()
                && !CodePointSetData::new::<BidiControl>().contains(c)
                && !CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
        })
}

async fn representation(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    target: Target,
) -> Result<Display, RepositoryError> {
    match target {
        Target::Organization(id) => {
            let row = sqlx::query("SELECT display_name,display_revision FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 AND id=$3 FOR UPDATE")
                .bind(scope.environment_id).bind(scope.domain_id).bind(id).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
            let display_name: Option<String> = row.try_get("display_name")?;
            require(display_name.as_deref().is_none_or(valid_text))?;
            Ok(Display::Organization(OrganizationDisplay {
                id,
                revision: row.try_get("display_revision")?,
                display_name,
            }))
        }
        Target::Roles => {
            let revision = sqlx::query_scalar("SELECT role_display_revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2")
                .bind(scope.environment_id).bind(scope.domain_id).fetch_one(&mut **tx).await?;
            let rows=sqlx::query("SELECT role_key,display_label FROM aegaeon.organization_role_definitions WHERE environment_id=$1 AND domain_id=$2 AND display_label IS NOT NULL ORDER BY role_key LIMIT $3")
                .bind(scope.environment_id).bind(scope.domain_id).bind((crate::organizations::MAX_ROLES+1) as i64).fetch_all(&mut **tx).await?;
            require(rows.len() <= crate::organizations::MAX_ROLES)?;
            let mut labels = Labels::new();
            for row in rows {
                let label: String = row.try_get("display_label")?;
                require(valid_text(&label))?;
                labels.insert(row.try_get("role_key")?, label);
            }
            Ok(Display::Roles(RoleDisplay {
                id: scope.domain_id,
                revision,
                labels,
            }))
        }
    }
}

pub(crate) async fn read(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
    target: Target,
) -> Result<Display, RepositoryError> {
    lock_operator_authority(tx, scope, team, principal, target.capability()).await?;
    representation(tx, scope, target).await
}

pub(crate) async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    expected: i64,
    change: &Change,
) -> Result<Display, RepositoryError> {
    let target = change.target();
    let capability = target.capability();
    receipts::validate_actor(actor, key)?;
    let authority = lock_operator_authority(tx, scope, team, actor.id, capability).await?;
    let actor = actor.with_operator(&authority, capability);
    let digest = receipts::digest(
        &serde_json::json!({"command":change,"revision":expected,"reason":actor.reason}),
    )?;
    let operation = target.operation();
    if let Some(replay) = receipts::previous(tx, scope, &actor, key, operation, &digest).await? {
        return Ok(replay);
    }
    let before = representation(tx, scope, target).await?;
    if before.revision() != expected {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    receipts::capacity(tx, scope, false).await?;
    match (change, &before) {
        (Change::Name(id, value), Display::Organization(old)) => {
            require(value.as_deref().is_none_or(valid_text))?;
            if old.display_name != *value {
                let revision = expected.checked_add(1).ok_or(AuthorityError::Exhausted)?;
                sqlx::query("UPDATE aegaeon.application_organizations SET display_name=$4, display_revision=$5 WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
                        .bind(scope.environment_id).bind(scope.domain_id).bind(id).bind(value.as_deref()).bind(revision).execute(&mut **tx).await?;
            }
        }
        (Change::Labels(patch), Display::Roles(_)) => {
            patch_labels(tx, scope, expected, patch).await?
        }
        _ => return Err(RepositoryError::Unavailable),
    }
    let result = representation(tx, scope, target).await?;
    receipts::event(tx,scope,&actor,operation,serde_json::json!({"id":target.id(scope),"before":{"revision":expected},"after":{"revision":result.revision()}})).await?;
    receipts::save(tx, scope, &actor, key, operation, &digest, &result).await?;
    Ok(result)
}

async fn patch_labels(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    expected: i64,
    patch: &Patch,
) -> Result<(), RepositoryError> {
    require(patch.len() <= crate::organizations::MAX_ROLES)?;
    let mut changed = false;
    for (key, value) in patch {
        require(value.as_deref().is_none_or(valid_text))?;
        let row=sqlx::query("SELECT display_label,display_revision FROM aegaeon.organization_role_definitions WHERE environment_id=$1 AND domain_id=$2 AND role_key=$3 FOR UPDATE")
            .bind(scope.environment_id).bind(scope.domain_id).bind(key).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Invalid)?;
        if row.try_get::<Option<String>, _>("display_label")? == *value {
            continue;
        }
        let revision = row
            .try_get::<i64, _>("display_revision")?
            .checked_add(1)
            .ok_or(AuthorityError::Exhausted)?;
        sqlx::query("UPDATE aegaeon.organization_role_definitions SET display_label=$4,display_revision=$5 WHERE environment_id=$1 AND domain_id=$2 AND role_key=$3")
            .bind(scope.environment_id).bind(scope.domain_id).bind(key).bind(value.as_deref()).bind(revision).execute(&mut **tx).await?;
        changed = true;
    }
    if changed {
        let revision = expected.checked_add(1).ok_or(AuthorityError::Exhausted)?;
        sqlx::query("UPDATE aegaeon.authorization_domains SET role_display_revision=$3 WHERE environment_id=$1 AND id=$2")
            .bind(scope.environment_id).bind(scope.domain_id).bind(revision).execute(&mut **tx).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::valid_text;
    #[test]
    fn requires_bounded_visible_nfc_text() {
        assert!(valid_text(&"é".repeat(64)));
        assert!(valid_text("研究 <A>"));
        for value in [
            "",
            "   ",
            " leading",
            "trailing\u{a0}",
            "e\u{301}",
            "a\0b",
            "名\u{202e}前",
            "a\u{fe0f}",
            "a\u{e0100}",
            "a\u{2060}",
            &"é".repeat(65),
        ] {
            assert!(!valid_text(value));
        }
    }
}
